"""Discover the host network and apply selected Ethernet settings with rollback."""
from __future__ import annotations
import base64
import copy
import fnmatch
import ipaddress
import json
import os
import platform
import pty
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Literal

import psutil
import yaml
from pydantic import BaseModel, Field, model_validator

NETPLAN_DIR = Path('/etc/netplan')
SYS_NET = Path('/sys/class/net')
NAME = r'^[a-zA-Z][a-zA-Z0-9_.-]{0,14}$'
_process = None
_master = None
_mutex = threading.RLock()


def command(*args):
    proc = subprocess.run(list(args), capture_output=True, text=True, timeout=15)
    if proc.returncode:
        raise RuntimeError(f'Не удалось выполнить {args[0]} (код {proc.returncode})')
    return proc.stdout.strip()


def merge(a, b):
    out = copy.deepcopy(a)
    for key, value in b.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = merge(out[key], value)
        elif isinstance(value, list) and isinstance(out.get(key), list):
            out[key] = out[key] + value
        else:
            out[key] = copy.deepcopy(value)
    return out


def documents():
    result = {}
    if NETPLAN_DIR.exists():
        for path in sorted(set(NETPLAN_DIR.glob('*.yaml')) | set(NETPLAN_DIR.glob('*.yml'))):
            if path.is_symlink():
                raise RuntimeError('Netplan содержит символьную ссылку; проверьте конфигурацию вручную')
            content = path.read_text()
            data = yaml.safe_load(content) or {}
            if not isinstance(data, dict):
                raise RuntimeError('Некорректная конфигурация Netplan')
            result[path] = (content, data)
    return result


def effective_config(docs):
    merged = {}
    for _, data in docs.values():
        merged = merge(merged, data)
    return merged.get('network', {})


def matching(network, name, mac):
    found = []
    for key, entry in network.get('ethernets', {}).items():
        match = entry.get('match', {})
        if (mac and str(match.get('macaddress', '')).lower() == mac.lower()) or entry.get('set-name') == name or (not match and key == name) or (match.get('name') and fnmatch.fnmatch(name, match['name'])):
            found.append((key, entry))
    return found


def discover():
    from . import privilege
    if privilege.enabled():
        return privilege.call("discover")
    stats = psutil.net_if_stats()
    addresses = psutil.net_if_addrs()
    linux = platform.system() == 'Linux'
    netplan = bool(linux and __import__('shutil').which('netplan'))
    network = {}
    config_error = ''
    try:
        network = effective_config(documents()) if netplan else {}
    except (OSError, ValueError, yaml.YAMLError, RuntimeError):
        config_error = 'Не удалось прочитать настройки Netplan'
    result = []
    for name in sorted(set(stats) | set(addresses)):
        addrs = addresses.get(name, [])
        mac = next((a.address.lower() for a in addrs if a.family == psutil.AF_LINK and a.address), '')
        flags = getattr(stats.get(name), 'flags', '')
        loopback = 'loopback' in flags or name in ('lo', 'lo0')
        physical = (SYS_NET / name / 'device').exists() if linux else name.startswith('en')
        wireless = (SYS_NET / name / 'wireless').exists() if linux else False
        ips = []
        for addr in addrs:
            if addr.family not in (socket.AF_INET, socket.AF_INET6):
                continue
            value = addr.address.split('%')[0]
            try:
                prefix = bin(int(ipaddress.ip_address((addr.netmask or '').split('%')[0]))).count('1')
            except ValueError:
                prefix = 32 if addr.family == socket.AF_INET else 128
            ips.append({'address': value, 'prefix': prefix, 'family': 4 if addr.family == socket.AF_INET else 6})
        candidates = matching(network, name, mac)
        entry = candidates[0][1] if len(candidates) == 1 else {}
        method = 'dhcp' if entry.get('dhcp4') is True else 'static' if entry.get('addresses') or entry.get('dhcp4') is False else 'unknown'
        if not linux and name.startswith('en'):
            try:
                if command('/usr/sbin/ipconfig', 'getpacket', name):
                    method = 'dhcp'
            except (OSError, RuntimeError, subprocess.TimeoutExpired):
                pass
        gateway = entry.get('gateway4', '')
        gateway = next((r.get('via', '') for r in entry.get('routes', []) if r.get('to') in ('default', '0.0.0.0/0') and ':' not in r.get('via', '')), gateway)
        result.append({'id': mac + '@' + name if mac else name, 'name': name, 'mac': mac,
                       'up': bool(getattr(stats.get(name), 'isup', False)), 'mtu': getattr(stats.get(name), 'mtu', 0),
                       'addresses': ips, 'method': method, 'gateway': gateway,
                       'dns': entry.get('nameservers', {}).get('addresses', []),
                       'kind': 'loopback' if loopback else 'wifi' if wireless else 'ethernet' if physical else 'virtual',
                       'selectable': physical and not loopback,
                       'editable': bool(netplan and physical and not wireless and mac and len(candidates) <= 1 and not config_error)})
    return {'interfaces': result, 'canApply': netplan and not config_error,
            'manager': 'Netplan' if netplan else 'Системные настройки',
            'message': config_error or ('' if netplan else 'Текущие адреса определены. Изменение системного IP и имени через мастер доступно на Linux с Netplan.')}


class HostInterfaceIn(BaseModel):
    id: str = Field(min_length=1, max_length=100)
    purpose: Literal['employees', 'routers', 'custom', 'later'] = 'later'
    originalName: str = Field(pattern=NAME)
    name: str = Field(pattern=NAME)
    mode: Literal['keep', 'dhcp', 'static'] = 'keep'
    address: str = Field(default='', max_length=50)
    gateway: str = Field(default='', max_length=50)
    dns: list[str] = Field(default_factory=list, max_length=6)

    @model_validator(mode='after')
    def validate_address(self):
        if self.mode == 'static':
            addr = ipaddress.ip_interface(self.address)
            if addr.version != 4 or addr.ip.is_unspecified or addr.ip.is_multicast or addr.ip.is_loopback:
                raise ValueError('Укажите IPv4-адрес интерфейса с маской, например 192.168.1.10/24')
            if addr.network.prefixlen < 31 and addr.ip in (addr.network.network_address, addr.network.broadcast_address):
                raise ValueError('Нельзя назначить адрес сети или broadcast')
            if self.gateway:
                gateway = ipaddress.IPv4Address(self.gateway)
                if gateway not in addr.network or gateway == addr.ip or (addr.network.prefixlen < 31 and gateway in (addr.network.network_address, addr.network.broadcast_address)):
                    raise ValueError('Шлюз должен быть другим адресом в подсети интерфейса')
        for value in self.dns:
            ipaddress.ip_address(value)
        return self


class HostPlanIn(BaseModel):
    interfaces: list[HostInterfaceIn] = Field(default_factory=list, max_length=64)

    @model_validator(mode='after')
    def unique(self):
        if len({i.id for i in self.interfaces}) != len(self.interfaces) or len({i.name for i in self.interfaces}) != len(self.interfaces):
            raise ValueError('Интерфейсы и их новые имена не должны повторяться')
        return self


def changes(plan):
    return [p for p in plan if p['mode'] != 'keep' or p['name'] != p['originalName']]


def validate_plan(plan, inventory):
    by_id = {item['id']: item for item in inventory['interfaces']}
    all_names = {item['name'] for item in inventory['interfaces']}
    for item in plan:
        detected = by_id.get(item['id'])
        if not detected or detected['name'] != item['originalName']:
            raise RuntimeError('Состав интерфейсов изменился. Обновите обнаружение')
        changed = item['mode'] != 'keep' or item['name'] != item['originalName']
        if changed and not detected['editable']:
            raise RuntimeError(f"Изменение {detected['name']} через мастер недоступно; оставьте текущие настройки")
        if item['name'] != item['originalName'] and item['name'] in all_names:
            raise RuntimeError(f"Имя {item['name']} уже занято другим интерфейсом")


def build_documents(plan, inventory, docs):
    network = effective_config(docs)
    updated = {path: copy.deepcopy(data) for path, (_, data) in docs.items()}
    managed = NETPLAN_DIR / '99-kontur-first-run.yaml'
    output = updated.setdefault(managed, {'network': {'version': 2}})['network'].setdefault('ethernets', {})
    by_id = {item['id']: item for item in inventory['interfaces']}
    for item in changes(plan):
        detected = by_id[item['id']]
        found = matching(network, item['originalName'], detected['mac'])
        if len(found) > 1:
            raise RuntimeError('Несколько настроек Netplan относятся к одному интерфейсу')
        if not found and item['mode'] == 'keep':
            raise RuntimeError('Для переименования этой карты выберите DHCP или задайте IP вручную: текущая конфигурация не найдена в Netplan')
        key, entry = found[0] if found else ('kontur-' + detected['mac'].replace(':', ''), {})
        entry = copy.deepcopy(entry)
        # Move only the selected adapter definition, preserving other devices.
        for data in updated.values():
            data.get('network', {}).get('ethernets', {}).pop(key, None)
        entry.setdefault('renderer', network.get('renderer', 'networkd'))
        entry.setdefault('match', {})['macaddress'] = detected['mac']
        entry['match'].pop('name', None)
        entry['set-name'] = item['name']
        if item['mode'] != 'keep':
            entry['dhcp4'] = item['mode'] == 'dhcp'
            ipv6_addresses = [a for a in entry.get('addresses', []) if isinstance(a, str) and ':' in a]
            entry['addresses'] = ipv6_addresses + ([item['address']] if item['mode'] == 'static' else [])
            entry.pop('gateway4', None)
            routes = [r for r in entry.get('routes', []) if r.get('to') not in ('default', '0.0.0.0/0') or ':' in str(r.get('via', ''))]
            if item['mode'] == 'static' and item['gateway']:
                routes.append({'to': 'default', 'via': item['gateway']})
            entry['routes'] = routes
            if item['dns']:
                entry.setdefault('nameservers', {})['addresses'] = item['dns']
            elif item['mode'] == 'dhcp':
                entry.pop('nameservers', None)
        output[key] = entry
    return updated


def atomic_write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix='.kontur-')
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(content)
            stream.flush(); os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def state_path(data_dir):
    return data_dir / 'network-transaction' / 'state.json'


def transaction(data_dir):
    path = state_path(data_dir)
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return {'status': 'none'}


def public_transaction(data_dir):
    from . import privilege
    if privilege.enabled():
        return privilege.call("network_status")
    state = transaction(data_dir)
    return {key: state.get(key) for key in ('status', 'expiresAt', 'error') if key in state}


def restore(data_dir):
    state = transaction(data_dir)
    if state.get('status') not in ('pending', 'applying', 'rollback_failed'):
        return
    try:
        for path_str, content in state['backup'].items():
            path = Path(path_str)
            if path.parent != NETPLAN_DIR or path.is_symlink():
                raise RuntimeError('Небезопасный путь восстановления Netplan')
            if content is None:
                path.unlink(missing_ok=True)
            else:
                atomic_write(path, base64.b64decode(content).decode())
        command('netplan', 'apply')
        state['status'] = 'rolled_back'
        state['error'] = 'Изменения сети отменены. Проверьте адрес, шлюз и имя интерфейса.'
    except Exception:
        state['status'] = 'rollback_failed'
        state['error'] = 'Автоматическое восстановление сети не завершено. Используйте консоль сервера и сохранённую копию настроек.'
    atomic_write(state_path(data_dir), json.dumps(state))


def watch_rollback(data_dir):
    while True:
        state = transaction(data_dir)
        if state.get('status') not in ('pending', 'applying'):
            return
        if time.time() >= state['expiresAt']:
            restore(data_dir); return
        time.sleep(1)


def drain(master):
    try:
        while os.read(master, 4096):
            pass
    except OSError:
        pass
    finally:
        os.close(master)


def apply(plan, data_dir):
    from . import privilege
    if privilege.enabled():
        return privilege.call("network_apply", plan=plan)
    global _process, _master
    with _mutex:
        state = transaction(data_dir)
        if state.get('status') in ('pending', 'applying', 'rollback_failed'):
            raise RuntimeError('Сначала подтвердите или отмените предыдущую настройку сети')
        inventory = discover()
        validate_plan(plan, inventory)
        if not changes(plan):
            return {'status': 'unchanged'}
        if platform.system() != 'Linux' or os.geteuid() != 0:
            raise RuntimeError('Для настройки IP и имени нужен Linux с Netplan и права root')
        docs = documents()
        updated = build_documents(plan, inventory, docs)
        backup = {str(path): base64.b64encode(docs[path][0].encode()).decode() if path in docs else None for path in updated}
        state = {'status': 'applying', 'expiresAt': time.time() + 150, 'backup': backup, 'plan': plan}
        atomic_write(state_path(data_dir), json.dumps(state))
        try:
            # Independent watchdog survives a backend restart or crash.
            subprocess.Popen([sys.executable, '-m', 'app.host_network', '--rollback', str(data_dir)],
                             cwd=Path(__file__).resolve().parents[1], stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            for path, data in updated.items():
                atomic_write(path, yaml.safe_dump(data, allow_unicode=True, sort_keys=False))
            command('netplan', 'generate')
            _master, slave = pty.openpty()
            try:
                _process = subprocess.Popen(['netplan', 'try', '--timeout', '120'], stdin=slave, stdout=slave,
                                            stderr=slave, start_new_session=True)
            finally:
                os.close(slave)
            threading.Thread(target=drain, args=(_master,), daemon=True).start()
            state['pid'] = _process.pid
            state['status'] = 'pending'
            atomic_write(state_path(data_dir), json.dumps(state))
            return public_transaction(data_dir)
        except Exception:
            restore(data_dir)
            message = 'Откат не завершён; проверьте сеть в консоли сервера.' if transaction(data_dir).get('status') == 'rollback_failed' else 'Исходные настройки Netplan восстановлены.'
            raise RuntimeError('Не удалось применить настройки сети. ' + message)


def matches_live(plan, inventory):
    by_name = {item['name']: item for item in inventory['interfaces']}
    for item in changes(plan):
        actual = by_name.get(item['name'])
        if not actual or not actual['up']:
            return False
        ipv4 = [a for a in actual['addresses'] if a['family'] == 4]
        if item['mode'] == 'static':
            wanted = ipaddress.ip_interface(item['address'])
            if not any(a['address'] == str(wanted.ip) and a['prefix'] == wanted.network.prefixlen for a in ipv4):
                return False
        elif item['mode'] == 'dhcp' and not ipv4:
            return False
    return True


def confirm(data_dir):
    from . import privilege
    if privilege.enabled():
        return privilege.call("network_confirm")
    with _mutex:
        state = transaction(data_dir)
        if state.get('status') != 'pending' or time.time() >= state['expiresAt'] - 35:
            raise RuntimeError('Время подтверждения истекло. Дождитесь восстановления сети')
        if not matches_live(state['plan'], discover()):
            raise RuntimeError('Новые адреса ещё не получены или интерфейсы не активны. Повторите проверку связи')
        try:
            proc = psutil.Process(state['pid'])
            if 'netplan' not in ' '.join(proc.cmdline()) or 'try' not in proc.cmdline():
                raise RuntimeError('Пробный запуск Netplan уже завершён')
            if _process is None or _process.pid != state['pid']:
                raise RuntimeError('Backend перезапущен во время изменения сети. Дождитесь отката и повторите настройку')
            os.kill(state['pid'], signal.SIGUSR1)
            _process.wait(timeout=10)
            if _process.returncode != 0:
                raise RuntimeError('Netplan не подтвердил изменения')
        except (psutil.Error, OSError, subprocess.TimeoutExpired):
            raise RuntimeError('Не удалось подтвердить сеть. Дождитесь автоматического отката')
        state['status'] = 'confirmed'
        state.pop('backup', None)
        atomic_write(state_path(data_dir), json.dumps(state))
        return public_transaction(data_dir)


def cancel(data_dir):
    from . import privilege
    if privilege.enabled():
        return privilege.call("network_cancel")
    state = transaction(data_dir)
    if state.get('status') not in ('pending', 'applying'):
        return public_transaction(data_dir)
    try:
        proc = psutil.Process(state['pid'])
        if 'netplan' in ' '.join(proc.cmdline()) and 'try' in proc.cmdline():
            os.kill(state['pid'], signal.SIGINT)
            if _process is not None:
                _process.wait(timeout=15)
    except (KeyError, psutil.Error, OSError, subprocess.TimeoutExpired):
        pass
    restore(data_dir)
    return public_transaction(data_dir)


if __name__ == '__main__' and len(sys.argv) == 3 and sys.argv[1] == '--rollback':
    watch_rollback(Path(sys.argv[2]))
