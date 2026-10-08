"""Local listener and firewall checks. External reachability is a separate test."""
import json
import platform
import re
import socket
import subprocess

import psutil


def read_listeners():
    try:
        if platform.system() == 'Linux':
            proc = subprocess.run(['ss', '-H', '-lntu'], capture_output=True, text=True, timeout=5)
            if proc.returncode:
                raise OSError('ss failed')
            ports = []
            for line in proc.stdout.splitlines():
                fields = line.split()
                if len(fields) < 5 or fields[0] not in ('tcp', 'udp'):
                    continue
                endpoint = fields[4]
                match = re.fullmatch(r'(.+):(\d+)', endpoint)
                if match:
                    address, port = match.groups()
                    ports.append({'protocol': fields[0].upper(), 'address': address.strip('[]'), 'port': int(port)})
        else:
            ports = [{'protocol': 'TCP' if c.type == socket.SOCK_STREAM else 'UDP',
                      'address': c.laddr.ip, 'port': c.laddr.port}
                     for c in psutil.net_connections(kind='inet')
                     if c.laddr and (c.type == socket.SOCK_DGRAM or c.status == psutil.CONN_LISTEN)]
        unique = {(p['protocol'], p['address'], p['port']): p for p in ports}
        return {'available': True, 'ports': sorted(unique.values(), key=lambda p: (p['port'], p['protocol'], p['address'])), 'error': ''}
    except (psutil.Error, OSError, subprocess.SubprocessError):
        return {'available': False, 'ports': [], 'error': 'Не удалось прочитать открытые порты. На Linux нужны ss и права управления сервером.'}


def firewall_allows(nic, port):
    try:
        from . import privilege
        if privilege.enabled():
            output = privilege.command(['nft', '-j', 'list', 'chain', 'inet', 'fortis_filter', 'input'])
        else:
            proc = subprocess.run(['nft', '-j', 'list', 'chain', 'inet', 'fortis_filter', 'input'], capture_output=True, text=True, timeout=5)
            if proc.returncode:
                return False
            output = proc.stdout
        data = json.loads(output)
        for item in data.get('nftables', []):
            expressions = item.get('rule', {}).get('expr', [])
            if not any('accept' in e for e in expressions):
                continue
            interface_ok = False
            port_ok = False
            for expression in expressions:
                match = expression.get('match', {})
                if match.get('op') != '==':
                    continue
                left, right = match.get('left', {}), match.get('right')
                if left.get('meta', {}).get('key') == 'iifname' and right == nic:
                    interface_ok = True
                payload = left.get('payload', {})
                if payload.get('protocol') == 'udp' and payload.get('field') == 'dport':
                    port_ok = right == port or (isinstance(right, dict) and port in right.get('set', []))
            if interface_ok and port_ok:
                return True
        return False
    except (OSError, RuntimeError, ValueError, TypeError, subprocess.SubprocessError):
        return False
