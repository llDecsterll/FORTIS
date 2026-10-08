"""Persistent first-run setup. No network changes until an administrator starts it."""
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import threading
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .config import settings
from .db import get_db
from .models import Role, Setting, User
from .security import create_token, hash_password, require_roles, set_session, revoke_session
from . import host_network
from .setup_ports import read_listeners, firewall_allows

router = APIRouter(prefix="/setup", tags=["setup"])
lock = threading.RLock()
WG_DIR = Path("/etc/wireguard")
FORWARD_FILE = Path("/proc/sys/net/ipv4/ip_forward")
PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def read(db, key, default=None):
    row = db.get(Setting, "setup." + key)
    return json.loads(row.value) if row else default


def write(db, key, value):
    row = db.get(Setting, "setup." + key)
    if row is None:
        row = Setting(key="setup." + key)
        db.add(row)
    row.value = json.dumps(value)


def completed(db):
    # Existing configured deployments continue to start normally.
    return read(db, "completed", False) or (not read(db, "managed", False) and bool(db.query(User).first()))


def load_interfaces(db):
    cfg = read(db, "interfaces", {}) or {}
    if not cfg:
        return
    settings.employees_enabled = 'employees' in cfg
    settings.sites_enabled = 'sites' in cfg
    settings.additional_interfaces = [item for key, item in cfg.items() if key not in ('employees', 'sites')]
    for contour in ('employees', 'sites'):
        item = cfg.get(contour)
        if not item:
            setattr(settings, f"{contour}_if", "")
            setattr(settings, f"{contour}_nic", "")
            setattr(settings, f"{contour}_port", 0)
            continue
        for suffix, key in (("if", "name"), ("net", "subnet"), ("port", "port"), ("nic", "uplink"), ("endpoint", "endpoint")):
            setattr(settings, f"{contour}_{suffix}", item[key])
        setattr(settings, f"{contour}_server_ip", str(next(ipaddress.ip_network(item["subnet"]).hosts())))


def role_label(key, item):
    return item.get('title') or ('Сотрудники' if key == 'employees' else 'Роутеры' if key == 'sites' else item.get('customName', key))


class AdminIn(BaseModel):
    fullName: str = Field(min_length=2, max_length=120)
    email: str = Field(min_length=3, max_length=120)
    password: str = Field(min_length=12, max_length=72)

    @model_validator(mode="after")
    def validate_values(self):
        self.fullName = self.fullName.strip()
        self.email = self.email.strip().lower()
        if len(self.fullName) < 2 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", self.email):
            raise ValueError("Укажите имя и корректный email")
        if len(self.password.encode()) > 72:
            raise ValueError("Пароль должен занимать не более 72 байт")
        return self


class InterfaceIn(BaseModel):
    name: str = Field(pattern=r"^[a-zA-Z][a-zA-Z0-9_-]{0,14}$")
    subnet: str
    port: int = Field(ge=1, le=65535)
    uplink: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$")
    endpoint: str = Field(min_length=1, max_length=253)

    @model_validator(mode="after")
    def validate_values(self):
        net = ipaddress.ip_network(self.subnet, strict=True)
        if net.version != 4 or not 8 <= net.prefixlen <= 30 or not any(net.subnet_of(p) for p in PRIVATE):
            raise ValueError("Нужна частная IPv4-подсеть с маской /8…/30")
        if not re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?", self.endpoint):
            raise ValueError("Укажите IPv4 или доменное имя сервера без протокола и порта")
        try:
            ipaddress.IPv4Address(self.endpoint)
        except ValueError:
            if re.fullmatch(r"[0-9.]+", self.endpoint) or any(not re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?", label) or len(label) > 63 for label in self.endpoint.split('.')):
                raise ValueError("Некорректный адрес сервера")
        return self


class InterfacesIn(BaseModel):
    employees: InterfaceIn | None = None
    sites: InterfaceIn | None = None

    @model_validator(mode="after")
    def distinct(self):
        values = [i for i in (self.employees, self.sites) if i is not None]
        validate_connections(values)
        return self


def validate_connections(values):
    if not values:
        raise ValueError('Назначьте хотя бы одну карту для подключения клиентов')
    for field in ('name', 'port', 'uplink'):
        if len({getattr(i, field) for i in values}) != len(values):
            raise ValueError('Каждому подключению нужны отдельная карта, имя VPN-интерфейса и UDP-порт')
    for index, item in enumerate(values):
        if item.name in {v.uplink for v in values}:
            raise ValueError('Имя VPN-интерфейса совпадает с сетевой картой')
        if any(ipaddress.ip_network(item.subnet).overlaps(ipaddress.ip_network(v.subnet)) for v in values[index + 1:]):
            raise ValueError('Подсети клиентов не должны пересекаться')


class ConnectionIn(InterfaceIn):
    role: str = Field(pattern=r'^(employees|routers|custom)$')
    customName: str = Field(default='', max_length=80)

    @model_validator(mode='after')
    def custom_required(self):
        if self.role == 'custom' and not self.customName.strip():
            raise ValueError('Укажите своё назначение карты')
        return self


def connections_dict(values):
    result = {}
    for item in values:
        key = 'employees' if item.role == 'employees' else 'sites' if item.role == 'routers' else 'custom.' + item.name
        result[key] = {**item.model_dump(), 'title': 'Сотрудники' if item.role == 'employees' else 'Роутеры' if item.role == 'routers' else item.customName.strip()}
    return result


def run(*args):
    proc = subprocess.run(list(args), capture_output=True, text=True, timeout=20)
    if proc.returncode:
        # Never return command stdout/stderr: it can contain WireGuard private keys.
        raise RuntimeError(f"Команда {args[0]} не выполнена (код {proc.returncode})")
    return proc.stdout.strip()


def active(item):
    try:
        links = json.loads(run("ip", "-j", "address", "show", "dev", item["name"]))
        address = str(next(ipaddress.ip_network(item["subnet"]).hosts()))
        return bool(links and "UP" in links[0].get("flags", []) and any(
            a.get("local") == address and a.get("prefixlen") == ipaddress.ip_network(item["subnet"]).prefixlen
            for a in links[0].get("addr_info", [])
        ) and run("wg", "show", item["name"], "listen-port") == str(item["port"]))
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired):
        return False


def checks(db, require_active=False, check_firewall=False):
    result = []
    def add(name, ok, detail):
        result.append({"name": name, "ok": bool(ok), "detail": detail})
    try:
        db.execute(text("SELECT 1"))
        add("База данных", True, "Соединение установлено")
    except Exception:
        db.rollback()
        add("База данных", False, "Нет соединения")
    add("Администратор", db.query(User).filter(User.role == Role.ADMIN, User.is_active.is_(True)).first(), "Учётная запись администратора")
    linux = platform.system() == "Linux"
    add("Операционная система", linux, "Linux" if linux else "Для VPN нужен Linux; панель доступна на этой системе")
    for cmd in ("wg", "wg-quick", "ip", "nft", "sysctl", "ss"):
        add(cmd, shutil.which(cmd), "Установлен" if shutil.which(cmd) else "Установите на Linux-сервере")
    add("Права управления сетью", os.geteuid() == 0, "Для первого запуска нужны права root")
    add("Хранилище", os.access(settings.data_dir, os.W_OK), "Каталог данных доступен для записи")
    free = shutil.disk_usage(settings.data_dir).free
    add("Место на диске", free >= 100 * 1024 * 1024, f"Свободно {free // (1024 * 1024)} МБ; необходимо не менее 100 МБ")
    plan = read(db, "host_plan", [])
    if host_network.changes(plan):
        state = host_network.public_transaction(settings.data_dir)
        add("Системная сеть", state.get("status") == "confirmed", "Новые IP и имена подтверждены" if state.get("status") == "confirmed" else "Примените и подтвердите настройки сетевых карт")
    cfg = read(db, "interfaces", {})
    add("Настройки интерфейсов", bool(cfg), f"Настроено подключений: {len(cfg)}" if cfg else "Настройте интерфейсы")
    for contour, item in cfg.items():
        label = role_label(contour, item)
        try:
            socket.getaddrinfo(item["endpoint"], item["port"], type=socket.SOCK_DGRAM)
            add(label + ": адрес сервера", True, item["endpoint"])
        except OSError:
            add(label + ": адрес сервера", False, "Адрес сервера не разрешается")
        if not linux or not shutil.which("ip") or not shutil.which("wg"):
            add(label + ": интерфейс", False, "Проверка доступна на Linux с WireGuard")
            continue
        try:
            uplink = json.loads(run("ip", "-j", "link", "show", "dev", item["uplink"]))
            add(label + ": внешняя сеть", uplink and "UP" in uplink[0].get("flags", []), item["uplink"])
            connections = json.loads(run("ip", "-j", "-4", "route", "show", "scope", "link"))
            conflict = any(r.get("dev") != item["name"] and r.get("dst") not in (None, "default") and ipaddress.ip_network(item["subnet"]).overlaps(ipaddress.ip_network(r["dst"], strict=False)) for r in connections)
            add(label + ": подсеть", not conflict, "Пересекается с сетью сервера" if conflict else item["subnet"])
            exists = item["name"] in run("wg", "show", "interfaces").split()
            links = json.loads(run("ip", "-j", "link", "show"))
            occupied_name = any(l["ifname"] == item["name"] for l in links)
            owned = read(db, "owned", [])
            add(label + ": имя", not occupied_name or (exists and item["name"] in owned), "Свободно или создано мастером" if not occupied_name or item["name"] in owned else "Интерфейс уже используется")
            used_ports = {int(run("wg", "show", n, "listen-port")) for n in run("wg", "show", "interfaces").split() if n != item["name"]}
            free = item["port"] not in used_ports
            if not exists and free:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                    probe.bind(("0.0.0.0", item["port"]))
            add(label + ": UDP-порт", free, str(item["port"]) + (" доступен" if free else " занят"))
            if require_active:
                add(label + ": активность", active(item), "Проверены адрес, состояние UP и порт WireGuard")
            if check_firewall:
                add(label + ": firewall UDP", firewall_allows(item["uplink"], item["port"]), f'Разрешение входящего UDP {item["port"]} на {item["uplink"]}')
        except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired):
            add(label + ": сеть", False, "Проверьте внешний интерфейс, права и занятость порта")
    if require_active:
        path = FORWARD_FILE
        add("Маршрутизация IPv4", path.exists() and path.read_text().strip() == "1", "Пересылка пакетов на сервере")
    listeners = read_listeners()
    if require_active and check_firewall:
        add("Чтение открытых портов", listeners["available"], "Список локальных TCP/UDP-портов" if listeners["available"] else listeners["error"])
        for contour, item in cfg.items():
            label = role_label(contour, item)
            bound = any(p["protocol"] == "UDP" and p["port"] == item["port"] and p["address"] in ("0.0.0.0", "::", "*") for p in listeners["ports"])
            add(label + ": открытый UDP-порт", bound, f'Сервер слушает UDP {item["port"]}')
    return {"openPorts": listeners, "checks": result, "ready": bool(cfg) and all(c["ok"] for c in result),
            "notice": "Доступность UDP из интернета и обмен с клиентом проверяются после подключения первого клиента."}


@router.get("/status")
def status(request: Request, db: Session = Depends(get_db)):
    done = completed(db)
    return {"completed": done, "adminCreated": bool(db.query(User).first()),
            "runtimeActive": bool(getattr(request.app.state, "scheduler", None)),
            "platform": platform.system(), "interfacesLocked": bool(read(db, "owned", [])),
            "serverReady": bool(read(db, "vpn_ready", False) and getattr(request.app.state, "scheduler", None)),
            "networkTransaction": host_network.public_transaction(settings.data_dir)}


@router.post("/admin")
def create_admin(payload: AdminIn, request: Request, response: Response, db: Session = Depends(get_db)):
    # A fresh installation can only be claimed locally, never through a public hostname.
    if request.url.hostname not in ('localhost', '127.0.0.1', '::1', 'testserver'):
        raise HTTPException(403, 'Создайте первого администратора через локальный адрес сервера')
    forwarded = request.headers.get("x-forwarded-for", request.headers.get("x-real-ip", ""))
    if forwarded and any(ip.strip() not in ("127.0.0.1", "::1") for ip in forwarded.split(",")):
        raise HTTPException(403, "Создайте первого администратора с самого сервера")
    if not request.client or request.client.host not in ("127.0.0.1", "::1", "testclient"):
        raise HTTPException(403, "Создайте первого администратора с самого сервера")
    with lock:
        if db.query(User).first() or read(db, "managed", False):
            raise HTTPException(409, "Администратор уже создан. Войдите в существующую учётную запись")
        write(db, "managed", True)
        try:
            db.flush()  # unique setup.managed key also serializes independent processes
            user = User(full_name=payload.fullName, email=payload.email, role=Role.ADMIN,
                        password_hash=hash_password(payload.password))
            db.add(user)
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(409, "Первичная настройка уже начата")
        token = create_token(user, purpose="setup")
        set_session(response, request, token, setup=True)
        return {"token": "cookie-session"}


admin = require_roles(Role.ADMIN)


@router.get("/interfaces")
def get_interfaces(user: User = Depends(admin), db: Session = Depends(get_db)):
    return read(db, "interfaces", {})


@router.put("/interfaces")
def save_interfaces(payload: InterfacesIn, user: User = Depends(admin), db: Session = Depends(get_db)):
    with lock:
        if completed(db):
            raise HTTPException(409, "Первичная настройка завершена")
        if read(db, "owned", []):
            raise HTTPException(409, "Интерфейсы уже созданы. Повторите запуск с сохранёнными настройками")
        write(db, "interfaces", payload.model_dump(exclude_none=True))
        db.commit()
        load_interfaces(db)
        return {"ok": True}


@router.get("/checks")
def get_checks(user: User = Depends(admin), db: Session = Depends(get_db)):
    active_runtime = completed(db) or read(db, "vpn_ready", False)
    return checks(db, require_active=active_runtime, check_firewall=active_runtime)


def activate_interfaces(db):
    cfg = read(db, "interfaces", {})
    owned = read(db, "owned", [])
    created = []
    forwarding = None
    try:
        for item in cfg.values():
            name = item["name"]
            target = WG_DIR / f"{name}.conf"
            if name not in owned:
                if target.exists():
                    raise RuntimeError(f"Конфигурация {name} уже существует; выберите другое имя")
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                key = run("wg", "genkey")
                network = ipaddress.ip_network(item["subnet"])
                content = f"[Interface]\nPrivateKey = {key}\nAddress = {next(network.hosts())}/{network.prefixlen}\nListenPort = {item['port']}\nMTU = {settings.mtu}\n"
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w") as stream:
                    stream.write(content)
                created.append(target)
            if not active(item):
                run("wg-quick", "up", name)
        forwarding = FORWARD_FILE.read_text().strip()
        run("sysctl", "-w", "net.ipv4.ip_forward=1")
        report = checks(db, require_active=True)
        # Ownership has not been committed yet; exclude name checks for new links.
        failing = [c for c in report["checks"] if not c["ok"] and not c["name"].endswith(": имя")]
        if failing:
            raise RuntimeError("Проверки после запуска не прошли: " + ", ".join(c["name"] for c in failing))
        write(db, "owned", list(dict.fromkeys(owned + [p.stem for p in created])))
        db.commit()
    except Exception:
        for target in reversed(created):
            try:
                run("wg-quick", "down", target.stem)
            except Exception:
                pass
            target.unlink(missing_ok=True)
        if forwarding == "0":
            try:
                run("sysctl", "-w", "net.ipv4.ip_forward=0")
            except Exception:
                pass
        raise


@router.post("/start")
def start(request: Request, user: User = Depends(admin), db: Session = Depends(get_db)):
    with lock:
        if completed(db):
            raise HTTPException(409, "Первичная настройка уже завершена")
        if read(db, "vpn_ready", False) and getattr(request.app.state, "scheduler", None):
            return {**checks(db, require_active=True, check_firewall=True), "serverReady": True, "completed": False}
        report = checks(db)
        if not report["ready"]:
            return {**report, "completed": False}
        try:
            activate_interfaces(db)
            from .main import start_runtime
            start_runtime(request.app)
            verification = checks(db, require_active=True, check_firewall=True)
            firewall = True
            try:
                run("nft", "list", "table", "inet", "filter")
                run("nft", "list", "table", "ip", "nat")
            except (OSError, RuntimeError, subprocess.TimeoutExpired):
                firewall = False
            if not verification["ready"] or not firewall or not getattr(request.app.state, "scheduler", None):
                raise RuntimeError("Проверка активности сервера или правил доступа не прошла")
            write(db, "vpn_ready", True)
            db.commit()
        except Exception as exc:
            db.rollback()
            scheduler = getattr(request.app.state, "scheduler", None)
            if scheduler:
                scheduler.shutdown(wait=False)
                request.app.state.scheduler = None
            # Log exception type only; never leak configuration or keys.
            return {**checks(db, require_active=True), "ready": False, "completed": False,
                    "error": str(exc) if type(exc) is RuntimeError else f"Запуск не завершён ({type(exc).__name__}). Проверьте журнал сервера."}
        return {**checks(db, require_active=True, check_firewall=True), "serverReady": True, "completed": False}


class NetworkSetupIn(BaseModel):
    hosts: host_network.HostPlanIn
    connections: list[ConnectionIn] = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def valid_connections(self):
        validate_connections(self.connections)
        named = [i.role for i in self.connections if i.role != "custom"]
        if len(set(named)) != len(named):
            raise ValueError("Роли сотрудников и роутеров назначаются одной карте каждая")
        return self


@router.get("/network")
def network_inventory(user: User = Depends(admin), db: Session = Depends(get_db)):
    try:
        return {**host_network.discover(), "plan": read(db, "host_plan", []),
                "transaction": host_network.public_transaction(settings.data_dir),
                "lockedUplinks": [item["uplink"] for item in read(db, "interfaces", {}).values() if item["name"] in read(db, "owned", [])]}
    except (OSError, RuntimeError) as exc:
        raise HTTPException(503, "Не удалось обнаружить интерфейсы сервера") from exc


@router.put("/network")
def save_network(payload: NetworkSetupIn, user: User = Depends(admin), db: Session = Depends(get_db)):
    with lock:
        if completed(db) and not read(db, "managed", False):
            raise HTTPException(409, "Для существующей установки настройте сеть в консоли сервера")
        owned = read(db, "owned", [])
        previous = read(db, "interfaces", {})
        proposed = connections_dict(payload.connections)
        for key, item in previous.items():
            if item['name'] in owned and (key not in proposed or any(proposed[key].get(field) != item.get(field) for field in ('name', 'subnet', 'port', 'uplink', 'endpoint'))):
                raise HTTPException(409, "Запущенные подключения нельзя изменить или удалить в этом мастере. Настройте свободную карту")
        if host_network.public_transaction(settings.data_dir).get("status") in ("pending", "applying", "rollback_failed"):
            raise HTTPException(409, "Подтвердите или отмените предыдущие изменения сети")
        plan = payload.hosts.model_dump()["interfaces"]
        inventory = host_network.discover()
        locked_uplinks = {i['uplink'] for i in previous.values() if i['name'] in owned}
        for item in plan:
            if item['originalName'] in locked_uplinks and (item['mode'] != 'keep' or item['name'] != item['originalName']):
                raise HTTPException(409, "IP и имя карты с активным подключением защищены от изменения")
        try:
            host_network.validate_plan(plan, inventory)
        except RuntimeError as exc:
            raise HTTPException(422, str(exc)) from exc
        selectable = {i['name'] for i in inventory['interfaces'] if i['selectable']}
        renamed = {i['originalName']: i['name'] for i in plan}
        allowed = {renamed.get(name, name) for name in selectable}
        for connection in payload.connections:
            item = connection.model_dump()
            if item['uplink'] not in allowed:
                raise HTTPException(422, "Выберите существующую сетевую карту сервера")
            pool = ipaddress.ip_network(item['subnet'])
            for host in plan:
                if host['mode'] == 'static' and pool.overlaps(ipaddress.ip_interface(host['address']).network):
                    raise HTTPException(422, "Подсеть клиентов пересекается с IP-подсетью сетевой карты")
        write(db, "host_plan", plan)
        write(db, "interfaces", connections_dict(payload.connections))
        db.commit()
        load_interfaces(db)
        return {"ok": True, "needsApply": bool(host_network.changes(plan))}


@router.post("/network/apply")
def apply_network(user: User = Depends(admin), db: Session = Depends(get_db)):
    with lock:
        if completed(db) and not read(db, "managed", False):
            raise HTTPException(409, "Существующая установка не использует мастер сети")
        try:
            return host_network.apply(read(db, "host_plan", []), settings.data_dir)
        except RuntimeError as exc:
            raise HTTPException(409, str(exc)) from exc


@router.post("/network/confirm")
def confirm_network(user: User = Depends(admin), db: Session = Depends(get_db)):
    with lock:
        try:
            return host_network.confirm(settings.data_dir)
        except RuntimeError as exc:
            raise HTTPException(409, str(exc)) from exc


@router.post("/network/cancel")
def cancel_network(user: User = Depends(admin)):
    with lock:
        return host_network.cancel(settings.data_dir)


class SetupAdIn(BaseModel):
    enabled: bool = False
    id: str = Field(default='', max_length=64)
    host: str = Field(default='', max_length=253)
    port: int = Field(default=636, ge=1, le=65535)
    useSsl: bool = True
    bindDn: str = Field(default='', max_length=512)
    password: str = Field(default='', max_length=512)
    baseDn: str = Field(default='', max_length=512)

    @model_validator(mode='after')
    def required(self):
        if self.enabled and not all((self.host.strip(), self.bindDn.strip(), self.password, self.baseDn.strip())):
            raise ValueError('Укажите сервер AD, учётную запись, пароль и Base DN')
        if self.enabled and not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9.-]*', self.host):
            raise ValueError('Укажите IP или DNS-имя AD без протокола и порта')
        return self


def verify_ad(payload):
    from . import ad
    from ldap3 import BASE
    conn = None
    try:
        conn, base = ad._connect_source(payload.model_dump())
        if not ad._search_entries(conn, base, '(objectClass=*)', BASE, ['objectClass']):
            raise HTTPException(422, 'Base DN не найден или учётная запись не имеет доступа')
        return {"ok": True, "detail": "Соединение, учётная запись и доступ к Base DN проверены"}
    finally:
        if conn is not None:
            try:
                conn.unbind()
            except Exception:
                pass


@router.get("/ad")
def get_setup_ad(user: User = Depends(admin), db: Session = Depends(get_db)):
    from . import ad
    return {**ad.read_settings(db), "skipped": read(db, "ad_skipped", False)}


@router.post("/ad/check")
def check_setup_ad(payload: SetupAdIn, user: User = Depends(admin)):
    if not payload.enabled:
        return {"ok": True, "detail": "AD не используется"}
    return verify_ad(payload)


@router.post("/finish")
def finish(payload: SetupAdIn, request: Request, response: Response, user: User = Depends(admin), db: Session = Depends(get_db)):
    with lock:
        if completed(db):
            raise HTTPException(409, "Первичная настройка завершена")
        if not read(db, "vpn_ready", False) or not getattr(request.app.state, "scheduler", None):
            raise HTTPException(409, "Сначала запустите и проверьте сервер")
        report = checks(db, require_active=True, check_firewall=True)
        if not report["ready"]:
            raise HTTPException(409, "Проверки сервера не прошли. Вернитесь к диагностике")
        if payload.enabled:
            verify_ad(payload)
            from . import ad
            from .schemas import AdSettingsIn, AdSourceIn
            sources = [AdSourceIn(**item) for item in ad._load_sources(db) if item['id'] != payload.id]
            sources.append(AdSourceIn(**payload.model_dump(exclude={'enabled'})))
            ad.save_settings(db, AdSettingsIn(sources=sources))
        write(db, "ad_skipped", not payload.enabled)
        write(db, "completed", True)
        revoke_session(request, response, db)
        db.commit()
        return {"completed": True}


@router.get("/network/transaction")
def network_transaction(user: User = Depends(admin)):
    return host_network.public_transaction(settings.data_dir)


@router.post("/network/activate")
def activate_later_network(request: Request, user: User = Depends(admin), db: Session = Depends(get_db)):
    with lock:
        if not completed(db):
            raise HTTPException(409, "Сначала завершите первый запуск")
        report = checks(db)
        if not report['ready']:
            return {**report, 'ready': False, 'error': 'Устраните ошибки настройки сети и портов'}
        try:
            activate_interfaces(db)
            from .nft import apply_acl
            apply_acl(db)
            from .osdetect import start as start_sniffer
            start_sniffer()
            return checks(db, require_active=True, check_firewall=True)
        except Exception as exc:
            return {**checks(db, require_active=True, check_firewall=True), 'ready': False,
                    'error': str(exc) if type(exc) is RuntimeError else f'Не удалось запустить подключение ({type(exc).__name__})'}
