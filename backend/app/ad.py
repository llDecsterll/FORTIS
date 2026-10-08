"""Синхронизация сотрудников из указанной папки Active Directory."""

from __future__ import annotations

import hashlib
import json
import ssl
import struct
import uuid
from datetime import datetime
from types import SimpleNamespace

from fastapi import HTTPException
from ldap3 import AUTO_BIND_NO_TLS, AUTO_BIND_TLS_BEFORE_BIND, BASE, ENCRYPT, NONE, NTLM, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException
from sqlalchemy.orm import Session

from .engine import disable_peer, enable_peer
from .models import AccessRequest, Contour, Device, DeviceStatus, RequestStatus, Role, Setting, User
from .security import hash_password
from .secret_storage import encrypt, decrypt
from .config import settings
from .ad_guard import serialized_ad
from .api.users import APPROVAL_WAIT, STAFF_ROLES, _ensure_company, _ensure_department

import secrets

_KEYS = ("ad_host", "ad_port", "ad_use_ssl", "ad_bind_dn", "ad_bind_password", "ad_base_dn")
_GONE = "Нет в папке Active Directory"
_DISABLED = "Заблокирован в Active Directory"
_FILTER = "(&(objectCategory=person)(objectClass=user))"
_PAGED_RESULTS = "1.2.840.113556.1.4.319"
_ATTRS = [
    "distinguishedName",
    "objectGUID",
    "displayName",
    "cn",
    "mail",
    "telephoneNumber",
    "mobile",
    "userPrincipalName",
    "sAMAccountName",
    "title",
    "department",
    "company",
    "userAccountControl",
    "lockoutTime",
    "msDS-User-Account-Control-Computed",
]


def _md4(data: bytes) -> bytes:
    def f(x, y, z):
        return (x & y) | (~x & z)
    def g(x, y, z):
        return (x & y) | (x & z) | (y & z)
    def h(x, y, z):
        return x ^ y ^ z
    def rol(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
    msg = bytearray(data)
    bit_len = (8 * len(data)) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", bit_len)
    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    for i in range(0, len(msg), 64):
        x = list(struct.unpack("<16I", msg[i:i + 64]))
        aa, bb, cc, dd = a, b, c, d
        for j in range(16):
            k = j
            s = (3, 7, 11, 19)[j % 4]
            a = rol((a + f(b, c, d) + x[k]) & 0xFFFFFFFF, s)
            a, b, c, d = d, a, b, c
        for j in range(16):
            k = (j % 4) * 4 + j // 4
            s = (3, 5, 9, 13)[j % 4]
            a = rol((a + g(b, c, d) + x[k] + 0x5A827999) & 0xFFFFFFFF, s)
            a, b, c, d = d, a, b, c
        for j in range(16):
            k = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)[j]
            s = (3, 9, 11, 15)[j % 4]
            a = rol((a + h(b, c, d) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)
            a, b, c, d = d, a, b, c
        a = (a + aa) & 0xFFFFFFFF
        b = (b + bb) & 0xFFFFFFFF
        c = (c + cc) & 0xFFFFFFFF
        d = (d + dd) & 0xFFFFFFFF
    return struct.pack("<4I", a, b, c, d)


class _Md4Hash:
    def __init__(self, data: bytes = b""):
        self._data = bytes(data)

    def update(self, data: bytes) -> None:
        self._data += data

    def digest(self) -> bytes:
        return _md4(self._data)

    def hexdigest(self) -> str:
        return self.digest().hex()


_original_hashlib_new = hashlib.new


def _new_with_md4(name, data=b"", **kwargs):
    if str(name).lower() == "md4":
        return _Md4Hash(data)
    return _original_hashlib_new(name, data, **kwargs)


def _enable_md4() -> None:
    # Repeated AD syncs must not grow a recursive chain of hashlib wrappers.
    hashlib.new = _new_with_md4


def _ntlm_account(bind: str, base: str) -> str:
    if "\\" in bind:
        return bind
    sam = bind.split("@", 1)[0] if "@" in bind else bind
    if "=" in sam:
        return ""
    netbios = _domain(base).split(".")[0]
    return f"{netbios}\\{sam}" if netbios and netbios != "local" else ""


def _get(db: Session, key: str) -> str:
    row = db.get(Setting, key)
    return row.value if row else ""


def _put(db: Session, key: str, value: str) -> None:
    row = db.get(Setting, key)
    if not row:
        db.add(Setting(key=key, value=value))
    else:
        row.value = value


def _public_source(item: dict) -> dict:
    return {
        "id": item["id"],
        "host": item["host"],
        "port": item["port"],
        "useSsl": item["useSsl"],
        "bindDn": item["bindDn"],
        "passwordSet": bool(item.get("password")),
        "baseDn": item["baseDn"],
        "deleting": bool(item.get("deleting")),
    }


def _load_sources(db: Session) -> list[dict]:
    raw = _get(db, "ad_sources")
    if raw:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            data = []
        if isinstance(data, list):
            return [{**item, "password": decrypt(item.get("password") or "")} for item in data]
    host = _get(db, "ad_host")
    if not host:
        return []
    return [{
        "id": "primary",
        "host": host,
        "port": int(_get(db, "ad_port") or "389"),
        "useSsl": _get(db, "ad_use_ssl") == "1",
        "bindDn": _get(db, "ad_bind_dn"),
        "password": decrypt(_get(db, "ad_bind_password")),
        "baseDn": _get(db, "ad_base_dn"),
    }]


def read_settings(db: Session) -> dict:
    sources = [_public_source(item) for item in _load_sources(db)]
    first = sources[0] if sources else {"host": "", "port": 389, "useSsl": False, "bindDn": "", "passwordSet": False, "baseDn": ""}
    return {"sources": sources, **first, "revision": _get(db, "ad_revision")}


def _mirror_first(db: Session, source: dict | None) -> None:
    if not source:
        for key in _KEYS:
            _put(db, key, "")
        return
    _put(db, "ad_host", source["host"])
    _put(db, "ad_port", str(source["port"]))
    _put(db, "ad_use_ssl", "1" if source["useSsl"] else "0")
    _put(db, "ad_bind_dn", source["bindDn"])
    _put(db, "ad_bind_password", encrypt(source.get("password") or ""))
    _put(db, "ad_base_dn", source["baseDn"])


@serialized_ad
def save_settings(db: Session, payload) -> dict:
    incoming = list(payload.sources or [])
    if not incoming and (payload.host or "").strip():
        incoming = [payload]
    if not incoming:
        raise HTTPException(status_code=422, detail="Добавьте хотя бы один домен Active Directory")
    stored = {item["id"]: item for item in _load_sources(db)}
    if payload.revision is not None and payload.revision != _get(db, "ad_revision"):
        raise HTTPException(409, "Настройки AD изменились. Обновите страницу")
    if any(item.get("deleting") for item in stored.values()):
        raise HTTPException(409, "Сначала завершите начатое удаление домена")
    incoming_ids = {item.id for item in incoming if item.id}
    if stored.keys() - incoming_ids:
        raise HTTPException(409, "Для удаления домена используйте отдельную команду с подтверждением")
    if incoming_ids - stored.keys():
        raise HTTPException(409, "Домен уже удалён. Обновите страницу")
    saved = []
    seen_ids: set[str] = set()
    for index, item in enumerate(incoming, start=1):
        host = item.host.strip()
        base = item.baseDn.strip()
        bind = item.bindDn.strip()
        if not host or not base or not bind:
            raise HTTPException(status_code=422, detail=f"Домен {index}: укажите сервер, учётную запись и папку")
        port = int(item.port or (636 if item.useSsl else 389))
        if port < 1 or port > 65535:
            raise HTTPException(status_code=422, detail=f"Домен {index}: некорректный порт")
        source_id = (item.id or "").strip() or uuid.uuid4().hex[:12]
        if source_id in seen_ids:
            raise HTTPException(422, "Один домен указан несколько раз")
        seen_ids.add(source_id)
        password = (item.password or "").strip() or stored.get(source_id, {}).get("password", "")
        if not password:
            raise HTTPException(status_code=422, detail=f"Домен {index}: укажите пароль учётной записи")
        saved.append({
            "id": source_id,
            "host": host,
            "port": port,
            "useSsl": bool(item.useSsl),
            "bindDn": bind,
            "password": password,
            "baseDn": base,
        })
    _store_sources(db, saved)
    _mirror_first(db, saved[0])
    _put(db, "ad_revision", uuid.uuid4().hex)
    db.commit()
    return read_settings(db)


def _text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return _text(value[0] if value else "")
    return str(value).strip()


def _guid(value) -> str:
    raw = value[0] if isinstance(value, list) and value else value
    if isinstance(raw, bytes):
        return raw.hex()
    return _text(raw)


def _flag(value, bit: int) -> bool:
    try:
        return bool(int(_text(value) or "0") & bit)
    except ValueError:
        return False


def _ad_blocked(entry) -> bool:
    if _flag(entry.userAccountControl, 2):
        return True
    return _flag(getattr(entry, "accountControlComputed", 0), 16)


def _domain(base_dn: str) -> str:
    parts = []
    for item in base_dn.split(","):
        item = item.strip()
        if item.lower().startswith("dc="):
            parts.append(item.split("=", 1)[1])
    return ".".join(parts) or "local"


def _login(entry, domain: str) -> str:
    mail = _text(entry.mail).lower()
    if mail:
        return mail
    upn = _text(entry.userPrincipalName).lower()
    if upn:
        return upn
    sam = _text(entry.sAMAccountName).lower()
    return f"{sam}@{domain}" if sam else ""


def _connect_source(source: dict) -> tuple[Connection, str]:
    host = source["host"]
    base = source["baseDn"]
    bind = source["bindDn"]
    password = source.get("password") or ""
    if not host or not base or not bind or not password:
        raise HTTPException(status_code=422, detail="Сначала сохраните подключение к Active Directory")
    port = int(source.get("port") or 389)
    use_ssl = bool(source.get("useSsl"))
    tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=settings.ad_ca_file or None, valid_names=[host],
              ssl_options=[ssl.OP_NO_TLSv1, ssl.OP_NO_TLSv1_1])
    server = Server(host, port=port, use_ssl=use_ssl, tls=tls, get_info=NONE, connect_timeout=8)
    try:
        conn = Connection(server, user=bind, password=password,
                          auto_bind=AUTO_BIND_NO_TLS if use_ssl else AUTO_BIND_TLS_BEFORE_BIND,
                          receive_timeout=20)
        return conn, base
    except LDAPException as exc:
        last = str(exc)
    if "invalidCredentials" in last:
        domain = _domain(base)
        hint = bind if "@" in bind or "\\" in bind else f"{bind}@{domain}"
        detail = f"Active Directory отклонил учётную запись или пароль. Укажите логин полностью, например {hint}"
    elif "strongerAuthRequired" in last:
        detail = "Active Directory требует защищённое соединение. Проверьте поддержку LDAPS/StartTLS и доверенную цепочку сертификатов."
    else:
        detail = "Не удалось подключиться к Active Directory"
    raise HTTPException(status_code=502, detail=detail)


def _entry_name(entry) -> str:
    return _text(entry.displayName) or _text(entry.cn) or _text(entry.sAMAccountName)


def _attr(entry, name: str):
    if name not in entry:
        return ""
    return entry[name].value


def _search_entries(conn: Connection, base: str, query: str, scope, attributes: list[str], **kwargs) -> list:
    try:
        conn.search(base, query, search_scope=scope, attributes=attributes, **kwargs)
    except LDAPException as exc:
        raise HTTPException(status_code=502, detail=f"Не удалось прочитать папку Active Directory: {exc}") from exc
    # ldap3 may return False without raising, including for a valid empty result.
    # Only a successful LDAP result is a complete snapshot for disabling absent users.
    result = conn.result or {}
    if result.get("result") != 0:
        raise HTTPException(status_code=502, detail="Не удалось полностью прочитать папку Active Directory")
    return list(conn.entries)


def _people(conn: Connection, base: str) -> list:
    entries = _search_entries(conn, base, "(objectClass=*)", BASE, ["objectClass", "member"])
    if not entries:
        raise HTTPException(status_code=422, detail="Папка Active Directory не найдена")
    current = entries[0]
    classes = [str(item).lower() for item in current.objectClass.values]
    if "group" in classes:
        if any(name.lower().startswith("member;range=") for name in current.entry_attributes):
            raise HTTPException(status_code=502, detail="Active Directory вернул неполный состав группы")
        sources = list(current.member.values) if "member" in current else []
        scope = BASE
    else:
        sources = [base]
        scope = SUBTREE
    people = []
    for dn in sources:
        cookie = None
        seen_cookies = set()
        while True:
            paging = {"paged_size": 500, "paged_cookie": cookie} if scope == SUBTREE else {}
            entries = _search_entries(conn, dn, _FILTER, scope, _ATTRS, **paging)
            for entry in entries:
                people.append(SimpleNamespace(
                    distinguishedName=_attr(entry, "distinguishedName"),
                    objectGUID=_attr(entry, "objectGUID"),
                    displayName=_attr(entry, "displayName"),
                    cn=_attr(entry, "cn"),
                    mail=_attr(entry, "mail"),
                    telephoneNumber=_attr(entry, "telephoneNumber"),
                    mobile=_attr(entry, "mobile"),
                    userPrincipalName=_attr(entry, "userPrincipalName"),
                    sAMAccountName=_attr(entry, "sAMAccountName"),
                    title=_attr(entry, "title"),
                    department=_attr(entry, "department"),
                    company=_attr(entry, "company"),
                    userAccountControl=_attr(entry, "userAccountControl"),
                    lockoutTime=_attr(entry, "lockoutTime"),
                    accountControlComputed=_attr(entry, "msDS-User-Account-Control-Computed"),
                ))
            if scope != SUBTREE:
                break
            cookie = (conn.result.get("controls") or {}).get(_PAGED_RESULTS, {}).get("value", {}).get("cookie")
            if not cookie:
                break
            if cookie in seen_cookies:
                raise HTTPException(status_code=502, detail="Не удалось полностью прочитать папку Active Directory")
            seen_cookies.add(cookie)
    return people


def _is_bind_entry(entry, source: dict) -> bool:
    """The directory connection identity is not an employee to import."""
    bind = source.get('bindDn', '').strip().casefold()
    if not bind:
        return False
    sam = _text(getattr(entry, 'sAMAccountName', '')).strip().casefold()
    upn = _text(getattr(entry, 'userPrincipalName', '')).strip().casefold()
    dn = _text(getattr(entry, 'distinguishedName', '')).strip().casefold()
    if '=' in bind:
        return bool(dn and bind == dn)
    if '\\' in bind:
        return bool(sam and bind.rsplit('\\', 1)[-1] == sam)
    if '@' in bind:
        return bool(upn and bind == upn)
    return bool(sam and bind == sam)


def _block_from_ad(db: Session, device: Device | None, reason: str) -> None:
    if device is None:
        return
    status = DeviceStatus.BLOCKED
    # AD must not erase an incident, revocation, expiry, or a manual block:
    # a later successful AD sync may automatically clear only AD-owned blocks.
    if device.status in (DeviceStatus.BLOCKED, DeviceStatus.EXPIRED, DeviceStatus.REVOKED):
        status = device.status
        reason = device.block_reason
    peer = device.peer
    if peer and peer.enabled:
        disable_peer(db, peer, reason, status=status)
    else:
        device.status = status
        device.block_reason = reason


def _apply_entry(db: Session, actor: User, entry, domain: str, source_id: str, seen: set[str]) -> tuple[int, int, int]:
    created = updated = disabled = 0
    guid = _guid(entry.objectGUID)
    login = _login(entry, domain)
    name = _entry_name(entry)
    if not guid or not login or not name:
        return 0, 0, 0
    seen.add(guid)
    user = db.query(User).filter(User.ad_guid == guid).one_or_none()
    if not user:
        user = db.query(User).filter(User.email == login).one_or_none()
    if user and user.role in STAFF_ROLES:
        return 0, 0, 0
    company_id = _ensure_company(db, None, _text(entry.company))
    department_id = _ensure_department(db, None, _text(entry.department), company_id)
    off = _ad_blocked(entry)
    if not user:
        user = User(
            full_name=name,
            email=login,
            title=_text(entry.title),
            role=Role.USER,
            company_id=company_id,
            department_id=department_id,
            password_hash=hash_password(secrets.token_urlsafe(18)),
            ad_guid=guid,
            ad_source=source_id,
            is_active=not off,
        )
        db.add(user)
        db.flush()
        created = 1
    else:
        user.full_name = name
        if user.email != login and not db.query(User).filter(User.email == login, User.id != user.id).one_or_none():
            user.email = login
        user.title = _text(entry.title)
        user.company_id = company_id
        user.department_id = department_id
        user.ad_guid = guid
        user.ad_source = source_id
        updated = 1
    # Contacts are directory-authoritative, including explicitly cleared attributes.
    # Keep mail separate from the existing login-selection and collision policy.
    user.phone = _text(getattr(entry, "telephoneNumber", "")) or _text(getattr(entry, "mobile", ""))
    user.contact_email = _text(getattr(entry, "mail", ""))
    device = (
        db.query(Device)
        .filter(Device.user_id == user.id, Device.site_id.is_(None))
        .first()
    )
    peer = device.peer if device else None
    reason = device.block_reason if device else ""
    if off:
        user.is_active = False
        user.blocked_by = user.blocked_by or "Active Directory"
        _block_from_ad(db, device, _DISABLED)
        disabled = 1
    elif _pending_approval(db, user):
        _block_from_ad(db, device, APPROVAL_WAIT)
    elif reason in (_GONE, _DISABLED):
        user.is_active = True
        if peer and not peer.enabled:
            enable_peer(db, peer)
    return created, updated, disabled


def _pending_approval(db: Session, user: User) -> bool:
    row = (
        db.query(AccessRequest)
        .filter(AccessRequest.user_id == user.id, AccessRequest.site_id.is_(None), AccessRequest.contour == Contour.EMPLOYEES)
        .order_by(AccessRequest.created_at.desc())
        .first()
    )
    return bool(row and row.status == RequestStatus.PENDING_APPROVAL)


@serialized_ad
def sync_users(db: Session, actor: User) -> dict:
    from .employee_exclusions import is_group_source, save_members
    sources = [item for item in _load_sources(db) if not item.get("deleting")]
    if not sources:
        raise HTTPException(status_code=422, detail="Сначала сохраните подключение к Active Directory")
    seen: set[str] = set()
    created = updated = disabled = 0
    failed: list[str] = []
    ok_ids: set[str] = set()
    for source in sources:
        label = source["host"]
        conn = None
        try:
            conn, base = _connect_source(source)
            people = _people(conn, base)
        except HTTPException as exc:
            failed.append(f"{label}: {exc.detail}")
            continue
        finally:
            if conn is not None:
                try:
                    conn.unbind()
                except Exception:
                    pass
        ok_ids.add(source["id"])
        domain = _domain(base)
        source_seen = set()
        for entry in people:
            if _is_bind_entry(entry, source):
                continue
            c, u, d = _apply_entry(db, actor, entry, domain, source["id"], source_seen)
            created += c
            updated += u
            disabled += d
        seen.update(source_seen)
        if is_group_source(source):
            save_members(db, source['id'], source_seen)
    if not ok_ids:
        raise HTTPException(status_code=502, detail=" ".join(failed) or "Не удалось подключиться к Active Directory")
    configured = {item["id"] for item in sources}
    for user in db.query(User).filter(User.ad_guid != "", User.role == Role.USER).all():
        if user.ad_guid in seen:
            continue
        if user.ad_source and user.ad_source not in ok_ids:
            continue
        if not user.ad_source and failed:
            continue
        if user.ad_source and user.ad_source not in configured:
            pass
        user.is_active = False
        user.blocked_by = user.blocked_by or "Active Directory"
        device = next((d for d in (user.devices or []) if d.peer and not d.site_id), None)
        if device and device.peer.enabled:
            _block_from_ad(db, device, _GONE)
        disabled += 1
    db.commit()
    return {
        "created": created,
        "updated": updated,
        "disabled": disabled,
        "seen": len(seen),
        "domains": len(ok_ids),
        "errors": failed,
        "at": datetime.utcnow().isoformat(),
    }


def sync_if_due(db: Session, interval_seconds: float = 5) -> None:
    if not _load_sources(db):
        return
    now = datetime.utcnow()
    row = db.get(Setting, "ad_last_check")
    if interval_seconds > 0 and row and row.value:
        try:
            if (now - datetime.fromisoformat(row.value)).total_seconds() < interval_seconds:
                return
        except ValueError:
            pass
    if not row:
        row = Setting(key="ad_last_check", value="")
        db.add(row)
    row.value = now.isoformat()
    db.commit()
    actor = db.query(User).filter(User.role == Role.ADMIN, User.is_active.is_(True)).first()
    if actor:
        result = sync_users(db, actor)
        success = db.get(Setting, "ad_last_success")
        if not success:
            success = Setting(key="ad_last_success", value="")
            db.add(success)
        success.value = result["at"]
        db.commit()



def _store_sources(db, sources):
    encrypted = [{**item, 'password': encrypt(item.get('password') or '')} for item in sources]
    _put(db, 'ad_sources', json.dumps(encrypted, ensure_ascii=False))


def migrate_secret_storage(db):
    sources = _load_sources(db)
    if sources:
        _store_sources(db, sources)
        _mirror_first(db, sources[0])
        db.commit()
