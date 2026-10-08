"""Движок доверия к устройству: ключ WireGuard сам по себе доступа не даёт."""
from __future__ import annotations

import ipaddress
import json
import secrets
from datetime import datetime, timedelta
from pathlib import Path

from sqlalchemy.orm import Session

from . import wireguard
from .config import settings
from fastapi import HTTPException
from .device_id import compute_device_id, normalize_mac
from .geo import lookup_geo, lookup_place
from .models import (
    AccessPolicy,
    AccessRequest,
    Contour,
    Device,
    DeviceCertificate,
    DeviceStatus,
    DeviceType,
    Document,
    EnrollmentNonce,
    EventSeverity,
    HostMetric,
    Network,
    Resource,
    ResourceVisit,
    RequestStatus,
    MacPolicy,
    Role,
    SecurityEvent,
    Session,
    Setting,
    Site,
    User,
    VpnRenewal,
    WireGuardPeer,
)
from .nft import apply_acl
from .notify import notify
from .ca import CorporateCA


BLOCK_STATUS = "ЗАБЛОКИРОВАНО — ОБНАРУЖЕНА ПОПЫТКА ПЕРЕНОСА КЛЮЧА"
KEY_LOCK = "К ключу подключились несколько компьютеров"


def _setting(db: Session, key: str, default: str) -> str:
    row = db.get(Setting, key)
    return row.value if row else default


def emit(
    db: Session,
    *,
    severity: EventSeverity,
    code: str,
    title: str,
    details: str = "",
    user_id: str | None = None,
    device: Device | None = None,
    public_key: str = "",
    old_device_id: str = "",
    new_device_id: str = "",
    external_ip: str = "",
    geo: str = "",
    isp: str = "",
    mac: str = "",
    auto_blocked: bool = False,
) -> SecurityEvent:
    event = SecurityEvent(
        severity=severity,
        code=code,
        title=title,
        details=details,
        user_id=user_id,
        device_id_fk=device.id if device else None,
        public_key=public_key,
        old_device_id=old_device_id,
        new_device_id=new_device_id,
        external_ip=external_ip,
        geo=geo,
        isp=isp,
        mac=mac,
        auto_blocked=auto_blocked,
        created_at=datetime.utcnow(),
    )
    db.add(event)
    db.commit()
    # Only a server-resolved device is authoritative. A claimed public key in
    # BAD_CERTIFICATE / UNKNOWN_DEVICE is untrusted and must never select a victim.
    if device is not None:
        peer = db.query(WireGuardPeer).filter(WireGuardPeer.device_id_fk == device.id).one_or_none()
        if peer is not None:
            event.public_key = peer.public_key
            event.user_id = device.user_id
            reason = f"Инцидент {code}: {title}"
            status = DeviceStatus.BLOCKED
            if not peer.enabled and device.status in (DeviceStatus.BLOCKED, DeviceStatus.EXPIRED, DeviceStatus.REVOKED):
                status = device.status
                reason = device.block_reason or reason
            event.auto_blocked = False
            db.commit()
            try:
                event.auto_blocked = disable_peer(db, peer, reason, status=status)
            except Exception:
                # The durable disabled state is written before OS operations;
                # watchdog retries removal. Never claim success after a failure.
                db.rollback()
                event.auto_blocked = False
            if not event.auto_blocked:
                event.details = (event.details + "\nАвтоотключение не подтверждено; требуется проверка сервера.").strip()
            db.commit()
            from .audit import audit
            audit(db, action="incident_vpn_block", target=device.name, vpn=peer.vpn_ip,
                  result="OK" if event.auto_blocked else "ERROR",
                  payload={"incident_id": event.id, "code": code, "device_id": device.id})
    db.refresh(event)
    if severity in (EventSeverity.HIGH, EventSeverity.CRITICAL):
        notify(title, details, critical=severity == EventSeverity.CRITICAL)
    return event


def disable_peer(db: Session, peer: WireGuardPeer, reason: str, status: DeviceStatus = DeviceStatus.BLOCKED) -> bool:
    device = db.get(Device, peer.device_id_fk)
    was_up = bool(peer.link_up)
    peer.enabled = False
    peer.link_up = False
    if device:
        device.status = status
        device.block_reason = reason
    db.query(Session).filter(Session.device_id_fk == peer.device_id_fk, Session.active.is_(True)).update(
        {"active": False}
    )
    db.flush()
    from .peer_publication import lock_peer_publication
    lock_peer_publication(db, peer.contour, peer.public_key)
    removed = False
    try:
        wireguard.remove_peer(peer.contour, peer.public_key)
        removed = True
    except Exception:
        pass
    try:
        apply_acl(db)
    finally:
        # Keep denial durable even if WireGuard or ACL application failed.
        # Row/publication locks must span removal so a later grant survives it.
        db.commit()
    if was_up:
        _write_link(db, peer, device, False, peer.endpoint or "")
    return removed


def _purge_documents(db: Session, query) -> None:
    documents = query.all()
    ids = [doc.id for doc in documents]
    root = settings.uploads_dir.resolve()
    paths = set()
    for doc in documents:
        path = Path(doc.path).resolve()
        if not path.is_relative_to(root) or path == root or (path.exists() and not path.is_file()):
            raise HTTPException(409, "Документ вне папки загрузок. Требуется проверка администратора")
        # Shared files remain available to records not being deleted.
        if not db.query(Document).filter(Document.path == doc.path, ~Document.id.in_(ids)).count():
            paths.add(path)
    for path in paths:
        try:
            path.unlink(missing_ok=True)
        except OSError as exc:
            raise HTTPException(503, "Не удалось удалить документ. Повторите удаление") from exc
    query.delete(synchronize_session=False)


def purge_device(db: Session, device: Device) -> None:
    did = device.id
    peer = db.query(WireGuardPeer).filter(WireGuardPeer.device_id_fk == did).one_or_none()
    if peer and peer.public_key:
        try:
            wireguard.remove_peer(peer.contour, peer.public_key)
        except Exception as exc:
            raise HTTPException(503, "Не удалось удалить VPN-ключ. Повторите удаление") from exc
    db.query(VpnRenewal).filter(VpnRenewal.device_id == did).delete(synchronize_session=False)
    db.query(ResourceVisit).filter(ResourceVisit.device_id_fk == did).delete(synchronize_session=False)
    db.query(Session).filter(Session.device_id_fk == did).delete(synchronize_session=False)
    db.query(AccessPolicy).filter(AccessPolicy.device_id_fk == did).delete(synchronize_session=False)
    db.query(DeviceCertificate).filter(DeviceCertificate.device_id_fk == did).delete(synchronize_session=False)
    db.query(WireGuardPeer).filter(WireGuardPeer.device_id_fk == did).delete(synchronize_session=False)
    _purge_documents(db, db.query(Document).filter(Document.device_id_fk == did))
    db.query(SecurityEvent).filter(SecurityEvent.device_id_fk == did).update({"device_id_fk": None}, synchronize_session=False)
    db.query(AccessRequest).filter(AccessRequest.issued_device_id == did).update({"issued_device_id": None}, synchronize_session=False)
    # Bulk deletions bypass loaded relationships; do not let ORM try to null
    # non-null foreign keys on peer/certificate rows that were already removed.
    db.expire(device, ["peer", "certificate"])
    db.delete(device)


def purge_user(db: Session, user: User) -> None:
    db.query(VpnRenewal).filter(VpnRenewal.user_id == user.id).delete(synchronize_session=False)
    db.query(Site).filter(Site.owner_id == user.id).update({"owner_id": None}, synchronize_session=False)
    req_ids = [r.id for r in db.query(AccessRequest).filter(AccessRequest.user_id == user.id).all()]
    if req_ids:
        tokens = [r.enrollment_token for r in db.query(AccessRequest).filter(AccessRequest.id.in_(req_ids)) if r.enrollment_token]
        db.query(EnrollmentNonce).filter(EnrollmentNonce.token.in_(tokens)).delete(synchronize_session=False)
        _purge_documents(db, db.query(Document).filter(Document.request_id.in_(req_ids)))
        db.query(AccessRequest).filter(AccessRequest.user_id == user.id).delete(synchronize_session=False)
    db.query(ResourceVisit).filter(ResourceVisit.user_id == user.id).delete(synchronize_session=False)
    db.query(SecurityEvent).filter(SecurityEvent.user_id == user.id).update({"user_id": None}, synchronize_session=False)
    for device in list(user.devices or []):
        if device.site_id:
            device.user_id = None
            continue
        purge_device(db, device)
    db.delete(user)
    db.flush()
    apply_acl(db)


def purge_site(db: Session, site: Site) -> None:
    for link in db.query(Setting).filter(Setting.key.startswith("site_link:")):
        try:
            endpoints = json.loads(link.value)
        except (TypeError, ValueError):
            continue
        if isinstance(endpoints, dict) and site.id in (endpoints.get("siteA"), endpoints.get("siteB")):
            db.delete(link)
    req_ids = [r.id for r in db.query(AccessRequest).filter(AccessRequest.site_id == site.id).all()]
    if req_ids:
        tokens = [r.enrollment_token for r in db.query(AccessRequest).filter(AccessRequest.id.in_(req_ids)) if r.enrollment_token]
        db.query(EnrollmentNonce).filter(EnrollmentNonce.token.in_(tokens)).delete(synchronize_session=False)
        _purge_documents(db, db.query(Document).filter(Document.request_id.in_(req_ids)))
        db.query(AccessRequest).filter(AccessRequest.site_id == site.id).delete(synchronize_session=False)
    for device in list(site.devices or []):
        purge_device(db, device)
    db.delete(site)
    db.flush()
    apply_acl(db)


def enable_peer(db: Session, peer: WireGuardPeer) -> None:
    device = db.get(Device, peer.device_id_fk)
    if device and (device.block_reason or "").startswith("Инцидент "):
        raise HTTPException(403, "VPN отключён после инцидента. Требуется ручное восстановление доступа")
    if device and (device.status == DeviceStatus.REVOKED or device.block_reason in (KEY_LOCK, BLOCK_STATUS)):
        raise HTTPException(403, "Ключ отозван или заблокирован после инцидента")
    if device and device.access_until and device.access_until <= datetime.utcnow():
        _expire_device(db, device, "Срок доступа истёк")
        raise HTTPException(403, "Срок VPN-доступа истёк. Требуется новая согласованная заявка")
    if device and device.block_reason == KEY_LOCK:
        raise RuntimeError("Ключ заблокирован после инцидента. Разблокировать может только администратор")
    allowed = [f"{peer.vpn_ip}/32"]
    if peer.allowed_lans:
        allowed.extend([p.strip() for p in peer.allowed_lans.split(",") if p.strip()])
    # AllowedIPs on server is the client's VPN IP (+ site LAN). Resource filtering is nftables.
    from .peer_publication import lock_peer_publication
    identity = (peer.contour, peer.public_key)
    acl_touched = False
    runtime_touched = False
    try:
        if not peer.enabled:
            peer.endpoint_trace = "[]"
        peer.enabled = True
        if device and device.status in (DeviceStatus.PENDING, DeviceStatus.BLOCKED):
            device.status = DeviceStatus.ACTIVE
            device.block_reason = ""
        db.flush()
        lock_peer_publication(db, *identity)
        acl_touched = True
        apply_acl(db)
        runtime_touched = True
        wireguard.set_peer(peer.contour, peer.public_key, peer.preshared_key, ", ".join(allowed))
        db.commit()
    except Exception as exc:
        db.rollback()
        recovery_failed = False
        if acl_touched or runtime_touched:
            try:
                # Rollback released the publication lock. Reacquire and read the
                # committed state so recovery cannot remove a concurrent grant.
                lock_peer_publication(db, *identity)
                if runtime_touched:
                    try:
                        current = (db.query(WireGuardPeer)
                                   .filter(WireGuardPeer.contour == identity[0], WireGuardPeer.public_key == identity[1])
                                   .populate_existing().one_or_none())
                        if current and current.enabled:
                            previous_allowed = [f"{current.vpn_ip}/32"]
                            previous_allowed.extend(p.strip() for p in (current.allowed_lans or '').split(',') if p.strip())
                            wireguard.set_peer(current.contour, current.public_key, current.preshared_key, ", ".join(previous_allowed))
                        else:
                            wireguard.remove_peer(*identity)
                    except Exception:
                        recovery_failed = True
                if acl_touched:
                    try:
                        apply_acl(db)
                    except Exception:
                        recovery_failed = True
            except Exception:
                recovery_failed = True
            finally:
                db.rollback()
        detail = "Не удалось включить peer. Изменения отменены."
        if recovery_failed:
            import logging
            logging.getLogger(__name__).critical("Peer enable rollback could not restore runtime policy; operator intervention required")
            detail += " Не удалось полностью восстановить сетевые правила; требуется проверка администратором."
        raise RuntimeError(detail) from exc


def block_key_copy(
    db: Session,
    peer: WireGuardPeer,
    *,
    old_device_id: str,
    new_device_id: str,
    external_ip: str,
    details: str,
) -> None:
    device = db.get(Device, peer.device_id_fk)
    geo = lookup_geo(external_ip)
    disable_peer(db, peer, BLOCK_STATUS)
    emit(
        db,
        severity=EventSeverity.CRITICAL,
        code="KEY_TRANSFER",
        title=BLOCK_STATUS,
        details=details,
        user_id=device.user_id if device else None,
        device=device,
        public_key=peer.public_key,
        old_device_id=old_device_id,
        new_device_id=new_device_id,
        external_ip=external_ip,
        geo=geo,
        auto_blocked=True,
    )


def verify_and_authorize(
    db: Session,
    *,
    certificate_pem: str,
    system_identifier: str,
    mac: str,
    wg_public_key: str,
    device_name: str,
    os_name: str,
    client_version: str,
    user_email: str,
    external_ip: str,
) -> dict:
    try:
        mac_n = normalize_mac(mac) if mac else ""
    except ValueError as exc:
        raise PermissionError(str(exc)) from exc

    presented_id = compute_device_id(certificate_pem, system_identifier, mac_n, wg_public_key)
    ca = CorporateCA()
    try:
        cert = ca.verify_device_cert(certificate_pem)
    except Exception as exc:
        emit(
            db,
            severity=EventSeverity.CRITICAL,
            code="BAD_CERTIFICATE",
            title="Неверный сертификат устройства",
            details=str(exc),
            public_key=wg_public_key,
            new_device_id=presented_id,
            external_ip=external_ip,
        )
        raise PermissionError("Сертификат устройства отклонён") from exc

    from hashlib import sha256
    from cryptography.hazmat.primitives.serialization import Encoding

    fingerprint = sha256(cert.public_bytes(Encoding.DER)).hexdigest()
    cert_row = db.query(DeviceCertificate).filter(DeviceCertificate.fingerprint == fingerprint).one_or_none()
    if not cert_row or cert_row.revoked:
        emit(
            db,
            severity=EventSeverity.CRITICAL,
            code="UNKNOWN_DEVICE",
            title="Неизвестное устройство",
            details="Сертификат не зарегистрирован или отозван",
            public_key=wg_public_key,
            new_device_id=presented_id,
            external_ip=external_ip,
        )
        raise PermissionError("Устройство не зарегистрировано")

    device = db.get(Device, cert_row.device_id_fk)
    if not device:
        raise PermissionError("Карточка устройства не найдена")
    peer = device.peer
    if not peer:
        raise PermissionError("Для устройства нет профиля WireGuard")

    now = datetime.utcnow()
    if device.status in (DeviceStatus.BLOCKED, DeviceStatus.REVOKED, DeviceStatus.EXPIRED):
        raise PermissionError(device.block_reason or "Устройство заблокировано")
    if device.user and not device.user.is_active:
        raise PermissionError("Учётная запись заблокирована")
    if device.access_from and now < device.access_from:
        raise PermissionError("Срок доступа ещё не начался")
    if device.access_until and now > device.access_until:
        _expire_device(db, device, "Срок доступа истёк")
        emit(
            db,
            severity=EventSeverity.HIGH,
            code="ACCESS_EXPIRED",
            title="Истёк срок VPN-доступа",
            device=device,
            user_id=device.user_id,
            public_key=peer.public_key,
        )
        raise PermissionError("Срок доступа истёк")

    if device.status in (DeviceStatus.BLOCKED, DeviceStatus.REVOKED, DeviceStatus.EXPIRED):
        raise PermissionError(device.block_reason or "Устройство заблокировано")

    if peer.public_key != wg_public_key:
        block_key_copy(
            db,
            peer,
            old_device_id=device.device_id,
            new_device_id=presented_id,
            external_ip=external_ip,
            details="Публичный ключ WireGuard не совпадает с зарегистрированным для этого сертификата",
        )
        raise PermissionError(BLOCK_STATUS)

    if device.device_id and device.device_id != presented_id:
        block_key_copy(
            db,
            peer,
            old_device_id=device.device_id,
            new_device_id=presented_id,
            external_ip=external_ip,
            details="Device ID не совпал со связкой сертификат + система + MAC + ключ",
        )
        raise PermissionError(BLOCK_STATUS)

    user = db.get(User, device.user_id) if device.user_id else None
    if user_email and user and user.email.lower() != user_email.lower():
        emit(
            db,
            severity=EventSeverity.HIGH,
            code="IDENTITY_MISMATCH",
            title="Несовпадение пользователя",
            device=device,
            user_id=device.user_id,
            public_key=peer.public_key,
            external_ip=external_ip,
        )
        raise PermissionError("Пользователь не совпадает с карточкой устройства")

    mac_policy = _setting(db, "mac_policy", settings.mac_policy)
    registered = {device.mac_ethernet.lower(), device.mac_wifi.lower()} - {""}
    if mac_n and registered and mac_n not in registered:
        if mac_policy == MacPolicy.BLOCK.value:
            emit(
                db,
                severity=EventSeverity.HIGH,
                code="MAC_CHANGED",
                title="Изменился MAC-адрес",
                device=device,
                user_id=device.user_id,
                external_ip=external_ip,
                auto_blocked=True,
            )
            disable_peer(db, peer, "MAC-адрес не совпадает с зарегистрированным")
            raise PermissionError("MAC-адрес не совпадает")
        if mac_policy == MacPolicy.REAPPROVE.value:
            emit(
                db,
                severity=EventSeverity.WARNING,
                code="MAC_CHANGED",
                title="MAC изменился, требуется подтверждение",
                device=device,
                user_id=device.user_id,
                external_ip=external_ip,
            )
            raise PermissionError("MAC изменился — требуется повторное подтверждение ИТ/СБ")

    db.query(Session).filter(Session.device_id_fk == device.id, Session.active.is_(True)).update({"active": False})
    token = secrets.token_urlsafe(32)
    geo = lookup_geo(external_ip)
    session = Session(
        device_id_fk=device.id,
        token=token,
        external_ip=external_ip,
        geo=geo,
        agent_version=client_version,
        attested_device_id=presented_id,
        expires_at=now + timedelta(seconds=settings.session_ttl_seconds),
        last_heartbeat=now,
        active=True,
    )
    db.add(session)
    device.last_seen_at = now
    device.last_external_ip = external_ip
    device.last_geo = geo
    device.os_name = os_name or device.os_name
    if device_name:
        device.name = device.name or device_name
    db.commit()
    enable_peer(db, peer)
    return {
        "ok": True,
        "session_token": token,
        "expires_in": settings.session_ttl_seconds,
        "vpn_ip": peer.vpn_ip,
        "contour": peer.contour.value,
        "device_id": presented_id,
    }


def heartbeat(db: Session, session_token: str, external_ip: str) -> dict:
    session = db.query(Session).filter(Session.token == session_token, Session.active.is_(True)).one_or_none()
    if not session:
        raise PermissionError("Сессия не найдена")
    now = datetime.utcnow()
    if session.expires_at < now:
        session.active = False
        peer = db.query(WireGuardPeer).filter(WireGuardPeer.device_id_fk == session.device_id_fk).one_or_none()
        if peer:
            disable_peer(db, peer, "Истекла сессия агента")
        db.commit()
        raise PermissionError("Сессия истекла")
    session.last_heartbeat = now
    session.expires_at = now + timedelta(seconds=settings.session_ttl_seconds)
    session.external_ip = external_ip or session.external_ip
    device = db.get(Device, session.device_id_fk)
    if device:
        device.last_seen_at = now
    db.commit()
    return {"ok": True, "expires_in": settings.session_ttl_seconds}


def _endpoint_ip(endpoint: str) -> str:
    if not endpoint or endpoint in ("(none)", "none"):
        return ""
    return endpoint.rsplit(":", 1)[0].strip("[]")


def _note_endpoint(peer: WireGuardPeer, endpoint: str, now: datetime) -> list[dict]:
    import json

    ip = _endpoint_ip(endpoint)
    if not ip:
        return []
    port = endpoint.rsplit(":", 1)[-1]
    if not port.isdigit():
        port = ""
    try:
        trace = json.loads(peer.endpoint_trace or "[]")
    except (TypeError, ValueError):
        trace = []
    cutoff = (now - timedelta(seconds=180)).isoformat()
    trace = [item for item in trace if isinstance(item, dict) and item.get("at", "") > cutoff]
    if not trace or trace[-1].get("ip") != ip or trace[-1].get("port") != port:
        trace.append({"ip": ip, "port": port, "at": now.isoformat()})
    peer.endpoint_trace = json.dumps(trace[-12:], ensure_ascii=False)
    return trace


def _shared_endpoints(trace: list[dict]) -> list[str]:
    if len(trace) < 3:
        return []
    ips = [item.get("ip") or "" for item in trace]
    switches = sum(1 for left, right in zip(ips, ips[1:]) if left and right and left != right)
    distinct = list(dict.fromkeys(ip for ip in ips if ip))
    if len(distinct) >= 2 and switches >= 2:
        return distinct
    ends = [f"{item.get('ip')}:{item.get('port')}" for item in trace if item.get("port")]
    seen_ends: list[str] = []
    returned = False
    for end in ends:
        if end in seen_ends and (not seen_ends or end != seen_ends[-1]):
            returned = True
            break
        seen_ends.append(end)
    distinct_ends = list(dict.fromkeys(ends))
    if len(distinct) == 1 and len(distinct_ends) >= 2 and returned:
        return distinct_ends
    return []


def _suspected_standard_key_share(peer: WireGuardPeer, endpoint: str, now: datetime) -> list[str]:
    """Opted-in heuristic, not device identity: repeated endpoint returns in 180s.

    A single roam/return or one-way NAT rebinding is insufficient. Sampling can
    miss alternation; unstable NAT can still produce false positives.
    """
    trace = _note_endpoint(peer, endpoint, now)
    endpoints = [(item.get("ip"), item.get("port")) for item in trace]
    repeated = {item for item in endpoints if endpoints.count(item) >= 2}
    if len(endpoints) < 4 or len(repeated) < 2:
        return []
    return list(dict.fromkeys(f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"
                             for ip, port in endpoints if (ip, port) in repeated))


def _apply_detected_os(device: Device | None, peer: WireGuardPeer) -> None:
    if not device or not peer.vpn_ip:
        return
    from .osdetect import device_kind, observe, should_store

    seen = observe(peer.vpn_ip, _endpoint_ip(peer.endpoint))
    if should_store(device.os_name, seen["os"], seen["confidence"]):
        device.os_name = seen["os"]
    kind = device_kind(device.os_name, site=bool(device.site_id) or peer.contour.value == "SITES")
    if kind and device.device_type in (DeviceType.LAPTOP, DeviceType.OTHER, DeviceType(kind)):
        try:
            device.device_type = DeviceType(kind)
        except ValueError:
            pass


def _remember_presence(db: Session, peer: WireGuardPeer, device: Device | None, seen_at: datetime | None) -> None:
    if not device:
        return
    ip = _endpoint_ip(peer.endpoint)
    if ip and (device.last_external_ip != ip or (ip and not device.isp and device.last_geo != "LAN")):
        device.last_external_ip = ip
        geo, isp = lookup_place(ip)
        if geo:
            device.last_geo = geo
        if isp:
            device.isp = isp
    if seen_at:
        device.last_seen_at = seen_at
        if device.user_id:
            user = db.get(User, device.user_id)
            if user and (not user.last_activity_at or seen_at > user.last_activity_at):
                user.last_activity_at = seen_at


def _expire_device(db: Session, device: Device, reason: str) -> None:
    # Expiration must never replace an administrative or incident lock.
    protected = device.status in (DeviceStatus.BLOCKED, DeviceStatus.REVOKED)
    status = device.status if protected else DeviceStatus.EXPIRED
    reason = device.block_reason if protected else reason
    if device.peer:
        disable_peer(db, device.peer, reason, status)
    else:
        device.status = status
        device.block_reason = reason
        db.commit()


from threading import Lock
_expiry_lock = Lock()


def _expire_access(db: Session) -> None:
    # The fast expiry job and watchdog must not disable the same peer concurrently.
    with _expiry_lock:
        _expire_access_locked(db)


def _expire_access_locked(db: Session) -> None:
    now = datetime.utcnow()
    due = (
        db.query(Device)
        .filter(Device.access_until.isnot(None), Device.access_until <= now, Device.status != DeviceStatus.EXPIRED)
        .all()
    )
    for device in due:
        # Renewal may commit between the candidate scan and this action. Read
        # current state under the same row lock used by renewal before revoking.
        device = (db.query(Device).filter(Device.id == device.id)
                  .populate_existing().with_for_update(skip_locked=True).one_or_none())
        if not device or not device.access_until or device.access_until > now or device.status == DeviceStatus.EXPIRED:
            db.commit()
            continue
        if device.peer:
            peer = (db.query(WireGuardPeer).filter(WireGuardPeer.device_id_fk == device.id)
                    .populate_existing().with_for_update(skip_locked=True).one_or_none())
            if not peer:
                # Watchdog can hold the peer while updating its device. Never
                # wait on that inverse lock order; retry expiry on the next tick.
                db.commit()
                continue
        if device.status in (DeviceStatus.BLOCKED, DeviceStatus.REVOKED) and (not device.peer or not device.peer.enabled):
            db.commit()
            continue
        _expire_device(db, device, "Срок доступа истёк")
    unused = (db.query(Device).join(WireGuardPeer, WireGuardPeer.device_id_fk == Device.id)
              .filter(Device.status.in_((DeviceStatus.PENDING, DeviceStatus.ACTIVE)),
                      Device.contour == Contour.EMPLOYEES,
                      Device.enrolled_at <= now - timedelta(days=7),
                      WireGuardPeer.handshake_at.is_(None)).all())
    for device in unused:
        device = (db.query(Device).filter(Device.id == device.id)
                  .populate_existing().with_for_update(skip_locked=True).one_or_none())
        if (not device or device.status not in (DeviceStatus.PENDING, DeviceStatus.ACTIVE)
                or not device.enrolled_at or device.enrolled_at > now - timedelta(days=7)):
            db.commit()
            continue
        peer = (db.query(WireGuardPeer).filter(WireGuardPeer.device_id_fk == device.id)
                .populate_existing().with_for_update(skip_locked=True).one_or_none())
        if not peer or peer.handshake_at:
            db.commit()
            continue
        issued = (db.query(AccessRequest)
                  .filter(AccessRequest.issued_device_id == device.id, AccessRequest.status == RequestStatus.ISSUED)
                  .order_by(AccessRequest.updated_at.desc()).first())
        if issued and issued.updated_at and issued.updated_at > now - timedelta(days=7):
            db.commit()
            continue
        _expire_device(db, device, "Нет первого подключения в течение 7 дней")


def _block_idle_accounts(db: Session) -> None:
    from .audit import audit

    now = datetime.utcnow()
    limit = now - timedelta(days=30)
    admins_left = db.query(User).filter(User.role == Role.ADMIN, User.is_active.is_(True)).count()
    for user in db.query(User).filter(User.is_active.is_(True)).all():
        if user.role == Role.ADMIN and admins_left <= 1:
            continue
        stamps = [t for t in (user.created_at, user.last_activity_at) if t]
        device = next((d for d in (user.devices or []) if d.peer and not d.site_id), None)
        if device:
            stamps.append(device.last_seen_at)
            if device.peer and device.peer.handshake_at:
                stamps.append(device.peer.handshake_at)
        stamps = [t for t in stamps if t]
        if not stamps or max(stamps) > limit:
            continue
        user.is_active = False
        user.blocked_by = user.blocked_by or "Система"
        if user.role == Role.ADMIN:
            admins_left -= 1
        if device and device.peer and device.peer.enabled:
            disable_peer(db, device.peer, "Нет активности 30 дней")
        else:
            if device:
                device.status = DeviceStatus.BLOCKED
                device.block_reason = "Нет активности 30 дней"
            db.commit()
        audit(db, action="user_block", target=user.email, payload={"reason": "Нет активности 30 дней"})


def _backfill_geo(db: Session) -> None:
    for peer in db.query(WireGuardPeer).all():
        device = db.get(Device, peer.device_id_fk)
        if not device or not peer.endpoint or device.last_external_ip:
            continue
        _remember_presence(db, peer, device, None)
    db.commit()


def _iface_bytes(iface: str, direction: str) -> int:
    try:
        return int(Path(f"/sys/class/net/{iface}/statistics/{direction}_bytes").read_text().strip())
    except OSError:
        return 0


def _link_mbps(iface: str) -> int:
    try:
        speed = int(Path(f"/sys/class/net/{iface}/speed").read_text().strip())
    except OSError:
        return 0
    return speed if speed > 0 else 0


def _cpu_jiffies() -> tuple[int, int]:
    parts = Path("/proc/stat").read_text().splitlines()[0].split()[1:]
    nums = [int(part) for part in parts]
    idle = nums[3] + (nums[4] if len(nums) > 4 else 0)
    return sum(nums), idle


def _mem_percent() -> float:
    info: dict[str, int] = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, raw = line.split(":", 1)
        info[key] = int(raw.strip().split()[0])
    total = info.get("MemTotal") or 0
    avail = info.get("MemAvailable", info.get("MemFree", 0))
    if not total:
        return 0
    return round((total - avail) * 100 / total, 1)


def _rate(current: int, previous: int | None, seconds: float) -> int:
    if previous is None or seconds <= 0:
        return 0
    delta = current - previous
    if delta < 0:
        delta = 0
    return int(delta / seconds)


def record_host_metrics(db: Session) -> None:
    from .operations import read_operations
    operations = read_operations(db)
    now = datetime.utcnow()
    last = db.query(HostMetric).order_by(HostMetric.captured_at.desc()).first()
    if last and (now - last.captured_at).total_seconds() < 4:
        return
    load = Path("/proc/loadavg").read_text().split()
    cpu_total, cpu_idle = _cpu_jiffies()
    seconds = (now - last.captured_at).total_seconds() if last else 0
    cpu_percent = 0.0
    if last and seconds > 0 and cpu_total > last.cpu_total:
        busy = (cpu_total - last.cpu_total) - (cpu_idle - last.cpu_idle)
        cpu_percent = round(max(busy, 0) * 100 / (cpu_total - last.cpu_total), 1)
    counters = {
        "wg_emp_rx": _iface_bytes(settings.employees_if, "rx"),
        "wg_emp_tx": _iface_bytes(settings.employees_if, "tx"),
        "wg_site_rx": _iface_bytes(settings.sites_if, "rx"),
        "wg_site_tx": _iface_bytes(settings.sites_if, "tx"),
        "nic_emp_rx": _iface_bytes(settings.employees_nic, "rx"),
        "nic_emp_tx": _iface_bytes(settings.employees_nic, "tx"),
        "nic_site_rx": _iface_bytes(settings.sites_nic, "rx"),
        "nic_site_tx": _iface_bytes(settings.sites_nic, "tx"),
    }
    db.add(
        HostMetric(
            load1=float(load[0]),
            load5=float(load[1]),
            load15=float(load[2]),
            cpu_percent=cpu_percent,
            mem_percent=_mem_percent(),
            cpu_total=cpu_total,
            cpu_idle=cpu_idle,
            nic_emp_mbps=operations.employeesMbps or _link_mbps(settings.employees_nic),
            nic_site_mbps=operations.sitesMbps or _link_mbps(settings.sites_nic),
            **counters,
            wg_emp_rx_bps=_rate(counters["wg_emp_rx"], last.wg_emp_rx if last else None, seconds),
            wg_emp_tx_bps=_rate(counters["wg_emp_tx"], last.wg_emp_tx if last else None, seconds),
            wg_site_rx_bps=_rate(counters["wg_site_rx"], last.wg_site_rx if last else None, seconds),
            wg_site_tx_bps=_rate(counters["wg_site_tx"], last.wg_site_tx if last else None, seconds),
            nic_emp_rx_bps=_rate(counters["nic_emp_rx"], last.nic_emp_rx if last else None, seconds),
            nic_emp_tx_bps=_rate(counters["nic_emp_tx"], last.nic_emp_tx if last else None, seconds),
            nic_site_rx_bps=_rate(counters["nic_site_rx"], last.nic_site_rx if last else None, seconds),
            nic_site_tx_bps=_rate(counters["nic_site_tx"], last.nic_site_tx if last else None, seconds),
        )
    )
    db.query(HostMetric).filter(HostMetric.captured_at < now - timedelta(days=operations.retentionDays)).delete(synchronize_session=False)
    db.commit()


def _internal_targets(db: Session) -> list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, int | None, str, str | None]]:
    targets: list[tuple] = []
    for res in db.query(Resource).all():
        host = (res.host or "").strip()
        try:
            network = ipaddress.ip_network(host if "/" in host else f"{host}/32", strict=False)
        except ValueError:
            continue
        targets.append((network, res.port, res.name, res.id))
    for net in db.query(Network).all():
        try:
            network = ipaddress.ip_network(net.cidr, strict=False)
        except ValueError:
            continue
        targets.append((network, None, net.name, None))
    for extra in [part.strip() for part in settings.extra_allowed_ips.split(",") if part.strip()]:
        try:
            network = ipaddress.ip_network(extra, strict=False)
        except ValueError:
            continue
        if network.prefixlen >= 8:
            targets.append((network, None, f"Сеть {extra}", None))
    return targets


def _match_target(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, port: int, targets: list) -> tuple[str, str | None] | None:
    best = None
    best_len = -1
    for network, want_port, name, resource_id in targets:
        if ip not in network or (want_port and port and want_port != port):
            continue
        score = network.prefixlen + (8 if resource_id else 0)
        if score > best_len:
            best = (name, resource_id)
            best_len = score
    return best


def _conntrack_flows() -> list[dict]:
    path = Path("/proc/net/nf_conntrack")
    if not path.exists():
        return []
    flows = []
    try:
        lines = path.read_text(errors="ignore").splitlines()
    except OSError:
        return []
    for line in lines:
        if "src=" not in line or "UNREPLIED" in line:
            continue
        proto = "tcp" if " tcp " in f" {line} " else "udp" if " udp " in f" {line} " else ""
        if not proto:
            continue
        parts = line.split()
        src = dst = sport = dport = ""
        up = down = 0
        srcs = bytes_n = 0
        for part in parts:
            if part.startswith("src="):
                srcs += 1
                if srcs == 1:
                    src = part[4:]
            elif part.startswith("dst=") and srcs == 1 and not dst:
                dst = part[4:]
            elif part.startswith("sport=") and srcs == 1 and not sport:
                sport = part[6:]
            elif part.startswith("dport=") and srcs == 1 and not dport:
                dport = part[6:]
            elif part.startswith("bytes="):
                bytes_n += 1
                if bytes_n == 1:
                    up = int(part[6:] or 0)
                elif bytes_n == 2:
                    down = int(part[6:] or 0)
        if not src or not dst or not dport:
            continue
        flows.append({"src": src, "dst": dst, "sport": sport, "dport": int(dport), "proto": proto, "up": up, "down": down})
    return flows


def record_resource_visits(db: Session) -> None:
    peers = db.query(WireGuardPeer).all()
    by_ip = {}
    for peer in peers:
        device = peer.device
        if not device or not peer.vpn_ip or not device.user_id or device.site_id:
            continue
        by_ip[peer.vpn_ip] = (device.user_id, device.id)
    if not by_ip:
        return
    targets = _internal_targets(db)
    if not targets:
        return
    now = datetime.utcnow()
    seen: set[str] = set()
    for flow in _conntrack_flows():
        owner = by_ip.get(flow["src"])
        if not owner or flow["dport"] in (53, settings.employees_port, settings.sites_port):
            continue
        try:
            dest_ip = ipaddress.ip_address(flow["dst"])
        except ValueError:
            continue
        if dest_ip.is_loopback or dest_ip.is_multicast:
            continue
        matched = _match_target(dest_ip, flow["dport"], targets)
        if not matched:
            continue
        name, resource_id = matched
        key = f"{flow['src']}|{flow['dst']}|{flow['dport']}|{flow['sport']}|{flow['proto']}"
        seen.add(key)
        row = (
            db.query(ResourceVisit)
            .filter(ResourceVisit.flow_key == key, ResourceVisit.closed_at.is_(None))
            .one_or_none()
        )
        if row:
            row.last_seen_at = now
            row.bytes_up = max(row.bytes_up, flow["up"])
            row.bytes_down = max(row.bytes_down, flow["down"])
            row.resource_name = name
            row.resource_id = resource_id
            continue
        db.add(
            ResourceVisit(
                user_id=owner[0],
                device_id_fk=owner[1],
                flow_key=key,
                resource_id=resource_id,
                resource_name=name,
                destination=flow["dst"],
                port=flow["dport"],
                proto=flow["proto"],
                opened_at=now,
                last_seen_at=now,
                bytes_up=flow["up"],
                bytes_down=flow["down"],
            )
        )
    stale = (
        db.query(ResourceVisit)
        .filter(ResourceVisit.closed_at.is_(None), ResourceVisit.last_seen_at < now - timedelta(seconds=40))
        .all()
    )
    for row in stale:
        if row.flow_key not in seen:
            row.closed_at = now
    db.query(ResourceVisit).filter(ResourceVisit.opened_at < now - timedelta(days=90)).delete(synchronize_session=False)
    db.commit()


def _write_link(db: Session, peer: WireGuardPeer, device: Device | None, online: bool, endpoint: str, *, commit: bool = True) -> None:
    from .audit import audit
    from .osdetect import client_mac

    site = db.get(Site, device.site_id) if device and device.site_id else None
    user = None if site else (db.get(User, device.user_id) if device and device.user_id else None)
    who = site.name if site else (user.full_name if user else (device.name if device else peer.vpn_ip))
    ip = (endpoint or "").rsplit(":", 1)[0].strip("[]")
    if ip in ("(none)", ""):
        ip = ""
    audit(
        db,
        actor_id=user.id if user else "",
        actor_email=who,
        action="vpn_up" if online else "vpn_down",
        target=who,
        ip=ip,
        mac=client_mac(ip) if ip else "",
        device="Объект" if site else "Пользователь",
        commit=commit,
    )


def _note_link(db: Session, peer: WireGuardPeer, device: Device | None, online: bool, endpoint: str, *, commit: bool = True) -> None:
    if bool(peer.link_up) == online:
        return
    peer.link_up = online
    _write_link(db, peer, device, online, endpoint, commit=commit)


def _note_link_lost(db: Session) -> None:
    from .presence import peer_online
    peers = db.query(WireGuardPeer).filter(WireGuardPeer.link_up.is_(True)).with_for_update().all()
    for peer in peers:
        if peer_online(peer):
            continue
        device = db.get(Device, peer.device_id_fk)
        peer.link_up = False
        _write_link(db, peer, device, False, peer.endpoint or "")


def watchdog_tick(db: Session) -> None:
    _expire_access(db)
    record_resource_visits(db)
    _backfill_geo(db)
    _block_idle_accounts(db)
    now = datetime.utcnow()
    policy = _setting(db, "concurrent_policy", settings.concurrent_policy)
    stale = db.query(Session).filter(Session.active.is_(True), Session.expires_at < now).all()
    for session in stale:
        session.active = False
        peer = db.query(WireGuardPeer).filter(WireGuardPeer.device_id_fk == session.device_id_fk).one_or_none()
        if peer and peer.enabled:
            device = db.get(Device, session.device_id_fk)
            if device and not getattr(device, "require_agent", False):
                continue
            disable_peer(db, peer, "Нет подтверждения агента — туннель закрыт")
            emit(
                db,
                severity=EventSeverity.WARNING,
                code="SESSION_EXPIRED",
                title="Туннель закрыт: агент не подтвердил устройство",
                device=db.get(Device, session.device_id_fk),
                public_key=peer.public_key,
            )

    for contour in (Contour.EMPLOYEES, Contour.SITES):
        for row in wireguard.dump(contour):
            peer = (
                db.query(WireGuardPeer)
                .filter(WireGuardPeer.public_key == row["public_key"], WireGuardPeer.contour == contour)
                .with_for_update()
                .one_or_none()
            )
            from .peer_publication import try_lock_peer_publication, recheck_peer_publication
            if not try_lock_peer_publication(db, contour, row["public_key"]):
                # Release any row lock the publisher needs; revisit on the next tick.
                db.commit()
                continue
            if not peer:
                peer = recheck_peer_publication(db, contour, row["public_key"])
            if peer:
                # Publishers and expiry can already hold Device/User before
                # needing this Peer. Never wait for them while holding Peer.
                device = (db.query(Device).filter(Device.id == peer.device_id_fk)
                          .populate_existing().with_for_update(skip_locked=True).one_or_none())
                if not device:
                    db.commit()
                    continue
                if device.user_id:
                    owner = (db.query(User).filter(User.id == device.user_id)
                             .populate_existing().with_for_update(skip_locked=True).one_or_none())
                    if not owner:
                        db.commit()
                        continue
            if peer and not peer.enabled:
                try:
                    wireguard.remove_peer(contour, peer.public_key)
                except Exception:
                    pass
                db.commit()
                continue
            if not peer:
                try:
                    wireguard.remove_peer(contour, row["public_key"])
                except Exception:
                    pass
                emit(
                    db,
                    severity=EventSeverity.CRITICAL,
                    code="UNKNOWN_PEER",
                    title="Неизвестный WireGuard peer",
                    public_key=row["public_key"],
                    details=f"endpoint={row.get('endpoint')}",
                    auto_blocked=True,
                )
                continue
            peer.endpoint = row.get("endpoint") or peer.endpoint
            peer.rx_bytes = row.get("rx") or 0
            peer.tx_bytes = row.get("tx") or 0
            if row.get("latest_handshake"):
                peer.handshake_at = datetime.utcfromtimestamp(row["latest_handshake"])
            device = db.get(Device, peer.device_id_fk)
            if device and device.block_reason == KEY_LOCK:
                peer.enabled = False
                device.status = DeviceStatus.BLOCKED
                db.commit()
                try:
                    wireguard.remove_peer(contour, peer.public_key)
                except Exception:
                    pass
                continue
            _remember_presence(db, peer, device, peer.handshake_at)
            _apply_detected_os(device, peer)
            if device and not device.require_agent:
                # User opted into heuristic containment for standard clients,
                # including objects. Do not label roaming as proven cloning.
                fresh = peer.handshake_at and (datetime.utcnow() - peer.handshake_at).total_seconds() < 180
                places = _suspected_standard_key_share(peer, row.get("endpoint") or "", datetime.utcnow()) if fresh and peer.enabled else []
                if places:
                    emit(db, severity=EventSeverity.CRITICAL, code="KEY_SHARE_SUSPECTED",
                         title="Подозрение на использование ключа несколькими устройствами",
                         details="За 180 секунд зафиксировано повторное чередование адресов подключения: "
                                 + ", ".join(places)
                                 + ". VPN отключён по согласованному правилу. Это эвристика: возможна нестабильная сеть или NAT.",
                         device=device, user_id=device.user_id, public_key=peer.public_key,
                         external_ip=_endpoint_ip(row.get("endpoint") or ""))
                    continue
                from .presence import peer_online
                _note_link(db, peer, device, peer_online(peer), row.get("endpoint") or "")
                db.commit()
                continue
            live = (
                db.query(Session)
                .filter(Session.device_id_fk == peer.device_id_fk, Session.active.is_(True))
                .one_or_none()
            )
            handshake_fresh = row.get("latest_handshake") and (
                0 <= (datetime.utcnow() - datetime.utcfromtimestamp(row["latest_handshake"])).total_seconds() < 180
            )
            if handshake_fresh and peer.enabled:
                places = _shared_endpoints(_note_endpoint(peer, row.get("endpoint") or "", datetime.utcnow()))
                if places:
                    site = db.get(Site, device.site_id) if device and device.site_id else None
                    owner = None if site else (db.get(User, device.user_id) if device and device.user_id else None)
                    if owner and owner.role == Role.USER:
                        owner.is_active = False
                    if site:
                        who = f"объекта «{site.name}»"
                    else:
                        who = owner.full_name if owner else (device.name if device else "сотрудника")
                    where = " и ".join(places)
                    second_ip = (places[1] if len(places) > 1 else places[-1]).split(":")[0]
                    geo, isp = lookup_place(second_ip)
                    from .osdetect import client_mac
                    mac = client_mac(second_ip)
                    disable_peer(db, peer, KEY_LOCK)
                    emit(
                        db,
                        severity=EventSeverity.CRITICAL,
                        code="KEY_SHARE",
                        title="К одному ключу подключились несколько компьютеров",
                        details=f"Ключ {who} использовали сразу с нескольких компьютеров: {where}. Второе устройство: {second_ip}. Подключения заблокированы.",
                        user_id=None if site else (device.user_id if device else None),
                        device=device,
                        public_key=peer.public_key,
                        external_ip=second_ip,
                        geo=geo,
                        isp=isp,
                        mac=mac,
                        auto_blocked=True,
                    )
                    continue
            if handshake_fresh and not live:
                if device and not getattr(device, "require_agent", False):
                    _note_link(db, peer, device, bool(peer.enabled), row.get("endpoint") or "")
                    db.commit()
                    continue
                block_key_copy(
                    db,
                    peer,
                    old_device_id=device.device_id if device else "",
                    new_device_id="unattested",
                    external_ip=(row.get("endpoint") or "").split(":")[0],
                    details="Handshake без живой сессии агента — вероятная копия ключа",
                )
                continue
            if live and handshake_fresh and row.get("endpoint") and row["endpoint"] not in ("(none)", ""):
                ep_ip = row["endpoint"].rsplit(":", 1)[0].strip("[]")
                if live.external_ip and ep_ip and live.external_ip != ep_ip and not live.external_ip.startswith("192.168."):
                    if policy == "WARN":
                        emit(
                            db,
                            severity=EventSeverity.WARNING,
                            code="CONCURRENT_USE",
                            title="Возможное копирование VPN-ключа",
                            device=device,
                            user_id=device.user_id if device else None,
                            public_key=peer.public_key,
                            external_ip=ep_ip,
                            details=f"Сессия с {live.external_ip}, handshake с {ep_ip}",
                        )
                    elif policy == "BLOCK_NEW":
                        try:
                            wireguard.remove_peer(peer.contour, peer.public_key)
                        except Exception:
                            pass
                    else:
                        block_key_copy(
                            db,
                            peer,
                            old_device_id=device.device_id if device else "",
                            new_device_id=live.attested_device_id,
                            external_ip=ep_ip,
                            details=f"Одновременное использование: сессия {live.external_ip}, handshake {ep_ip}",
                        )
            from .presence import peer_online
            _note_link(db, peer, device, peer_online(peer), row.get("endpoint") or "")
            db.commit()
    _note_link_lost(db)
