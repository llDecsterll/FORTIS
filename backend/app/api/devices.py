from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from .. import engine, wireguard
from ..audit import audit
from ..db import get_db
from ..models import AccessPolicy, Device, DeviceStatus, Network, Resource, Role, User
from ..presence import peer_online
from ..provision import config_for_device, slug
from ..security import current_user, require_roles
from .users import release_allowed, _require_released

router = APIRouter(tags=["devices"])


def _device_out(d: Device) -> dict:
    peer = d.peer
    cert = d.certificate
    return {
        "id": d.id,
        "name": d.name,
        "deviceId": d.device_id,
        "userId": d.user_id,
        "userName": d.user.full_name if d.user else "",
        "email": d.user.email if d.user else "",
        "company": d.user.company.name if d.user and d.user.company else "",
        "department": d.user.department.name if d.user and d.user.department else "",
        "siteId": d.site_id,
        "siteName": d.site.name if d.site else "",
        "contour": d.contour.value,
        "deviceType": d.device_type.value,
        "osName": d.os_name,
        "serial": d.serial,
        "macEthernet": d.mac_ethernet,
        "macWifi": d.mac_wifi,
        "systemIdentifier": d.system_identifier,
        "status": d.status.value,
        "blockReason": d.block_reason,
        "vpnIp": peer.vpn_ip if peer else "",
        "publicKey": peer.public_key if peer else "",
        "endpoint": peer.endpoint if peer else "",
        "handshakeAt": peer.handshake_at.isoformat() if peer and peer.handshake_at else None,
        "online": peer_online(peer),
        "rxBytes": peer.rx_bytes if peer else 0,
        "txBytes": peer.tx_bytes if peer else 0,
        "enabled": peer.enabled if peer else False,
        "certFingerprint": cert.fingerprint if cert else "",
        "certSerial": cert.serial if cert else "",
        "certRevoked": cert.revoked if cert else False,
        "accessFrom": d.access_from.isoformat() if d.access_from else None,
        "accessUntil": d.access_until.isoformat() if d.access_until else None,
        "lastSeenAt": d.last_seen_at.isoformat() if d.last_seen_at else None,
        "lastExternalIp": d.last_external_ip,
        "lastGeo": d.last_geo,
        "enrolledBy": d.enrolled_by,
        "enrolledAt": d.enrolled_at.isoformat() if d.enrolled_at else None,
        "hasConfig": bool(peer and (peer.client_config or peer.private_key)),
        "configName": f"{slug(d.name)}.conf" if peer else "",
        "requireAgent": d.require_agent,
    }


@router.get("/devices")
def list_devices(contour: str | None = None, status: str | None = None, db: Session = Depends(get_db), actor: User = Depends(current_user)):
    q = db.query(Device)
    if actor.role == Role.USER:
        q = q.filter(Device.user_id == actor.id, Device.site_id.is_(None))
    if contour:
        q = q.filter(Device.contour == contour)
    if status:
        q = q.filter(Device.status == status)
    rows = q.order_by(Device.created_at.desc()).all()
    return {"data": [_device_out(d) for d in rows]}


@router.get("/devices/{device_id}")
def get_device(device_id: str, db: Session = Depends(get_db), actor: User = Depends(current_user)):
    d = db.get(Device, device_id)
    if not d:
        raise HTTPException(404, "Устройство не найдено")
    if actor.role not in (Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF) and (d.site_id or d.user_id != actor.id):
        raise HTTPException(403, "Доступно только собственное устройство")
    policies = db.query(AccessPolicy).filter(AccessPolicy.device_id_fk == d.id).all()
    nets, resources = [], []
    for p in policies:
        if p.network:
            nets.append({"id": p.network.id, "name": p.network.name, "cidr": p.network.cidr})
        if p.resource:
            resources.append({"id": p.resource.id, "name": p.resource.name, "host": p.resource.host})
    config = ""
    if release_allowed(db, user_id=d.user_id, site_id=d.site_id):
        try:
            config = config_for_device(db, d)
        except LookupError:
            config = ""
    return {**_device_out(d), "networks": nets, "resources": resources, "config": config}


@router.get("/devices/{device_id}/wireguard.conf")
def download_device_config(device_id: str, request: Request, db: Session = Depends(get_db), actor: User = Depends(current_user)):
    d = db.get(Device, device_id)
    if not d:
        raise HTTPException(404, "Устройство не найдено")
    if actor.role not in (Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF) and (d.site_id or d.user_id != actor.id):
        raise HTTPException(403, "Можно получить только конфигурацию собственного устройства")
    _require_released(db, user_id=d.user_id, site_id=d.site_id)
    try:
        cfg = config_for_device(db, d)
    except LookupError as exc:
        raise HTTPException(409, str(exc)) from exc
    filename = f"{slug(d.name)}.conf"
    audit(db, actor_id=actor.id, actor_email=actor.email, action="wg_config_download", target=d.name, ip=request.client.host if request.client else "")
    return PlainTextResponse(
        cfg,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/devices/{device_id}/block")
def block_device(device_id: str, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN, Role.SECURITY, Role.IT_LEAD))):
    d = db.get(Device, device_id)
    if not d or not d.peer:
        raise HTTPException(404, "Устройство не найдено")
    engine.disable_peer(db, d.peer, "Блокировка администратором")
    audit(db, actor_id=actor.id, actor_email=actor.email, action="device_block", target=d.name, ip=request.client.host if request.client else "")
    return {"ok": True}


@router.post("/devices/{device_id}/unblock")
def unblock_device(device_id: str, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN, Role.SECURITY))):
    d = db.get(Device, device_id)
    if not d:
        raise HTTPException(404, "Устройство не найдено")
    if d.status == DeviceStatus.REVOKED:
        raise HTTPException(409, "Отозванное устройство нельзя разблокировать — зарегистрируйте новое")
    if d.certificate and d.certificate.revoked:
        raise HTTPException(409, "Сертификат устройства отозван — зарегистрируйте новое")
    if not d.site_id and d.user and not d.user.is_active:
        raise HTTPException(409, "Сначала разблокируйте учётную запись сотрудника")
    _require_released(db, user_id=d.user_id, site_id=d.site_id)
    now = datetime.utcnow()
    if d.access_until and d.access_until <= now:
        raise HTTPException(409, "Срок VPN истёк. Сначала согласуйте продление доступа")
    if d.access_from and d.access_from > now:
        raise HTTPException(409, "Срок VPN-доступа ещё не начался")
    if not d.require_agent and not d.peer:
        raise HTTPException(409, "У устройства нет профиля WireGuard")
    d.status = DeviceStatus.ACTIVE
    d.block_reason = ""
    if d.require_agent:
        db.commit()
    else:
        engine.enable_peer(db, d.peer)
    audit(db, actor_id=actor.id, actor_email=actor.email, action="device_unblock", target=d.name, ip=request.client.host if request.client else "")
    return {"ok": True}


@router.post("/devices/{device_id}/revoke")
def revoke_device(device_id: str, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN, Role.SECURITY, Role.IT_LEAD))):
    d = db.get(Device, device_id)
    if not d or not d.peer:
        raise HTTPException(404, "Устройство не найдено")
    if d.certificate:
        d.certificate.revoked = True
        d.certificate.revoked_at = datetime.utcnow()
    d.status = DeviceStatus.REVOKED
    engine.disable_peer(db, d.peer, "Устройство отозвано", DeviceStatus.REVOKED)
    audit(db, actor_id=actor.id, actor_email=actor.email, action="device_revoke", target=d.name, ip=request.client.host if request.client else "")
    return {"ok": True}
