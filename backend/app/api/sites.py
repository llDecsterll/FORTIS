from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse
import secrets
import re
import ipaddress
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..audit import audit
from ..db import get_db
from ..models import AccessRequest, Company, Contour, DeviceStatus, RequestStatus, Role, Site, User
from .. import engine
from ..provision import access_until_from_days, ensure_peer_for_site, slug
from .users import APPROVAL_WAIT, _require_released
from ..presence import peer_online
from ..schemas import ContactEmail, ContactPhone, ProviderName, SiteIn
from ..security import current_user, require_roles
from ..wireguard import WireGuardError
from ..site_validation import site_lan

router = APIRouter(tags=["sites"])


class ConfigNameIn(BaseModel):
    name: str = Field(min_length=1, max_length=20)


def config_filename(db, site):
    from ..models import Setting
    saved = db.get(Setting, 'site_config_name:' + site.id)
    return (saved.value if saved else ('site-' + site.id[:8])) + '.conf'


@router.put('/sites/{site_id}/config-name')
def set_config_name(site_id: str, payload: ConfigNameIn, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF))):
    from ..models import Setting
    site = _site_or_404(db, site_id)
    name = payload.name.strip()
    if name.endswith('.conf'): name = name[:-5]
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,14}', name):
        raise HTTPException(422, 'Имя: 1–15 латинских букв, цифр, дефисов или подчёркиваний; без пути и пробелов')
    key = 'site_config_name:' + site.id
    row = db.get(Setting, key)
    if row: row.value = name
    else: db.add(Setting(key=key, value=name))
    audit(db, actor_id=actor.id, actor_email=actor.email, action='site_config_rename', target=site.id, payload={'name':name})
    return {'filename':name + '.conf'}


class DestinationNetworkIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    cidr: str = Field(min_length=1, max_length=40)


@router.post('/sites/{site_id}/networks', status_code=201)
def add_destination_network(site_id: str, payload: DestinationNetworkIn, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF))):
    from ..models import Network
    from ..config import settings
    site = _site_or_404(db, site_id)
    try:
        if '/' not in payload.cidr: raise ValueError()
        net = ipaddress.ip_network(payload.cidr.strip(), strict=False)
        if net.version != 4 or not net.is_private or net.is_loopback or net.is_link_local or net.is_unspecified:
            raise ValueError()
        if any(net.overlaps(ipaddress.ip_network(pool)) for pool in (settings.employees_net, settings.sites_net)):
            raise ValueError()
    except ValueError:
        raise HTTPException(422, 'Укажите частную IPv4-подсеть вне VPN-пулов')
    if not payload.name.strip(): raise HTTPException(422, 'Укажите название сети')
    local = [ipaddress.ip_network(v.strip(), strict=False) for v in site.lan_cidr.split(',') if v.strip()]
    if any(net.overlaps(n) for n in local):
        raise HTTPException(422, 'Сеть назначения пересекается с локальной сетью роутера')
    if db.query(Network).filter(Network.contour == Contour.SITES, Network.cidr == str(net)).first():
        raise HTTPException(409, 'Такая сеть уже есть в каталоге объектов')
    n = Network(name=payload.name.strip(), cidr=str(net), contour=Contour.SITES, description='', is_restricted=False)
    db.add(n)
    db.flush()
    audit(db, actor_id=actor.id, actor_email=actor.email, action='network_create', target=n.id, payload={'cidr':str(net),'siteId':site.id})
    return {'id':n.id, 'cidr':str(net), 'name':n.name}


class SiteLanIn(BaseModel):
    lanCidr: str = Field(min_length=1, max_length=2048)
    destinations: list[str] | None = Field(default=None, max_length=256)


@router.get('/sites/{site_id}/routing')
def site_routing(site_id: str, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF))):
    from ..models import Device, WireGuardPeer
    from ..site_destinations import available_destinations
    _require_released(db, site_id=site_id)
    peer=db.query(WireGuardPeer).join(Device).filter(Device.site_id==site_id).first()
    if not peer: raise HTTPException(404,'VPN объекта не найден')
    return {'available':available_destinations(db),'selected':peer.destination_cidrs.split(',') if peer.destination_cidrs else []}


@router.put('/sites/{site_id}/lan')
def set_site_lan(site_id: str, payload: SiteLanIn, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF))):
    from ..site_lan import update_site_lan
    _require_released(db, site_id=site_id)
    result = update_site_lan(db, site_id, payload.lanCidr, payload.destinations)
    audit(db, actor_id=actor.id, actor_email=actor.email, action='site_lan_update', target=site_id,
          ip=request.client.host if request.client else '', payload=result)
    return result


def _site_approval(db: Session, site_id: str) -> tuple[str, str]:
    row = (
        db.query(AccessRequest)
        .filter(AccessRequest.site_id == site_id)
        .order_by(AccessRequest.created_at.desc())
        .first()
    )
    if not row:
        return "", ""
    return row.status.value, row.id


def _site_out(s: Site, db: Session) -> dict:
    from ..approval_author import approval_author
    device = next((d for d in (s.devices or []) if d.peer), None)
    peer = device.peer if device else None
    approval, approval_id = _site_approval(db, s.id)
    return {
        "id": s.id,
        "name": s.name,
        "createdAt": s.created_at.isoformat() + "Z" if s.created_at else None,
        "address": s.address,
        "lanCidr": s.lan_cidr,
        "routerName": s.router_name,
        "providerName": s.provider_name,
        "providerPhone": s.provider_phone,
        "providerEmail": s.provider_email,
        "ownerId": s.owner_id,
        "owner": s.owner.full_name if s.owner else "",
        "company": s.company.name if s.company else "",
        "notes": s.notes,
        "vpnIp": peer.vpn_ip if peer else "",
        "status": device.status.value if device else "NONE",
        "endpoint": peer.endpoint if peer else "",
        "handshakeAt": peer.handshake_at.isoformat() if peer and peer.handshake_at else None,
        "online": peer_online(peer),
        "rxBytes": peer.rx_bytes if peer else 0,
        "txBytes": peer.tx_bytes if peer else 0,
        "deviceId": device.id if device else "",
        "publicKey": peer.public_key if peer else "",
        "contour": Contour.SITES.value,
        "enrollmentToken": None,
        "hasConfig": bool(peer and (peer.client_config or peer.private_key)),
        "configName": config_filename(db, s) if peer else "",
        "osName": device.os_name if device else "",
        "deviceType": device.device_type.value if device else "",
        "deviceName": device.name if device else "",
        "lastGeo": device.last_geo if device else "",
        "accessUntil": device.access_until.isoformat() if device and device.access_until else None,
        "vpnEnabled": bool(peer and peer.enabled),
        "suspended": bool(device and device.status == DeviceStatus.BLOCKED and (device.block_reason or "") == "Работа приостановлена"),
        "disconnected": bool(device and device.status == DeviceStatus.BLOCKED and (device.block_reason or "") == "Объект отключён"),
        "keyLocked": (device.block_reason or "") == "К ключу подключились несколько компьютеров" if device else False,
        "approval": approval,
        "approvalId": approval_id,
        **approval_author(db, db.get(AccessRequest, approval_id) if approval_id else None),
    }


@router.get("/sites")
def list_sites(db: Session = Depends(get_db), _=Depends(require_roles(Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF))):
    return {"data": [_site_out(s, db) for s in db.query(Site).order_by(Site.name)]}


@router.post("/sites", status_code=201)
def create_site(payload: SiteIn, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF))):
    lan = site_lan(payload.lanCidr)
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Укажите название объекта")
    company_id = payload.companyId
    company_name = (payload.companyName or "").strip()
    if not company_id and company_name:
        existing = db.query(Company).filter(Company.name.ilike(company_name)).first()
        if existing:
            company_id = existing.id
        else:
            company = Company(name=company_name)
            db.add(company)
            db.flush()
            company_id = company.id
    try:
        access_until = access_until_from_days(payload.accessDays)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    site = Site(
        name=name,
        address=payload.address.strip(),
        lan_cidr=lan,
        router_name=payload.routerName.strip(),
        provider_name=payload.providerName,
        provider_phone=payload.providerPhone,
        provider_email=payload.providerEmail,
        owner_id=payload.ownerId or actor.id,
        company_id=company_id,
        notes=payload.notes.strip(),
    )
    db.add(site)
    db.flush()
    db.add(AccessRequest(
        user_id=site.owner_id or actor.id,
        device_name=site.router_name or site.name,
        contour=Contour.SITES,
        site_id=site.id,
        reason=payload.reason or f"VPN объекта {site.name}",
        status=RequestStatus.PENDING_APPROVAL,
        access_until=access_until,
        created_by=actor.email,
    ))
    db.commit()
    db.refresh(site)
    audit(db, actor_id=actor.id, actor_email=actor.email, action="site_create", target=site.name, ip=request.client.host if request.client else "")
    out = _site_out(site, db)
    out["vpnIp"] = ""
    out["hasConfig"] = False
    return out


@router.get("/sites/{site_id}")
def get_site(site_id: str, db: Session = Depends(get_db), _=Depends(require_roles(Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF))):
    s = db.get(Site, site_id)
    if not s:
        raise HTTPException(404, "Объект не найден")
    return _site_out(s, db)


class SiteEditIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    address: str = Field(default='', max_length=500)
    routerName: str = Field(default='', max_length=200)
    notes: str = Field(default='', max_length=4000)
    lanCidr: str = Field(min_length=1, max_length=2048)
    providerName: ProviderName | None = None
    providerPhone: ContactPhone | None = None
    providerEmail: ContactEmail | None = None


@router.patch('/sites/{site_id}')
def edit_site(site_id: str, payload: SiteEditIn, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF))):
    site = db.query(Site).filter(Site.id == site_id).with_for_update().one_or_none()
    if not site:
        raise HTTPException(404, 'Объект не найден')
    name = payload.name.strip()
    if not name:
        raise HTTPException(422, 'Укажите название объекта')
    lan = site_lan(payload.lanCidr)
    has_peer = any(d.peer for d in site.devices)
    if has_peer and lan != site_lan(site.lan_cidr):
        raise HTTPException(409, 'VPN уже выдан. Меняйте LAN через «Скачать → Настроить роутер», чтобы одновременно обновить маршруты сервера.')
    site.name, site.address = name, payload.address.strip()
    site.router_name, site.notes, site.lan_cidr = payload.routerName.strip(), payload.notes.strip(), lan
    for field, attribute in (("providerName", "provider_name"), ("providerPhone", "provider_phone"), ("providerEmail", "provider_email")):
        value = getattr(payload, field)
        if value is not None:
            setattr(site, attribute, value)
    for row in db.query(AccessRequest).filter(AccessRequest.site_id == site.id, AccessRequest.status == RequestStatus.PENDING_APPROVAL).all():
        row.device_name = site.router_name or site.name
    audit(db, actor_id=actor.id, actor_email=actor.email, action='site_edit', target=site.id,
          ip=request.client.host if request.client else '', payload={'lanCidr':lan})
    db.refresh(site)
    return _site_out(site, db)


@router.get("/sites/{site_id}/vpn")
def site_vpn(site_id: str, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF))):
    site = db.get(Site, site_id)
    if not site:
        raise HTTPException(404, "Объект не найден")
    _require_released(db, site_id=site.id)
    vpn = ensure_peer_for_site(db, site, actor.email)
    vpn['filename'] = config_filename(db, site)
    db.commit()
    return vpn


def _site_or_404(db: Session, site_id: str) -> Site:
    site = db.get(Site, site_id)
    if not site:
        raise HTTPException(404, "Объект не найден")
    return site


def _site_peer(site: Site):
    device = next((d for d in (site.devices or []) if d.peer), None)
    if not device or not device.peer:
        raise HTTPException(status_code=409, detail="У объекта нет профиля WireGuard")
    if device.status == DeviceStatus.EXPIRED:
        raise HTTPException(status_code=409, detail="Срок доступа истёк")
    if device.status == DeviceStatus.REVOKED:
        raise HTTPException(status_code=409, detail="Ключ отозван. Требуется новый VPN-профиль")
    return device


@router.post("/sites/{site_id}/suspend")
def suspend_site(site_id: str, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF, Role.SECURITY))):
    site = _site_or_404(db, site_id)
    device = _site_peer(site)
    engine.disable_peer(db, device.peer, "Работа приостановлена")
    audit(db, actor_id=actor.id, actor_email=actor.email, action="site_suspend", target=site.name, ip=request.client.host if request.client else "")
    db.refresh(site)
    return _site_out(site, db)


@router.post("/sites/{site_id}/resume")
def resume_site(site_id: str, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF, Role.SECURITY))):
    site = _site_or_404(db, site_id)
    device = _site_peer(site)
    if device.block_reason in (APPROVAL_WAIT, "Отклонено службой безопасности"):
        raise HTTPException(status_code=409, detail="Ключ закрыт до согласования заявки")
    if device.block_reason == "К ключу подключились несколько компьютеров":
        raise HTTPException(status_code=409, detail="Ключ заблокирован после инцидента. Разблокировать может только администратор")
    device.block_reason = ""
    engine.enable_peer(db, device.peer)
    audit(db, actor_id=actor.id, actor_email=actor.email, action="site_resume", target=site.name, ip=request.client.host if request.client else "")
    db.refresh(site)
    return _site_out(site, db)


@router.post("/sites/{site_id}/disconnect")
def disconnect_site(site_id: str, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF, Role.SECURITY))):
    site = _site_or_404(db, site_id)
    device = _site_peer(site)
    engine.disable_peer(db, device.peer, "Объект отключён")
    audit(db, actor_id=actor.id, actor_email=actor.email, action="site_disconnect", target=site.name, ip=request.client.host if request.client else "")
    db.refresh(site)
    return _site_out(site, db)


@router.post("/sites/{site_id}/connect")
def connect_site(site_id: str, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF, Role.SECURITY))):
    site = _site_or_404(db, site_id)
    device = _site_peer(site)
    if device.block_reason in (APPROVAL_WAIT, "Отклонено службой безопасности"):
        raise HTTPException(status_code=409, detail="Ключ закрыт до согласования заявки")
    if device.block_reason == "К ключу подключились несколько компьютеров":
        raise HTTPException(status_code=409, detail="Ключ заблокирован после инцидента. Разблокировать может только администратор")
    device.block_reason = ""
    engine.enable_peer(db, device.peer)
    audit(db, actor_id=actor.id, actor_email=actor.email, action="site_connect", target=site.name, ip=request.client.host if request.client else "")
    db.refresh(site)
    return _site_out(site, db)


@router.post("/sites/{site_id}/unblock")
def unblock_site(site_id: str, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN))):
    site = _site_or_404(db, site_id)
    device = _site_peer(site)
    if device.block_reason in (APPROVAL_WAIT, "Отклонено службой безопасности"):
        raise HTTPException(status_code=409, detail="Ключ закрыт до согласования заявки")
    device.block_reason = ""
    device.status = DeviceStatus.ACTIVE
    engine.enable_peer(db, device.peer)
    audit(db, actor_id=actor.id, actor_email=actor.email, action="site_unblock", target=site.name, ip=request.client.host if request.client else "")
    db.refresh(site)
    return _site_out(site, db)


@router.delete("/sites/{site_id}")
def delete_site(site_id: str, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF))):
    site = db.get(Site, site_id)
    if not site:
        raise HTTPException(404, "Объект не найден")
    target = site.name
    engine.purge_site(db, site)
    db.commit()
    audit(db, actor_id=actor.id, actor_email=actor.email, action="site_delete", target=target, ip=request.client.host if request.client else "")
    return {"ok": True}


@router.get("/sites/{site_id}/wireguard.conf")
def download_site_config(site_id: str, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF))):
    site = db.get(Site, site_id)
    if not site:
        raise HTTPException(404, "Объект не найден")
    _require_released(db, site_id=site.id)
    vpn = ensure_peer_for_site(db, site, actor.email)
    vpn['filename'] = config_filename(db, site)
    db.commit()
    audit(db, actor_id=actor.id, actor_email=actor.email, action="wg_config_download", target=site.name, ip=request.client.host if request.client else "")
    return PlainTextResponse(
        vpn["config"],
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{vpn["filename"]}"'},
    )
