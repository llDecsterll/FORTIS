from __future__ import annotations

import re
import ipaddress
import uuid
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from . import engine as security_engine, wireguard
from .config import settings
from .models import AccessPolicy, Contour, Device, DeviceStatus, DeviceType, Network, WireGuardPeer
from .nft import apply_acl


def slug(name: str) -> str:
    text = re.sub(r"[^a-zA-Z0-9._-]+", "_", name.strip())
    return (text.strip("_") or "peer")[:48]


def _default_networks(db: Session, contour: Contour) -> list[Network]:
    return (
        db.query(Network)
        .filter(Network.contour == contour, Network.is_restricted.is_(False))
        .all()
    )


def _site_destinations(db: Session, lan_cidr: str) -> list[str]:
    local = [ipaddress.ip_network(p.strip(), strict=False) for p in lan_cidr.split(',') if p.strip()]
    candidates = [settings.sites_net] + [n.cidr for n in _default_networks(db, Contour.SITES)]
    return [cidr for cidr in candidates if not any(ipaddress.ip_network(cidr, strict=False).overlaps(net) for net in local)]


def access_until_from_days(days: int | None) -> datetime | None:
    if days is None or int(days) <= 0:
        return None
    if int(days) > 3650:
        raise ValueError("Срок доступа не больше 10 лет")
    return datetime.utcnow() + timedelta(days=int(days))


def issue_wireguard(
    db: Session,
    *,
    name: str,
    contour: Contour,
    user_id: str | None = None,
    site_id: str | None = None,
    lan_cidr: str = "",
    actor_email: str = "",
    os_name: str = "",
    device_name: str = "",
    access_until: datetime | None = None,
) -> dict:
    priv, pub = wireguard.gen_keypair()
    psk = wireguard.gen_psk()
    used = {p.vpn_ip for p in db.query(WireGuardPeer).all()}
    vpn_ip = wireguard.next_vpn_ip(contour, used)
    now = datetime.utcnow()
    device = Device(
        name=(device_name or name).strip() or name,
        device_id=f"issued-{uuid.uuid4()}",
        user_id=user_id,
        site_id=site_id,
        contour=contour,
        device_type=DeviceType.ROUTER if contour == Contour.SITES else DeviceType.LAPTOP,
        os_name=(os_name or "").strip(),
        status=DeviceStatus.PENDING,
        require_agent=False,
        enrolled_by=actor_email,
        enrolled_at=now,
        access_from=now if access_until else None,
        access_until=access_until,
    )
    db.add(device)
    db.flush()
    nets = _default_networks(db, contour)
    for net in nets:
        db.add(AccessPolicy(device_id_fk=device.id, network_id=net.id, allowed=True))
    if contour == Contour.EMPLOYEES:
        parts = [n.cidr for n in nets] or [settings.employees_net]
    else:
        parts = _site_destinations(db, lan_cidr)
    for extra in [p.strip() for p in settings.extra_allowed_ips.split(",") if p.strip()]:
        parts.append(extra)
    allowed_client = ", ".join(dict.fromkeys(parts))
    cfg = wireguard.client_config(
        private_key=priv,
        address=vpn_ip,
        contour=contour,
        server_public=wireguard.server_public_key(contour),
        psk=psk,
        extra_allowed=allowed_client,
    )
    peer = WireGuardPeer(
        device_id_fk=device.id,
        contour=contour,
        public_key=pub,
        private_key=priv,
        preshared_key=psk,
        vpn_ip=vpn_ip,
        allowed_lans=lan_cidr,
        client_config=cfg,
        enabled=False,
    )
    db.add(peer)
    db.flush()
    # Creation alone is not authorization. The approval handler installs the peer.
    filename = f"{slug(name)}.conf"
    return {
        "deviceId": device.id,
        "vpnIp": vpn_ip,
        "publicKey": pub,
        "filename": filename,
        "config": cfg,
    }


def render_stored_config(db: Session, peer: WireGuardPeer) -> str:
    from .site_destinations import effective_destinations
    from .employee_networks import auto_site_access, automatic_company_lans
    if peer.contour == Contour.EMPLOYEES:
        nets = _default_networks(db, Contour.EMPLOYEES)
        parts = [n.cidr for n in nets] or [settings.employees_net]
    else:
        parts = _site_destinations(db, peer.allowed_lans)
    for extra in [p.strip() for p in settings.extra_allowed_ips.split(",") if p.strip()]:
        parts.append(extra)
    if peer.contour == Contour.SITES and peer.destination_cidrs:
        parts = effective_destinations(db, peer)
    resource_policies = db.query(AccessPolicy).filter(AccessPolicy.device_id_fk == peer.device_id_fk, AccessPolicy.resource_id.is_not(None), AccessPolicy.allowed.is_(True)).first()
    if peer.contour == Contour.EMPLOYEES and (peer.destination_cidrs or resource_policies or auto_site_access(db) or automatic_company_lans(db)):
        from .employee_networks import effective_employee_destinations
        parts = effective_employee_destinations(db, peer)
        if not parts and not db.query(AccessPolicy).filter(AccessPolicy.device_id_fk == peer.device_id_fk, AccessPolicy.resource_id.is_not(None), AccessPolicy.allowed.is_(True)).first():
            raise ValueError('Для сотрудника не осталось разрешённых сетей')
    from .resource_acl import permitted_services
    device = db.get(Device, peer.device_id_fk)
    if device:
        parts.extend(host + "/32" for host, _, _ in permitted_services(db, device))
    from .site_links import linked_destinations
    parts.extend(linked_destinations(db, peer))
    extra = ", ".join(dict.fromkeys(parts))
    cfg = wireguard.client_config(
        private_key=peer.private_key,
        address=peer.vpn_ip,
        contour=peer.contour,
        server_public=wireguard.server_public_key(peer.contour),
        psk=peer.preshared_key,
        extra_allowed=extra,
    )
    peer.client_config = cfg
    return cfg


def refresh_client_configs(db: Session) -> int:
    updated = 0
    for peer in db.query(WireGuardPeer).all():
        if not peer.private_key:
            continue
        render_stored_config(db, peer)
        updated += 1
    return updated


def restore_enabled_peers(db: Session) -> int:
    restored = 0
    for peer in db.query(WireGuardPeer).filter(WireGuardPeer.enabled.is_(True)).all():
        if not peer.public_key or not peer.preshared_key or not peer.vpn_ip:
            continue
        allowed = [f"{peer.vpn_ip}/32"]
        if peer.allowed_lans:
            allowed.extend([part.strip() for part in peer.allowed_lans.split(",") if part.strip()])
        try:
            wireguard.set_peer(peer.contour, peer.public_key, peer.preshared_key, ", ".join(allowed))
            restored += 1
        except Exception:
            continue
    return restored


def _restore_if_allowed(db: Session, device: Device) -> None:
    if not device.peer or device.peer.enabled:
        return
    if device.status in (DeviceStatus.BLOCKED, DeviceStatus.EXPIRED, DeviceStatus.REVOKED) or device.require_agent:
        return
    security_engine.enable_peer(db, device.peer)


def config_for_device(db: Session, device: Device) -> str:
    peer = device.peer
    if not peer:
        raise LookupError("У устройства нет профиля WireGuard")
    if not peer.private_key:
        if peer.client_config:
            return peer.client_config
        raise LookupError("Приватный ключ не сохранён — выдайте профиль заново")
    return render_stored_config(db, peer)


def ensure_peer_for_user(db: Session, user, actor_email: str, os_name: str = "", device_name: str = "", access_until: datetime | None = None) -> dict:
    existing = next((d for d in user.devices if d.peer and not d.site_id), None)
    if existing and existing.peer and (existing.peer.client_config or existing.peer.private_key):
        cfg = config_for_device(db, existing)
        _restore_if_allowed(db, existing)
        return {
            "deviceId": existing.id,
            "vpnIp": existing.peer.vpn_ip,
            "publicKey": existing.peer.public_key,
            "filename": f"{slug(user.full_name)}.conf",
            "config": cfg,
        }
    return issue_wireguard(
        db,
        name=user.full_name,
        contour=Contour.EMPLOYEES,
        user_id=user.id,
        actor_email=actor_email,
        os_name=os_name,
        device_name=device_name,
        access_until=access_until,
    )


def ensure_peer_for_site(db: Session, site, actor_email: str, os_name: str = "", access_until: datetime | None = None) -> dict:
    existing = next((d for d in site.devices if d.peer), None)
    if existing and existing.peer and (existing.peer.client_config or existing.peer.private_key):
        cfg = config_for_device(db, existing)
        _restore_if_allowed(db, existing)
        return {
            "deviceId": existing.id,
            "vpnIp": existing.peer.vpn_ip,
            "publicKey": existing.peer.public_key,
            "filename": f"{slug(site.name)}.conf",
            "config": cfg,
        }
    return issue_wireguard(
        db,
        name=site.router_name or site.name,
        contour=Contour.SITES,
        user_id=site.owner_id,
        site_id=site.id,
        lan_cidr=site.lan_cidr,
        actor_email=actor_email,
        os_name=os_name,
        device_name=site.router_name or site.name,
        access_until=access_until,
    )
