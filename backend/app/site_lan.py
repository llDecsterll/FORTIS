"""Approved site LAN updates; preserve peer identity and compensate OS failures."""
from datetime import datetime
import ipaddress
import json
import logging
from sqlalchemy import text
from fastapi import HTTPException
from . import wireguard
from .config import settings
from .models import Contour, Device, DeviceStatus, Network, Site, WireGuardPeer
from .nft import apply_acl
from .provision import render_stored_config

log = logging.getLogger(__name__)


def connected_networks():
    return [r['dst'] for r in json.loads(wireguard._run(['ip','-j','-4','route','show','table','all']))
            if r.get('dst') and r['dst'] != 'default' and r.get('dev') != settings.sites_if]


def validate_lans(db, site_id, value):
    parts = [p.strip() for p in value.split(',') if p.strip()]
    if not parts or len(parts) > 16:
        raise ValueError('Укажите от 1 до 16 локальных IPv4-подсетей через запятую')
    nets = []
    private = [ipaddress.ip_network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')]
    for part in parts:
        try:
            net = ipaddress.ip_network(part, strict=True)
        except ValueError as exc:
            raise ValueError('Укажите адрес сети с маской, например 192.168.88.0/24. Адрес устройства вместо адреса сети не допускается.') from exc
        if '/' not in part or net.version != 4 or not any(net.subnet_of(n) for n in private):
            raise ValueError('Нужна локальная IPv4-подсеть с маской, например 192.168.88.0/24')
        if net in nets:
            continue
        if any(net.overlaps(n) for n in nets):
            raise ValueError('Указанные подсети пересекаются между собой')
        nets.append(net)
    occupied = [settings.employees_net, settings.sites_net, *connected_networks()]
    occupied += [n.cidr for n in db.query(Network).all()]
    occupied += [p.strip() for p in settings.extra_allowed_ips.split(',') if p.strip()]
    for site in db.query(Site).filter(Site.id != site_id).all():
        occupied += [p.strip() for p in (site.lan_cidr or '').split(',') if p.strip()]
    for peer in db.query(WireGuardPeer).join(Device).filter(Device.site_id != site_id).all():
        occupied += [p.strip() for p in (peer.allowed_lans or '').split(',') if p.strip()]
    for cidr in occupied:
        other = ipaddress.ip_network(cidr, strict=False)
        # Internet policy is not ownership of all LANs; narrower destinations are.
        if other.version == 4 and other.prefixlen and any(n.overlaps(other) for n in nets):
            raise ValueError(f'Подсеть пересекается с сетью сервера, VPN или другого объекта: {other}')
    return ', '.join(str(n) for n in nets)


def update_site_lan(db, site_id, value, destinations=None):
    # Serialize concurrent allocations across API workers; transaction-scoped lock.
    if db.bind.dialect.name == 'postgresql':
        db.execute(text('SELECT pg_advisory_xact_lock(734027)'))
    site = db.query(Site).filter(Site.id == site_id).with_for_update().first()
    if not site:
        raise HTTPException(404, 'Объект не найден')
    peer = db.query(WireGuardPeer).join(Device).filter(Device.site_id == site_id).with_for_update(of=WireGuardPeer).first()
    if not peer:
        raise HTTPException(409, 'Сначала согласуйте и выдайте VPN-доступ объекту')
    device = db.query(Device).filter(Device.id == peer.device_id_fk).with_for_update().one()
    if not peer.enabled or device.status != DeviceStatus.ACTIVE or (device.access_until and device.access_until <= datetime.utcnow()):
        raise HTTPException(409, 'Изменение сетей доступно только для действующего VPN. Сначала восстановите доступ установленным порядком.')
    try:
        new = validate_lans(db, site_id, value)
        from .site_destinations import validate_destinations
        selected = validate_destinations(db, destinations, new) if destinations is not None else peer.destination_cidrs
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    old = peer.allowed_lans or ''
    identity = (peer.contour, peer.public_key, peer.preshared_key)
    vpn_ip = peer.vpn_ip
    allowed = lambda lans: ', '.join([f'{vpn_ip}/32', *[p.strip() for p in lans.split(',') if p.strip()]])
    try:
        site.lan_cidr = new
        peer.destination_cidrs = selected
        peer.allowed_lans = new
        peer.client_config = render_stored_config(db, peer)
        db.flush()
        wireguard.set_peer(*identity, allowed(new))
        wireguard.sync_site_lan_routes(new, old)
        apply_acl(db)
        db.commit()
    except Exception as exc:
        db.rollback()
        try:
            wireguard.set_peer(*identity, allowed(old))
            wireguard.sync_site_lan_routes(old, new)
            apply_acl(db)
        except Exception:
            log.exception('Site LAN rollback failed for site %s; disabling peer', site_id)
            # Never leave uncommitted network access intentionally enabled.
            peer = db.query(WireGuardPeer).filter(WireGuardPeer.device_id_fk == device.id).one()
            peer.enabled = False
            device.status = DeviceStatus.BLOCKED
            device.block_reason = 'Ошибка применения сети объекта: требуется проверка администратора'
            db.commit()
            try:
                wireguard.remove_peer(*identity[:2])
                apply_acl(db)
            except Exception:
                log.exception('Emergency site LAN disable failed for site %s', site_id)
        raise HTTPException(503, 'Не удалось применить подсети. Прежняя настройка восстановлена либо VPN отключён; проверьте журнал сервера.') from exc
    return {'lanCidr': new, 'previousLanCidr': old, 'destinations': selected.split(',') if selected else []}
