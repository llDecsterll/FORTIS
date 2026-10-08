"""Explicit employee destinations, shared by issuance, config and firewall."""
import ipaddress
import json
from datetime import datetime
from fastapi import HTTPException
from .config import settings
from .models import Contour, Network, Setting, WireGuardPeer, DeviceStatus

def auto_site_access(db):
    flag=db.get(Setting,'employee_auto_site_access')
    return bool(settings.employees_enabled and settings.sites_enabled and flag and flag.value=='true')

def live_peer(peer):
    d=peer.device
    now=datetime.utcnow()
    return bool(peer.enabled and d and d.status==DeviceStatus.ACTIVE
                and (not d.access_from or d.access_from<=now)
                and (not d.access_until or d.access_until>now))

def automatic_site_lans(db):
    if not auto_site_access(db): return []
    result=[]
    pools=[ipaddress.ip_network(settings.employees_net),ipaddress.ip_network(settings.sites_net)]
    for p in db.query(WireGuardPeer).filter(WireGuardPeer.contour==Contour.SITES):
        if not live_peer(p) or not p.device.site: continue
        owned={x.strip() for x in (p.device.site.lan_cidr or '').split(',')}
        for value in (p.allowed_lans or '').split(','):
            if value.strip() not in owned: continue
            try: net=ipaddress.ip_network(value.strip(),strict=True)
            except ValueError: continue
            if net.version==4 and net.prefixlen>0 and not any(net.overlaps(pool) for pool in pools):
                result.append(str(net))
    return sorted(set(result))

def auto_forward_rules(db):
    if not auto_site_access(db): return [],[]
    forward,nat=[],[]
    emp,site=settings.employees_if,settings.sites_if
    lans=automatic_site_lans(db)
    for p in db.query(WireGuardPeer).filter(WireGuardPeer.contour==Contour.EMPLOYEES):
        if not live_peer(p):
            forward.append(f'    iifname "{emp}" ip saddr {p.vpn_ip} drop')
            forward.append(f'    oifname "{emp}" ip daddr {p.vpn_ip} drop')
            continue
        for lan in lans:
            forward.append(f'    iifname "{emp}" oifname "{site}" ip saddr {p.vpn_ip} ip daddr {lan} accept')
            forward.append(f'    iifname "{site}" oifname "{emp}" ip saddr {lan} ip daddr {p.vpn_ip} ct state established,related accept')
            nat.append(f'    oifname "{site}" ip saddr {p.vpn_ip} ip daddr {lan} snat to {settings.sites_server_ip}')
    # Revoke established cross-contour flows too; other contours remain isolated.
    forward.extend([f'    iifname "{emp}" oifname "{site}" drop',f'    iifname "{site}" oifname "{emp}" drop'])
    return forward,nat

def selectable(net):
    subnet = ipaddress.ip_network(net.cidr, strict=True)
    pools = [ipaddress.ip_network(settings.employees_net), ipaddress.ip_network(settings.sites_net)]
    return net.contour == Contour.EMPLOYEES and not net.is_restricted and subnet.version == 4 and subnet.prefixlen > 0 and not any(subnet.overlaps(p) for p in pools)

def automatic_company_lans(db):
    """Explicit deployment policy; deleted/restricted catalog entries fail closed."""
    policy = db.get(Setting, 'employee_auto_company_lans')
    if not policy:
        return []
    try:
        values = json.loads(policy.value)
    except (ValueError, TypeError):
        return []
    if not isinstance(values, list) or any(not isinstance(v, str) for v in values):
        return []
    allowed = {n.cidr for n in db.query(Network).filter(Network.contour == Contour.EMPLOYEES) if selectable(n)}
    return list(dict.fromkeys(v for v in values if v in allowed))

def selected_networks(db, values):
    if isinstance(values, str):
        try: values = json.loads(values)
        except (ValueError, TypeError): raise HTTPException(422, 'Некорректный список сетей')
    if not isinstance(values, list) or not values or len(values) > 256 or any(not isinstance(v, str) for v in values):
        raise HTTPException(422, 'Выберите хотя бы одну сеть сотрудника')
    rows = []
    for value in dict.fromkeys(values):
        net = db.get(Network, value)
        if not net or not selectable(net):
            raise HTTPException(422, 'Выбранная сеть недоступна для сотрудников. Обновите список сетей')
        rows.append(net)
    return rows

def effective_employee_destinations(db, peer):
    allowed = {n.cidr for n in db.query(Network).filter(Network.contour == Contour.EMPLOYEES) if selectable(n)}
    result=[cidr for cidr in (peer.destination_cidrs or '').split(',') if cidr in allowed]
    result.extend(automatic_company_lans(db))
    if auto_site_access(db): result.extend(['192.168.3.0/24',*automatic_site_lans(db)])
    return list(dict.fromkeys(result))
