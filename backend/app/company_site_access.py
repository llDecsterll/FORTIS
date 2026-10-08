"""Explicit company LAN access to active site LANs; return traffic only."""
import ipaddress
import json

from .config import settings
from .models import Contour, Setting, WireGuardPeer
from .employee_networks import live_peer


def company_site_rules(db):
    policy = db.get(Setting, "company_site_access_sources")
    try:
        values = json.loads(policy.value) if policy else []
        if not isinstance(values, list):
            return [], []
        sources = sorted({str(ipaddress.IPv4Network(v, strict=True)) for v in values
                          if isinstance(v, str)})
        if len(sources) != len(set(values)) or any(ipaddress.ip_network(v).prefixlen == 0 for v in sources):
            return [], []
    except (ValueError, TypeError):
        return [], []
    forward, nat = [], []
    pools = [ipaddress.ip_network(settings.employees_net), ipaddress.ip_network(settings.sites_net)]
    lans = set()
    for peer in db.query(WireGuardPeer).filter(WireGuardPeer.contour == Contour.SITES):
        if not live_peer(peer) or not peer.device.site:
            continue
        owned = {v.strip() for v in peer.device.site.lan_cidr.split(",")}
        for value in (peer.allowed_lans or "").split(","):
            if value.strip() not in owned:
                continue
            try:
                lan = ipaddress.IPv4Network(value.strip(), strict=True)
            except ValueError:
                continue
            if lan.prefixlen and not any(lan.overlaps(p) for p in pools):
                lans.add(str(lan))
    for source in sources:
        if any(ipaddress.ip_network(source).overlaps(p) for p in pools):
            continue
        for lan in sorted(lans):
            if ipaddress.ip_network(source).overlaps(ipaddress.ip_network(lan)):
                continue
            for nic in dict.fromkeys(n for n in (settings.employees_nic, settings.sites_nic) if n):
                forward.append(f'    iifname "{nic}" oifname "{settings.sites_if}" ip saddr {source} ip daddr {lan} ct state new,established,related accept')
                forward.append(f'    iifname "{settings.sites_if}" oifname "{nic}" ip saddr {lan} ip daddr {source} ct state established,related accept')
                nat.append(f'    iifname "{nic}" oifname "{settings.sites_if}" ip saddr {source} ip daddr {lan} snat to {settings.sites_server_ip}')
    return forward, nat
