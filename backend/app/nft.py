from __future__ import annotations

import ipaddress
import subprocess
from pathlib import Path

from sqlalchemy.orm import Session

from .config import settings
from .configured_interfaces import profiles, contour_enabled
from .models import AccessPolicy, Contour, Device, DeviceStatus, Network, Resource, WireGuardPeer
from .site_destinations import effective_destinations


NFT_FILE = Path("/etc/nftables.d/kontur.nft")


def _cidrs_for_device(db: Session, device: Device) -> list[str]:
    cidrs: list[str] = []
    policies = db.query(AccessPolicy).filter(AccessPolicy.device_id_fk == device.id, AccessPolicy.allowed.is_(True)).all()
    for p in policies:
        if p.network_id:
            net = db.get(Network, p.network_id)
            if net:
                cidrs.append(net.cidr)
        # Resource grants are quarantined until protocol/port ACLs are implemented.
        # Never translate a service permission into unrestricted access to its IP.
    return sorted(set(cidrs))


def quarantined_resource_hosts(db, device):
    result = set()
    for policy in db.query(AccessPolicy).filter(AccessPolicy.device_id_fk == device.id, AccessPolicy.allowed.is_(True)):
        resource = db.get(Resource, policy.resource_id) if policy.resource_id else None
        if resource:
            try:
                host = ipaddress.ip_address(resource.host)
                if host.version == 4:
                    result.add(str(host))
            except ValueError:
                continue
    return sorted(result)


def render_ruleset(db: Session) -> str:
    from .employee_networks import auto_site_access, auto_forward_rules, live_peer, automatic_company_lans
    emp_if = settings.employees_if
    site_if = settings.sites_if
    configured = profiles()
    lines = [
        "#!/usr/sbin/nft -f",
        # Replace only control-plane-owned tables in one atomic transaction.
        # A global flush would erase Fail2Ban and other services' protection.
        "add table inet filter",
        "delete table inet filter",
        "add table ip nat",
        "delete table ip nat",
        "",
        "table inet filter {",
        "  chain input {",
        "    type filter hook input priority filter; policy drop;",
        '    iif "lo" accept',
        "    ct state established,related accept",
        "    ct state invalid drop",
        "    ip protocol icmp icmp type { echo-request, destination-unreachable, time-exceeded, parameter-problem } accept",
        "    tcp dport { 22, 80, 443, 8443 } accept",
        *[f'    iifname "{item["uplink"]}" udp dport {item["port"]} accept' for item in configured],
        "    udp dport 68 accept",
        "  }",
        "  chain forward {",
        "    type filter hook forward priority filter; policy drop;",
        "    ct state established,related accept",
        "    ct state invalid drop",
        *[f'    iifname "{a["name"]}" oifname "{b["name"]}" drop' for a in configured for b in configured if a["name"] != b["name"]],
    ]
    peers = (
        db.query(WireGuardPeer)
        .join(Device, Device.id == WireGuardPeer.device_id_fk)
        .filter(Device.status == DeviceStatus.ACTIVE, WireGuardPeer.enabled.is_(True))
        .all()
    )
    peers = [peer for peer in peers if contour_enabled(peer.contour)]
    input_guards, forward_guards = [], []
    for peer in peers:
        device = db.get(Device, peer.device_id_fk)
        if not device:
            continue
        if not live_peer(peer):
            continue
        iface = emp_if if peer.contour == Contour.EMPLOYEES else site_if
        uplink = settings.employees_nic if peer.contour == Contour.EMPLOYEES else settings.sites_nic
        cidrs = _cidrs_for_device(db, device)
        for extra in [p.strip() for p in settings.extra_allowed_ips.split(",") if p.strip()]:
            cidrs.append(extra)
        cidrs = list(dict.fromkeys(cidrs))
        if peer.contour == Contour.SITES and peer.destination_cidrs:
            cidrs = effective_destinations(db, peer)
        sources = [peer.vpn_ip]
        if peer.contour == Contour.EMPLOYEES and (peer.destination_cidrs or auto_site_access(db) or automatic_company_lans(db)):
            from .employee_networks import effective_employee_destinations
            cidrs = effective_employee_destinations(db, peer)
            guard = f'    iifname "{emp_if}" ip saddr {peer.vpn_ip}'
            if cidrs:
                guard += ' ip daddr != { ' + ', '.join(cidrs) + ' }'
            guard += ' drop'
            input_guards.append(guard)
            forward_guards.append(guard)
        if peer.contour == Contour.SITES:
            sources.extend(str(ipaddress.ip_network(p.strip(), strict=False)) for p in (peer.allowed_lans or '').split(',') if p.strip())
            if peer.destination_cidrs:
                source_set='{ '+', '.join(sources)+' }'
                destination_set='{ '+', '.join(cidrs)+' }'
                guard=f'    iifname "{site_if}" ip saddr {source_set} ip daddr != {destination_set} drop'
                input_guards.append(guard)
                forward_guards.extend([guard,f'    oifname "{site_if}" ip daddr {source_set} ip saddr != {destination_set} drop'])
        # Revoke previously established resource-only flows before conntrack accepts.
        for host in quarantined_resource_hosts(db, device):
            if any(ipaddress.ip_address(host) in ipaddress.ip_network(cidr) for cidr in cidrs):
                continue  # An independent, explicit network permission still applies.
            for source in sources:
                rule = f'    iifname "{iface}" ip saddr {source} ip daddr {host} drop'
                input_guards.insert(0, rule)
                forward_guards.insert(0, rule)
        for source in sources:
            for cidr in cidrs:
                lines.append(f'    iifname "{iface}" ip saddr {source} ip daddr {cidr} accept')
        # Only authorized server-side networks may initiate into this site's LAN.
        # Cross-contour drops above remain unchanged.
        if peer.contour == Contour.SITES:
            for lan in sources[1:]:
                for cidr in cidrs:
                    if cidr == '0.0.0.0/0':
                        continue
                    for nic in dict.fromkeys(i["uplink"] for i in configured):
                        lines.append(f'    iifname "{nic}" oifname "{site_if}" ip saddr {cidr} ip daddr {lan} accept')
        # deny-by-default: no catch-all accept for internet unless resource 0.0.0.0/0 assigned
        if "0.0.0.0/0" in cidrs:
            lines.append(f'    iifname "{iface}" oifname "{uplink}" ip saddr {peer.vpn_ip} accept')
    # Narrowed policies must also stop previously established flows immediately.
    forward_start=lines.index('    type filter hook forward priority filter; policy drop;')+1
    from .site_links import link_rules
    employee_forward,employee_nat=auto_forward_rules(db)
    from .company_site_access import company_site_rules
    company_forward, company_nat = company_site_rules(db) if settings.sites_enabled else ([], [])
    lines[forward_start:forward_start]=company_forward+employee_forward+(link_rules(db, site_if) if settings.sites_enabled else [])+forward_guards
    input_start=lines.index('    type filter hook input priority filter; policy drop;')+1
    lines[input_start:input_start]=input_guards
    routed_nat = []
    for peer in peers:
        if peer.contour == Contour.SITES:
            for cidr in (peer.allowed_lans or '').split(','):
                if cidr.strip():
                    subnet = str(ipaddress.ip_network(cidr.strip(), strict=False))
                    for nic in dict.fromkeys(i["uplink"] for i in configured):
                        routed_nat.append(f'    oifname "{nic}" ip saddr {subnet} masquerade')
    lines += [
        "  }",
        "}",
        "",
        "table ip nat {",
        "  chain postrouting {",
        "    type nat hook postrouting priority srcnat; policy accept;",
        *employee_nat,
        *company_nat,
        *[f'    oifname "{a["uplink"]}" ip saddr {b["subnet"]} masquerade' for a in configured for b in configured],
        *routed_nat,
        "  }",
        "}",
        "",
    ]
    return "\n".join(lines) + "\n"


def apply_acl(db: Session) -> None:
    from .employee_networks import auto_site_access, automatic_company_lans
    if auto_site_access(db) or automatic_company_lans(db):
        from .provision import render_stored_config
        for peer in db.query(WireGuardPeer).filter(WireGuardPeer.contour==Contour.EMPLOYEES):
            if peer.private_key: render_stored_config(db,peer)
        db.flush()
    NFT_FILE.parent.mkdir(parents=True, exist_ok=True)
    text = render_ruleset(db)
    NFT_FILE.write_text(text)
    Path("/etc/nftables.conf").write_text(f"#!/usr/sbin/nft -f\ninclude \"{NFT_FILE}\"\n")
    subprocess.run(["nft", "-c", "-f", str(NFT_FILE)], check=True, capture_output=True)
    subprocess.run(["nft", "-f", str(NFT_FILE)], check=True, capture_output=True)
