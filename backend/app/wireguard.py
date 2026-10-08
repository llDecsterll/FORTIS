from __future__ import annotations

import ipaddress
import json
import os
import secrets
import subprocess
import tempfile
from pathlib import Path

from .config import settings
from .models import Contour
from .configured_interfaces import contour_enabled


WG_DIR = Path("/etc/wireguard")


class WireGuardError(RuntimeError):
    pass


def _run(cmd: list[str]) -> str:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise WireGuardError(proc.stderr.strip() or proc.stdout.strip() or "wg failed")
    return proc.stdout


def iface_for(contour: Contour) -> str:
    if not contour_enabled(contour):
        raise WireGuardError("Этот контур не настроен. Назначьте ему отдельную сетевую карту")
    return settings.employees_if if contour == Contour.EMPLOYEES else settings.sites_if


def net_for(contour: Contour) -> str:
    return settings.employees_net if contour == Contour.EMPLOYEES else settings.sites_net


def endpoint_for(contour: Contour) -> tuple[str, int]:
    if contour == Contour.EMPLOYEES:
        return settings.employees_endpoint, settings.employees_port
    return settings.sites_endpoint, settings.sites_port


def gen_keypair() -> tuple[str, str]:
    priv = _run(["wg", "genkey"]).strip()
    pub = subprocess.run(
        ["wg", "pubkey"], input=priv + "\n", capture_output=True, text=True, check=True
    ).stdout.strip()
    return priv, pub


def gen_psk() -> str:
    return _run(["wg", "genpsk"]).strip()


def next_vpn_ip(contour: Contour, used: set[str]) -> str:
    if not contour_enabled(contour):
        from fastapi import HTTPException
        raise HTTPException(409, "Назначьте этому контуру отдельную сетевую карту в настройках сервера")
    network = ipaddress.ip_network(net_for(contour))
    server = (
        settings.employees_server_ip if contour == Contour.EMPLOYEES else settings.sites_server_ip
    )
    used.add(server)
    for host in network.hosts():
        ip = str(host)
        if ip not in used:
            return ip
    raise WireGuardError("В подсети не осталось адресов")


def sync_site_lan_routes(new_lans: str, old_lans: str = '') -> None:
    """Own only exact static site routes and priority-52 destination rules."""
    new = {str(ipaddress.ip_network(p.strip(), strict=True)) for p in new_lans.split(',') if p.strip()}
    old = {str(ipaddress.ip_network(p.strip(), strict=True)) for p in old_lans.split(',') if p.strip()}
    rules = json.loads(_run(['ip','-j','-4','rule','show']))
    managed = {str(ipaddress.ip_network(r['dst'] if '/' in r['dst'] else f"{r['dst']}/{r.get('dstlen',32)}", strict=False))
               for r in rules if r.get('dst') and r.get('priority') == 52 and r.get('table') in ('main',254)}
    for cidr in sorted(new):
        _run(['ip','-4','route','replace',cidr,'dev',settings.sites_if,'proto','static'])
        if cidr not in managed:
            _run(['ip','-4','rule','add','priority','52','to',cidr,'lookup','main'])
    for cidr in sorted(old-new):
        if cidr in managed:
            _run(['ip','-4','rule','del','priority','52','to',cidr,'lookup','main'])
        routes = json.loads(_run(['ip','-j','-4','route','show','exact',cidr]))
        if any(r.get('dev') == settings.sites_if and r.get('protocol') == 'static' for r in routes):
            _run(['ip','-4','route','del',cidr,'dev',settings.sites_if,'proto','static'])


def set_peer(contour: Contour, public_key: str, psk: str, allowed_ips: str) -> None:
    iface = iface_for(contour)
    networks = [ipaddress.ip_network(p.strip(), strict=False) for p in allowed_ips.split(',') if p.strip()]
    lans = networks[1:] if contour == Contour.SITES else []
    if lans:
        connected = json.loads(_run(['ip', '-j', '-4', 'route', 'show', 'scope', 'link']))
        for lan in lans:
            if lan.version != 4 or lan.prefixlen == 0:
                raise WireGuardError('Недопустимая LAN объекта')
            for route in connected:
                if route.get('dev') == iface and route.get('protocol') == 'static':
                    continue
                if route.get('dst') and route['dst'] != 'default' and lan.overlaps(ipaddress.ip_network(route['dst'], strict=False)):
                    raise WireGuardError('LAN объекта пересекается с подключённой сетью сервера')
    fd, psk_file = tempfile.mkstemp(prefix='kontur-', suffix='.psk')
    with os.fdopen(fd, 'w') as stream:
        stream.write(psk)
    try:
        _run(
            [
                "wg",
                "set",
                iface,
                "peer",
                public_key,
                "preshared-key",
                psk_file,
                "allowed-ips",
                allowed_ips,
            ]
        )
        if lans:
            sync_site_lan_routes(', '.join(str(lan) for lan in lans))
    finally:
        Path(psk_file).unlink(missing_ok=True)


def remove_peer(contour: Contour, public_key: str) -> None:
    iface = iface_for(contour)
    proc = subprocess.run(["wg", "set", iface, "peer", public_key, "remove"], capture_output=True, text=True, timeout=10)
    if proc.returncode != 0:
        raise WireGuardError("Не удалось отключить VPN-подключение")


def dump(contour: Contour) -> list[dict]:
    if not contour_enabled(contour):
        return []
    iface = iface_for(contour)
    proc = subprocess.run(["wg", "show", iface, "dump"], capture_output=True, text=True)
    if proc.returncode != 0:
        return []
    rows = []
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    if not lines:
        return rows
    # first line is interface
    for line in lines[1:]:
        parts = line.split("\t")
        if len(parts) < 8:
            continue
        rows.append(
            {
                "public_key": parts[0],
                "preshared_key": parts[1],
                "endpoint": parts[2],
                "allowed_ips": parts[3],
                "latest_handshake": int(parts[4] or 0),
                "rx": int(parts[5] or 0),
                "tx": int(parts[6] or 0),
                "keepalive": parts[7],
            }
        )
    return rows


def client_allowed_ips(contour: Contour, extra_allowed: str = "") -> str:
    parts = [p.strip() for p in extra_allowed.split(",") if p.strip()]
    if not parts:
        parts = ["0.0.0.0/0"] if contour == Contour.EMPLOYEES else [settings.employees_net, settings.sites_net]
    for extra in [p.strip() for p in settings.extra_allowed_ips.split(",") if p.strip()]:
        if extra not in parts:
            parts.append(extra)
    return ", ".join(dict.fromkeys(parts))


def client_config(
    *,
    private_key: str,
    address: str,
    contour: Contour,
    server_public: str,
    psk: str,
    extra_allowed: str = "",
) -> str:
    host, port = endpoint_for(contour)
    allowed = client_allowed_ips(contour, extra_allowed)
    return f"""[Interface]
PrivateKey = {private_key}
Address = {address}/{ipaddress.ip_network(net_for(contour)).prefixlen if contour == Contour.SITES else 32}
DNS = {settings.dns_servers}
MTU = {settings.mtu}

[Peer]
PublicKey = {server_public}
PresharedKey = {psk}
Endpoint = {host}:{port}
AllowedIPs = {allowed}
PersistentKeepalive = 10
"""


def server_public_key(contour: Contour) -> str:
    iface = iface_for(contour)
    proc = subprocess.run(["wg", "show", iface, "public-key"], capture_output=True, text=True)
    return proc.stdout.strip()
