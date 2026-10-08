"""Read-only channel diagnostics. No key material, probes, or route mutations."""
import ipaddress
import json
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from .config import settings
from .configured_interfaces import profiles

def _output(args):
    return subprocess.check_output(args, text=True, stderr=subprocess.DEVNULL, timeout=2).strip()

def _interfaces():
    try:
        return json.loads(_output(['ip', '-j', 'address', 'show']))
    except (OSError, ValueError, subprocess.SubprocessError):
        return []

def _route(mark):
    try:
        rows = json.loads(_output(['ip', '-j', 'route', 'get', '1.1.1.1', 'mark', str(mark)]))
        return rows[0] if rows else {}
    except (OSError, ValueError, subprocess.SubprocessError):
        return {}

def _safe_name(name):
    return bool(re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', name))

def _link_speed(name):
    try:
        value = int((Path('/sys/class/net') / name / 'speed').read_text())
        return value if value > 0 else None
    except (OSError, ValueError):
        return None

def _counters(name):
    out = {}
    for field, filename in [('rxBytes','rx_bytes'),('txBytes','tx_bytes'),('rxErrors','rx_errors'),('txErrors','tx_errors'),('rxDropped','rx_dropped'),('txDropped','tx_dropped')]:
        try:
            out[field] = int((Path('/sys/class/net') / name / 'statistics' / filename).read_text())
        except (OSError, ValueError):
            out[field] = None
    return out

def _wg(name):
    try:
        port = int(_output(['wg', 'show', name, 'listen-port']))
        rows = _output(['wg', 'show', name, 'latest-handshakes']).splitlines()
        now = time.time()
        recent = sum(1 for row in rows if len(row.split()) == 2 and 0 <= now - int(row.split()[1]) < 180)
        return {'available':True,'port':port,'peers':len(rows),'recentPeers':recent}
    except (OSError, ValueError, subprocess.SubprocessError):
        return {'available':False,'port':None,'peers':None,'recentPeers':None}

def _ipv4(interface):
    addresses, subnets = [], []
    for row in interface.get('addr_info', []):
        if row.get('family') != 'inet':
            continue
        try:
            address = ipaddress.ip_interface(f"{row['local']}/{row['prefixlen']}")
            addresses.append(str(address))
            subnets.append(str(address.network))
        except (KeyError, ValueError):
            continue
    return addresses, sorted(set(subnets))

def read_channel_status():
    interfaces = {i['ifname']:i for i in _interfaces() if 'ifname' in i}
    channels = []
    # Marks correspond to the existing employee/site policy routes, not browser traffic.
    for item in profiles():
        key = 'employees' if item['role'] == 'employees' else 'sites' if item['role'] == 'routers' else 'custom.' + item['name']
        label, nic, tunnel, net, expected_port = item['title'], item['uplink'], item['name'], item['subnet'], item['port']
        mark = 256 if item['role'] == 'employees' else 512 if item['role'] == 'routers' else 0
        physical = interfaces.get(nic, {})
        vpn = interfaces.get(tunnel, {})
        addresses, lans = _ipv4(physical)
        vpn_addresses, vpn_networks = _ipv4(vpn)
        safe = _safe_name(nic) and _safe_name(tunnel)
        wg = _wg(tunnel) if safe else {'available':False,'port':None,'peers':None,'recentPeers':None}
        route = _route(mark)
        link_up = 'UP' in physical.get('flags', []) and 'LOWER_UP' in physical.get('flags', [])
        vpn_up = 'UP' in vpn.get('flags', []) and wg['available']
        route_ok = route.get('dev') == nic and bool(route.get('gateway')) and bool(route.get('table'))
        subnet_ok = str(ipaddress.ip_network(net, strict=False)) in vpn_networks
        status = 'down' if not link_up or not vpn_up else ('up' if route_ok and subnet_ok and wg['port'] == expected_port else 'warning')
        channels.append({
            'id':key,'name':label,'physicalInterface':nic,'wireguardInterface':tunnel,
            'status':status,'physicalStatus':'up' if link_up else 'down','wireguardStatus':'up' if vpn_up else 'down',
            'addresses':addresses,'lanSubnets':lans,'vpnAddresses':vpn_addresses,'vpnSubnet':net,
            'linkMbps':_link_speed(nic) if safe else None,'mtu':vpn.get('mtu'),
            'gateway':route.get('gateway'),'routeInterface':route.get('dev'),'routeTable':route.get('table'),
            'routeStatus':'valid' if route_ok else 'warning','fwmark':hex(mark),
            'listenPort':wg['port'],'peers':wg['peers'],'recentPeers':wg['recentPeers'],
            'counters':_counters(nic) if safe else {},'internetStatus':'not_tested',
        })
    return {'checkedAt':datetime.now(timezone.utc).isoformat(),'channels':channels}
