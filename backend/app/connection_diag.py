"""Bounded, non-saturating tunnel diagnostics. No bandwidth test traffic."""
import ipaddress
import os
import re
import subprocess
import time


def parse_ping(output):
    count = re.search(r'(\d+) packets transmitted, (\d+) (?:packets )?received', output)
    rtt = re.search(r'= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)', output)
    sent, received = (int(count[1]), int(count[2])) if count else (0, 0)
    return {'sent': sent, 'received': received,
            'loss': round(100 * (sent - received) / sent, 1) if sent else None,
            'avgMs': float(rtt[2]) if rtt else None,
            'jitterMs': float(rtt[4]) if rtt else None}


def peer_counters(iface, vpn_ip):
    try:
        output = subprocess.check_output(['wg', 'show', iface, 'dump'], text=True, timeout=3, stderr=subprocess.DEVNULL)
        for line in output.splitlines()[1:]:
            parts = line.split('\t')
            if len(parts) < 8:
                continue
            addresses = [str(ipaddress.ip_interface(cidr).ip) for cidr in parts[3].split(',') if cidr != '(none)']
            if vpn_ip in addresses:
                return {'handshake': int(parts[4]), 'rx': int(parts[5]), 'tx': int(parts[6])}
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return None


def traffic_rates(before, after, seconds):
    if not before or not after or seconds <= 0 or any(after[k] < before[k] for k in ('rx', 'tx')):
        return {'toClientMbps': None, 'fromClientMbps': None}
    return {'toClientMbps': round((after['tx'] - before['tx']) * 8 / seconds / 1_000_000, 4),
            'fromClientMbps': round((after['rx'] - before['rx']) * 8 / seconds / 1_000_000, 4)}


def diagnose(iface, vpn_ip):
    vpn_ip = str(ipaddress.ip_address(vpn_ip))
    before = peer_counters(iface, vpn_ip)
    started = time.monotonic()
    try:
        result = subprocess.run(['ping', '-n', '-c', '5', '-i', '0.2', '-W', '1', '-I', iface, vpn_ip],
                                capture_output=True, text=True, timeout=7, env={**os.environ, 'LC_ALL': 'C'})
        ping = parse_ping(result.stdout)
    except (OSError, subprocess.SubprocessError):
        ping = parse_ping('')
    remaining = 1.0 - (time.monotonic() - started)
    if remaining > 0:
        time.sleep(remaining)
    after = peer_counters(iface, vpn_ip)
    elapsed = time.monotonic() - started
    handshake = after['handshake'] if after else 0
    return {'ip': vpn_ip, **ping, **traffic_rates(before, after, elapsed),
            'sampleSeconds': round(elapsed, 2),
            'handshakeAgeSeconds': max(0, int(time.time() - handshake)) if handshake else None,
            'peerPresent': after is not None,
            'reachable': bool(ping['received']), 'mbps': None}


def conclusion(result, server):
    overloaded = server and (server.get('cpuPercent', 0) >= 90 or server.get('memPercent', 0) >= 95 or
                             (server.get('linkUtilPercent') or 0) >= 90)
    if overloaded:
        return 'На сервере высокая нагрузка. Это возможная причина ухудшения связи, но не доказательство неисправности канала.'
    if not result['peerPresent']:
        return 'VPN-профиль отсутствует на интерфейсе сервера. Проверьте статус доступа и подключение.'
    if not result['received']:
        return 'Ответа на ping нет: устройство может блокировать ICMP или быть недоступно. Качество интернета не определено.'
    if (result['loss'] or 0) > 0 or (result['avgMs'] or 0) > 150:
        return 'Есть потери или повышенная задержка внутри VPN. Причина может быть в устройстве, Wi-Fi, провайдере или маршруте; виновная сторона не установлена.'
    return 'В этой короткой проверке ответ получен без потерь и высокой задержки. Это не измерение максимальной скорости интернета.'
