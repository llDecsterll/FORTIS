"""Bounded, on-demand ICMP diagnostics; never invoke a shell or change routes."""
import ipaddress
import os
import re
import subprocess
import threading
import time

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .models import Role
from .security import require_roles

router = APIRouter()
_lock = threading.Lock()
_next_run = 0.0


class PingInput(BaseModel):
    ip: str = Field(min_length=1, max_length=45)


def ping_address(raw):
    try:
        address = ipaddress.IPv4Address(raw.strip())
        if (address.is_loopback or address.is_link_local or address.is_multicast
                or address.is_unspecified or address.is_reserved or int(address) == 0xffffffff):
            raise ValueError()
    except ValueError:
        raise HTTPException(422, 'Укажите IPv4-адрес устройства без порта, маски и команд')
    return str(address)


@router.post('/networks/ping')
def ping(payload: PingInput, actor=Depends(require_roles(Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF))):
    global _next_run
    target = ping_address(payload.ip)
    if not _lock.acquire(blocking=False):
        raise HTTPException(429, 'Другая проверка уже выполняется. Повторите позже')
    try:
        if time.monotonic() < _next_run:
            raise HTTPException(429, 'Между проверками требуется пауза 10 секунд')
        _next_run = time.monotonic() + 10
        try:
            result = subprocess.run(
                ['/usr/bin/ping', '-n', '-c', '3', '-W', '1', '-w', '5', '--', target],
                capture_output=True, text=True, timeout=7,
                env={**os.environ, 'LC_ALL': 'C'}, check=False,
            )
        except subprocess.TimeoutExpired:
            raise HTTPException(504, 'Проверка превысила время ожидания. Повторите позже')
        except OSError:
            raise HTTPException(503, 'Серверная команда ping недоступна')
        output = (result.stdout + result.stderr)[:4096]
        packets = re.search(r'(\d+) packets transmitted, (\d+) received,.*?([\d.]+)% packet loss', output)
        rtt = re.search(r'(?:rtt|round-trip).*?= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms', output)
        if result.returncode not in (0, 1) or not packets:
            raise HTTPException(503, 'Не удалось выполнить ping: проверьте права и маршруты сервера')
        return {
            'ip': target, 'sent': int(packets[1]), 'received': int(packets[2]),
            'lossPercent': float(packets[3]), 'reachable': int(packets[2]) > 0,
            'rttMs': {'min': float(rtt[1]), 'avg': float(rtt[2]), 'max': float(rtt[3])} if rtt else None,
            'output': output,
        }
    finally:
        _lock.release()
