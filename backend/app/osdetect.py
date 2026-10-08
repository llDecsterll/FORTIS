"""Пассивное определение ОС клиента по пакетам WireGuard.

Протокол WireGuard ОС не передаёт. Берём TTL внешнего UDP-пакета на физическом
интерфейсе и отпечаток TCP внутри туннеля.
"""
from __future__ import annotations

import json
import ipaddress
import socket
import struct
import threading
import time
from pathlib import Path

from .config import settings
from .configured_interfaces import profiles

_LOCK = threading.Lock()
_SEEN: dict[str, dict] = {}
_STARTED = False
_LOCK_HANDLE = None
_FILE = Path("/var/lib/kontur/os-seen.json")


def classify(inner: dict | None, outer: dict | None) -> tuple[str, str]:
    """Возвращает (название, уверенность high|low)."""
    syn = (inner or {}).get("syn") or {}
    opts = syn.get("opts") or []
    inner_ttl = (inner or {}).get("ttl")
    outer_ttl = (outer or {}).get("ttl")
    mss = syn.get("mss") or 0
    if inner_ttl and inner_ttl >= 96:
        return "Windows", "high"
    if outer_ttl and outer_ttl >= 90 and not syn:
        return "Windows", "high"
    if _apple(opts):
        if mss and mss <= 1400:
            return "iOS", "high"
        if mss and mss >= 1440:
            return "macOS", "high"
        return "macOS / iOS", "low"
    if _linux(opts):
        if mss and mss <= 1400:
            return "Android", "high"
        return "Linux", "high"
    if _windows_tcp(opts) or (inner_ttl and inner_ttl >= 96):
        return "Windows", "high"
    if inner_ttl and inner_ttl <= 80:
        return "Linux / macOS / Android", "low"
    if outer_ttl and outer_ttl <= 80:
        return "Linux / macOS / Android", "low"
    return "", ""


def should_store(current: str, detected: str, confidence: str) -> bool:
    if not detected:
        return False
    current = (current or "").strip()
    if not current:
        return True
    if confidence == "high":
        return current != detected
    return "/" in current or current in {"Не указана"}


def device_kind(os_name: str, site: bool = False) -> str:
    if os_name in {"iOS", "Android"}:
        return "PHONE"
    if os_name == "macOS":
        return "LAPTOP"
    if os_name == "Windows":
        return "DESKTOP"
    if os_name == "Linux":
        return "ROUTER" if site else "DESKTOP"
    return ""


def client_mac(public_ip: str) -> str:
    if not public_ip:
        return ""
    seen = _read()
    fresh = time.time() - 180
    for key in (f"pub:{public_ip}", public_ip):
        row = seen.get(key) or {}
        if row.get("mac") and row.get("ts", 0) >= fresh:
            return str(row["mac"])
    return ""


def observe(vpn_ip: str = "", public_ip: str = "") -> dict:
    seen = _read()
    inner = seen.get(vpn_ip) if vpn_ip else None
    outer = seen.get(f"pub:{public_ip}") if public_ip else None
    fresh = time.time() - 180
    if inner and inner.get("ts", 0) < fresh:
        inner = None
    if outer and outer.get("ts", 0) < fresh:
        outer = None
    os_name, confidence = classify(inner, outer)
    return {"os": os_name, "confidence": confidence, "kind": device_kind(os_name)}


_SNIFFERS = set()

def start() -> None:
    global _STARTED, _LOCK_HANDLE
    if not _STARTED:
        try:
            import fcntl
            _LOCK_HANDLE = open("/tmp/kontur-osdetect.lock", "w")
            fcntl.flock(_LOCK_HANDLE, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except Exception:
            return
        _STARTED = True
    for item in profiles():
        for iface, public in ((item['name'], False), (item['uplink'], True)):
            if not iface or (iface, public) in _SNIFFERS:
                continue
            _SNIFFERS.add((iface, public))
            threading.Thread(target=_sniff, args=(iface, public), name=f"os-{iface}", daemon=True).start()


def _apple(opts: list[str]) -> bool:
    return "ws" in opts and "ts" in opts and opts[:3] == ["mss", "nop", "ws"]


def _linux(opts: list[str]) -> bool:
    return opts[:3] == ["mss", "sok", "ts"] or opts[:4] == ["mss", "sok", "ts", "nop"]


def _windows_tcp(opts: list[str]) -> bool:
    return "ws" in opts and "sok" in opts and "ts" not in opts and opts[:1] == ["mss"]


def _sniff(iface: str, public: bool) -> None:
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        sock.bind((iface, 0))
        sock.settimeout(1.0)
    except Exception:
        return
    while True:
        try:
            frame = sock.recv(2048)
        except socket.timeout:
            continue
        except Exception:
            return
        parsed = _parse(frame)
        if not parsed:
            continue
        src, ttl, proto, payload, _mac = parsed
        if any(ipaddress.ip_address(src) in ipaddress.ip_network(item["subnet"]) for item in profiles()):
            key = src
        elif public:
            key = f"pub:{src}"
        else:
            continue
        row = _SEEN.get(key) or {"ts": 0}
        row["ttl"] = ttl
        row["ts"] = time.time()
        if _mac and (src.startswith("192.168.") or src.startswith("10.") or src.startswith("172.")):
            row["mac"] = _mac
        if proto == 6:
            syn = _tcp_syn(payload)
            if syn:
                row["syn"] = syn
        with _LOCK:
            _SEEN[key] = row
            if len(_SEEN) > 500:
                oldest = sorted(_SEEN, key=lambda k: _SEEN[k].get("ts", 0))[:100]
                for item in oldest:
                    _SEEN.pop(item, None)
        _save()


def _parse(frame: bytes):
    data = frame
    mac = ""
    if len(data) >= 14 and int.from_bytes(data[12:14], "big") == 0x0800:
        mac = ":".join(f"{b:02x}" for b in data[6:12])
        data = data[14:]
    if len(data) < 20 or data[0] >> 4 != 4:
        return None
    ihl = (data[0] & 0x0F) * 4
    if len(data) < ihl:
        return None
    ttl = data[8]
    proto = data[9]
    src = socket.inet_ntoa(data[12:16])
    return src, ttl, proto, data[ihl:], mac


def _tcp_syn(payload: bytes):
    if len(payload) < 20:
        return None
    flags = payload[13]
    if not (flags & 0x02) or (flags & 0x10):
        return None
    window = struct.unpack("!H", payload[14:16])[0]
    offset = (payload[12] >> 4) * 4
    opts, mss = _tcp_opts(payload[20:offset])
    return {"win": window, "opts": opts, "mss": mss}


def _tcp_opts(raw: bytes) -> tuple[list[str], int]:
    names: list[str] = []
    mss = 0
    i = 0
    while i < len(raw):
        kind = raw[i]
        if kind == 0:
            names.append("eol")
            break
        if kind == 1:
            names.append("nop")
            i += 1
            continue
        if i + 1 >= len(raw):
            break
        length = raw[i + 1]
        if length < 2 or i + length > len(raw):
            break
        if kind == 2 and length >= 4:
            mss = struct.unpack("!H", raw[i + 2 : i + 4])[0]
            names.append("mss")
        elif kind == 3:
            names.append("ws")
        elif kind == 4:
            names.append("sok")
        elif kind == 8:
            names.append("ts")
        else:
            names.append(str(kind))
        i += length
    return names, mss


def _save() -> None:
    try:
        _FILE.parent.mkdir(parents=True, exist_ok=True)
        _FILE.write_text(json.dumps(_SEEN))
    except Exception:
        return


def _read() -> dict:
    try:
        data = json.loads(_FILE.read_text())
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}
