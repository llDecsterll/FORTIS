from __future__ import annotations

import json
import re
from urllib.request import urlopen

_LEGAL = re.compile(
    r"\b(PJSC|OJSC|CJSC|JSC|LLC|LTD|INC|CORP|PUBLIC JOINT STOCK COMPANY|JOINT STOCK COMPANY)\b",
    re.I,
)
_KNOWN = (
    ("megafon", "МегаФон"),
    ("mega fon", "МегаФон"),
    ("mobile telesystems", "МТС"),
    ("mts pjsc", "МТС"),
    (" мтс", "МТС"),
    ("beeline", "билайн"),
    ("vimpelcom", "билайн"),
    ("vimpel-communications", "билайн"),
    ("rostelecom", "Ростелеком"),
    ("tele2", "Tele2"),
    ("t2 mobile", "Tele2"),
    ("yandex", "Яндекс"),
    ("er-telecom", "Дом.ru"),
    ("dom.ru", "Дом.ru"),
    ("transtelecom", "ТТК"),
    ("ttk-", "ТТК"),
)


def pretty_isp(name: str) -> str:
    raw = (name or "").strip()
    if not raw:
        return ""
    folded = raw.lower()
    for needle, label in _KNOWN:
        if needle.strip() in folded:
            return label
    cleaned = _LEGAL.sub("", raw)
    cleaned = re.sub(r"\s+", " ", cleaned).strip(" .,;-")
    return cleaned or raw


def lookup_place(ip: str) -> tuple[str, str]:
    """Город и провайдер по внешнему IP. Для локальной сети провайдер не запрашивается."""
    if not ip or ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10."):
        return "LAN", ""
    try:
        with urlopen(f"http://ip-api.com/json/{ip}?lang=ru&fields=status,country,city,isp,query", timeout=3) as resp:
            data = json.loads(resp.read().decode())
        if data.get("status") == "success":
            geo = f"{data.get('country') or ''}, {data.get('city') or ''}".strip(", ")
            return geo, pretty_isp(data.get("isp") or "")
    except Exception:
        return "", ""
    return "", ""


def lookup_geo(ip: str) -> str:
    return lookup_place(ip)[0]
