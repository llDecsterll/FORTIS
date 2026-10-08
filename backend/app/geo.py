from __future__ import annotations

import ipaddress
import re

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
    """No external disclosure of client addresses. Online GeoIP is disabled."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return "", ""
    return ("LAN", "") if not address.is_global else ("", "")


def lookup_geo(ip: str) -> str:
    return lookup_place(ip)[0]
