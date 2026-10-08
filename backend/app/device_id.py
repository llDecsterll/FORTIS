import hashlib
import json
import re


MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def normalize_mac(value: str) -> str:
    raw = value.strip().replace("-", ":").lower()
    if not raw:
        return ""
    if not MAC_RE.match(raw):
        raise ValueError(f"Некорректный MAC: {value}")
    return raw


def compute_device_id(
    certificate_pem: str,
    system_identifier: str,
    registered_mac: str,
    wireguard_public_key: str,
) -> str:
    """Составной Device ID — не MAC и не ключ WireGuard по отдельности."""
    payload = "|".join(
        [
            certificate_pem.strip(),
            system_identifier.strip(),
            registered_mac.strip().lower(),
            wireguard_public_key.strip(),
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def fingerprint_bundle(data: dict) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
