"""Create the same self-contained client package used by the existing Windows client."""
import base64, json, os, struct, uuid
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"WGACCESS-PKG-02!"
ROOT = Path(__file__).resolve().parent / "assets"

def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")

def build_client_exe(*, name: str, employee: str, device: str, config: str, rdp_host: str, rdp_user: str, rdp_password: str, rdp_port: int, rdp_save_password: bool, shortcut: str | None = None, auto_start: bool = True) -> bytes:
    payload = build_client_payload(name=name, employee=employee, device=device, config=config, rdp_host=rdp_host, rdp_user=rdp_user, rdp_password=rdp_password, rdp_port=rdp_port, rdp_save_password=rdp_save_password, shortcut=shortcut, auto_start=auto_start)
    template = (ROOT / "ClientTemplate.exe").read_bytes()
    return template + payload

def build_client_payload(*, name: str, employee: str, device: str, config: str, rdp_host: str, rdp_user: str, rdp_password: str, rdp_port: int, rdp_save_password: bool, enable_rdp: bool = True, shortcut: str | None = None, auto_start: bool = True) -> bytes:
    if not config or (enable_rdp and (not rdp_host or not rdp_user)):
        raise ValueError("Для EXE нужны VPN-конфигурация, адрес рабочего ПК и логин RDP")
    package = uuid.uuid4(); connection = uuid.uuid4(); version = 1
    key = os.urandom(32); nonce = os.urandom(12); salt = os.urandom(16)
    settings = {
        "Name": name, "Employee": employee, "Device": device, "Config": config,
        "RdpHost": rdp_host, "User": rdp_user, "Password": rdp_password if rdp_save_password else "",
        "SavePassword": bool(rdp_save_password), "Shortcut": shortcut or name,
        "AutoStart": bool(auto_start), "RdpPort": int(rdp_port), "EnableRdp": bool(enable_rdp),
    }
    context = f"RemoteAccessOffline|3|{package.hex}|{connection.hex}|{version}".encode()
    plain = json.dumps(settings, ensure_ascii=False, separators=(",", ":")).encode()
    encrypted = AESGCM(key).encrypt(nonce, plain, context)
    ciphertext, tag = encrypted[:-16], encrypted[-16:]
    bootstrap = {"Format": 3, "Package": str(package), "Connection": str(connection), "Version": version, "Salt": _b64(salt), "Nonce": _b64(nonce), "Tag": _b64(tag), "Ciphertext": _b64(ciphertext), "EmbeddedKey": _b64(key)}
    payload = json.dumps(bootstrap, ensure_ascii=False, separators=(",", ":")).encode()
    return payload + struct.pack("<I", len(payload)) + MAGIC

def iter_client_exe(*, name: str, employee: str, device: str, config: str, rdp_host: str, rdp_user: str, rdp_password: str, rdp_port: int, rdp_save_password: bool, enable_rdp: bool = True):
    payload = build_client_payload(name=name, employee=employee, device=device, config=config, rdp_host=rdp_host, rdp_user=rdp_user, rdp_password=rdp_password, rdp_port=rdp_port, rdp_save_password=rdp_save_password, enable_rdp=enable_rdp)
    with (ROOT / "ClientTemplate.exe").open("rb") as source:
        while chunk := source.read(1024 * 1024):
            yield chunk
    yield payload
