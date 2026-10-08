from pathlib import Path
import os
import secrets
import tempfile
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

ROOT = Path(__file__).resolve().parents[2]
RUNTIME = Path(os.environ.get("DATA_DIR", str(ROOT / ".runtime")))

def local_secret():
    RUNTIME.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = RUNTIME / "secret.key"
    if path.exists():
        return path.read_text().strip()
    fd, temporary = tempfile.mkstemp(dir=RUNTIME, prefix=".secret-")
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(secrets.token_urlsafe(48))
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            pass
        return path.read_text().strip()
    finally:
        Path(temporary).unlink(missing_ok=True)

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', extra='ignore')
    app_name: str = "FORTIS"
    standard_wireguard: bool = True
    panel_gate_enabled: bool = False
    secret_key: str = Field(default_factory=local_secret)
    jwt_expire_minutes: int = 480
    session_ttl_seconds: int = 28800
    database_url: str = f"sqlite:///{RUNTIME / 'kontur.db'}"
    data_dir: Path = RUNTIME
    ca_dir: Path = RUNTIME / "ca"
    docs_dir: Path = RUNTIME / "docs"
    uploads_dir: Path = RUNTIME / "uploads"
    employees_enabled: bool = True
    sites_enabled: bool = True
    additional_interfaces: list[dict] = Field(default_factory=list)
    employees_if: str = "wg-employees"
    employees_port: int = 51820
    employees_net: str = "10.80.0.0/24"
    employees_server_ip: str = "10.80.0.1"
    employees_nic: str = ""
    employees_endpoint: str = ""
    sites_if: str = "wg-sites"
    sites_port: int = 51821
    sites_net: str = "10.81.0.0/24"
    sites_server_ip: str = "10.81.0.1"
    sites_nic: str = ""
    sites_endpoint: str = ""
    mtu: int = 1420
    dns_servers: str = "1.1.1.1"
    extra_allowed_ips: str = ""
    concurrent_policy: str = "deny"
    mac_policy: str = "strict"
    geoip_enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    webhook_url: str = ""
    security_notify_email: str = ""
    ad_ca_file: str = ""
    trusted_proxy_ips: str = ""
    allowed_hosts: str = "localhost,127.0.0.1,::1,testserver"
    public_origin: str = "http://127.0.0.1:5173"
settings = Settings()
