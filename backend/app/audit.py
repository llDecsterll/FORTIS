from datetime import datetime, timedelta
import re
import subprocess

from fastapi import Request
from sqlalchemy.orm import Session

from .models import AuditLog

AUDIT_RETENTION_DAYS = 30


def prune_audit_logs(db: Session, *, now: datetime | None = None) -> int:
    """Remove only journal records older than 30 days; caller owns commit."""
    cutoff = (now or datetime.utcnow()) - timedelta(days=AUDIT_RETENTION_DAYS)
    return db.query(AuditLog).filter(AuditLog.created_at < cutoff).delete(synchronize_session=False)


def _private(ip: str) -> bool:
    return ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31."))


def browser_name(user_agent: str) -> str:
    ua = user_agent or ""
    if "Edg/" in ua:
        return "Edge"
    if "YaBrowser/" in ua:
        return "Yandex"
    if "Firefox/" in ua:
        return "Firefox"
    if "Chrome/" in ua:
        return "Chrome"
    if "Safari/" in ua:
        return "Safari"
    return (ua[:80] or "—")


def lan_mac(ip: str) -> str:
    if not ip or not _private(ip):
        return ""
    try:
        out = subprocess.check_output(["ip", "neigh", "show", ip], text=True, timeout=2)
    except Exception:
        return ""
    match = re.search(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", out.lower())
    return match.group(0) if match else ""


def client_context(request: Request) -> tuple[str, str, str]:
    ip = (request.headers.get("x-real-ip") or "").strip()
    if not ip and request.client:
        ip = request.client.host or ""
    return ip[:64], browser_name(request.headers.get("user-agent") or ""), lan_mac(ip)


def audit(
    db: Session,
    *,
    actor_id: str = "",
    actor_email: str = "",
    action: str,
    target: str = "",
    ip: str = "",
    device: str = "",
    vpn: str = "",
    resource: str = "",
    result: str = "OK",
    payload: dict | None = None,
    mac: str = "",
    browser: str = "",
    commit: bool = True,
) -> None:
    db.add(
        AuditLog(
            actor_id=actor_id,
            actor_email=actor_email,
            action=action,
            target=target,
            ip=ip,
            device=device,
            vpn=vpn,
            resource=resource,
            result=result,
            payload=payload or {},
            mac=mac,
            browser=browser,
            created_at=datetime.utcnow(),
        )
    )
    if commit:
        db.commit()
