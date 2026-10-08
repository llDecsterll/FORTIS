from datetime import datetime, timedelta
import ipaddress
import re
import subprocess

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Contour, Device, DeviceStatus, HostMetric, Role, SecurityEvent, Site, TrafficSample, User, WireGuardPeer
from ..geo import pretty_isp
from ..presence import ONLINE_SECONDS, peer_online
from ..security import current_user, require_roles

router = APIRouter(tags=["dashboard"])


def _util(rx_bps: int, tx_bps: int, link_mbps: int) -> float | None:
    if link_mbps <= 0:
        return None
    used = max(rx_bps, tx_bps) * 8
    return round(min(used * 100 / (link_mbps * 1_000_000), 100), 1)


from ..host_memory import memory_status
from ..dashboard_counts import connection_counts, connection_members

def _metric_out(row: HostMetric) -> dict:
    return {
        "at": row.captured_at.isoformat(),
        "load1": row.load1,
        "load5": row.load5,
        "load15": row.load15,
        "cpuPercent": row.cpu_percent,
        "memPercent": row.mem_percent,
        "wgEmployeesRxBps": row.wg_emp_rx_bps,
        "wgEmployeesTxBps": row.wg_emp_tx_bps,
        "wgSitesRxBps": row.wg_site_rx_bps,
        "wgSitesTxBps": row.wg_site_tx_bps,
        "nicEmployeesRxBps": row.nic_emp_rx_bps,
        "nicEmployeesTxBps": row.nic_emp_tx_bps,
        "nicSitesRxBps": row.nic_site_rx_bps,
        "nicSitesTxBps": row.nic_site_tx_bps,
        "nicEmployeesMbps": row.nic_emp_mbps,
        "nicSitesMbps": row.nic_site_mbps,
        "nicEmployeesUtil": _util(row.nic_emp_rx_bps, row.nic_emp_tx_bps, row.nic_emp_mbps),
        "nicSitesUtil": _util(row.nic_site_rx_bps, row.nic_site_tx_bps, row.nic_site_mbps),
    }


def _account(device: Device, is_site: bool) -> tuple[str, str]:
    user = device.user
    reason = device.block_reason or ""
    status = device.status.value if device.status else ""
    if not is_site and user and not user.is_active:
        return "blocked", "Заблокирован"
    if reason == "Ожидает согласования СБ":
        return "pending", "На согласовании"
    if reason == "Отклонено службой безопасности":
        return "rejected", "Отклонено СБ"
    if status == "EXPIRED" or reason == "Срок доступа истёк":
        return "expired", "Срок истёк"
    if reason == "К ключу подключились несколько компьютеров":
        return "blocked", "Заблокирован"
    if reason == "Объект отключён":
        return "disconnected", "Отключён"
    if reason == "Работа приостановлена" or status == "BLOCKED":
        return "suspended", "Приостановлен"
    return "active", "Активен"


_STAFF = {Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF, Role.SECURITY, Role.AUDITOR}


def _staff_peer(peer: WireGuardPeer) -> bool:
    device = peer.device
    user = device.user if device else None
    return bool(user and user.role in _STAFF and not device.site_id)


def _online(peer: WireGuardPeer | None, cutoff: datetime) -> bool:
    return peer_online(peer)


@router.get("/dashboard")
def dashboard(db: Session = Depends(get_db), _=Depends(require_roles(Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF))):
    now = datetime.utcnow()
    day_ago = now - timedelta(days=1)
    cutoff = now - timedelta(seconds=ONLINE_SECONDS)
    peers = db.query(WireGuardPeer).all()
    employees = [p for p in peers if p.contour == Contour.EMPLOYEES and not _staff_peer(p)]
    sites = [p for p in peers if p.contour == Contour.SITES]
    employees_on = [p for p in employees if _online(p, cutoff)]
    sites_on = [p for p in sites if _online(p, cutoff)]
    blocked = db.query(Device).filter(Device.status == DeviceStatus.BLOCKED).count()
    expiring = (
        db.query(Device)
        .filter(Device.access_until.isnot(None), Device.access_until < now + timedelta(days=7), Device.access_until >= now, Device.status == DeviceStatus.ACTIVE)
        .count()
    )
    incidents = db.query(SecurityEvent).filter(SecurityEvent.created_at > day_ago).count()
    traffic = db.query(func.coalesce(func.sum(TrafficSample.rx_bytes + TrafficSample.tx_bytes), 0)).filter(TrafficSample.captured_at > day_ago).scalar()
    rx = db.query(func.coalesce(func.sum(WireGuardPeer.rx_bytes), 0)).scalar()
    tx = db.query(func.coalesce(func.sum(WireGuardPeer.tx_bytes), 0)).scalar()
    sessions = []
    for peer, connection_state in connection_members(employees + sites, lambda p: _online(p, cutoff), now):
        device = peer.device
        if not device:
            continue
        is_site = peer.contour == Contour.SITES or bool(device.site_id)
        if is_site and not device.site:
            continue
        if not is_site and not device.user:
            continue
        if not is_site and device.user.role in _STAFF:
            continue
        account, account_text = _account(device, is_site)
        name = device.site.name if device.site else device.user.full_name
        sessions.append(
            {
                "id": device.id,
                "userId": device.user_id or "",
                "siteId": device.site_id or "",
                "kind": "object" if is_site else "employee",
                "name": name,
                "email": device.user.email if device.user and not is_site else "",
                "device": device.name or "",
                "deviceType": device.device_type.value if device.device_type else "",
                "os": device.os_name or "",
                "geo": device.last_geo or "",
                "isp": pretty_isp(device.isp or ""),
                "providerName": device.site.provider_name if device.site else "",
                "lanCidr": device.site.lan_cidr if device.site else "",
                "providerPhone": device.site.provider_phone if device.site else "",
                "providerEmail": device.site.provider_email if device.site else "",
                "endpoint": peer.endpoint or "",
                "vpnIp": peer.vpn_ip,
                "online": connection_state == 'online',
                "connectionState": connection_state,
                "connected": bool(peer.enabled),
                "account": account,
                "accountText": account_text,
                "handshakeAt": peer.handshake_at.isoformat() if peer.handshake_at else None,
                "accessUntil": device.access_until.isoformat() if device.access_until else None,
            }
        )
    sessions.sort(key=lambda row: (not row["online"], row["kind"], row["name"] or ""))
    history = (
        db.query(HostMetric)
        .filter(HostMetric.captured_at > now - timedelta(minutes=30))
        .order_by(HostMetric.captured_at.asc())
        .all()
    )
    latest = history[-1] if history else db.query(HostMetric).order_by(HostMetric.captured_at.desc()).first()
    return {
        "usersTotal": db.query(User).count(),
        "connectedNow": len(employees_on) + len(sites_on),
        "employeesConnected": len(employees_on),
        "sitesConnected": len(sites_on),
        "employeesOnline": len(employees_on),
        "sitesOnline": len(sites_on),
        "employeeStates": connection_counts(employees, lambda p: _online(p, cutoff)),
        "siteStates": connection_counts(sites, lambda p: _online(p, cutoff)),
        "employeesVpn": len(employees_on),
        "sitesVpn": len(sites_on),
        "blockedDevices": blocked,
        "expiringAccess": expiring,
        "incidentsToday": incidents,
        "trafficToday": int(traffic or 0),
        "bytesRx": int(rx or 0),
        "bytesTx": int(tx or 0),
        "channels": {
            "memory": memory_status(),
            "now": _metric_out(latest) if latest else None,
            "history": [_metric_out(row) for row in history],
        },
        "sessions": sessions,
    }


class SpeedIn(BaseModel):
    userId: str = ""
    siteId: str = ""


def _endpoint_ip(endpoint: str) -> str:
    raw = (endpoint or "").strip()
    if raw.startswith("[") and "]" in raw:
        raw = raw[1:raw.index("]")]
    elif raw.count(":") == 1:
        raw = raw.rsplit(":", 1)[0]
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return ""


def _peer_target(db: Session, user_id: str, site_id: str) -> tuple[str, str, str]:
    if site_id:
        site = db.get(Site, site_id)
        if not site:
            raise HTTPException(404, "Объект не найден")
        device = next((d for d in (site.devices or []) if d.peer), None)
    else:
        user = db.get(User, user_id)
        if not user:
            raise HTTPException(404, "Пользователь не найден")
        device = next((d for d in (user.devices or []) if d.peer and not d.site_id), None)
    if not device or not device.peer:
        raise HTTPException(status_code=409, detail="Нет подключения для проверки")
    peer = device.peer
    from ..config import settings
    iface = settings.sites_if if peer.contour == Contour.SITES else settings.employees_if
    nic = settings.sites_nic if peer.contour == Contour.SITES else settings.employees_nic
    if not peer.enabled:
        raise HTTPException(status_code=409, detail="VPN-доступ отключён. Проверка недоступна")
    return str(ipaddress.ip_address(peer.vpn_ip)), peer.vpn_ip, nic




@router.post("/speed")
def speed_check(payload: SpeedIn, db: Session = Depends(get_db), _=Depends(require_roles(Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF))):
    if bool(payload.userId) == bool(payload.siteId):
        raise HTTPException(status_code=422, detail="Укажите ровно одно подключение")
    ip, vpn_ip, nic = _peer_target(db, payload.userId, payload.siteId)
    from ..config import settings
    from ..connection_diag import diagnose, conclusion
    import fcntl
    iface = settings.sites_if if nic == settings.sites_nic else settings.employees_if
    # Bound concurrent probes across gunicorn workers without changing VPN state.
    with open('/run/lock/kontur-connection-check.lock', 'a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise HTTPException(429, 'Уже выполняется проверка соединения. Повторите через несколько секунд')
        result = diagnose(iface, vpn_ip)
    metric = db.query(HostMetric).order_by(HostMetric.captured_at.desc()).first()
    server = None
    if metric and 0 <= (datetime.utcnow() - metric.captured_at).total_seconds() <= 120:
        values = _metric_out(metric)
        server = {'at': values['at'], 'cpuPercent': values['cpuPercent'], 'memPercent': values['memPercent'],
                  'linkUtilPercent': values['nicSitesUtil' if nic == settings.sites_nic else 'nicEmployeesUtil']}
    result['server'] = server
    result['summary'] = conclusion(result, server)
    result['checkedAt'] = datetime.utcnow().isoformat() + 'Z'
    return result
