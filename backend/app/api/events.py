from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..audit import AUDIT_RETENTION_DAYS, audit, client_context
from ..db import get_db
from ..models import AuditLog, Device, EventSeverity, Role, SecurityEvent, Session, Site, User
from ..security import current_user, require_roles
from .users import release_allowed

router = APIRouter(tags=["security"])


@router.get("/incidents")
def incidents(
    db: Session = Depends(get_db),
    _=Depends(require_roles(Role.ADMIN)),
    severity: EventSeverity | None = None,
    page: int = Query(1, ge=1),
    pageSize: int = Query(50, ge=1, le=100),
    status: Literal["current", "archived"] = "current",
    code: str | None = None,
):
    q = db.query(SecurityEvent).filter(SecurityEvent.archived_at.is_(None) if status == "current" else SecurityEvent.archived_at.isnot(None))
    if code:
        q = q.filter(SecurityEvent.code == code)
    if severity:
        q = q.filter(SecurityEvent.severity == severity)
    total = q.count()
    rows = q.order_by(SecurityEvent.created_at.desc(), SecurityEvent.id.desc()).offset((page - 1) * pageSize).limit(pageSize).all()
    user_ids = [e.user_id for e in rows if e.user_id]
    names = {u.id: u.full_name for u in db.query(User).filter(User.id.in_(user_ids)).all()} if user_ids else {}
    device_ids = [e.device_id_fk for e in rows if e.device_id_fk]
    devices = {d.id: d for d in db.query(Device).filter(Device.id.in_(device_ids)).all()} if device_ids else {}
    site_ids = [d.site_id for d in devices.values() if d.site_id]
    sites = {s.id: s.name for s in db.query(Site).filter(Site.id.in_(site_ids)).all()} if site_ids else {}
    return {
        "data": [
            {
                "id": e.id,
                "severity": e.severity.value,
                "code": e.code,
                "title": e.title,
                "details": e.details,
                "userId": e.user_id,
                "userName": names.get(e.user_id, ""),
                "subject": sites.get(devices[e.device_id_fk].site_id, "") if e.device_id_fk in devices and devices[e.device_id_fk].site_id else names.get(e.user_id, ""),
                "subjectKind": "object" if e.device_id_fk in devices and devices[e.device_id_fk].site_id else "user",
                "deviceId": e.device_id_fk,
                "publicKey": e.public_key,
                "oldDeviceId": e.old_device_id,
                "newDeviceId": e.new_device_id,
                "externalIp": e.external_ip,
                "geo": e.geo,
                "isp": e.isp,
                "mac": e.mac,
                "autoBlocked": e.auto_blocked,
                "createdAt": e.created_at.isoformat(),
                "archivedAt": e.archived_at.isoformat() if e.archived_at else None,
                "archivedBy": e.archived_by,
            }
            for e in rows
        ],
        "pagination": {"page": page, "pageSize": pageSize, "totalItems": total},
    }


class IncidentArchiveIn(BaseModel):
    archived: bool


@router.put("/incidents/{incident_id}/archive")
def archive_incident(incident_id: str, payload: IncidentArchiveIn, request: Request,
                     db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN))):
    row = db.query(SecurityEvent).filter(SecurityEvent.id == incident_id).with_for_update().one_or_none()
    if row is None:
        raise HTTPException(404, "Инцидент не найден")
    if (row.archived_at is not None) != payload.archived:
        row.archived_at = datetime.utcnow() if payload.archived else None
        row.archived_by = actor.email if payload.archived else ""
        ip, browser, mac = client_context(request)
        audit(db, actor_id=actor.id, actor_email=actor.email,
              action="incident_archive" if payload.archived else "incident_restore",
              target=row.id, ip=ip, browser=browser, mac=mac)
    db.commit()
    return {"id": row.id, "archivedAt": row.archived_at.isoformat() if row.archived_at else None,
            "archivedBy": row.archived_by}


class KeyCopyIn(BaseModel):
    userId: str = ""
    siteId: str = ""
    action: str = "copy"


_KEY_ACTIONS = {
    "open": "wg_config_open",
    "copy": "wg_config_copy",
    "download": "wg_config_download",
}


@router.post("/audit/key-copy")
def note_key_copy(payload: KeyCopyIn, request: Request, db: Session = Depends(get_db), actor: User = Depends(current_user)):
    if payload.siteId:
        site = db.get(Site, payload.siteId)
        if not site:
            raise HTTPException(404, "Объект не найден")
        if actor.role not in (Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF):
            raise HTTPException(403, "Недостаточно прав для работы с конфигурацией объекта")
        if not release_allowed(db, site_id=site.id):
            raise HTTPException(status_code=403, detail="Ключ закрыт до согласования заявки")
        target = site.name
    elif payload.userId:
        user = db.get(User, payload.userId)
        if not user:
            raise HTTPException(404, "Пользователь не найден")
        if actor.role not in (Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF) and actor.id != user.id:
            raise HTTPException(403, "Можно работать только с собственной конфигурацией")
        if not release_allowed(db, user_id=user.id):
            raise HTTPException(status_code=403, detail="Ключ закрыт до согласования заявки")
        target = user.full_name
    else:
        raise HTTPException(status_code=422, detail="Не указан ключ")
    ip, browser, mac = client_context(request)
    audit(
        db,
        actor_id=actor.id,
        actor_email=actor.email,
        action=_KEY_ACTIONS.get(payload.action, "wg_config_copy"),
        target=target,
        ip=ip,
        browser=browser,
        mac=mac,
    )
    return {"ok": True}


@router.get("/audit")
def audit_log(
    db: Session = Depends(get_db),
    _=Depends(require_roles(Role.ADMIN)),
    page: int = Query(1, ge=1),
    pageSize: int = Query(200, ge=1, le=1000),
    q: str = "",
    kind: Literal["all", "people", "vpn"] = "all",
    actor: str = "",
):
    query = db.query(AuditLog)
    if kind == "people":
        query = query.filter(AuditLog.action.in_(["login", "wg_config_open", "wg_config_copy", "wg_config_download"]))
    elif kind == "vpn":
        query = query.filter(AuditLog.action.in_(["vpn_up", "vpn_down"]))
    actors = [r[0] for r in query.with_entities(AuditLog.actor_email).distinct().order_by(AuditLog.actor_email).all() if r[0]] if kind == "people" else []
    if actor:
        query = query.filter(AuditLog.actor_email == actor)
    if q:
        like = f"%{q}%"
        query = query.filter(AuditLog.action.ilike(like) | AuditLog.actor_email.ilike(like) | AuditLog.target.ilike(like))
    total = query.count()
    rows = query.order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).offset((page - 1) * pageSize).limit(pageSize).all()
    # Resolve by immutable user ID first; old journal entries may only have a login.
    ids = {a.actor_id for a in rows if a.actor_id}
    logins = set(actors) | {a.actor_email for a in rows if a.actor_email}
    users = db.query(User).filter(User.id.in_(ids) | User.email.in_(logins)).all() if ids or logins else []
    by_id = {u.id: u.full_name.strip() for u in users if u.full_name and u.full_name.strip()}
    by_login = {u.email: u.full_name.strip() for u in users if u.full_name and u.full_name.strip()}
    for row in rows:
        if row.actor_email and row.actor_id in by_id:
            by_login.setdefault(row.actor_email, by_id[row.actor_id])
    return {
        "data": [
            {
                "id": a.id,
                "actor": by_id.get(a.actor_id) or by_login.get(a.actor_email) or a.actor_email,
                "action": a.action,
                "target": a.target,
                "ip": a.ip,
                "mac": a.mac or "",
                "browser": a.browser or "",
                "device": a.device,
                "vpn": a.vpn,
                "resource": a.resource,
                "result": a.result,
                "createdAt": a.created_at.isoformat(),
            }
            for a in rows
        ],
        "pagination": {"page": page, "pageSize": pageSize, "totalItems": total},
        "retentionDays": AUDIT_RETENTION_DAYS,
        "actors": actors,
        "actorNames": {login: by_login.get(login, login) for login in actors},
    }


@router.get("/connections")
def connections(db: Session = Depends(get_db), _=Depends(require_roles(Role.ADMIN))):
    now = datetime.utcnow()
    from ..models import Device

    rows = db.query(Session).filter(Session.active.is_(True), Session.expires_at > now).all()
    out = []
    for s in rows:
        d = db.get(Device, s.device_id_fk)
        out.append(
            {
                "sessionId": s.id,
                "deviceName": d.name if d else "",
                "deviceId": d.device_id if d else "",
                "userName": d.user.full_name if d and d.user else "",
                "contour": d.contour.value if d else "",
                "vpnIp": d.peer.vpn_ip if d and d.peer else "",
                "externalIp": s.external_ip,
                "geo": s.geo,
                "agentVersion": s.agent_version,
                "heartbeatAt": s.last_heartbeat.isoformat(),
                "expiresAt": s.expires_at.isoformat(),
            }
        )
    return {"data": out}
