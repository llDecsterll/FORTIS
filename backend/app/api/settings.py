from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from ..audit import audit
from ..config import settings as app_settings
from ..db import get_db
from .. import ad
from ..models import Role, Setting, User
from ..schemas import AdSettingsIn, SettingsIn
from ..security import current_user, require_roles

router = APIRouter(tags=["settings"])

@router.get('/settings/channels/status')
def get_channel_status(_=Depends(require_roles(Role.ADMIN))):
    from ..channel_status import read_channel_status
    return read_channel_status()

@router.get('/settings/backups/status')
def get_backup_status(_=Depends(require_roles(Role.ADMIN))):
    from ..backup_status import read_backup_status
    return read_backup_status()

from ..operations import OperationsIn, read_operations, save_operations, public_operations
from pydantic import BaseModel
from ..ad_delete import deletion_info, delete_source
from ..ad_availability import check_availability


@router.post('/settings/ad/{source_id}/check')
def check_ad_source(source_id: str, db: Session = Depends(get_db), _=Depends(require_roles(Role.ADMIN))):
    return check_availability(db, source_id)


class AdDeleteIn(BaseModel):
    confirmation: str
    revision: str


@router.get('/settings/ad/{source_id}/deletion')
def preview_ad_delete(source_id: str, db: Session = Depends(get_db), _=Depends(require_roles(Role.ADMIN))):
    return deletion_info(db, source_id)


@router.delete('/settings/ad/{source_id}')
def remove_ad_source(source_id: str, payload: AdDeleteIn, request: Request,
                     db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN))):
    return delete_source(db, source_id, payload.confirmation, payload.revision, actor,
                         request.client.host if request.client else '')


@router.get('/settings/operations')
def get_operations(db: Session = Depends(get_db), _=Depends(require_roles(Role.ADMIN))):
    return public_operations(read_operations(db))


@router.put('/settings/operations')
def put_operations(payload: OperationsIn, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN))):
    save_operations(db, payload)
    db.commit()
    audit(db, actor_id=actor.id, actor_email=actor.email, action='operations_settings_update', ip=request.client.host if request.client else '')
    return public_operations(payload)


DEFAULTS = {
    "concurrent_policy": app_settings.concurrent_policy,
    "mac_policy": app_settings.mac_policy,
    "telegram_chat_id": app_settings.telegram_chat_id,
    "webhook_url": app_settings.webhook_url,
    "security_notify_email": app_settings.security_notify_email,
}


@router.get("/settings")
def get_settings(db: Session = Depends(get_db), _=Depends(require_roles(Role.ADMIN, Role.SECURITY))):
    out = dict(DEFAULTS)
    for row in db.query(Setting).all():
        out[row.key] = row.value
    return {
        "concurrentPolicy": out.get("concurrent_policy"),
        "macPolicy": out.get("mac_policy"),
        "telegramChatId": out.get("telegram_chat_id"),
        "webhookUrl": out.get("webhook_url"),
        "securityNotifyEmail": out.get("security_notify_email"),
        "employeesEndpoint": f"{app_settings.employees_endpoint}:{app_settings.employees_port}",
        "sitesEndpoint": f"{app_settings.sites_endpoint}:{app_settings.sites_port}",
        "employeesNet": app_settings.employees_net,
        "sitesNet": app_settings.sites_net,
    }


@router.put("/settings")
def put_settings(payload: SettingsIn, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN))):
    mapping = {
        "concurrent_policy": payload.concurrentPolicy,
        "mac_policy": payload.macPolicy,
        "telegram_chat_id": payload.telegramChatId,
        "webhook_url": payload.webhookUrl,
        "security_notify_email": payload.securityNotifyEmail,
    }
    for key, value in mapping.items():
        if value is None:
            continue
        row = db.get(Setting, key)
        if not row:
            row = Setting(key=key, value=value)
            db.add(row)
        else:
            row.value = value
    db.commit()
    audit(db, actor_id=actor.id, actor_email=actor.email, action="settings_update", ip=request.client.host if request.client else "")
    return {"ok": True}


@router.get("/settings/ad")
def get_ad(db: Session = Depends(get_db), _=Depends(require_roles(Role.ADMIN))):
    return ad.read_settings(db)


@router.put("/settings/ad")
def put_ad(payload: AdSettingsIn, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN))):
    out = ad.save_settings(db, payload)
    audit(db, actor_id=actor.id, actor_email=actor.email, action="ad_settings", ip=request.client.host if request.client else "")
    return out


@router.post("/settings/ad/sync")
def sync_ad(request: Request, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN))):
    out = ad.sync_users(db, actor)
    audit(db, actor_id=actor.id, actor_email=actor.email, action="ad_sync", ip=request.client.host if request.client else "", payload=out)
    return out
