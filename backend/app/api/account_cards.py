"""System-account cards. Passwords are reset, never recovered or retained."""
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel
from sqlalchemy import or_
from sqlalchemy.orm import Session

from ..audit import audit
from ..db import get_db
from ..models import Role, User
from ..panel_gate import entry_key
from ..security import current_user, hash_password

router = APIRouter(prefix="/account-cards", tags=["account-cards"])
SYSTEM_ROLES = (Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF, Role.SECURITY, Role.AUDITOR)


def allowed(actor, target):
    return actor.is_active and (target.is_management or target.role in SYSTEM_ROLES) and (
        actor.id == target.id or actor.role == Role.ADMIN
        or (actor.role == Role.IT_LEAD and target.role == Role.IT_STAFF)
    )


def private(response):
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    response.headers["Referrer-Policy"] = "no-referrer"


def identity(user):
    return {"id": user.id, "fullName": user.full_name, "email": user.email,
            "role": user.role.value, "active": user.is_active}


def target_account(db, actor, user_id, lock=False):
    query = db.query(User).filter(User.id == user_id)
    if lock:
        query = query.populate_existing().with_for_update()
    target = query.one_or_none()
    if target is None or not allowed(actor, target):
        raise HTTPException(403, "Карточка этой учётной записи вам недоступна")
    return target


@router.get("")
def accounts(response: Response, db: Session = Depends(get_db), actor: User = Depends(current_user)):
    private(response)
    query = db.query(User).filter(or_(User.is_management.is_(True), User.role.in_(SYSTEM_ROLES)))
    if actor.role == Role.IT_LEAD:
        query = query.filter(or_(User.id == actor.id, User.role == Role.IT_STAFF))
    elif actor.role != Role.ADMIN:
        query = query.filter(User.id == actor.id)
    return {"selfId": actor.id, "data": [identity(u) for u in query.order_by(User.full_name).all() if allowed(actor, u)]}


@router.get("/{user_id}")
def card(user_id: str, response: Response, db: Session = Depends(get_db), actor: User = Depends(current_user)):
    private(response)
    target = target_account(db, actor, user_id)
    return {**identity(target), "path": "/" + entry_key(target) + "/", "self": target.id == actor.id}


class ResetIn(BaseModel):
    confirmLogin: str
    expectedPath: str


@router.post("/{user_id}/reset-password")
def reset(user_id: str, payload: ResetIn, request: Request, response: Response,
          db: Session = Depends(get_db), actor: User = Depends(current_user)):
    private(response)
    target = target_account(db, actor, user_id, lock=True)
    if payload.confirmLogin != target.email:
        raise HTTPException(400, "Для подтверждения введите логин пользователя")
    if not secrets.compare_digest(payload.expectedPath, "/" + entry_key(target) + "/"):
        raise HTTPException(409, "Данные изменились. Закройте и заново откройте карточку")
    if not target.is_active:
        raise HTTPException(409, "Учётная запись заблокирована")
    password = secrets.token_urlsafe(18)
    target.password_hash = hash_password(password)
    target.panel_nonce = secrets.token_urlsafe(32)
    # Audit commits the password, nonce and log entry in one transaction.
    audit(db, actor_id=actor.id, actor_email=actor.email, action="account_password_reset",
          target=target.id, ip=request.client.host if request.client else "",
          payload={"sessionsRevoked": True, "linkRotated": True})
    return {**identity(target), "path": "/" + entry_key(target) + "/",
            "self": target.id == actor.id, "password": password}
