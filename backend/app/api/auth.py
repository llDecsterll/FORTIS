import base64
import io
import secrets
from hashlib import sha256
from datetime import datetime, timedelta

import pyotp
import qrcode
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.exc import IntegrityError
import jwt
from sqlalchemy.orm import Session

from ..audit import audit, client_context
from ..config import settings
from ..db import get_db
from ..models import FailedAuth, RevokedSession, Role, User
from ..schemas import LoginIn, LoginOut, TokenOut, TotpIn
from ..security import create_token, current_user, decode_token, verify_password, set_session, clear_session, session_token

router = APIRouter(tags=["auth"])

STAFF_ROLES = {Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF, Role.SECURITY, Role.AUDITOR}
_WINDOW = timedelta(minutes=15)
_LOGIN_LIMIT = 5
_IP_LIMIT = 20


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def _row(db: Session, ip: str, bucket: str) -> FailedAuth | None:
    return db.query(FailedAuth).filter(FailedAuth.ip == ip, FailedAuth.bucket == bucket).one_or_none()


def _wait_seconds(row: FailedAuth | None, now: datetime, limit: int) -> int:
    if not row or row.count < limit or now - row.last_at > _WINDOW:
        return 0
    left = _WINDOW - (now - row.last_at)
    return max(1, int(left.total_seconds() + 0.999))


def _guard(db: Session, ip: str, login: str) -> None:
    now = datetime.utcnow()
    wait = max(
        _wait_seconds(_row(db, "*", f"login:{login}"), now, _LOGIN_LIMIT),
        _wait_seconds(_row(db, ip, "ip"), now, _IP_LIMIT),
    )
    if wait:
        raise HTTPException(
            status_code=429,
            detail={"message": "Слишком много попыток. Повторите через", "retryAfter": wait},
        )


def _hit(db: Session, ip: str, bucket: str) -> None:
    now = datetime.utcnow()
    row = _row(db, ip, bucket)
    if not row:
        db.add(FailedAuth(ip=ip, bucket=bucket, count=1, last_at=now))
    elif now - row.last_at > _WINDOW:
        row.count = 1
        row.last_at = now
    else:
        row.count += 1
        row.last_at = now
    db.commit()


def _clear(db: Session, ip: str, bucket: str) -> None:
    row = _row(db, ip, bucket)
    if row and row.count:
        row.count = 0
        db.commit()


def _challenge(user: User, purpose: str) -> str:
    payload = {
        "sub": user.id,
        "jti": secrets.token_urlsafe(24),
        "purpose": purpose,
        "panel_nonce": user.panel_nonce,
        "exp": datetime.utcnow() + timedelta(minutes=5),
    }
    return jwt.encode(payload, settings.secret_key, algorithm="HS256")


def _qr(uri: str) -> str:
    image = qrcode.make(uri)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buffer.getvalue()).decode()


def _session(user: User, request: Request, db: Session, response: Response) -> TokenOut:
    _clear(db, "*", f"login:{user.email}")
    _clear(db, _client_ip(request), "ip")
    user.last_activity_at = datetime.utcnow()
    token = create_token(user, mfa=user.role in STAFF_ROLES)
    set_session(response, request, token)
    ip, browser, mac = client_context(request)
    audit(db, actor_id=user.id, actor_email=user.email, action="login", ip=ip, browser=browser, mac=mac)
    return TokenOut(token="cookie-session", role=user.role.value, fullName=user.full_name, email=user.email)


@router.post("/auth/login", response_model=LoginOut)
def login(payload: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)):
    login_name = payload.email.strip().lower()[:120]
    ip = _client_ip(request)
    _guard(db, ip, login_name)
    user = db.query(User).filter(User.email == login_name).one_or_none()
    if not user or (settings.panel_gate_enabled and getattr(request.state,'panel_user_id',None) != user.id) or not verify_password(payload.password, user.password_hash):
        _hit(db, "*", f"login:{login_name}")
        _hit(db, ip, "ip")
        audit(db, action="login_failed", ip=ip, result="DENY", payload={"email": login_name})
        raise HTTPException(status_code=401, detail="Неверный логин или пароль")
    if not user.is_active:
        audit(db, action="login_failed", ip=request.client.host if request.client else "", result="DENY", payload={"email": payload.email, "reason": "blocked"})
        return LoginOut(blocked=True, blockedBy=user.blocked_by or "администратор", fullName=user.full_name, email=user.email)
    if user.role in STAFF_ROLES:
        if not user.totp_confirmed:
            if not user.totp_secret:
                user.totp_secret = pyotp.random_base32()
                db.commit()
            uri = pyotp.TOTP(user.totp_secret).provisioning_uri(name=user.email, issuer_name="FORTIS")
            return LoginOut(
                totpSetup=True,
                challenge=_challenge(user, "totp-setup"),
                qr=_qr(uri),
                secret=user.totp_secret,
                email=user.email,
                fullName=user.full_name,
            )
        return LoginOut(totpRequired=True, challenge=_challenge(user, "totp"), email=user.email, fullName=user.full_name)
    return LoginOut(**_session(user, request, db, response).model_dump())


@router.post("/auth/totp", response_model=LoginOut)
def confirm_totp(payload: TotpIn, request: Request, response: Response, db: Session = Depends(get_db)):
    data = decode_token(payload.challenge)
    challenge_hash = sha256(payload.challenge.encode()).hexdigest()
    if db.get(RevokedSession, challenge_hash):
        raise HTTPException(status_code=401, detail="Запрос 2FA уже использован. Войдите заново")
    purpose = data.get("purpose")
    if purpose not in ("totp", "totp-setup"):
        raise HTTPException(status_code=401, detail="Сессия недействительна")
    user = db.get(User, data.get("sub"))
    if not user or data.get("panel_nonce") != user.panel_nonce:
        raise HTTPException(status_code=401, detail="Сессия завершена. Войдите заново")
    if settings.panel_gate_enabled and (not user or getattr(request.state,'panel_user_id',None) != user.id):
        raise HTTPException(status_code=401, detail="Сессия недействительна")
    if not user or user.role not in STAFF_ROLES or not user.totp_secret:
        raise HTTPException(status_code=401, detail="Сессия недействительна")
    if not user.is_active:
        return LoginOut(blocked=True, blockedBy=user.blocked_by or "администратор", fullName=user.full_name, email=user.email)
    ip = _client_ip(request)
    _guard(db, ip, user.email)
    code = "".join(ch for ch in payload.code if ch.isdigit())
    if not pyotp.TOTP(user.totp_secret).verify(code, valid_window=1):
        _hit(db, "*", f"login:{user.email}")
        _hit(db, ip, "ip")
        audit(db, action="login_failed", ip=ip, result="DENY", payload={"email": user.email, "reason": "totp"})
        raise HTTPException(status_code=401, detail="Неверный код")
    _clear(db, "*", f"login:{user.email}")
    _clear(db, ip, "ip")
    if purpose == "totp-setup":
        user.totp_confirmed = True
        db.commit()
    elif not user.totp_confirmed:
        raise HTTPException(status_code=401, detail="Сначала подключите приложение")
    db.query(RevokedSession).filter(RevokedSession.expires_at < datetime.utcnow()).delete(synchronize_session=False)
    db.add(RevokedSession(token_hash=challenge_hash, expires_at=datetime.utcfromtimestamp(data["exp"])))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=401, detail="Запрос 2FA уже использован. Войдите заново")
    return LoginOut(**_session(user, request, db, response).model_dump())


@router.post("/auth/logout")
def logout(request: Request, response: Response, user: User = Depends(current_user), db: Session = Depends(get_db)):
    # Store only a digest; keep personal panel links and other sessions intact.
    token = session_token(request)
    data = decode_token(token)
    digest = sha256(token.encode()).hexdigest()
    db.query(RevokedSession).filter(RevokedSession.expires_at < datetime.utcnow()).delete(synchronize_session=False)
    try:
        with db.begin_nested():
            if not db.get(RevokedSession, digest):
                db.add(RevokedSession(token_hash=digest, expires_at=datetime.utcfromtimestamp(data["exp"])))
                db.flush()
        db.commit()
    except IntegrityError:
        # A simultaneous logout may already have revoked this same session.
        db.rollback()
        if not db.get(RevokedSession, digest):
            raise
    clear_session(response)
    return {"ok": True}


@router.get("/auth/me")
def me(user: User = Depends(current_user)):
    return {
        "id": user.id,
        "fullName": user.full_name,
        "email": user.email,
        "role": user.role.value,
        "companyId": user.company_id,
        "departmentId": user.department_id,
        "blocked": not user.is_active,
        "blockedBy": user.blocked_by or "",
    }
