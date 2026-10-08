from datetime import datetime, timedelta
from hashlib import sha256
import secrets
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt
from jwt import InvalidTokenError as JWTError
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from .config import settings
from .db import get_db
from .models import RevokedSession, Role, User

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer = HTTPBearer(auto_error=False)

def hash_password(password: str) -> str:
    return pwd.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return pwd.verify(password, hashed)


def create_token(user: User, *, purpose: str = "", mfa: bool = False) -> str:
    payload = {
        "sub": user.id,
        "jti": secrets.token_urlsafe(24),
        "email": user.email,
        "role": user.role.value,
        "panel_nonce": user.panel_nonce,
        "exp": datetime.utcnow() + timedelta(minutes=30 if purpose == "setup" else settings.jwt_expire_minutes),
        "mfa": mfa,
        **({"purpose": purpose} if purpose else {}),
    }
    return jwt.encode(payload, settings.secret_key, algorithm="HS256")


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, settings.secret_key, algorithms=["HS256"])
    except JWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Сессия недействительна") from exc


def current_user(
    request: Request,
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    token = None
    if creds:
        token = creds.credentials
    if not token:
        token = request.cookies.get("fortis_session")
    if not token:
        raise HTTPException(status_code=401, detail="Требуется вход")
    data = decode_token(token)
    if db.get(RevokedSession, sha256(token.encode()).hexdigest()):
        raise HTTPException(status_code=401, detail="Сессия завершена. Войдите заново")
    purpose = data.get("purpose")
    if purpose:
        from .setup import completed
        if purpose != "setup" or not request.url.path.startswith("/api/setup/") or completed(db):
            raise HTTPException(status_code=401, detail="Сессия недействительна")
    user = db.get(User, data.get("sub"))
    if not user:
        raise HTTPException(status_code=401, detail="Учётная запись недоступна")
    if data.get('panel_nonce') != user.panel_nonce:
        raise HTTPException(status_code=401, detail="Сессия завершена. Войдите заново")
    if not purpose and user.role in (Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF, Role.SECURITY, Role.AUDITOR) and not data.get("mfa"):
        raise HTTPException(status_code=401, detail="Требуется вход с двухфакторной проверкой")
    if settings.panel_gate_enabled and getattr(request.state,'panel_user_id',None) != user.id:
        raise HTTPException(status_code=401, detail="Войдите по своей персональной ссылке")
    if not user.is_active and request.url.path not in ("/api/auth/me", "/api/auth/logout"):
        raise HTTPException(status_code=403, detail="Учётная запись заблокирована")
    return user


def require_roles(*roles: Role):
    def _inner(user: Annotated[User, Depends(current_user)]) -> User:
        if user.role == Role.ADMIN:
            return user
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="Недостаточно прав")
        return user

    return _inner


SESSION_COOKIE = "fortis_session"
HINT_COOKIE = "fortis_session_hint"
CSRF_COOKIE = "fortis_csrf"


def session_token(request):
    authorization = request.headers.get("authorization", "")
    return authorization.split(None, 1)[1] if authorization.lower().startswith("bearer ") else request.cookies.get(SESSION_COOKIE, "")


def set_session(response, request, token, *, setup=False):
    from urllib.parse import urlsplit
    secure = request.url.scheme == 'https' or urlsplit(settings.public_origin).scheme == 'https'
    if not secure and request.url.hostname not in ('localhost', '127.0.0.1', '::1', 'testserver'):
        raise HTTPException(400, 'Для удалённого входа требуется HTTPS')
    age = 1800 if setup else settings.jwt_expire_minutes * 60
    response.set_cookie(SESSION_COOKIE, token, max_age=age, httponly=True, secure=secure, samesite='strict', path='/')
    response.set_cookie('fortis_session_kind', 'setup' if setup else 'full', max_age=age, secure=secure, samesite='strict', path='/')
    for name in (HINT_COOKIE, CSRF_COOKIE):
        response.set_cookie(name, secrets.token_urlsafe(24), max_age=age, secure=secure, samesite='strict', path='/')


def clear_session(response):
    for name in (SESSION_COOKIE, HINT_COOKIE, CSRF_COOKIE, 'fortis_session_kind', 'kontur_session'):
        response.delete_cookie(name, path='/')


def revoke_session(request, response, db):
    token = session_token(request)
    if token:
        data = decode_token(token)
        digest = sha256(token.encode()).hexdigest()
        if not db.get(RevokedSession, digest):
            db.add(RevokedSession(token_hash=digest, expires_at=datetime.utcfromtimestamp(data['exp'])))
    clear_session(response)
