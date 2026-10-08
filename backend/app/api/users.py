from __future__ import annotations

import re
import secrets
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from pydantic import BaseModel, Field
from fastapi.responses import FileResponse, PlainTextResponse, Response, StreamingResponse
from sqlalchemy.orm import Session, object_session

from ..audit import audit
from ..config import settings
from ..db import get_db
from ..models import AccessRequest, Company, Contour, Department, DeviceStatus, Document, RequestStatus, ResourceVisit, Role, User
from ..geo import pretty_isp
from ..presence import peer_online
from .. import engine
from ..provision import access_until_from_days, config_for_device, ensure_peer_for_user, slug
from ..access_term import future_access_until
from ..models import VpnRenewal
from ..schemas import CompanyIn, DepartmentIn, TotpBindIn, TotpCodeIn, UserIn, UserPatch
from ..security import current_user, hash_password, require_roles
from ..wireguard import WireGuardError
from .auth import STAFF_ROLES, _qr
import pyotp

router = APIRouter(tags=["directory"])

APPROVAL_WAIT = "Ожидает согласования СБ"
APPROVAL_NO = "Отклонено службой безопасности"
_PDF_LIMIT = 15 * 1024 * 1024

_RU = str.maketrans({
    "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "e",
    "ж": "zh", "з": "z", "и": "i", "й": "y", "к": "k", "л": "l", "м": "m",
    "н": "n", "о": "o", "п": "p", "р": "r", "с": "s", "т": "t", "у": "u",
    "ф": "f", "х": "h", "ц": "ts", "ч": "ch", "ш": "sh", "щ": "sch",
    "ъ": "", "ы": "y", "ь": "", "э": "e", "ю": "yu", "я": "ya",
})


def _login_email(db: Session, full_name: str, given: str) -> str:
    email = (given or "").strip().lower()
    if email:
        return email
    folded = full_name.strip().lower().translate(_RU)
    base = re.sub(r"[^a-z0-9]+", ".", folded).strip(".")[:40] or "user"
    candidate = f"{base}@avtodor.local"
    n = 2
    while db.query(User).filter(User.email == candidate).one_or_none():
        candidate = f"{base}.{n}@avtodor.local"
        n += 1
    return candidate


def _user_out(u: User) -> dict:
    device = next((d for d in (u.devices or []) if d.peer and not d.site_id), None)
    peer = device.peer if device else None
    return {
        "id": u.id,
        "fullName": u.full_name,
        "email": u.email,
        "phone": u.phone,
        "contactEmail": u.contact_email,
        "title": u.title,
        "role": u.role.value,
        "isManagement": bool(u.is_management),
        "hasRdp": bool(u.rdp_host and u.rdp_user),
        "companyId": u.company_id,
        "company": u.company.name if u.company else "",
        "departmentId": u.department_id,
        "department": u.department.name if u.department else "",
        "isActive": u.is_active,
        "totpConfirmed": bool(u.totp_confirmed),
        "createdAt": u.created_at.isoformat() if u.created_at else None,
        "vpnIp": peer.vpn_ip if peer else "",
        "deviceId": device.id if device else "",
        "hasConfig": bool(peer and (peer.client_config or peer.private_key)),
        "configName": f"{slug(u.full_name)}.conf" if peer else "",
        "online": peer_online(peer) if u.is_active and device and device.status.value == "ACTIVE" and peer and peer.enabled else False,
        "handshakeAt": peer.handshake_at.isoformat() if peer and peer.handshake_at else None,
        "activated": bool(peer and peer.handshake_at),
        "activationStatus": "ACTIVATED" if peer and peer.handshake_at else "NOT_ACTIVATED",
        "status": device.status.value if device else "NONE",
        "vpnEnabled": bool(peer and peer.enabled),
        "suspended": bool(device and device.status.value == "BLOCKED" and u.is_active),
        "blocked": not u.is_active,
        "blockReason": (device.block_reason if device and device.block_reason else ""),
        **_approval_out(u),
        "publicKey": peer.public_key if peer else "",
        "endpoint": peer.endpoint if peer else "",
        "deviceName": device.name if device else "",
        "deviceType": device.device_type.value if device else "",
        "osName": device.os_name if device else "",
        "lastGeo": device.last_geo if device else "",
        "isp": pretty_isp(device.isp) if device else "",
        "accessUntil": device.access_until.isoformat() if device and device.access_until else None,
    }


@router.get("/users")
def list_users(db: Session = Depends(get_db), actor: User = Depends(current_user), page: int = 1, pageSize: int = 50, q: str = ""):
    from ..employee_exclusions import excluded_ids
    query = db.query(User)
    if actor.role == Role.USER:
        query = query.filter(User.id == actor.id)
    else:
        query = query.filter(User.id.notin_(excluded_ids(db)))
    if q:
        like = f"%{q}%"
        query = query.filter((User.full_name.ilike(like)) | (User.email.ilike(like)))
    total = query.count()
    rows = query.order_by(User.full_name).offset((page - 1) * pageSize).limit(pageSize).all()
    return {"data": [_user_out(u) for u in rows], "pagination": {"page": page, "pageSize": pageSize, "totalItems": total}}


def _ensure_company(db: Session, company_id: str | None, company_name: str | None) -> str | None:
    if company_id:
        return company_id
    name = (company_name or "").strip()
    if not name:
        return None
    row = db.query(Company).filter(Company.name.ilike(name)).first()
    if row:
        return row.id
    row = Company(name=name)
    db.add(row)
    db.flush()
    return row.id


def _ensure_department(db: Session, department_id: str | None, department_name: str | None, company_id: str | None) -> str | None:
    if department_id:
        return department_id
    name = (department_name or "").strip()
    if not name or not company_id:
        return None
    row = db.query(Department).filter(Department.company_id == company_id, Department.name.ilike(name)).first()
    if row:
        return row.id
    row = Department(company_id=company_id, name=name)
    db.add(row)
    db.flush()
    return row.id


@router.post("/users", status_code=201)
def create_user(payload: UserIn, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN))):
    if actor.role != Role.ADMIN:
        raise HTTPException(status_code=403, detail="Создавать учётные записи управления может только администратор")
    if not payload.fullName.strip():
        raise HTTPException(status_code=422, detail="Укажите ФИО")
    email = _login_email(db, payload.fullName, payload.email)
    if db.query(User).filter(User.email == email).one_or_none():
        raise HTTPException(status_code=409, detail="Пользователь с такой почтой уже есть")
    try:
        role = Role(payload.role)
    except ValueError:
        role = Role.USER
    if role in (Role.SECURITY, Role.AUDITOR):
        raise HTTPException(status_code=422, detail="Эта роль больше не используется")
    company_id = _ensure_company(db, payload.companyId, payload.companyName)
    department_id = _ensure_department(db, payload.departmentId, payload.departmentName, company_id)
    try:
        access_until = access_until_from_days(payload.accessDays)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    chosen = (payload.password or "").strip()
    if chosen and len(chosen) < 8:
        raise HTTPException(status_code=422, detail="Пароль должен быть не короче 8 символов")
    password = chosen or secrets.token_urlsafe(10)
    user = User(
        full_name=payload.fullName.strip(),
        email=email,
        title=payload.title.strip(),
        role=role,
        is_management=payload.isManagement,
        rdp_host=payload.rdpHost.strip(), rdp_port=payload.rdpPort, rdp_user=payload.rdpUser.strip(),
        rdp_password=payload.rdpPassword, rdp_save_password=payload.rdpSavePassword,
        company_id=company_id,
        department_id=department_id,
        password_hash=hash_password(password),
    )
    db.add(user)
    db.flush()
    db.commit()
    db.refresh(user)
    audit(db, actor_id=actor.id, actor_email=actor.email, action="user_create", target=user.email, ip=request.client.host if request.client else "")
    return {
        **_user_out(user),
        "temporaryPassword": password,
        "hasConfig": False,
        "vpnIp": "",
    }


@router.get('/users/{user_id}/panel-link')
def panel_link(user_id: str, db: Session = Depends(get_db), actor: User = Depends(current_user)):
    if actor.role != Role.ADMIN and actor.id != user_id:
        raise HTTPException(403, 'Чужие ссылки доступны только администратору')
    user=db.get(User,user_id)
    if not user:
        raise HTTPException(404,'Пользователь не найден')
    from ..panel_gate import entry_key
    return {'path':'/'+entry_key(user)+'/', 'active':user.is_active}


def _pdf_blobs(files: list[UploadFile]) -> list[tuple[str, bytes]]:
    blobs: list[tuple[str, bytes]] = []
    for upload in files:
        name = Path(upload.filename or "").name
        raw = upload.file.read(_PDF_LIMIT + 1)
        if not name.lower().endswith(".pdf") or not raw.startswith(b"%PDF"):
            raise HTTPException(status_code=422, detail="Служебная записка должна быть файлом PDF")
        if len(raw) > _PDF_LIMIT:
            raise HTTPException(status_code=422, detail="PDF больше 15 МБ")
        blobs.append((name, raw))
    if not blobs:
        raise HTTPException(status_code=422, detail="Прикрепите PDF служебной записки")
    return blobs


@router.post("/users/employee", status_code=201)
def create_employee(
    request: Request,
    fullName: str = Form(...),
    email: str = Form(""),
    title: str = Form(""),
    companyName: str = Form(...),
    departmentName: str = Form(...),
    isManagement: bool = Form(False),
    rdpHost: str = Form(""), rdpPort: int = Form(3389), rdpUser: str = Form(""), rdpPassword: str = Form(""), rdpSavePassword: bool = Form(True),
    deviceName: str = Form(""),
    accessDays: str = Form(""),
    accessUntil: str = Form(...),
    files: list[UploadFile] = File(...),
    networkIds: str = Form(...),
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles(Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF)),
):
    from ..employee_networks import selected_networks
    networks = selected_networks(db, networkIds)
    name = fullName.strip()
    company_name = companyName.strip()
    department_name = departmentName.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Укажите ФИО")
    if not company_name:
        raise HTTPException(status_code=422, detail="Укажите компанию")
    if not department_name:
        raise HTTPException(status_code=422, detail="Укажите отдел")
    blobs = _pdf_blobs(files)
    login = _login_email(db, name, email)
    if db.query(User).filter(User.email == login).one_or_none():
        raise HTTPException(status_code=409, detail="Пользователь с такой почтой уже есть")
    access_until = future_access_until(accessUntil)
    company_id = _ensure_company(db, None, company_name)
    department_id = _ensure_department(db, None, department_name, company_id)
    password = secrets.token_urlsafe(10)
    user = User(
        full_name=name,
        email=login,
        title=title.strip(),
        role=Role.USER,
        is_management=isManagement,
        rdp_host=rdpHost.strip(), rdp_port=rdpPort, rdp_user=rdpUser.strip(), rdp_password=rdpPassword, rdp_save_password=rdpSavePassword,
        company_id=company_id,
        department_id=department_id,
        password_hash=hash_password(password),
    )
    db.add(user)
    db.flush()
    row = AccessRequest(
        user_id=user.id,
        device_name="Определится при подключении",
        contour=Contour.EMPLOYEES,
        reason="Ручная заявка на VPN-доступ",
        networks_json=[n.id for n in networks],
        memo="Служебная записка",
        status=RequestStatus.PENDING_APPROVAL,
        access_until=access_until,
        created_by=actor.email,
    )
    db.add(row)
    db.flush()
    settings.uploads_dir.mkdir(parents=True, exist_ok=True)
    for index, (filename, raw) in enumerate(blobs, start=1):
        safe = re.sub(r"[^0-9A-Za-z._-]+", "_", filename)[:80] or "memo.pdf"
        dest = settings.uploads_dir / f"{row.id}_{index}_{safe}"
        dest.write_bytes(raw)
        db.add(Document(
            request_id=row.id,
            title="Служебная записка",
            kind="MEMO",
            filename=filename,
            content_type="application/pdf",
            path=str(dest),
            uploaded_by=actor.email,
        ))
    db.commit()
    db.refresh(row)
    audit(db, actor_id=actor.id, actor_email=actor.email, action="manual_vpn_request", target=user.email, ip=request.client.host if request.client else "")
    return {
        **_user_out(user),
        "requestId": row.id,
        "temporaryPassword": password,
    }


@router.get("/documents/{document_id}")
def download_document(document_id: str, db: Session = Depends(get_db), actor: User = Depends(current_user)):
    doc = db.get(Document, document_id)
    if not doc:
        raise HTTPException(404, "Документ не найден")
    access_request = db.get(AccessRequest, doc.request_id)
    if actor.role not in (Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF) and (not access_request or access_request.user_id != actor.id):
        raise HTTPException(403, "Недостаточно прав для просмотра документа")
    path = Path(doc.path)
    root = settings.uploads_dir.resolve()
    if not path.is_file() or root not in path.resolve().parents:
        raise HTTPException(404, "Файл не найден")
    return FileResponse(path, media_type="application/pdf", filename=doc.filename or "memo.pdf")


@router.post("/companies", status_code=201)
def create_company(payload: CompanyIn, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF))):
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Укажите название компании")
    if db.query(Company).filter(Company.name == name).one_or_none():
        raise HTTPException(status_code=409, detail="Компания уже есть")
    row = Company(name=name)
    db.add(row)
    db.commit()
    audit(db, actor_id=actor.id, actor_email=actor.email, action="company_create", target=row.name, ip=request.client.host if request.client else "")
    return {"id": row.id, "name": row.name}


@router.post("/departments", status_code=201)
def create_department(payload: DepartmentIn, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF))):
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Укажите подразделение")
    first = db.query(Company).order_by(Company.name).first()
    company_id = payload.companyId or (first.id if first else None)
    if not company_id:
        raise HTTPException(status_code=422, detail="Сначала создайте компанию")
    row = Department(company_id=company_id, name=name)
    db.add(row)
    db.commit()
    audit(db, actor_id=actor.id, actor_email=actor.email, action="department_create", target=row.name, ip=request.client.host if request.client else "")
    return {"id": row.id, "name": row.name, "companyId": row.company_id}


def _visit_out(row: ResourceVisit, now: datetime) -> dict:
    live = row.closed_at is None and row.last_seen_at and row.last_seen_at > now - timedelta(seconds=45)
    return {
        "id": row.id,
        "resource": row.resource_name or row.destination,
        "destination": row.destination,
        "port": row.port,
        "proto": row.proto,
        "openedAt": row.opened_at.isoformat() if row.opened_at else None,
        "lastSeenAt": row.last_seen_at.isoformat() if row.last_seen_at else None,
        "closedAt": row.closed_at.isoformat() if row.closed_at else None,
        "bytesUp": int(row.bytes_up or 0),
        "bytesDown": int(row.bytes_down or 0),
        "live": live,
        "download": int(row.bytes_down or 0) >= 65536,
    }


@router.get("/users/{user_id}")
def get_user(user_id: str, db: Session = Depends(get_db), actor: User = Depends(current_user)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "Сотрудник не найден")
    if actor.role not in (Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF) and actor.id != user.id:
        raise HTTPException(403, "Доступна только собственная учётная запись")
    from .devices import _device_out
    device = next((d for d in (user.devices or []) if d.peer and not d.site_id), None)
    config = ""
    if device and (actor.role in (Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF) or actor.id == user.id) and release_allowed(db, user_id=user.id):
        try:
            config = config_for_device(db, device)
        except LookupError:
            config = ""
    now = datetime.utcnow()
    visits = (
        db.query(ResourceVisit)
        .filter(ResourceVisit.user_id == user.id)
        .order_by(ResourceVisit.opened_at.desc())
        .limit(80)
        .all()
    )
    journal = [_visit_out(row, now) for row in visits]
    return {
        **_user_out(user),
        "config": config,
        "filename": f"{slug(user.full_name)}.conf" if device and device.peer else "",
        "devices": [_device_out(d) for d in (user.devices or []) if not d.site_id],
        "accessNow": [row for row in journal if row["live"]],
        "accessJournal": journal,
    }


@router.get("/users/{user_id}/wireguard.conf")
def download_user_config(user_id: str, request: Request, db: Session = Depends(get_db), actor: User = Depends(current_user)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "Сотрудник не найден")
    if actor.role not in (Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF) and actor.id != user.id:
        raise HTTPException(403, "Можно получить только собственную VPN-конфигурацию")
    _require_released(db, user_id=user.id)
    vpn = ensure_peer_for_user(db, user, actor.email)
    db.commit()
    audit(db, actor_id=actor.id, actor_email=actor.email, action="wg_config_download", target=user.email, ip=request.client.host if request.client else "")
    return PlainTextResponse(
        vpn["config"],
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{vpn["filename"]}"'},
    )


@router.get("/users/{user_id}/remote.rdp")
def download_user_rdp(user_id: str, request: Request, db: Session = Depends(get_db), actor: User = Depends(current_user)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "Сотрудник не найден")
    if actor.role not in (Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF) and actor.id != user.id:
        raise HTTPException(403, "RDP-файл доступен только сотруднику и операторам")
    if not user.rdp_host or not user.rdp_user:
        raise HTTPException(422, "Для пользователя не заполнены адрес и логин RDP")
    if user.rdp_port < 1 or user.rdp_port > 65535:
        raise HTTPException(422, "Порт RDP должен быть от 1 до 65535")
    host = user.rdp_host.replace("\r", "").replace("\n", "").strip()
    login = user.rdp_user.replace("\r", "").replace("\n", "").strip()
    lines = [
        f"full address:s:{host}:{user.rdp_port}",
        f"username:s:{login}",
        f"prompt for credentials:i:{0 if user.rdp_save_password and user.rdp_password else 1}",
        "authentication level:i:2",
        "enablecredsspsupport:i:1",
    ]
    if user.rdp_save_password and user.rdp_password:
        # Windows stores the password through Credential Manager on first use;
        # the .rdp file itself never contains a plaintext password.
        lines.append("promptcredentialonce:i:1")
    audit(db, actor_id=actor.id, actor_email=actor.email, action="rdp_download", target=user.email, ip=request.client.host if request.client else "")
    filename = f"{slug(user.full_name)}.rdp"
    return PlainTextResponse("\r\n".join(lines) + "\r\n", media_type="application/rdp", headers={"Content-Disposition": f'attachment; filename="{filename}"'})


class AccessExeOptions(BaseModel):
    rdp_host: str = ""
    rdp_user: str = ""
    rdp_password: str = ""
    enable_rdp: bool = True


@router.get("/users/{user_id}/access.exe")
@router.post("/users/{user_id}/access.exe")
def download_user_access_exe(user_id: str, request: Request, payload: AccessExeOptions | None = None, db: Session = Depends(get_db), actor: User = Depends(current_user)):
    if request.query_params:
        raise HTTPException(400, "Параметры установщика передаются только в JSON-теле POST-запроса")
    if request.method == "GET" and payload is not None:
        raise HTTPException(400, "GET доступен только без параметров установщика")
    if request.method == "POST" and payload is None:
        raise HTTPException(422, "Требуется JSON-тело запроса")
    options = payload or AccessExeOptions()
    rdp_host, rdp_user, rdp_password = options.rdp_host, options.rdp_user, options.rdp_password
    enable_rdp = options.enable_rdp
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "Сотрудник не найден")
    if actor.role not in (Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF):
        raise HTTPException(403, "Персональный установщик доступен операторам")
    _require_released(db, user_id=user.id)
    device = next((d for d in (user.devices or []) if d.peer and not d.site_id), None)
    if not device:
        raise HTTPException(422, "Сначала выдайте пользователю VPN-доступ")
    config = config_for_device(db, device)
    from ..access_package import iter_client_exe
    try:
        body = iter_client_exe(name="MSK-GK-TSI", employee=user.full_name, device=device.name, config=config, rdp_host=rdp_host or user.rdp_host, rdp_user=rdp_user or user.rdp_user, rdp_password=rdp_password or user.rdp_password, rdp_port=user.rdp_port, rdp_save_password=bool(rdp_password) or user.rdp_save_password, enable_rdp=enable_rdp)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    db.commit()
    audit(db, actor_id=actor.id, actor_email=actor.email, action="access_exe_download", target=user.email, ip=request.client.host if request.client else "")
    return StreamingResponse(body, media_type="application/vnd.microsoft.portable-executable", headers={"Content-Disposition": f'attachment; filename="{slug(user.full_name)}_Access.exe"'})


@router.get("/users/{user_id}/vpn")
def user_vpn(user_id: str, db: Session = Depends(get_db), actor: User = Depends(current_user)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "Сотрудник не найден")
    if actor.role not in (Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF) and actor.id != user.id:
        raise HTTPException(403, "Можно получить только собственную VPN-конфигурацию")
    _require_released(db, user_id=user.id)
    vpn = ensure_peer_for_user(db, user, actor.email)
    db.commit()
    return vpn


def _approval_out(user: User) -> dict:
    from ..approval_author import approval_author
    from ..models import Network
    db = object_session(user)
    if db is None:
        return {"approval": "", "approvalId": "", "documents": []}
    row = (
        db.query(AccessRequest)
        .filter(AccessRequest.user_id == user.id, AccessRequest.site_id.is_(None), AccessRequest.contour == Contour.EMPLOYEES)
        .order_by(AccessRequest.created_at.desc())
        .first()
    )
    if not row:
        return {"approval": "", "approvalId": "", "documents": []}
    renewal = db.query(VpnRenewal).filter(VpnRenewal.user_id == user.id).order_by(VpnRenewal.created_at.desc()).first()
    return {
        "renewal": {"id": renewal.id, "status": renewal.status, "accessUntil": renewal.requested_until.isoformat() + "Z", "createdBy": renewal.created_by, "reviewedBy": renewal.reviewed_by} if renewal else None,
        "approval": row.status.value,
        "approvalId": row.id,
        **approval_author(db, row),
        "requestedNetworks": [{"name": n.name, "cidr": n.cidr} for n in db.query(Network).filter(Network.id.in_(row.networks_json or []))],
        "requestedAccessUntil": row.access_until.isoformat() + "Z" if row.access_until else None,
        "documents": [{"id": d.id, "title": d.title, "filename": d.filename} for d in row.documents if d.kind != "MEMO_ARCHIVE"],
    }


def release_allowed(db: Session, *, user_id: str | None = None, site_id: str | None = None) -> bool:
    query = db.query(AccessRequest)
    if site_id:
        query = query.filter(AccessRequest.site_id == site_id)
    else:
        query = query.filter(
            AccessRequest.user_id == user_id,
            AccessRequest.site_id.is_(None),
            AccessRequest.contour == Contour.EMPLOYEES,
        )
    row = query.order_by(AccessRequest.created_at.desc()).first()
    if not row:
        return False
    return row.status == RequestStatus.ISSUED


def _require_released(db: Session, *, user_id: str | None = None, site_id: str | None = None) -> None:
    if not release_allowed(db, user_id=user_id, site_id=site_id):
        raise HTTPException(status_code=403, detail="Ключ закрыт до согласования заявки")


def _employee_device(user: User):
    return next((d for d in (user.devices or []) if d.peer and not d.site_id), None)


def _guard_self(user: User, actor: User) -> None:
    if user.id == actor.id:
        raise HTTPException(status_code=400, detail="Нельзя изменить собственную учётную запись")


@router.post("/users/{user_id}/block")
def block_user(user_id: str, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN))):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "Сотрудник не найден")
    _guard_self(user, actor)
    user.is_active = False
    user.blocked_by = actor.full_name or actor.email
    device = _employee_device(user)
    if device and device.peer:
        engine.disable_peer(db, device.peer, "Учётная запись заблокирована")
    else:
        db.commit()
    audit(db, actor_id=actor.id, actor_email=actor.email, action="user_block", target=user.email, ip=request.client.host if request.client else "")
    db.refresh(user)
    return _user_out(user)


@router.post("/users/{user_id}/unblock")
def unblock_user(user_id: str, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN))):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "Сотрудник не найден")
    user.is_active = True
    user.blocked_by = ""
    user.last_activity_at = datetime.utcnow()
    device = _employee_device(user)
    if device:
        device.last_seen_at = user.last_activity_at
    if device and device.block_reason in (APPROVAL_WAIT, APPROVAL_NO):
        raise HTTPException(status_code=409, detail="Ключ закрыт до согласования заявки")
    if device and device.peer and device.status == DeviceStatus.BLOCKED:
        device.block_reason = ""
        engine.enable_peer(db, device.peer)
    else:
        db.commit()
    audit(db, actor_id=actor.id, actor_email=actor.email, action="user_unblock", target=user.email, ip=request.client.host if request.client else "")
    db.refresh(user)
    return _user_out(user)


@router.post("/users/{user_id}/suspend")
def suspend_user(user_id: str, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF))):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "Сотрудник не найден")
    _guard_self(user, actor)
    if actor.role != Role.ADMIN and user.role != Role.USER:
        raise HTTPException(403, "Можно управлять VPN только сотрудников")
    if not user.is_active:
        raise HTTPException(status_code=409, detail="Сначала разблокируйте учётную запись")
    device = _employee_device(user)
    if not device or not device.peer:
        raise HTTPException(status_code=409, detail="У сотрудника нет профиля WireGuard")
    if device.block_reason in (APPROVAL_WAIT, APPROVAL_NO):
        raise HTTPException(status_code=409, detail="Сначала нужно согласование СБ")
    _require_released(db, user_id=user.id)
    if device.status != DeviceStatus.ACTIVE or not device.peer.enabled:
        raise HTTPException(409, "VPN уже отключён или заблокирован. Причина блокировки сохранена")
    engine.disable_peer(db, device.peer, "Работа приостановлена")
    audit(db, actor_id=actor.id, actor_email=actor.email, action="user_suspend", target=user.email, ip=request.client.host if request.client else "")
    db.refresh(user)
    return _user_out(user)


@router.post("/users/{user_id}/resume")
def resume_user(user_id: str, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN, Role.IT_LEAD))):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "Сотрудник не найден")
    if actor.role != Role.ADMIN and user.role != Role.USER:
        raise HTTPException(403, "Можно управлять VPN только сотрудников")
    if not user.is_active:
        raise HTTPException(status_code=409, detail="Учётная запись заблокирована — сначала разблокируйте")
    device = _employee_device(user)
    if not device or not device.peer:
        raise HTTPException(status_code=409, detail="У сотрудника нет профиля WireGuard")
    if device.block_reason in (APPROVAL_WAIT, APPROVAL_NO):
        raise HTTPException(status_code=409, detail="Сначала нужно согласование СБ")
    _require_released(db, user_id=user.id)
    if device.status != DeviceStatus.BLOCKED or device.block_reason != "Работа приостановлена":
        raise HTTPException(409, "Возобновить можно только вручную приостановленный VPN. Другие блокировки снимаются отдельно")
    if not device.access_until or device.access_until <= datetime.utcnow():
        raise HTTPException(409, "Срок VPN истёк. Сначала согласуйте продление доступа")
    engine.enable_peer(db, device.peer)
    audit(db, actor_id=actor.id, actor_email=actor.email, action="user_resume", target=user.email, ip=request.client.host if request.client else "")
    db.refresh(user)
    return _user_out(user)


from ..models import AccessPolicy, Network, Device
from ..employee_networks import selectable, selected_networks, auto_site_access, automatic_site_lans
import hashlib
import logging


class EmployeeVpnSettings(BaseModel):
    accessUntil: str
    networkIds: list[str] = Field(max_length=256)
    version: str


def _vpn_settings_target(db, user_id, actor):
    user = db.query(User).filter(User.id == user_id).with_for_update().first()
    if not user:
        raise HTTPException(404, "Сотрудник не найден")
    if user.role != Role.USER:
        raise HTTPException(403, "Эта форма предназначена только для VPN сотрудников")
    if not user.is_active:
        raise HTTPException(409, "Учётная запись заблокирована")
    _require_released(db, user_id=user.id)
    device = _employee_device(user)
    if not device or device.contour != Contour.EMPLOYEES:
        raise HTTPException(409, "У сотрудника нет VPN-профиля")
    device = db.query(Device).filter(Device.id == device.id).with_for_update().populate_existing().one()
    if device.status != DeviceStatus.ACTIVE and not (device.status == DeviceStatus.BLOCKED and device.block_reason == "Работа приостановлена"):
        raise HTTPException(409, "VPN заблокирован. Сначала устраните причину блокировки")
    return user, device, device.peer


def _vpn_settings_out(db, device, peer):
    networks = [n for n in db.query(Network).filter(Network.contour == Contour.EMPLOYEES) if selectable(n)]
    selected = set((peer.destination_cidrs or "").split(","))
    expiry = device.access_until.isoformat() + "Z" if device.access_until else None
    version = hashlib.sha256(repr((expiry, peer.destination_cidrs, device.status.value, peer.enabled)).encode()).hexdigest()
    automatic = ["192.168.3.0/24", *automatic_site_lans(db)] if auto_site_access(db) else []
    return {"accessUntil": expiry, "version": version,
            "networkIds": [n.id for n in networks if n.cidr in selected],
            "networks": [{"id": n.id, "name": n.name, "cidr": n.cidr} for n in networks],
            "automaticNetworks": list(dict.fromkeys(automatic))}


@router.get("/users/{user_id}/vpn-settings")
def employee_vpn_settings(user_id: str, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN, Role.IT_LEAD))):
    _, device, peer = _vpn_settings_target(db, user_id, actor)
    return {**_vpn_settings_out(db, device, peer), **_employee_memo_state(db, user_id)}


def _employee_memo_state(db, user_id):
    row = db.query(AccessRequest).filter_by(user_id=user_id, site_id=None, status=RequestStatus.ISSUED).order_by(AccessRequest.created_at.desc()).first()
    if not row:
        raise HTTPException(409, "Нет согласованной заявки сотрудника")
    docs = sorted((d for d in row.documents if d.kind == "MEMO"), key=lambda d: d.id)
    return {"memoVersion": hashlib.sha256(repr((row.id, [d.id for d in docs])).encode()).hexdigest(),
            "documents": [{"id": d.id, "filename": d.filename, "title": d.title} for d in docs]}


@router.post("/users/{user_id}/memo")
def replace_employee_memo(user_id: str, request: Request, file: UploadFile = File(...), version: str = Form(...),
                          db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN, Role.IT_LEAD))):
    user, _, _ = _vpn_settings_target(db, user_id, actor)
    state = _employee_memo_state(db, user_id)
    if version != state["memoVersion"]:
        raise HTTPException(409, "Записка уже изменена. Откройте форму заново")
    name, raw = _pdf_blobs([file])[0]
    row = db.query(AccessRequest).filter_by(user_id=user_id, site_id=None, status=RequestStatus.ISSUED).order_by(AccessRequest.created_at.desc()).first()
    path = settings.uploads_dir / (secrets.token_hex(24) + ".pdf")
    old_ids = [d["id"] for d in state["documents"]]
    created = False
    try:
        settings.uploads_dir.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as output:
            created = True
            output.write(raw)
        for doc in row.documents:
            if doc.kind == "MEMO":
                doc.kind = "MEMO_ARCHIVE"
        doc = Document(request_id=row.id, title="Служебная записка", kind="MEMO", filename=name,
                       content_type="application/pdf", path=str(path), uploaded_by=actor.email)
        db.add(doc)
        db.flush()
        audit(db, actor_id=actor.id, actor_email=actor.email, action="employee_memo_replace", target=user.email,
              ip=request.client.host if request.client else "", payload={"previousDocumentIds": old_ids, "documentId": doc.id})
    except Exception:
        db.rollback()
        if created:
            path.unlink(missing_ok=True)
        raise HTTPException(503, "Не удалось сохранить записку. Прежний документ сохранён")
    db.expire(row, ["documents"])
    return _employee_memo_state(db, user_id)


@router.patch("/users/{user_id}/vpn-settings")
def edit_employee_vpn(user_id: str, payload: EmployeeVpnSettings, request: Request,
                      db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN, Role.IT_LEAD))):
    from ..nft import apply_acl
    from ..provision import render_stored_config
    user, device, peer = _vpn_settings_target(db, user_id, actor)
    before = _vpn_settings_out(db, device, peer)
    if payload.version != before["version"]:
        raise HTTPException(409, "VPN уже изменён. Закройте форму и откройте её заново")
    if db.query(VpnRenewal).filter_by(device_id=device.id, status="PENDING").first():
        raise HTTPException(409, "Сначала согласуйте или отклоните ожидающее продление VPN")
    expiry = future_access_until(payload.accessUntil)
    if device.access_until is not None and expiry > device.access_until:
        raise HTTPException(409, "Для увеличения срока VPN подайте заявку на продление в разделе «Согласование»")
    networks = selected_networks(db, payload.networkIds) if payload.networkIds or not auto_site_access(db) else []
    try:
        device.access_until = expiry
        peer.destination_cidrs = ",".join(dict.fromkeys(n.cidr for n in networks))
        db.query(AccessPolicy).filter(AccessPolicy.device_id_fk == device.id, AccessPolicy.network_id.isnot(None), AccessPolicy.resource_id.is_(None)).delete(synchronize_session=False)
        for network in networks:
            db.add(AccessPolicy(device_id_fk=device.id, network_id=network.id, allowed=True))
        issued = db.query(AccessRequest).filter_by(user_id=user.id, contour=Contour.EMPLOYEES, site_id=None, status=RequestStatus.ISSUED).order_by(AccessRequest.created_at.desc()).first()
        issued.networks_json = [n.id for n in networks]
        issued.access_until = expiry
        db.flush()
        render_stored_config(db, peer)
        apply_acl(db)
        audit(db, actor_id=actor.id, actor_email=actor.email, action="employee_vpn_edit", target=user.email,
              ip=request.client.host if request.client else "", payload={"before": {"accessUntil": before["accessUntil"], "networkIds": before["networkIds"]},
              "after": {"accessUntil": payload.accessUntil, "networkIds": [n.id for n in networks]}})
    except Exception:
        db.rollback()
        try:
            apply_acl(db)
        except Exception:
            logging.getLogger(__name__).exception("Failed to restore employee VPN ACL")
        raise HTTPException(503, "Не удалось применить настройки VPN. Изменения отменены; повторите попытку или проверьте журнал сервера")
    return _vpn_settings_out(db, device, peer)


@router.patch("/users/{user_id}")
def update_user(user_id: str, payload: UserPatch, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN))):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "Учётная запись не найдена")
    if payload.isManagement is not None:
        user.is_management = payload.isManagement
    if payload.rdpHost is not None: user.rdp_host = payload.rdpHost.strip()
    if payload.rdpPort is not None: user.rdp_port = payload.rdpPort
    if payload.rdpUser is not None: user.rdp_user = payload.rdpUser.strip()
    if payload.rdpPassword is not None: user.rdp_password = payload.rdpPassword
    if payload.rdpSavePassword is not None: user.rdp_save_password = payload.rdpSavePassword
    if payload.fullName is not None:
        name = payload.fullName.strip()
        if not name:
            raise HTTPException(status_code=422, detail="Укажите ФИО")
        user.full_name = name
    if payload.email is not None:
        login = payload.email.strip().lower()
        if not login:
            raise HTTPException(status_code=422, detail="Укажите логин")
        taken = db.query(User).filter(User.email == login, User.id != user.id).one_or_none()
        if taken:
            raise HTTPException(status_code=409, detail="Такой логин уже есть")
        user.email = login
    password = (payload.password or "").strip()
    if password:
        if len(password) < 8:
            raise HTTPException(status_code=422, detail="Пароль должен быть не короче 8 символов")
        user.password_hash = hash_password(password)
    if payload.role is not None:
        try:
            role = Role(payload.role)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="Неизвестная роль") from exc
        if role in (Role.SECURITY, Role.AUDITOR):
            raise HTTPException(status_code=422, detail="Эта роль больше не используется")
        if user.role == Role.ADMIN and role != Role.ADMIN:
            admins = db.query(User).filter(User.role == Role.ADMIN, User.id != user.id).count()
            if admins < 1:
                raise HTTPException(status_code=409, detail="Нельзя снять роль с последнего администратора")
        user.role = role
    db.commit()
    db.refresh(user)
    audit(db, actor_id=actor.id, actor_email=actor.email, action="user_update", target=user.email, ip=request.client.host if request.client else "")
    return _user_out(user)


def _staff_for_totp(db: Session, user_id: str) -> User:
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "Учётная запись не найдена")
    if user.role not in STAFF_ROLES:
        raise HTTPException(status_code=422, detail="2ФА доступна только учётным записям управления")
    return user


@router.post("/users/{user_id}/totp")
def bind_totp(user_id: str, payload: TotpBindIn, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN))):
    user = _staff_for_totp(db, user_id)
    if user.totp_confirmed and not payload.reset:
        return {"confirmed": True, "qr": "", "secret": ""}
    if payload.reset or not user.totp_secret:
        user.totp_secret = pyotp.random_base32()
        user.totp_confirmed = False
        db.commit()
    uri = pyotp.TOTP(user.totp_secret).provisioning_uri(name=user.email, issuer_name="FORTIS")
    audit(db, actor_id=actor.id, actor_email=actor.email, action="totp_bind", target=user.email, ip=request.client.host if request.client else "")
    return {"confirmed": False, "qr": _qr(uri), "secret": user.totp_secret}


@router.post("/users/{user_id}/totp/confirm")
def confirm_totp_bind(user_id: str, payload: TotpCodeIn, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN))):
    user = _staff_for_totp(db, user_id)
    if not user.totp_secret:
        raise HTTPException(status_code=409, detail="Сначала откройте код для приложения")
    code = "".join(ch for ch in payload.code if ch.isdigit())
    if not pyotp.TOTP(user.totp_secret).verify(code, valid_window=1):
        raise HTTPException(status_code=401, detail="Неверный код")
    user.totp_confirmed = True
    db.commit()
    audit(db, actor_id=actor.id, actor_email=actor.email, action="totp_confirmed", target=user.email, ip=request.client.host if request.client else "")
    return _user_out(user)


@router.delete("/users/{user_id}")
def delete_user(user_id: str, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN, Role.IT_LEAD))):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "Сотрудник не найден")
    if user.id == actor.id:
        raise HTTPException(status_code=400, detail="Нельзя удалить собственную учётную запись")
    if actor.role != Role.ADMIN and user.role != Role.USER:
        raise HTTPException(403, "Можно удалять только сотрудников, не учётные записи панели")
    if user.role == Role.ADMIN:
        admins = db.query(User).filter(User.role == Role.ADMIN).count()
        if admins <= 1:
            raise HTTPException(status_code=409, detail="Нельзя удалить последнего администратора")
    target = user.email
    engine.purge_user(db, user)
    db.commit()
    audit(db, actor_id=actor.id, actor_email=actor.email, action="user_delete", target=target, ip=request.client.host if request.client else "")
    return {"ok": True}


@router.get("/companies")
def companies(db: Session = Depends(get_db), _=Depends(current_user)):
    return [{"id": c.id, "name": c.name} for c in db.query(Company).order_by(Company.name)]


@router.get("/departments")
def departments(db: Session = Depends(get_db), _=Depends(current_user)):
    return [
        {"id": d.id, "name": d.name, "companyId": d.company_id}
        for d in db.query(Department).order_by(Department.name)
    ]
