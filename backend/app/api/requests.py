from datetime import datetime, timezone
from pathlib import Path
import re
import secrets
import logging

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from sqlalchemy.orm import Session, object_session

from ..audit import audit
from ..access_term import future_access_until
from ..config import settings
from ..db import get_db
from ..models import AccessRequest, Contour, Device, DeviceStatus, Document, RequestStatus, Role, Site, User
from .users import APPROVAL_WAIT
from .. import engine, wireguard
from ..schemas import RequestIn
from ..provision import ensure_peer_for_site, ensure_peer_for_user
from ..security import current_user, require_roles
from ..models import VpnRenewal, AuditLog, WireGuardPeer
from .users import release_allowed

router = APIRouter(tags=["requests"])


@router.post("/users/{user_id}/renewal", status_code=201)
def request_renewal(user_id: str, request: Request, accessUntil: str = Form(...), db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF))):
    until = future_access_until(accessUntil)
    user = db.get(User, user_id)
    if not user or user.role != Role.USER or not user.is_active:
        raise HTTPException(409, "Продление доступно только действующей учётной записи сотрудника")
    device = db.query(Device).filter(Device.user_id == user_id, Device.site_id.is_(None)).with_for_update().first()
    if not device or not device.peer or not release_allowed(db, user_id=user_id):
        raise HTTPException(409, "Сначала требуется выданный VPN-доступ")
    if device.access_until and until <= device.access_until:
        raise HTTPException(422, "Новый срок должен быть позже текущего")
    if db.query(VpnRenewal).filter(VpnRenewal.device_id == device.id, VpnRenewal.status == "PENDING").first():
        raise HTTPException(409, "Заявка на продление уже ожидает согласования")
    row = VpnRenewal(user_id=user_id, device_id=device.id, previous_until=device.access_until, requested_until=until, created_by=actor.email)
    db.add(row)
    db.commit()
    audit(db, actor_id=actor.id, actor_email=actor.email, action="vpn_renewal_requested", target=user.email, ip=request.client.host if request.client else "")
    return {"id": row.id, "status": row.status}


@router.post("/renewals/{renewal_id}/{decision}")
def decide_renewal(renewal_id: str, decision: str, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN, Role.IT_LEAD))):
    if decision not in ("approve", "reject"):
        raise HTTPException(404, "Неизвестное действие")
    row = db.query(VpnRenewal).filter(VpnRenewal.id == renewal_id).with_for_update().first()
    if not row:
        raise HTTPException(404, "Заявка не найдена")
    if row.status != "PENDING":
        raise HTTPException(409, "Заявка уже обработана")
    restore_peer = None
    acl_touched = False
    peer_touched = False
    if decision == "approve":
        until = future_access_until(row.requested_until, stored=True)
        user = db.get(User, row.user_id)
        device = db.query(Device).filter(Device.id == row.device_id).with_for_update().first()
        if not user or not user.is_active or not device or not device.peer or not release_allowed(db, user_id=row.user_id):
            raise HTTPException(409, "VPN-доступ больше недоступен для продления")
        if device.access_until != row.previous_until:
            raise HTTPException(409, "Срок изменился. Отклоните заявку и подайте новую")
        if device.block_reason == engine.KEY_LOCK:
            raise HTTPException(409, "Сначала требуется разбор инцидента блокировки ключа")
        peer = db.query(WireGuardPeer).filter_by(device_id_fk=device.id).with_for_update().one()
        device.access_until = until
        # Do not re-enable administratively suspended keys or bypass agent verification.
        if device.status == DeviceStatus.EXPIRED and device.block_reason == "Срок доступа истёк":
            device.status = DeviceStatus.PENDING
            device.block_reason = ""
            if not device.require_agent and device.peer:
                # Do not use enable_peer here: it commits before applying ACL.
                restore_peer = (peer.contour, peer.public_key, peer.preshared_key,
                                ", ".join([f"{peer.vpn_ip}/32"] + [p.strip() for p in (peer.allowed_lans or '').split(',') if p.strip()]))
                peer.enabled = True
                peer.endpoint_trace = "[]"
                device.status = DeviceStatus.ACTIVE
        row.status = "APPROVED"
    else:
        row.status = "REJECTED"
    row.reviewed_by = actor.email
    row.reviewed_at = datetime.utcnow()
    try:
        db.add(AuditLog(actor_id=actor.id, actor_email=actor.email,
                        action="vpn_renewal_" + decision, target=row.user_id,
                        ip=request.client.host if request.client else ""))
        db.flush()
        if restore_peer:
            # Apply policy before opening the peer; commit the decision and term together.
            acl_touched = True
            engine.apply_acl(db)
            peer_touched = True
            wireguard.set_peer(*restore_peer)
        db.commit()
    except Exception:
        db.rollback()
        recovery_failed = False
        if peer_touched:
            try:
                wireguard.remove_peer(restore_peer[0], restore_peer[1])
            except Exception:
                recovery_failed = True
                logging.getLogger(__name__).critical("Renewal rollback could not remove peer; operator intervention required")
        if acl_touched:
            try:
                engine.apply_acl(db)
            except Exception:
                recovery_failed = True
                logging.getLogger(__name__).critical("Renewal rollback could not restore ACL; operator intervention required")
        detail = "Не удалось применить продление. Срок не изменён, заявка ожидает согласования."
        if recovery_failed:
            detail += " Не удалось полностью восстановить сетевые правила; требуется проверка администратором."
        raise HTTPException(503, detail) from None
    return {"id": row.id, "status": row.status}


_PDF_LIMIT = 15 * 1024 * 1024


def _memo_blob(upload: UploadFile) -> tuple[str, bytes]:
    name = Path(upload.filename or "").name
    raw = upload.file.read(_PDF_LIMIT + 1)
    if not name.lower().endswith(".pdf") or not raw.startswith(b"%PDF"):
        raise HTTPException(status_code=422, detail="Служебная записка должна быть файлом PDF")
    if len(raw) > _PDF_LIMIT:
        raise HTTPException(status_code=422, detail="PDF больше 15 МБ")
    return name, raw


def _store_memo(db: Session, row: AccessRequest, upload: UploadFile, actor_email: str) -> Document:
    name, raw = _memo_blob(upload)
    settings.uploads_dir.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^0-9A-Za-z._-]+", "_", name)[:80] or "memo.pdf"
    dest = settings.uploads_dir / f"{row.id}_memo_{safe}"
    dest.write_bytes(raw)
    doc = Document(
        request_id=row.id,
        title="Служебная записка",
        kind="MEMO",
        filename=name,
        content_type="application/pdf",
        path=str(dest),
        uploaded_by=actor_email,
    )
    db.add(doc)
    return doc


def _has_memo(row: AccessRequest) -> bool:
    return any(doc.kind == "MEMO" and Path(doc.path).is_file() for doc in row.documents)


def _issue_row(db: Session, row: AccessRequest, actor_email: str) -> None:
    if row.resources_json:
        raise HTTPException(409, "Ресурсные доступы временно отключены; заявка не может быть выдана")
    if not row.site_id and row.user and not row.user.is_active:
        raise HTTPException(409, "Учётная запись заблокирована. Сначала разблокируйте пользователя")
    devices = row.site.devices if row.site_id and row.site else (row.user.devices if row.user else [])
    existing = next((d for d in devices if d.peer and (row.site_id or not d.site_id)), None)
    if existing:
        existing = db.query(Device).filter(Device.id == existing.id).with_for_update().populate_existing().one()
    if existing and existing.status == DeviceStatus.REVOKED:
        raise HTTPException(409, "Ключ отозван. Требуется новый VPN-профиль; повторная выдача старого запрещена")
    if existing and (
        (existing.status == DeviceStatus.BLOCKED and existing.block_reason != APPROVAL_WAIT)
        or existing.block_reason in (engine.KEY_LOCK, engine.BLOCK_STATUS)
        or (existing.block_reason or "").startswith("Инцидент ")
    ):
        raise HTTPException(409, "VPN заблокирован или приостановлен. Сначала устраните причину блокировки; согласование заявки её не снимает")
    access_from = row.access_from
    if access_from and access_from.tzinfo is not None:
        access_from = access_from.astimezone(timezone.utc).replace(tzinfo=None)
    if access_from and access_from > datetime.utcnow():
        raise HTTPException(409, "Срок доступа ещё не начался. Повторите выдачу после даты начала")
    from ..employee_networks import selected_networks
    chosen = selected_networks(db, row.networks_json) if not row.site_id and row.networks_json else None
    if not row.site_id or row.access_until is not None:
        row.access_until = future_access_until(row.access_until, stored=True)
    if row.site_id:
        site = db.get(Site, row.site_id)
        if not site:
            raise HTTPException(404, "Объект не найден")
        from ..site_validation import site_lan
        site_lan(site.lan_cidr)
        vpn = ensure_peer_for_site(db, site, actor_email, access_until=row.access_until)
    else:
        if not row.user:
            raise HTTPException(404, "Пользователь не найден")
        existing = next((d for d in row.user.devices if d.peer and not d.site_id), None)
        if existing and (existing.peer.client_config or existing.peer.private_key):
            vpn = {"deviceId": existing.id}
        else:
            vpn = ensure_peer_for_user(db, row.user, actor_email, device_name=row.device_name, access_until=row.access_until)
    device = db.get(Device, vpn["deviceId"])
    if not device or not device.peer:
        raise HTTPException(503, "Не удалось сформировать VPN-профиль")
    if chosen is not None:
        from ..models import AccessPolicy
        from ..provision import render_stored_config
        db.query(AccessPolicy).filter(AccessPolicy.device_id_fk == device.id).delete(synchronize_session=False)
        for net in chosen:
            db.add(AccessPolicy(device_id_fk=device.id, network_id=net.id, allowed=True))
        device.peer.destination_cidrs = ','.join(n.cidr for n in chosen)
        render_stored_config(db, device.peer)
    # Standard WireGuard clients and routers do not run the KONTUR agent.
    # Install only in this authorized issuance path, never while downloading a file.
    device.peer.link_up = False
    device.status = DeviceStatus.ACTIVE
    device.block_reason = ""
    device.require_agent = False
    device.enrolled_at = datetime.utcnow()
    device.access_from = access_from
    device.access_until = row.access_until
    row.issued_device_id = device.id
    row.enrollment_token = None
    row.status = RequestStatus.ISSUED
    allowed = [f"{device.peer.vpn_ip}/32"]
    if device.peer.allowed_lans:
        allowed.extend(p.strip() for p in device.peer.allowed_lans.split(',') if p.strip())
    runtime_touched = False
    try:
        from ..peer_publication import lock_peer_publication
        device.peer.enabled = True
        db.flush()
        lock_peer_publication(db, device.peer.contour, device.peer.public_key)
        runtime_touched = True
        wireguard.set_peer(device.peer.contour, device.peer.public_key, device.peer.preshared_key, ', '.join(allowed))
        engine.apply_acl(db)
    except Exception as exc:
        if runtime_touched:
            wireguard.remove_peer(device.peer.contour, device.peer.public_key)
        db.rollback()
        raise HTTPException(503, "Не удалось включить VPN. Выдача не завершена") from exc


def _out(r: AccessRequest) -> dict:
    db = object_session(r)
    reviewer = db.query(User).filter(User.email == r.reviewed_by).one_or_none() if db and r.reviewed_by else None
    return {
        "id": r.id,
        "userId": r.user_id,
        "userName": r.user.full_name if r.user else "",
        "email": r.user.email if r.user else "",
        "company": r.user.company.name if r.user and r.user.company else "",
        "department": r.user.department.name if r.user and r.user.department else "",
        "title": r.user.title if r.user else "",
        "deviceName": r.device_name,
        "contour": r.contour.value,
        "siteId": r.site_id,
        "siteName": r.site.name if r.site else "",
        "subjectName": r.site.name if r.site else (r.user.full_name if r.user else ""),
        "subjectKind": "SITE" if r.site_id else "EMPLOYEE",
        "reason": r.reason,
        "memo": r.memo,
        "status": r.status.value,
        "accessFrom": r.access_from.isoformat() if r.access_from else None,
        "accessUntil": r.access_until.isoformat() if r.access_until else None,
        "enrollmentToken": r.enrollment_token if r.status == RequestStatus.ISSUED else None,
        "createdBy": r.created_by,
        "reviewedBy": r.reviewed_by,
        "reviewedByName": reviewer.full_name if reviewer else "",
        "createdAt": r.created_at.isoformat() if r.created_at else None,
        "documents": [
            {"id": d.id, "title": d.title, "kind": d.kind, "filename": d.filename, "createdAt": d.created_at.isoformat()}
            for d in r.documents
        ],
    }


@router.get("/requests")
def list_requests(db: Session = Depends(get_db), _=Depends(require_roles(Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF))):
    rows = db.query(AccessRequest).order_by(AccessRequest.created_at.desc()).all()
    return {"data": [_out(r) for r in rows]}


@router.post("/requests/employee", status_code=201)
def create_employee_request(
    request: Request,
    userId: str = Form(...),
    deviceName: str = Form(""),
    reason: str = Form("VPN-доступ сотрудника"),
    accessUntil: str = Form(...),
    file: UploadFile = File(...),
    networkIds: str = Form(...),
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles(Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF)),
):
    from ..employee_networks import selected_networks
    networks = selected_networks(db, networkIds)
    access_until = future_access_until(accessUntil)
    user = db.get(User, userId)
    if not user:
        raise HTTPException(404, "Пользователь не найден")
    duplicate = (
        db.query(AccessRequest)
        .filter(
            AccessRequest.user_id == user.id,
            AccessRequest.site_id.is_(None),
            AccessRequest.status.in_((RequestStatus.PENDING_APPROVAL, RequestStatus.APPROVED_SB)),
        )
        .first()
    )
    if duplicate:
        raise HTTPException(409, "Для пользователя уже есть заявка на согласовании")
    row = AccessRequest(
        user_id=user.id,
        device_name="Определится при подключении",
        contour=Contour.EMPLOYEES,
        reason=reason.strip() or "VPN-доступ сотрудника",
        networks_json=[n.id for n in networks],
        access_until=access_until,
        memo="Служебная записка",
        status=RequestStatus.PENDING_APPROVAL,
        created_by=actor.email,
    )
    db.add(row)
    db.flush()
    _store_memo(db, row, file, actor.email)
    db.commit()
    db.refresh(row)
    audit(db, actor_id=actor.id, actor_email=actor.email, action="request_create", target=row.id, ip=request.client.host if request.client else "")
    return _out(row)


@router.post("/requests", status_code=201)
def create_request(payload: RequestIn, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF))):
    access_until = future_access_until(payload.accessUntil) if not payload.siteId else payload.accessUntil
    user = db.get(User, payload.userId)
    if not user:
        raise HTTPException(404, "Пользователь не найден")
    row = AccessRequest(
        user_id=user.id,
        device_name=payload.deviceName,
        contour=Contour(payload.contour),
        site_id=payload.siteId,
        reason=payload.reason,
        memo=payload.memo,
        status=RequestStatus.PENDING_APPROVAL,
        access_from=payload.accessFrom,
        access_until=access_until,
        created_by=actor.email,
    )
    if not payload.siteId:
        from ..employee_networks import selected_networks
        row.networks_json = [n.id for n in selected_networks(db, payload.networkIds)]
    else:
        row.networks_json = payload.networkIds
    if payload.resourceIds:
        raise HTTPException(422, "Ресурсные доступы временно отключены до реализации ACL по протоколу и порту")
    row.resources_json = []
    db.add(row)
    db.commit()
    db.refresh(row)
    audit(db, actor_id=actor.id, actor_email=actor.email, action="request_create", target=row.id, ip=request.client.host if request.client else "")
    return _out(row)


@router.post("/requests/{request_id}/approve")
def approve(request_id: str, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN, Role.IT_LEAD))):
    row = db.query(AccessRequest).filter(AccessRequest.id == request_id).with_for_update().first()
    if not row:
        raise HTTPException(404, "Заявка не найдена")
    if row.resources_json:
        raise HTTPException(409, "Ресурсные доступы временно отключены; создайте заявку только с явно разрешёнными сетями")
    if row.status != RequestStatus.PENDING_APPROVAL:
        raise HTTPException(409, "Заявка уже обработана")
    if not row.site_id and not _has_memo(row):
        raise HTTPException(422, "Для сотрудника обязательна служебная записка PDF")
    if row.site_id:
        from ..site_validation import site_lan
        site = db.get(Site, row.site_id)
        if not site:
            raise HTTPException(404, 'Объект не найден')
        site_lan(site.lan_cidr)
    row.status = RequestStatus.APPROVED_SB
    row.reviewed_by = actor.email
    _issue_row(db, row, actor.email)
    db.commit()
    audit(db, actor_id=actor.id, actor_email=actor.email, action="request_approve_and_issue", target=row.id, ip=request.client.host if request.client else "")
    return _out(row)


@router.post("/requests/{request_id}/reject")
def reject(request_id: str, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN, Role.IT_LEAD))):
    row = db.query(AccessRequest).filter(AccessRequest.id == request_id).with_for_update().first()
    if not row:
        raise HTTPException(404, "Заявка не найдена")
    if row.status != RequestStatus.PENDING_APPROVAL:
        raise HTTPException(409, "Заявка уже обработана")
    row.status = RequestStatus.REJECTED
    row.reviewed_by = actor.email
    # A pending request has not granted access. Rejecting it must not revoke
    # the subject's existing VPN granted by a different, issued request.
    db.commit()
    audit(db, actor_id=actor.id, actor_email=actor.email, action="request_reject", target=row.id, ip=request.client.host if request.client else "")
    return _out(row)


@router.post("/requests/{request_id}/issue")
def issue(request_id: str, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF))):
    row = db.query(AccessRequest).filter(AccessRequest.id == request_id).with_for_update().first()
    if not row:
        raise HTTPException(404, "Заявка не найдена")
    if row.status != RequestStatus.APPROVED_SB:
        raise HTTPException(409, "Сначала требуется согласование СБ")
    _issue_row(db, row, actor.email)
    db.commit()
    audit(db, actor_id=actor.id, actor_email=actor.email, action="access_issue", target=row.id, ip=request.client.host if request.client else "")
    return _out(row)


@router.post("/requests/{request_id}/documents")
async def upload_doc(
    request_id: str,
    request: Request,
    title: str = Form(...),
    kind: str = Form("OTHER"),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles(Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF)),
):
    row = db.get(AccessRequest, request_id)
    if not row:
        raise HTTPException(404, "Заявка не найдена")
    if row.status != RequestStatus.PENDING_APPROVAL:
        raise HTTPException(409, "Документы обработанной заявки изменять нельзя")
    name, raw = _memo_blob(file)
    settings.uploads_dir.mkdir(parents=True, exist_ok=True)
    dest = settings.uploads_dir / f"{row.id}_{secrets.token_hex(16)}.pdf"
    dest.write_bytes(raw)
    dest.chmod(0o600)
    doc = Document(
        request_id=row.id,
        title=title,
        kind=kind,
        filename=name,
        content_type="application/pdf",
        path=str(dest),
        uploaded_by=actor.email,
    )
    db.add(doc)
    db.commit()
    audit(db, actor_id=actor.id, actor_email=actor.email, action="document_upload", target=row.id, ip=request.client.host if request.client else "")
    return _out(row)
