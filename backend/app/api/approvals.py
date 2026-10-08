"""Read-only approval view over existing requests and renewals; no shadow registry."""
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import false, func, literal, or_, select, union_all
from sqlalchemy.orm import Session, selectinload

from ..db import get_db
from ..models import AccessPolicy, AccessRequest, Device, Network, RequestStatus, Role, Site, User, VpnRenewal
from ..security import require_roles

router = APIRouter(tags=["approvals"])
ApprovalStatus = Literal["pending", "approved"]
ApprovalKind = Literal["all", "employee", "site", "renewal"]


class ApprovalNetwork(BaseModel):
    name: str
    cidr: str


class ApprovalDocument(BaseModel):
    id: str
    title: str
    kind: str
    filename: str
    createdAt: str | None


class ApprovalRow(BaseModel):
    id: str
    sourceType: Literal["request", "renewal"]
    sourceId: str
    subjectKind: Literal["EMPLOYEE", "SITE"]
    userId: str
    siteId: str | None
    subjectName: str
    userName: str
    siteName: str
    siteLanCidr: str = ""
    email: str
    company: str
    department: str
    title: str
    deviceName: str
    contour: str
    status: str
    reason: str
    memo: str
    accessFrom: str | None
    accessUntil: str | None
    currentAccessUntil: str | None
    createdBy: str
    reviewedBy: str
    reviewedByName: str
    createdAt: str | None
    documents: list[ApprovalDocument] = Field(default_factory=list)
    networks: list[ApprovalNetwork] = Field(default_factory=list)


class ApprovalPage(BaseModel):
    data: list[ApprovalRow]
    total: int
    page: int
    pageSize: int


class ApprovalSummary(BaseModel):
    pending: int
    pendingIds: list[str]


def _candidates(status: ApprovalStatus, kind: ApprovalKind, excluded=()):
    missing_ad_user = select(Device.id).where(
        Device.user_id == User.id, Device.site_id.is_(None),
        Device.block_reason == "Нет в папке Active Directory").exists()
    request_statuses = [RequestStatus.PENDING_APPROVAL] if status == "pending" else [RequestStatus.ISSUED, RequestStatus.APPROVED_SB]
    requests = select(literal("request").label("source_type"), AccessRequest.id.label("source_id"),
                      AccessRequest.created_at.label("created_at")).join(User, User.id == AccessRequest.user_id).where(
                          AccessRequest.status.in_(request_statuses),
                          or_(AccessRequest.site_id.isnot(None), ~missing_ad_user),
                          or_(AccessRequest.site_id.is_(None), select(Site.id).where(Site.id == AccessRequest.site_id).exists()))
    if kind == "employee":
        requests = requests.where(AccessRequest.site_id.is_(None))
    elif kind == "site":
        requests = requests.where(AccessRequest.site_id.isnot(None))
    elif kind == "renewal":
        requests = requests.where(false())
    renewals = select(literal("renewal").label("source_type"), VpnRenewal.id.label("source_id"),
                     VpnRenewal.created_at.label("created_at")).join(User, User.id == VpnRenewal.user_id).join(
                         Device, Device.id == VpnRenewal.device_id).where(
                             VpnRenewal.status == ("PENDING" if status == "pending" else "APPROVED"),
                             or_(Device.site_id.isnot(None), Device.block_reason != "Нет в папке Active Directory"))
    if kind not in ("all", "renewal"):
        renewals = renewals.where(false())
    requests = requests.where(or_(AccessRequest.site_id.isnot(None), User.id.notin_(excluded)))
    renewals = renewals.where(or_(Device.site_id.isnot(None), User.id.notin_(excluded)))
    return union_all(requests, renewals).subquery()


def _ordering(candidates):
    # A stable tie-break prevents equal creation times from moving between pages.
    return (candidates.c.created_at.desc(), candidates.c.source_type.desc(), candidates.c.source_id.desc())


def _ordered(candidates):
    return select(candidates).order_by(*_ordering(candidates))


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _details(db: Session, selected) -> list[dict]:
    request_ids = [row.source_id for row in selected if row.source_type == "request"]
    renewal_ids = [row.source_id for row in selected if row.source_type == "renewal"]
    requests = {row.id: row for row in db.query(AccessRequest).filter(AccessRequest.id.in_(request_ids)).options(
        selectinload(AccessRequest.documents), selectinload(AccessRequest.site).selectinload(Site.company))} if request_ids else {}
    renewals = {row.id: row for row in db.query(VpnRenewal).filter(VpnRenewal.id.in_(renewal_ids))} if renewal_ids else {}
    rows = [*requests.values(), *renewals.values()]
    user_ids = {row.user_id for row in rows}
    reviewers = {row.reviewed_by for row in rows if row.reviewed_by}
    users = list(db.query(User).filter(or_(User.id.in_(user_ids), User.email.in_(reviewers))).options(
        selectinload(User.company), selectinload(User.department))) if rows else []
    users_by_id = {user.id: user for user in users}
    reviewer_names = {user.email: user.full_name for user in users}
    site_ids = {row.site_id for row in requests.values() if row.site_id}
    device_ids = {row.device_id for row in renewals.values()} | {row.issued_device_id for row in requests.values() if row.issued_device_id}
    devices = list(db.query(Device).filter(or_(Device.id.in_(device_ids), Device.user_id.in_(user_ids), Device.site_id.in_(site_ids)))
                   .order_by(Device.created_at.desc(), Device.id.desc())) if rows else []
    devices_by_id = {device.id: device for device in devices}
    current_by_subject = {}
    for device in devices:
        key = ("site", device.site_id) if device.site_id else ("user", device.user_id)
        current_by_subject.setdefault(key, device)

    renewal_network_ids = {}
    if renewal_ids:
        for policy in db.query(AccessPolicy).filter(AccessPolicy.device_id_fk.in_({r.device_id for r in renewals.values()}),
                                                    AccessPolicy.allowed.is_(True), AccessPolicy.network_id.isnot(None)):
            renewal_network_ids.setdefault(policy.device_id_fk, []).append(policy.network_id)
    network_ids = {network_id for row in requests.values() for network_id in (row.networks_json or [])}
    network_ids.update(network_id for values in renewal_network_ids.values() for network_id in values)
    networks = {network.id: network for network in db.query(Network).filter(Network.id.in_(network_ids))} if network_ids else {}

    result = []
    for selection in selected:
        initial = selection.source_type == "request"
        row = requests.get(selection.source_id) if initial else renewals.get(selection.source_id)
        if row is None:  # A concurrent deletion must not break the rest of the page.
            continue
        user = users_by_id.get(row.user_id)
        site = row.site if initial else None
        site_id = row.site_id if initial else None
        device = (devices_by_id.get(row.issued_device_id) or current_by_subject.get(("site", site_id) if site_id else ("user", row.user_id))) if initial else devices_by_id.get(row.device_id)
        chosen_ids = (row.networks_json or []) if initial else renewal_network_ids.get(row.device_id, [])
        company = site.company if site else (user.company if user and not site_id else None)
        result.append({
            "id": row.id, "sourceType": selection.source_type, "sourceId": row.id,
            "subjectKind": "SITE" if site_id else "EMPLOYEE", "userId": row.user_id, "siteId": site_id,
            "subjectName": site.name if site else (user.full_name if user and not site_id else ""),
            "userName": user.full_name if user else "", "siteName": site.name if site else "",
            "siteLanCidr": site.lan_cidr if site else "",
            "email": user.email if user else "", "company": company.name if company else "",
            "department": user.department.name if user and user.department and not site_id else "",
            "title": user.title if user and not site_id else "",
            "deviceName": row.device_name if initial else (device.name if device else ""),
            "contour": row.contour.value if initial else "EMPLOYEES",
            "status": row.status.value if initial else row.status,
            "reason": row.reason if initial else "Продление VPN-доступа", "memo": row.memo if initial else "",
            "accessFrom": _iso(row.access_from) if initial else None,
            "accessUntil": _iso(row.access_until if initial else row.requested_until),
            "currentAccessUntil": _iso(device.access_until) if device else None,
            "createdBy": row.created_by, "reviewedBy": row.reviewed_by,
            "reviewedByName": reviewer_names.get(row.reviewed_by, ""), "createdAt": _iso(row.created_at),
            "documents": [{"id": document.id, "title": document.title, "kind": document.kind,
                           "filename": document.filename, "createdAt": _iso(document.created_at)} for document in row.documents if document.kind != "MEMO_ARCHIVE"] if initial else [],
            "networks": [{"name": networks[network_id].name, "cidr": networks[network_id].cidr}
                         for network_id in dict.fromkeys(chosen_ids) if network_id in networks],
        })
    return result


@router.get("/approvals/summary", response_model=ApprovalSummary)
def summary(db: Session = Depends(get_db), _=Depends(require_roles(Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF))):
    from ..employee_exclusions import excluded_ids
    selected = db.execute(_ordered(_candidates("pending", "all", excluded_ids(db)))).all()
    ids = [f"{row.source_type}:{row.source_id}" for row in selected]
    return {"pending": len(ids), "pendingIds": ids}


@router.get("/approvals", response_model=ApprovalPage)
def list_approvals(status: ApprovalStatus = "pending", kind: ApprovalKind = "all",
                   page: int = Query(1, ge=1), pageSize: int = Query(50, ge=1, le=100),
                   focus: str | None = Query(None, max_length=200, pattern=r"^(request|renewal):[^:]+$"),
                   db: Session = Depends(get_db), _=Depends(require_roles(Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF))):
    from ..employee_exclusions import excluded_ids
    candidates = _candidates(status, kind, excluded_ids(db))
    total = db.scalar(select(func.count()).select_from(candidates)) or 0
    if focus:
        source_type, source_id = focus.split(":", 1)
        ranked = select(candidates.c.source_type, candidates.c.source_id,
                        func.row_number().over(order_by=_ordering(candidates)).label("position")).subquery()
        position = db.scalar(select(ranked.c.position).where(ranked.c.source_type == source_type, ranked.c.source_id == source_id))
        if position is not None:
            page = (position - 1) // pageSize + 1
    selected = db.execute(_ordered(candidates).offset((page - 1) * pageSize).limit(pageSize)).all()
    return {"data": _details(db, selected), "total": total, "page": page, "pageSize": pageSize}
