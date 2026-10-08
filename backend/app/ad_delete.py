"""Explicit, previewed AD source removal; never infer ownership from email."""
import hashlib
import json
import uuid
from datetime import datetime
from pathlib import Path

from fastapi import HTTPException
from sqlalchemy import or_

from . import ad, wireguard
from .ad_guard import serialized_ad
from .audit import audit
from .config import settings
from .models import (AccessPolicy, AccessRequest, Device, DeviceCertificate, DeviceStatus,
                     Document, EnrollmentNonce, ResourceVisit, Role, SecurityEvent,
                     Session, Site, User, VpnRenewal, WireGuardPeer)
from .nft import apply_acl


def _linked(db, source_id):
    source = next((s for s in ad._load_sources(db) if s["id"] == source_id), None)
    if source is None:
        raise HTTPException(404, "Домен AD не найден")
    users = db.query(User).filter(User.ad_source == source_id).order_by(User.id).all()
    ids = [u.id for u in users]
    devices = db.query(Device).filter(Device.user_id.in_(ids), Device.site_id.is_(None)).all()
    dids = [d.id for d in devices]
    peers = db.query(WireGuardPeer).filter(WireGuardPeer.device_id_fk.in_(dids)).all()
    requests = db.query(AccessRequest).filter(AccessRequest.user_id.in_(ids)).all()
    docs = db.query(Document).filter(or_(Document.device_id_fk.in_(dids),
                                       Document.request_id.in_([r.id for r in requests]))).all()
    return source, users, devices, peers, requests, docs


def deletion_info(db, source_id):
    source, users, devices, peers, requests, docs = _linked(db, source_id)
    blockers = []
    if any(u.role != Role.USER for u in users):
        blockers.append("С доменом связана учётная запись управления. Сначала перенесите её в другой источник")
    if db.query(User).filter(User.ad_guid != "", or_(User.ad_source == "", User.ad_source.is_(None))).count():
        blockers.append("Есть сотрудники AD без привязки к источнику. Сначала выполните синхронизацию и проверьте привязки")
    root = settings.uploads_dir.resolve()
    for doc in docs:
        path = Path(doc.path).resolve()
        if not path.is_relative_to(root) or path == root or (path.exists() and not path.is_file()):
            blockers.append("Документ находится вне разрешённой папки. Требуется проверка администратора")
            break
        if db.query(Document).filter(Document.path == doc.path, ~Document.id.in_([d.id for d in docs])).count():
            blockers.append("Файл документа используется другими записями")
            break
    state = [ad._get(db, "ad_revision"), ad._public_source(source),
             [(u.id, u.role.value, u.ad_guid) for u in users],
             sorted(d.id for d in devices), sorted((p.id, p.public_key) for p in peers),
             sorted(r.id for r in requests), sorted(d.id for d in docs)]
    revision = hashlib.sha256(json.dumps(state, sort_keys=True).encode()).hexdigest()
    return {"id": source_id, "host": source["host"], "baseDn": source["baseDn"],
            "users": [{"id": u.id, "name": u.full_name} for u in users],
            "devices": len(devices), "keys": len(peers), "requests": len(requests),
            "documents": len(docs), "blockers": blockers, "revision": revision,
            "deleting": bool(source.get("deleting"))}


@serialized_ad
def delete_source(db, source_id, confirmation, revision, actor, ip=""):
    info = deletion_info(db, source_id)
    if info["blockers"]:
        raise HTTPException(409, "; ".join(info["blockers"]))
    if confirmation != info["host"]:
        raise HTTPException(422, "Введите точное имя сервера домена")
    if revision != info["revision"]:
        raise HTTPException(409, "Состав домена изменился. Закройте окно и проверьте удаление заново")
    source, users, devices, peers, requests, docs = _linked(db, source_id)
    ids, dids = [u.id for u in users], [d.id for d in devices]
    # Durable tombstone prevents a concurrent/subsequent sync recreating access
    # if any OS operation fails. Retry resumes the same deletion, fail-closed.
    sources = ad._load_sources(db)
    for item in sources:
        if item["id"] == source_id:
            item["deleting"] = True
    ad._store_sources(db, sources)
    ad._put(db, "ad_revision", uuid.uuid4().hex)
    for user in users:
        user.is_active = False
        user.panel_nonce = uuid.uuid4().hex
    for device in devices:
        device.status = DeviceStatus.REVOKED
        device.block_reason = "Удаление домена Active Directory"
    for peer in peers:
        peer.enabled = peer.link_up = False
    db.query(Session).filter(Session.device_id_fk.in_(dids)).update({"active": False}, synchronize_session=False)
    db.query(DeviceCertificate).filter(DeviceCertificate.device_id_fk.in_(dids)).update(
        {"revoked": True, "revoked_at": datetime.utcnow()}, synchronize_session=False)
    db.commit()
    audit(db, actor_id=actor.id, actor_email=actor.email, action="ad_delete_started",
          target=source_id, ip=ip, payload={"users": len(ids), "keys": len(peers)})
    try:
        for peer in peers:
            wireguard.remove_peer(peer.contour, peer.public_key)
        apply_acl(db)
        # Unlink only validated individual uploads. A failed unlink retains DB
        # rows and the tombstone for retry; downloaded copies cannot be erased.
        for doc in docs:
            Path(doc.path).unlink(missing_ok=True)
        tokens = [r.enrollment_token for r in requests if r.enrollment_token]
        db.query(EnrollmentNonce).filter(EnrollmentNonce.token.in_(tokens)).delete(synchronize_session=False)
        db.query(Document).filter(Document.id.in_([d.id for d in docs])).delete(synchronize_session=False)
        db.query(AccessRequest).filter(AccessRequest.user_id.in_(ids)).delete(synchronize_session=False)
        db.query(VpnRenewal).filter(or_(VpnRenewal.user_id.in_(ids), VpnRenewal.device_id.in_(dids))).delete(synchronize_session=False)
        db.query(ResourceVisit).filter(ResourceVisit.user_id.in_(ids)).delete(synchronize_session=False)
        # Sites and common catalogs are not owned by an AD source. Keep them.
        db.query(Site).filter(Site.owner_id.in_(ids)).update({"owner_id": None}, synchronize_session=False)
        db.query(Device).filter(Device.user_id.in_(ids), Device.site_id.isnot(None)).update({"user_id": None}, synchronize_session=False)
        db.query(SecurityEvent).filter(SecurityEvent.user_id.in_(ids)).update({"user_id": None}, synchronize_session=False)
        db.query(SecurityEvent).filter(SecurityEvent.device_id_fk.in_(dids)).update({"device_id_fk": None}, synchronize_session=False)
        db.query(AccessRequest).filter(AccessRequest.issued_device_id.in_(dids)).update({"issued_device_id": None}, synchronize_session=False)
        for model in (Session, AccessPolicy, DeviceCertificate, WireGuardPeer):
            db.query(model).filter(model.device_id_fk.in_(dids)).delete(synchronize_session=False)
        db.query(Device).filter(Device.id.in_(dids)).delete(synchronize_session=False)
        db.query(User).filter(User.id.in_(ids)).delete(synchronize_session=False)
        remaining = [s for s in sources if s["id"] != source_id]
        ad._store_sources(db, remaining)
        ad._mirror_first(db, remaining[0] if remaining else None)
        ad._put(db, "ad_revision", uuid.uuid4().hex)
        db.flush()
        audit(db, actor_id=actor.id, actor_email=actor.email, action="ad_delete",
              target=source_id, ip=ip, payload={"users": len(ids), "keys": len(peers)})
    except Exception as exc:
        db.rollback()
        raise HTTPException(503, "Удаление не завершено. Доступы помечены отозванными; повторите удаление. При повторной ошибке требуется проверка VPN на сервере") from exc
    return {"deleted": source_id, "users": len(ids), "keys": len(peers)}
