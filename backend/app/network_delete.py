import hashlib
import ipaddress
import json
from fastapi import HTTPException
from sqlalchemy import text
from .models import Network, AccessPolicy, AccessRequest, Resource, WireGuardPeer, Contour
from .config import settings
from .audit import audit
from .nft import apply_acl
from .provision import render_stored_config

def deletion_info(db, network_id):
    n=db.get(Network,network_id)
    if not n: raise HTTPException(404,'Сеть не найдена')
    policies=db.query(AccessPolicy).filter(AccessPolicy.network_id==n.id).all()
    resources=db.query(Resource).filter(Resource.network_id==n.id).all()
    requests=[r for r in db.query(AccessRequest) if n.id in (r.networks_json or [])]
    peers=db.query(WireGuardPeer).filter(WireGuardPeer.contour==n.contour).all()
    blockers=[]
    if any(ipaddress.ip_network(n.cidr,strict=False).overlaps(ipaddress.ip_network(p)) for p in (settings.employees_net,settings.sites_net)):
        blockers.append('VPN-пул нельзя удалить из каталога')
    if resources: blockers.append(f'Связанные ресурсы: {len(resources)}. Сначала перенесите их в другую сеть')
    if requests: blockers.append(f'Связанные заявки: {len(requests)}. Сначала перенесите связанные доступы')
    if n.cidr in [s.strip() for s in settings.extra_allowed_ips.split(',')]:
        blockers.append('Сеть также задана в настройках сервера EXTRA_ALLOWED_IPS')
    for p in peers:
        values=[v.strip() for v in (p.destination_cidrs or '').split(',') if v.strip()]
        if n.contour==Contour.EMPLOYEES and values==[n.cidr]:
            blockers.append('Это последняя выбранная сеть сотрудника. Сначала назначьте другую сеть')
            break
    state=[n.id,n.name,n.cidr,n.contour.value,sorted(p.id for p in policies),sorted(r.id for r in resources),sorted(r.id for r in requests),sorted((p.id,p.destination_cidrs or '') for p in peers)]
    revision=hashlib.sha256(json.dumps(state,ensure_ascii=False).encode()).hexdigest()
    return {'name':n.name,'cidr':n.cidr,'contour':n.contour.value,'policies':len(policies),'configs':len(peers),'blockers':blockers,'revision':revision}

def delete_network_record(db, network_id, confirmation, revision, actor):
    if db.bind.dialect.name=='postgresql': db.execute(text('SELECT pg_advisory_xact_lock(734027)'))
    n=db.query(Network).filter(Network.id==network_id).with_for_update().first()
    if not n: raise HTTPException(404,'Сеть не найдена')
    info=deletion_info(db,network_id)
    if info['blockers']: raise HTTPException(409,'; '.join(info['blockers']))
    if confirmation!=n.cidr: raise HTTPException(422,'Введите точный CIDR удаляемой сети')
    if revision!=info['revision']: raise HTTPException(409,'Связи сети изменились. Закройте окно и повторите удаление')
    policies=db.query(AccessPolicy).filter(AccessPolicy.network_id==n.id).all()
    snapshot={'network':{c.name:getattr(n,c.name) for c in n.__table__.columns},'policies':[{c.name:getattr(p,c.name) for c in p.__table__.columns} for p in policies]}
    # Audit contains no keys; snapshot supports administrator-assisted recovery.
    snapshot=json.loads(json.dumps(snapshot,default=str))
    peers=db.query(WireGuardPeer).filter(WireGuardPeer.contour==n.contour).all()
    cidr=n.cidr
    try:
        for p in policies: db.delete(p)
        db.delete(n);db.flush()
        for p in peers:
            if p.destination_cidrs:
                p.destination_cidrs=','.join(v.strip() for v in p.destination_cidrs.split(',') if v.strip()!=cidr)
                if not p.destination_cidrs and p.contour==Contour.SITES:
                    # Explicit server-only selection must never fall back to all networks.
                    p.destination_cidrs=settings.sites_server_ip+'/32'
            if p.private_key: render_stored_config(db,p)
        db.flush()
        apply_acl(db)
        audit(db,actor_id=actor.id,actor_email=actor.email,action='network_delete',target=network_id,payload=snapshot)
    except Exception:
        db.rollback()
        apply_acl(db)
        raise HTTPException(503,'Удаление не завершено. Прежние данные восстановлены; проверьте журнал сервера')
    return {'deleted':network_id,'cidr':cidr}
