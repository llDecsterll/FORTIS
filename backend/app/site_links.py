"""Explicit LAN-to-LAN links. No changes to employee permissions or peer keys."""
import ipaddress
import json
import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import text
from .models import Setting, Site, Device, WireGuardPeer, Contour, DeviceStatus, Role, User
from .db import get_db
from .security import require_roles
from .audit import audit

PREFIX='site_link:'
router=APIRouter()

def records(db, include_deleted=False):
    rows=[json.loads(s.value) for s in db.query(Setting).filter(Setting.key.startswith(PREFIX))]
    return rows if include_deleted else [r for r in rows if not r.get('deleted')]

def site_peer(db, sid):
    return db.query(WireGuardPeer).join(Device).filter(Device.site_id==sid,WireGuardPeer.contour==Contour.SITES).first()

def lans(value):
    return [str(ipaddress.ip_network(n.strip(),strict=True)) for n in (value or '').split(',') if n.strip()]

def owned(db,row):
    for suffix in ('A','B'):
        site=db.get(Site,row['site'+suffix]);peer=site_peer(db,row['site'+suffix])
        if not site or not peer or row['lan'+suffix] not in lans(site.lan_cidr) or row['lan'+suffix] not in lans(peer.allowed_lans): return False
    return True

def active(db,row):
    if not row['enabled'] or not owned(db,row): return False
    for sid in (row['siteA'],row['siteB']):
        p=site_peer(db,sid);d=p.device
        if not p.enabled or d.status!=DeviceStatus.ACTIVE or (d.access_until and d.access_until<=datetime.utcnow()): return False
    return True

def linked_destinations(db,peer):
    if peer.contour!=Contour.SITES or not peer.device: return []
    result=[]
    for row in records(db):
        if not active(db,row): continue
        if row['siteA']==peer.device.site_id: result.append(row['lanB'])
        if row['siteB']==peer.device.site_id: result.append(row['lanA'])
    return result

def link_rules(db,iface):
    result=[]
    rows=records(db,include_deleted=True)
    current={frozenset((r['lanA'],r['lanB'])) for r in rows if not r.get('deleted')}
    for row in rows:
        if row.get('deleted') and frozenset((row['lanA'],row['lanB'])) in current: continue
        # Explicit disabled links stop existing flows as well as new connections.
        if not owned(db,row): continue
        verdict='accept' if active(db,row) else 'drop'
        for source,dest in ((row['lanA'],row['lanB']),(row['lanB'],row['lanA'])):
            result.append(f'    iifname "{iface}" oifname "{iface}" ip saddr {source} ip daddr {dest} {verdict}')
    return result

class LinkIn(BaseModel):
    siteA:str
    siteB:str
    lanA:str
    lanB:str

class ToggleIn(BaseModel):
    enabled:bool

def lock(db):
    if db.bind.dialect.name=='postgresql': db.execute(text('SELECT pg_advisory_xact_lock(734027)'))

def validate(db,row):
    if row['siteA']==row['siteB']: raise HTTPException(422,'Выберите два разных объекта')
    try:
        a,b=ipaddress.ip_network(row['lanA'],strict=True),ipaddress.ip_network(row['lanB'],strict=True)
        if a.version!=4 or b.version!=4 or a.overlaps(b): raise ValueError()
        row['lanA'],row['lanB']=str(a),str(b)
    except ValueError: raise HTTPException(422,'Нужны две непересекающиеся IPv4-подсети')
    if not owned(db,row): raise HTTPException(409,'Подсети должны принадлежать выбранным объектам и быть настроены в VPN')
    if not active(db,{**row,'enabled':True}): raise HTTPException(409,'Оба объекта должны иметь действующий VPN-доступ')

def apply_change(db,row,actor,action):
    from .nft import apply_acl
    from .provision import render_stored_config
    from .wireguard import sync_site_lan_routes
    try:
        db.flush()
        for sid in (row['siteA'],row['siteB']):
            p=site_peer(db,sid)
            if p and p.private_key:
                render_stored_config(db,p)
                if row['enabled']: sync_site_lan_routes(p.allowed_lans, p.allowed_lans)
        db.flush()
        apply_acl(db)
        audit(db,actor_id=actor.id,actor_email=actor.email,action=action,target=row['id'],payload=row)
    except Exception as exc:
        db.rollback()
        apply_acl(db)
        raise HTTPException(503,'Не удалось применить связь. Изменения отменены; проверьте журнал сервера') from exc
    return row

@router.get('/site-links')
def list_links(db=Depends(get_db),actor=Depends(require_roles(Role.ADMIN,Role.IT_LEAD,Role.IT_STAFF))):
    result=[]
    for row in records(db):
        a,b=db.get(Site,row['siteA']),db.get(Site,row['siteB'])
        result.append({**row,'nameA':a.name if a else 'Объект удалён','nameB':b.name if b else 'Объект удалён','active':active(db,row)})
    return {'data':result}

@router.post('/site-links',status_code=201)
def create_link(payload:LinkIn,db=Depends(get_db),actor=Depends(require_roles(Role.ADMIN,Role.IT_LEAD))):
    lock(db)
    row={**payload.model_dump(),'enabled':True,'id':str(uuid.uuid4())}
    validate(db,row)
    endpoints={(row['siteA'],row['lanA']),(row['siteB'],row['lanB'])}
    if any({(r['siteA'],r['lanA']),(r['siteB'],r['lanB'])}==endpoints for r in records(db)):
        raise HTTPException(409,'Связь уже существует. Используйте её переключатель')
    db.add(Setting(key=PREFIX+row['id'],value=json.dumps(row)))
    return apply_change(db,row,actor,'site_link_create')

@router.put('/site-links/{link_id}')
def toggle_link(link_id:str,payload:ToggleIn,db=Depends(get_db),actor=Depends(require_roles(Role.ADMIN,Role.IT_LEAD))):
    lock(db)
    setting=db.get(Setting,PREFIX+link_id)
    if not setting: raise HTTPException(404,'Связь не найдена')
    row=json.loads(setting.value);row['enabled']=payload.enabled
    if row.get('deleted'): raise HTTPException(404,'Связь удалена')
    if payload.enabled: validate(db,row)
    setting.value=json.dumps(row)
    return apply_change(db,row,actor,'site_link_toggle')

@router.delete('/site-links/{link_id}')
def delete_link(link_id:str,db=Depends(get_db),actor=Depends(require_roles(Role.ADMIN,Role.IT_LEAD))):
    lock(db)
    setting=db.get(Setting,PREFIX+link_id)
    if not setting: raise HTTPException(404,'Связь не найдена')
    row=json.loads(setting.value)
    if row.get('deleted'): raise HTTPException(404,'Связь удалена')
    # Keep a deny tombstone: removing the row must not reopen established flows.
    row.update(enabled=False,deleted=True)
    setting.value=json.dumps(row)
    apply_change(db,row,actor,'site_link_delete')
    return {'ok':True}
