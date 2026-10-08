from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
import ipaddress

from ..audit import audit
from ..db import get_db
from ..models import Contour, Network, Resource, Role, User
from ..schemas import NetworkIn, ResourceIn
from ..security import current_user, require_roles
from ..employee_networks import selectable

router = APIRouter(tags=["networks"])
from ..site_links import router as site_links_router
router.include_router(site_links_router)
from ..network_ping import router as ping_router
router.include_router(ping_router)


@router.get('/networks/{network_id}/deletion')
def preview_deletion(network_id: str, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN, Role.IT_LEAD))):
    from ..network_delete import deletion_info
    return deletion_info(db, network_id)


@router.delete('/networks/{network_id}')
def remove_network(network_id: str, confirmation: str, revision: str, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN, Role.IT_LEAD))):
    from ..network_delete import delete_network_record
    return delete_network_record(db, network_id, confirmation, revision, actor)


@router.put("/networks/{network_id}")
def update_network(network_id: str, payload: NetworkIn, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN, Role.IT_LEAD))):
    from ..models import AccessPolicy, AccessRequest, WireGuardPeer
    from ..config import settings
    n = db.query(Network).filter(Network.id == network_id).with_for_update().first()
    if not n:
        raise HTTPException(404, "Сеть не найдена")
    if not payload.name.strip() or len(payload.name.strip()) > 200 or len(payload.description) > 2000:
        raise HTTPException(422, "Укажите название до 200 символов и описание до 2000 символов")
    try:
        net = ipaddress.ip_network(payload.cidr.strip(), strict=True)
        if net.version != 4 or net.prefixlen == 0:
            raise ValueError()
    except ValueError:
        raise HTTPException(422, "Укажите адрес IPv4-подсети в формате CIDR, например 192.168.3.0/24")
    if payload.contour != n.contour.value:
        raise HTTPException(409, "Перенос сети между контурами запрещён")
    cidr = str(net)
    routing_changed = cidr != n.cidr or payload.isRestricted != n.is_restricted
    if routing_changed:
        pools = [ipaddress.ip_network(settings.employees_net), ipaddress.ip_network(settings.sites_net)]
        if any(net.overlaps(p) or ipaddress.ip_network(n.cidr).overlaps(p) for p in pools):
            raise HTTPException(409, "Адреса VPN-пулов изменяются только вместе с настройкой сервера")
        used = db.query(AccessPolicy).filter(AccessPolicy.network_id == n.id).first() or db.query(Resource).filter(Resource.network_id == n.id).first()
        used = used or any(n.id in (r.networks_json or []) for r in db.query(AccessRequest))
        used = used or any(n.cidr in (p.destination_cidrs or '').split(',') or n.cidr in (p.client_config or '') for p in db.query(WireGuardPeer))
        # Legacy site peers inherit the available network catalogue.
        used = used or (n.contour == Contour.SITES and any(not p.destination_cidrs for p in db.query(WireGuardPeer).filter(WireGuardPeer.contour == Contour.SITES)))
        if used:
            raise HTTPException(409, "Сеть используется в доступах или конфигурациях. Сначала перенесите связанные доступы; название и описание можно менять сейчас")
        if db.query(Network).filter(Network.id != n.id, Network.contour == n.contour, Network.cidr == cidr).first():
            raise HTTPException(409, "Такая сеть уже существует в этом контуре")
    n.name = payload.name.strip()
    n.description = payload.description.strip()
    n.cidr = cidr
    n.is_restricted = payload.isRestricted
    db.commit()
    audit(db, actor_id=actor.id, actor_email=actor.email, action="network_update", target=n.id, ip=request.client.host if request.client else "")
    return {"id": n.id}


@router.get("/networks")
def list_networks(contour: str | None = None, db: Session = Depends(get_db), _=Depends(require_roles(Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF))):
    q = db.query(Network)
    if contour:
        q = q.filter(Network.contour == contour)
    return {
        "data": [
            {
                "id": n.id,
                "name": n.name,
                "cidr": n.cidr,
                "contour": n.contour.value,
                "description": n.description,
                "isRestricted": n.is_restricted,
                "employeeSelectable": selectable(n),
            }
            for n in q.order_by(Network.name)
        ]
    }


@router.post("/networks", status_code=201)
def create_network(payload: NetworkIn, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN, Role.IT_LEAD))):
    if not payload.name.strip() or len(payload.name.strip()) > 200 or len(payload.description) > 2000:
        raise HTTPException(422, 'Укажите название до 200 символов и описание до 2000 символов')
    try:
        net = ipaddress.ip_network(payload.cidr.strip(), strict=True)
        if '/' not in payload.cidr or net.version != 4 or net.prefixlen == 0: raise ValueError()
    except ValueError:
        raise HTTPException(422, 'Укажите адрес IPv4-сети и маску, например 192.168.90.0/24')
    from ..config import settings
    if any(net.overlaps(ipaddress.ip_network(pool)) for pool in (settings.employees_net, settings.sites_net)):
        raise HTTPException(409, 'Сеть пересекается с VPN-пулом')
    if db.query(Network).filter(Network.contour == Contour(payload.contour), Network.cidr == str(net)).first():
        raise HTTPException(409, 'Такая сеть уже существует в этом контуре')
    payload.cidr = str(net)
    payload.name = payload.name.strip()
    n = Network(
        name=payload.name,
        cidr=payload.cidr,
        contour=Contour(payload.contour),
        description=payload.description,
        is_restricted=payload.isRestricted,
    )
    db.add(n)
    db.commit()
    audit(db, actor_id=actor.id, actor_email=actor.email, action="network_create", target=n.cidr, ip=request.client.host if request.client else "")
    return {"id": n.id}


@router.get("/resources")
def list_resources(contour: str | None = None, db: Session = Depends(get_db), _=Depends(require_roles(Role.ADMIN, Role.IT_LEAD, Role.IT_STAFF))):
    q = db.query(Resource)
    if contour:
        q = q.filter(Resource.contour == contour)
    return {
        "data": [
            {
                "id": r.id,
                "name": r.name,
                "kind": r.kind,
                "host": r.host,
                "port": r.port,
                "networkId": r.network_id,
                "contour": r.contour.value,
                "description": r.description,
            }
            for r in q.order_by(Resource.name)
        ]
    }


@router.post("/resources", status_code=201)
def create_resource(payload: ResourceIn, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN, Role.IT_LEAD))):
    validate_resource(db, payload)
    r = Resource(
        name=payload.name,
        kind=payload.kind,
        host=payload.host,
        port=payload.port,
        network_id=payload.networkId,
        contour=Contour(payload.contour),
        description=payload.description,
    )
    db.add(r)
    db.commit()
    audit(db, actor_id=actor.id, actor_email=actor.email, action="resource_create", target=r.name, ip=request.client.host if request.client else "")
    return {"id": r.id}


def validate_resource(db, payload):
    if not payload.name.strip() or len(payload.name.strip()) > 200 or len(payload.description) > 2000:
        raise HTTPException(422, 'Укажите название до 200 символов и описание до 2000 символов')
    try:
        host = ipaddress.ip_address(payload.host.strip())
        if host.version != 4 or host.is_multicast or host.is_unspecified: raise ValueError()
    except ValueError:
        raise HTTPException(422, 'Укажите IPv4-адрес ресурса без порта и маски')
    if payload.port is not None and not 1 <= payload.port <= 65535:
        raise HTTPException(422, 'Порт должен быть от 1 до 65535')
    if not payload.kind.strip() or len(payload.kind) > 50:
        raise HTTPException(422, 'Укажите тип ресурса до 50 символов')
    if payload.networkId:
        network = db.get(Network, payload.networkId)
        if not network or network.contour.value != payload.contour:
            raise HTTPException(422, 'Выберите сеть того же контура')
        if host not in ipaddress.ip_network(network.cidr):
            raise HTTPException(422, 'Адрес ресурса не входит в выбранную сеть')
    payload.name = payload.name.strip()
    payload.host = str(host)


def resource_used(db, resource_id):
    from ..models import AccessPolicy, AccessRequest
    return bool(db.query(AccessPolicy).filter(AccessPolicy.resource_id == resource_id).first()) or any(resource_id in (r.resources_json or []) for r in db.query(AccessRequest))


@router.put('/resources/{resource_id}')
def update_resource(resource_id: str, payload: ResourceIn, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN, Role.IT_LEAD))):
    r = db.query(Resource).filter(Resource.id == resource_id).with_for_update().first()
    if not r: raise HTTPException(404, 'Ресурс не найден')
    validate_resource(db, payload)
    if payload.contour != r.contour.value:
        raise HTTPException(409, 'Перенос ресурса между контурами запрещён')
    if (payload.host, payload.port, payload.networkId, payload.kind) != (r.host, r.port, r.network_id, r.kind) and resource_used(db, r.id):
        raise HTTPException(409, 'Ресурс используется в доступах или заявках. Можно изменить название и описание; сначала перенесите связанные доступы для изменения адреса')
    for key, value in dict(name=payload.name, host=payload.host, port=payload.port, network_id=payload.networkId, kind=payload.kind, description=payload.description).items():
        setattr(r, key, value)
    audit(db, actor_id=actor.id, actor_email=actor.email, action='resource_update', target=r.id, ip=request.client.host if request.client else '')
    return {'id': r.id}


@router.delete('/resources/{resource_id}')
def delete_resource(resource_id: str, confirmation: str, db: Session = Depends(get_db), actor: User = Depends(require_roles(Role.ADMIN, Role.IT_LEAD))):
    r = db.query(Resource).filter(Resource.id == resource_id).with_for_update().first()
    if not r: raise HTTPException(404, 'Ресурс не найден')
    if confirmation != r.name: raise HTTPException(422, 'Введите точное название ресурса')
    if resource_used(db, r.id): raise HTTPException(409, 'Ресурс используется в доступах или заявках. Сначала перенесите связанные доступы')
    snapshot = {c.name: getattr(r,c.name) for c in r.__table__.columns}
    snapshot['contour'] = r.contour.value
    db.delete(r)
    audit(db, actor_id=actor.id, actor_email=actor.email, action='resource_delete', target=resource_id, payload=snapshot)
    return {'deleted':resource_id}
