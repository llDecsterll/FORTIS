"""Explicit destination selection for site-to-site configurations."""
import ipaddress
from .config import settings
from .models import Contour, Network

def available_destinations(db):
    values=[n.cidr for n in db.query(Network).filter(Network.contour==Contour.SITES,Network.is_restricted.is_(False)).all()]
    values += settings.extra_allowed_ips.split(',')
    excluded=[ipaddress.ip_network(settings.employees_net),ipaddress.ip_network(settings.sites_net)]
    result=[]
    for value in values:
        if not value.strip(): continue
        net=ipaddress.ip_network(value.strip(),strict=False)
        if net.version!=4 or net.prefixlen==0 or any(net.overlaps(n) for n in excluded): continue
        if str(net) not in result: result.append(str(net))
    return result

def validate_destinations(db,values,lan):
    if not values or len(values)>256: raise ValueError('Выберите хотя бы одну сеть назначения')
    allowed=set(available_destinations(db))
    local=[ipaddress.ip_network(n.strip()) for n in lan.split(',') if n.strip()]
    result=[]
    for value in values:
        net=ipaddress.ip_network(value,strict=True)
        if str(net) not in allowed: raise ValueError('Сеть назначения не разрешена для объектов: '+str(net))
        if any(net.overlaps(n) for n in local): raise ValueError('Подсеть роутера пересекается с сетью назначения')
        if str(net) not in result: result.append(str(net))
    return ','.join(result)

def effective_destinations(db,peer):
    allowed=set(available_destinations(db))
    return [settings.sites_server_ip+'/32', *[n for n in peer.destination_cidrs.split(',') if n in allowed]]
