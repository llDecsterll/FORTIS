"""Service permissions are host/protocol/port tuples, never host-wide grants."""
import ipaddress
from fastapi import HTTPException
from .models import Resource, AccessPolicy


def service(resource):
    try:
        host = ipaddress.ip_address(resource.host)
        if host.version != 4 or host.is_unspecified or host.is_multicast:
            return None
        if resource.protocol not in ('TCP', 'UDP') or resource.port is None or not 1 <= resource.port <= 65535:
            return None
        return str(host), resource.protocol.lower(), resource.port
    except (ValueError, TypeError):
        return None


def validate_grants(db, ids, contour):
    result = []
    for rid in dict.fromkeys(ids or []):
        resource = db.get(Resource, rid)
        if not resource or resource.contour != contour or not service(resource):
            raise HTTPException(422, 'Выберите ресурс этого контура с IPv4-адресом, протоколом TCP/UDP и портом')
        result.append(resource)
    return result


def permitted_services(db, device):
    result = []
    for policy in db.query(AccessPolicy).filter_by(device_id_fk=device.id, allowed=True):
        resource = db.get(Resource, policy.resource_id) if policy.resource_id else None
        if resource and resource.contour == device.contour and service(resource):
            result.append(service(resource))
    return sorted(set(result))
