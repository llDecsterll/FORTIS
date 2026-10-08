from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .. import engine, wireguard
from ..audit import audit
from ..ca import CorporateCA
from ..config import settings
from ..db import get_db
from ..device_id import compute_device_id, normalize_mac
from ..models import (
    AccessPolicy,
    AccessRequest,
    Contour,
    Device,
    DeviceCertificate,
    DeviceStatus,
    DeviceType,
    RequestStatus,
    WireGuardPeer,
)
from ..schemas import DeviceVerifyIn, EnrollIn, HeartbeatIn

def require_agent_mode():
    if settings.standard_wireguard:
        raise HTTPException(410, "Используется стандартный WireGuard. Регистрация агента отключена")


router = APIRouter(tags=["agent"], dependencies=[Depends(require_agent_mode)])


@router.get("/agent/ca")
def ca_cert():
    return {"pem": CorporateCA().ca_pem()}


@router.post("/device/verify")
def verify(payload: DeviceVerifyIn, request: Request, db: Session = Depends(get_db)):
    ip = request.client.host if request.client else ""
    try:
        return engine.verify_and_authorize(
            db,
            certificate_pem=payload.certificatePem,
            system_identifier=payload.systemIdentifier,
            mac=payload.mac,
            wg_public_key=payload.wireguardPublicKey,
            device_name=payload.deviceName,
            os_name=payload.osName,
            client_version=payload.clientVersion,
            user_email=payload.userEmail,
            external_ip=ip,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.post("/device/heartbeat")
def heartbeat(payload: HeartbeatIn, request: Request, db: Session = Depends(get_db)):
    ip = request.client.host if request.client else ""
    try:
        return engine.heartbeat(db, payload.sessionToken, ip)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.post("/device/register")
def register(payload: EnrollIn, request: Request, db: Session = Depends(get_db)):
    row = db.query(AccessRequest).filter(AccessRequest.enrollment_token == payload.token).one_or_none()
    if not row or row.status != RequestStatus.ISSUED:
        raise HTTPException(403, "Недействительный токен регистрации")
    mac_eth = normalize_mac(payload.macEthernet) if payload.macEthernet else ""
    mac_wifi = normalize_mac(payload.macWifi) if payload.macWifi else ""
    registered_mac = mac_eth or mac_wifi
    ca = CorporateCA()
    cn = f"{row.user.email}:{payload.deviceName}"[:64]
    cert_pem, key_pem, serial, fingerprint, nb, na = ca.issue_device_cert(cn)
    device_id = compute_device_id(cert_pem, payload.systemIdentifier, registered_mac, payload.wireguardPublicKey)
    used = {p.vpn_ip for p in db.query(WireGuardPeer).all()}
    vpn_ip = wireguard.next_vpn_ip(row.contour, used)
    psk = wireguard.gen_psk()
    device = Device(
        name=payload.deviceName or row.device_name,
        device_id=device_id,
        user_id=row.user_id,
        site_id=row.site_id,
        contour=row.contour,
        device_type=DeviceType.ROUTER if row.contour == Contour.SITES else DeviceType.LAPTOP,
        os_name=payload.osName,
        serial=payload.serial,
        mac_ethernet=mac_eth,
        mac_wifi=mac_wifi,
        macs_json={"ethernet": mac_eth, "wifi": mac_wifi},
        system_identifier=payload.systemIdentifier,
        status=DeviceStatus.PENDING,
        enrolled_by=row.created_by,
        enrolled_at=datetime.utcnow(),
        access_from=row.access_from,
        access_until=row.access_until,
    )
    db.add(device)
    db.flush()
    db.add(
        DeviceCertificate(
            device_id_fk=device.id,
            serial=serial,
            fingerprint=fingerprint,
            pem=cert_pem,
            not_before=nb,
            not_after=na,
        )
    )
    lans = ""
    if device.site and device.site.lan_cidr:
        lans = device.site.lan_cidr
    db.add(
        WireGuardPeer(
            device_id_fk=device.id,
            contour=row.contour,
            public_key=payload.wireguardPublicKey,
            preshared_key=psk,
            vpn_ip=vpn_ip,
            allowed_lans=lans,
            enabled=False,
        )
    )
    for nid in row.networks_json or []:
        db.add(AccessPolicy(device_id_fk=device.id, network_id=nid, allowed=True))
    for rid in row.resources_json or []:
        db.add(AccessPolicy(device_id_fk=device.id, resource_id=rid, allowed=True))
    row.issued_device_id = device.id
    row.enrollment_token = None
    db.commit()
    audit(
        db,
        action="device_register",
        target=device.name,
        ip=request.client.host if request.client else "",
        device=device_id,
        vpn=row.contour.value,
    )
    server_pub = wireguard.server_public_key(row.contour)
    from ..models import Network

    cidrs = []
    for nid in row.networks_json or []:
        net = db.get(Network, nid)
        if net:
            cidrs.append(net.cidr)
    if device.site and device.site.lan_cidr:
        cidrs.append(device.site.lan_cidr)
    for extra in [p.strip() for p in settings.extra_allowed_ips.split(",") if p.strip()]:
        cidrs.append(extra)
    allowed = ", ".join(dict.fromkeys(cidrs)) if cidrs else (
        "0.0.0.0/0" if row.contour == Contour.EMPLOYEES else f"{settings.employees_net}, {settings.sites_net}"
    )
    return {
        "deviceId": device_id,
        "vpnIp": vpn_ip,
        "presharedKey": psk,
        "certificatePem": cert_pem,
        "certificateKeyPem": key_pem,
        "caPem": ca.ca_pem(),
        "serverPublicKey": server_pub,
        "endpoint": f"{wireguard.endpoint_for(row.contour)[0]}:{wireguard.endpoint_for(row.contour)[1]}",
        "allowedIps": allowed or "0.0.0.0/0",
        "dns": settings.dns_servers,
        "mtu": settings.mtu,
        "contour": row.contour.value,
    }
