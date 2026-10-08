import enum
import uuid
import secrets
from datetime import datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def uid() -> str:
    return str(uuid.uuid4())


class Contour(str, enum.Enum):
    EMPLOYEES = "EMPLOYEES"
    SITES = "SITES"


class Role(str, enum.Enum):
    ADMIN = "ADMIN"
    IT_LEAD = "IT_LEAD"
    IT_STAFF = "IT_STAFF"
    SECURITY = "SECURITY"
    AUDITOR = "AUDITOR"
    USER = "USER"


class DeviceStatus(str, enum.Enum):
    PENDING = "PENDING"
    ACTIVE = "ACTIVE"
    BLOCKED = "BLOCKED"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


class DeviceType(str, enum.Enum):
    LAPTOP = "LAPTOP"
    DESKTOP = "DESKTOP"
    PHONE = "PHONE"
    ROUTER = "ROUTER"
    SERVER = "SERVER"
    CAMERA = "CAMERA"
    CONTROLLER = "CONTROLLER"
    OTHER = "OTHER"


class RequestStatus(str, enum.Enum):
    CREATED = "CREATED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED_SB = "APPROVED_SB"
    REJECTED = "REJECTED"
    ISSUED = "ISSUED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class EventSeverity(str, enum.Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ConcurrentPolicy(str, enum.Enum):
    WARN = "WARN"
    BLOCK_NEW = "BLOCK_NEW"
    BLOCK_KEY = "BLOCK_KEY"


class MacPolicy(str, enum.Enum):
    ALLOW_IF_CERT = "ALLOW_IF_CERT"
    REAPPROVE = "REAPPROVE"
    BLOCK = "BLOCK"


class Company(Base):
    __tablename__ = "companies"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String, unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Department(Base):
    __tablename__ = "departments"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    company_id: Mapped[str] = mapped_column(ForeignKey("companies.id"))
    name: Mapped[str] = mapped_column(String)
    company = relationship("Company")


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    full_name: Mapped[str] = mapped_column(String)
    email: Mapped[str] = mapped_column(String, unique=True, index=True)
    phone: Mapped[str] = mapped_column(Text, default="", server_default="")
    contact_email: Mapped[str] = mapped_column(Text, default="", server_default="")
    title: Mapped[str] = mapped_column(String, default="")
    password_hash: Mapped[str] = mapped_column(String)
    panel_nonce: Mapped[str] = mapped_column(String, default=lambda: secrets.token_urlsafe(32))
    role: Mapped[Role] = mapped_column(Enum(Role), default=Role.USER)
    is_management: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    rdp_host: Mapped[str] = mapped_column(String, default="")
    rdp_port: Mapped[int] = mapped_column(Integer, default=3389)
    rdp_user: Mapped[str] = mapped_column(String, default="")
    rdp_password: Mapped[str] = mapped_column(String, default="")
    rdp_save_password: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    company_id: Mapped[str | None] = mapped_column(ForeignKey("companies.id"), nullable=True)
    department_id: Mapped[str | None] = mapped_column(ForeignKey("departments.id"), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    blocked_by: Mapped[str] = mapped_column(String, default="")
    totp_secret: Mapped[str] = mapped_column(String, default="")
    totp_confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    last_activity_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    ad_guid: Mapped[str] = mapped_column(String, default="", index=True)
    ad_source: Mapped[str] = mapped_column(String, default="", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    company = relationship("Company")
    department = relationship("Department")
    devices = relationship("Device", back_populates="user")


class Site(Base):
    __tablename__ = "sites"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String)
    company_id: Mapped[str | None] = mapped_column(ForeignKey("companies.id"), nullable=True)
    address: Mapped[str] = mapped_column(String, default="")
    owner_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    lan_cidr: Mapped[str] = mapped_column(String, default="")
    router_name: Mapped[str] = mapped_column(String, default="")
    provider_name: Mapped[str] = mapped_column(Text, default="", server_default="")
    provider_phone: Mapped[str] = mapped_column(Text, default="", server_default="")
    provider_email: Mapped[str] = mapped_column(Text, default="", server_default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    company = relationship("Company")
    owner = relationship("User")
    devices = relationship("Device", back_populates="site")


class Network(Base):
    __tablename__ = "networks"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String)
    cidr: Mapped[str] = mapped_column(String)
    contour: Mapped[Contour] = mapped_column(Enum(Contour))
    description: Mapped[str] = mapped_column(String, default="")
    is_restricted: Mapped[bool] = mapped_column(Boolean, default=False)


class Resource(Base):
    __tablename__ = "resources"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String)
    kind: Mapped[str] = mapped_column(String, default="SERVICE")
    host: Mapped[str] = mapped_column(String)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    network_id: Mapped[str | None] = mapped_column(ForeignKey("networks.id"), nullable=True)
    contour: Mapped[Contour] = mapped_column(Enum(Contour))
    description: Mapped[str] = mapped_column(String, default="")
    network = relationship("Network")


class Device(Base):
    __tablename__ = "devices"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String)
    device_id: Mapped[str] = mapped_column(String, unique=True, index=True, default="")
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    site_id: Mapped[str | None] = mapped_column(ForeignKey("sites.id"), nullable=True)
    contour: Mapped[Contour] = mapped_column(Enum(Contour))
    device_type: Mapped[DeviceType] = mapped_column(Enum(DeviceType), default=DeviceType.LAPTOP)
    os_name: Mapped[str] = mapped_column(String, default="")
    serial: Mapped[str] = mapped_column(String, default="")
    mac_ethernet: Mapped[str] = mapped_column(String, default="")
    mac_wifi: Mapped[str] = mapped_column(String, default="")
    macs_json: Mapped[dict] = mapped_column(JSON, default=dict)
    system_identifier: Mapped[str] = mapped_column(String, default="")
    status: Mapped[DeviceStatus] = mapped_column(Enum(DeviceStatus), default=DeviceStatus.PENDING)
    enrolled_by: Mapped[str] = mapped_column(String, default="")
    enrolled_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    access_from: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    access_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_external_ip: Mapped[str] = mapped_column(String, default="")
    last_geo: Mapped[str] = mapped_column(String, default="")
    isp: Mapped[str] = mapped_column(String, default="")
    block_reason: Mapped[str] = mapped_column(Text, default="")
    require_agent: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    user = relationship("User", back_populates="devices")
    site = relationship("Site", back_populates="devices")
    certificate = relationship("DeviceCertificate", back_populates="device", uselist=False)
    peer = relationship("WireGuardPeer", back_populates="device", uselist=False)


class DeviceCertificate(Base):
    __tablename__ = "device_certificates"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    device_id_fk: Mapped[str] = mapped_column(ForeignKey("devices.id"), unique=True)
    serial: Mapped[str] = mapped_column(String, unique=True)
    fingerprint: Mapped[str] = mapped_column(String, unique=True)
    pem: Mapped[str] = mapped_column(Text)
    not_before: Mapped[datetime] = mapped_column(DateTime)
    not_after: Mapped[datetime] = mapped_column(DateTime)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    device = relationship("Device", back_populates="certificate")


class WireGuardPeer(Base):
    __tablename__ = "wireguard_peers"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    device_id_fk: Mapped[str] = mapped_column(ForeignKey("devices.id"), unique=True)
    contour: Mapped[Contour] = mapped_column(Enum(Contour))
    public_key: Mapped[str] = mapped_column(String, unique=True, index=True)
    private_key: Mapped[str] = mapped_column(Text, default="")
    preshared_key: Mapped[str] = mapped_column(String)
    vpn_ip: Mapped[str] = mapped_column(String, unique=True)
    allowed_lans: Mapped[str] = mapped_column(String, default="")
    destination_cidrs: Mapped[str] = mapped_column(String, default="")
    client_config: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    link_up: Mapped[bool] = mapped_column(Boolean, default=False)
    handshake_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    endpoint: Mapped[str] = mapped_column(String, default="")
    endpoint_trace: Mapped[str] = mapped_column(Text, default="[]")
    rx_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    tx_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    device = relationship("Device", back_populates="peer")


class VpnRenewal(Base):
    __tablename__ = "vpn_renewals"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    user_id: Mapped[str] = mapped_column(String, index=True)
    device_id: Mapped[str] = mapped_column(String, index=True)
    status: Mapped[str] = mapped_column(String, default="PENDING")
    previous_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    requested_until: Mapped[datetime] = mapped_column(DateTime)
    created_by: Mapped[str] = mapped_column(String)
    reviewed_by: Mapped[str] = mapped_column(String, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class AccessPolicy(Base):
    __tablename__ = "access_policies"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    device_id_fk: Mapped[str] = mapped_column(ForeignKey("devices.id"))
    network_id: Mapped[str | None] = mapped_column(ForeignKey("networks.id"), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(ForeignKey("resources.id"), nullable=True)
    allowed: Mapped[bool] = mapped_column(Boolean, default=True)
    device = relationship("Device")
    network = relationship("Network")
    resource = relationship("Resource")


class AccessRequest(Base):
    __tablename__ = "access_requests"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    device_name: Mapped[str] = mapped_column(String)
    contour: Mapped[Contour] = mapped_column(Enum(Contour))
    site_id: Mapped[str | None] = mapped_column(ForeignKey("sites.id"), nullable=True)
    reason: Mapped[str] = mapped_column(Text, default="")
    memo: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[RequestStatus] = mapped_column(Enum(RequestStatus), default=RequestStatus.CREATED)
    access_from: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    access_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    enrollment_token: Mapped[str | None] = mapped_column(String, unique=True, nullable=True)
    created_by: Mapped[str] = mapped_column(String, default="")
    reviewed_by: Mapped[str] = mapped_column(String, default="")
    issued_device_id: Mapped[str | None] = mapped_column(String, nullable=True)
    networks_json: Mapped[list] = mapped_column(JSON, default=list)
    resources_json: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user = relationship("User")
    site = relationship("Site")
    documents = relationship("Document", back_populates="request")


class Document(Base):
    __tablename__ = "documents"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    request_id: Mapped[str | None] = mapped_column(ForeignKey("access_requests.id"), nullable=True)
    device_id_fk: Mapped[str | None] = mapped_column(ForeignKey("devices.id"), nullable=True)
    title: Mapped[str] = mapped_column(String)
    kind: Mapped[str] = mapped_column(String, default="OTHER")
    filename: Mapped[str] = mapped_column(String)
    content_type: Mapped[str] = mapped_column(String, default="application/octet-stream")
    path: Mapped[str] = mapped_column(String)
    uploaded_by: Mapped[str] = mapped_column(String, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    request = relationship("AccessRequest", back_populates="documents")


class Session(Base):
    __tablename__ = "sessions"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    device_id_fk: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    token: Mapped[str] = mapped_column(String, unique=True, index=True)
    external_ip: Mapped[str] = mapped_column(String, default="")
    geo: Mapped[str] = mapped_column(String, default="")
    agent_version: Mapped[str] = mapped_column(String, default="")
    attested_device_id: Mapped[str] = mapped_column(String)
    expires_at: Mapped[datetime]
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_heartbeat: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class SecurityEvent(Base):
    __tablename__ = "security_events"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    severity: Mapped[EventSeverity] = mapped_column(Enum(EventSeverity), default=EventSeverity.INFO)
    code: Mapped[str] = mapped_column(String, index=True)
    title: Mapped[str] = mapped_column(String)
    details: Mapped[str] = mapped_column(Text, default="")
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    device_id_fk: Mapped[str | None] = mapped_column(ForeignKey("devices.id"), nullable=True)
    public_key: Mapped[str] = mapped_column(String, default="")
    old_device_id: Mapped[str] = mapped_column(String, default="")
    new_device_id: Mapped[str] = mapped_column(String, default="")
    external_ip: Mapped[str] = mapped_column(String, default="")
    geo: Mapped[str] = mapped_column(String, default="")
    isp: Mapped[str] = mapped_column(String, default="")
    mac: Mapped[str] = mapped_column(String, default="")
    auto_blocked: Mapped[bool] = mapped_column(Boolean, default=False)
    archived_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    archived_by: Mapped[str] = mapped_column(String, default="", server_default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    actor_id: Mapped[str] = mapped_column(String, default="")
    actor_email: Mapped[str] = mapped_column(String, default="")
    action: Mapped[str] = mapped_column(String, index=True)
    target: Mapped[str] = mapped_column(String, default="")
    ip: Mapped[str] = mapped_column(String, default="")
    device: Mapped[str] = mapped_column(String, default="")
    vpn: Mapped[str] = mapped_column(String, default="")
    resource: Mapped[str] = mapped_column(String, default="")
    result: Mapped[str] = mapped_column(String, default="OK")
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    mac: Mapped[str] = mapped_column(String, default="")
    browser: Mapped[str] = mapped_column(String, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)


class Setting(Base):
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String, primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")


class EnrollmentNonce(Base):
    __tablename__ = "enrollment_nonces"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    token: Mapped[str] = mapped_column(String, unique=True)
    challenge: Mapped[str] = mapped_column(String)
    used: Mapped[bool] = mapped_column(Boolean, default=False)
    expires_at: Mapped[datetime]


class RevokedSession(Base):
    __tablename__ = "revoked_sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)


class FailedAuth(Base):
    __tablename__ = "failed_auths"
    __table_args__ = (UniqueConstraint("ip", "bucket"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    ip: Mapped[str] = mapped_column(String, index=True)
    bucket: Mapped[str] = mapped_column(String)
    count: Mapped[int] = mapped_column(Integer, default=1)
    last_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class TrafficSample(Base):
    __tablename__ = "traffic_samples"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    contour: Mapped[Contour] = mapped_column(Enum(Contour))
    rx_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    tx_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    captured_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)


class HostMetric(Base):
    """Снимок нагрузки и скорости каналов. История живёт в БД, не в браузере."""

    __tablename__ = "host_metrics"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    captured_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    load1: Mapped[float] = mapped_column(Float, default=0)
    load5: Mapped[float] = mapped_column(Float, default=0)
    load15: Mapped[float] = mapped_column(Float, default=0)
    cpu_percent: Mapped[float] = mapped_column(Float, default=0)
    mem_percent: Mapped[float] = mapped_column(Float, default=0)
    cpu_total: Mapped[int] = mapped_column(BigInteger, default=0)
    cpu_idle: Mapped[int] = mapped_column(BigInteger, default=0)
    wg_emp_rx: Mapped[int] = mapped_column(BigInteger, default=0)
    wg_emp_tx: Mapped[int] = mapped_column(BigInteger, default=0)
    wg_site_rx: Mapped[int] = mapped_column(BigInteger, default=0)
    wg_site_tx: Mapped[int] = mapped_column(BigInteger, default=0)
    nic_emp_rx: Mapped[int] = mapped_column(BigInteger, default=0)
    nic_emp_tx: Mapped[int] = mapped_column(BigInteger, default=0)
    nic_site_rx: Mapped[int] = mapped_column(BigInteger, default=0)
    nic_site_tx: Mapped[int] = mapped_column(BigInteger, default=0)
    wg_emp_rx_bps: Mapped[int] = mapped_column(BigInteger, default=0)
    wg_emp_tx_bps: Mapped[int] = mapped_column(BigInteger, default=0)
    wg_site_rx_bps: Mapped[int] = mapped_column(BigInteger, default=0)
    wg_site_tx_bps: Mapped[int] = mapped_column(BigInteger, default=0)
    nic_emp_rx_bps: Mapped[int] = mapped_column(BigInteger, default=0)
    nic_emp_tx_bps: Mapped[int] = mapped_column(BigInteger, default=0)
    nic_site_rx_bps: Mapped[int] = mapped_column(BigInteger, default=0)
    nic_site_tx_bps: Mapped[int] = mapped_column(BigInteger, default=0)
    nic_emp_mbps: Mapped[int] = mapped_column(Integer, default=0)
    nic_site_mbps: Mapped[int] = mapped_column(Integer, default=0)


class ResourceVisit(Base):
    """Обращение сотрудника к внутреннему ресурсу через WireGuard. История в БД."""

    __tablename__ = "resource_visits"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    device_id_fk: Mapped[str | None] = mapped_column(String, nullable=True)
    flow_key: Mapped[str] = mapped_column(String, index=True)
    resource_id: Mapped[str | None] = mapped_column(String, nullable=True)
    resource_name: Mapped[str] = mapped_column(String, default="")
    destination: Mapped[str] = mapped_column(String, default="")
    port: Mapped[int] = mapped_column(Integer, default=0)
    proto: Mapped[str] = mapped_column(String, default="tcp")
    opened_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    bytes_up: Mapped[int] = mapped_column(BigInteger, default=0)
    bytes_down: Mapped[int] = mapped_column(BigInteger, default=0)
