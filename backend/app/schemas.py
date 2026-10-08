from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal

from email_validator import validate_email
from pydantic import AfterValidator, BaseModel, Field, StringConstraints


def _contact_email(value: str) -> str:
    # Optional contact data, never an authentication identifier. No DNS lookup.
    return validate_email(value, check_deliverability=False).normalized if value else ""


ProviderName = Annotated[str, StringConstraints(strip_whitespace=True, max_length=200)]
ContactPhone = Annotated[str, StringConstraints(strip_whitespace=True, max_length=64)]
ContactEmail = Annotated[str, StringConstraints(strip_whitespace=True, max_length=254), AfterValidator(_contact_email)]


class APIError(BaseModel):
    code: str
    message: str
    details: Any | None = None


class LoginIn(BaseModel):
    email: str
    password: str


class TokenOut(BaseModel):
    token: str
    role: str
    fullName: str
    email: str


class LoginOut(BaseModel):
    token: str = ""
    role: str = ""
    fullName: str = ""
    email: str = ""
    totpRequired: bool = False
    totpSetup: bool = False
    challenge: str = ""
    qr: str = ""
    secret: str = ""
    blocked: bool = False
    blockedBy: str = ""


class TotpIn(BaseModel):
    challenge: str
    code: str


class TotpBindIn(BaseModel):
    reset: bool = False


class TotpCodeIn(BaseModel):
    code: str


class UserPatch(BaseModel):
    isManagement: bool | None = None
    rdpHost: str | None = None
    rdpPort: int | None = None
    rdpUser: str | None = None
    rdpPassword: str | None = None
    rdpSavePassword: bool | None = None
    fullName: str | None = None
    email: str | None = None
    password: str | None = None
    role: str | None = None


class UserIn(BaseModel):
    isManagement: bool = False
    rdpHost: str = ""
    rdpPort: int = 3389
    rdpUser: str = ""
    rdpPassword: str = ""
    rdpSavePassword: bool = True
    fullName: str
    email: str = ""
    title: str = ""
    role: str = "USER"
    companyId: str | None = None
    departmentId: str | None = None
    companyName: str | None = None
    departmentName: str | None = None
    password: str | None = None
    deviceName: str = ""
    osName: str = ""
    accessDays: int | None = None


class CompanyIn(BaseModel):
    name: str


class DepartmentIn(BaseModel):
    name: str
    companyId: str | None = None


class DeviceVerifyIn(BaseModel):
    certificatePem: str
    systemIdentifier: str
    mac: str = ""
    wireguardPublicKey: str
    deviceName: str = ""
    osName: str = ""
    clientVersion: str = "1.0.0"
    userEmail: str = ""


class HeartbeatIn(BaseModel):
    sessionToken: str


class EnrollIn(BaseModel):
    token: str
    systemIdentifier: str
    macEthernet: str = ""
    macWifi: str = ""
    osName: str = ""
    serial: str = ""
    deviceName: str = ""
    wireguardPublicKey: str


class RequestIn(BaseModel):
    userId: str
    deviceName: str
    contour: Literal["EMPLOYEES", "SITES"]
    siteId: str | None = None
    reason: str = ""
    memo: str = ""
    accessFrom: datetime | None = None
    accessUntil: datetime | None = None
    networkIds: list[str] = Field(default_factory=list)
    resourceIds: list[str] = Field(default_factory=list)


class SiteIn(BaseModel):
    name: str
    address: str = ""
    lanCidr: str = ""
    routerName: str = ""
    providerName: ProviderName = ""
    providerPhone: ContactPhone = ""
    providerEmail: ContactEmail = ""
    ownerId: str | None = None
    companyId: str | None = None
    companyName: str | None = None
    notes: str = ""
    issueVpn: bool = True
    reason: str = ""
    osName: str = ""
    accessDays: int | None = None


class NetworkIn(BaseModel):
    name: str
    cidr: str
    contour: Literal["EMPLOYEES", "SITES"]
    description: str = ""
    isRestricted: bool = False


class ResourceIn(BaseModel):
    name: str
    kind: str = "SERVICE"
    host: str
    port: int | None = None
    networkId: str | None = None
    contour: Literal["EMPLOYEES", "SITES"]
    description: str = ""


class AdSourceIn(BaseModel):
    id: str = ""
    host: str = ""
    port: int = 389
    useSsl: bool = False
    bindDn: str = ""
    password: str = ""
    baseDn: str = ""


class AdSettingsIn(BaseModel):
    revision: str | None = None
    sources: list[AdSourceIn] = []
    host: str = ""
    port: int = 389
    useSsl: bool = False
    bindDn: str = ""
    password: str = ""
    baseDn: str = ""


class SettingsIn(BaseModel):
    concurrentPolicy: str | None = None
    macPolicy: str | None = None
    telegramChatId: str | None = None
    webhookUrl: str | None = None
    securityNotifyEmail: str | None = None
