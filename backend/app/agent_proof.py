"""Agent protocol v2: expiring, one-use RSA-PSS proof over the full request."""
import base64
import hashlib
import json
import secrets
from datetime import datetime, timezone, timedelta
import jwt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import HTTPException
from .config import settings
from .ca import CorporateCA
from .models import DeviceCertificate, RevokedSession


def canonical(action, payload):
    return json.dumps({'protocol': 'fortis-agent-v2', 'action': action, 'payload': payload},
                      sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()


def identity(db, pem):
    try:
        cert = CorporateCA().verify_device_cert(pem)
        fingerprint = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
        row = db.query(DeviceCertificate).filter_by(fingerprint=fingerprint, revoked=False).one_or_none()
        if not row or not row.device or not row.device.peer:
            raise ValueError('unknown certificate')
        return row, cert
    except Exception as exc:
        raise HTTPException(403, 'Сертификат устройства отклонён') from exc


def challenge(db, pem):
    row, _ = identity(db, pem)
    now = datetime.now(timezone.utc)
    token = jwt.encode({'purpose': 'agent-proof-v2', 'sub': row.device_id_fk, 'fingerprint': row.fingerprint,
                        'jti': secrets.token_urlsafe(32), 'iat': now, 'exp': now + timedelta(seconds=120)},
                       settings.secret_key, algorithm='HS256')
    return {'challenge': token, 'expiresIn': 120, 'algorithm': 'RSA-PSS-SHA256', 'protocol': 2}


def prove(db, action, payload, pem=None):
    try:
        data = jwt.decode(payload.challenge, settings.secret_key, algorithms=['HS256'],
                          options={'require': ['exp', 'iat', 'jti', 'sub', 'fingerprint', 'purpose']})
        if data['purpose'] != 'agent-proof-v2':
            raise ValueError('purpose')
        if pem is None:
            row = db.query(DeviceCertificate).filter_by(fingerprint=data['fingerprint'], revoked=False).one_or_none()
            if not row:
                raise ValueError('unknown certificate')
            pem = row.pem
        row, cert = identity(db, pem)
        if row.device_id_fk != data['sub'] or row.fingerprint != data['fingerprint']:
            raise ValueError('binding')
        key = cert.public_key()
        if not isinstance(key, rsa.RSAPublicKey):
            raise ValueError('algorithm')
        signature = base64.b64decode(payload.signature, validate=True)
        key.verify(signature, canonical(action, payload.model_dump(exclude={'signature'})),
                   padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH), hashes.SHA256())
        token_hash = hashlib.sha256(payload.challenge.encode()).hexdigest()
        db.query(RevokedSession).filter(RevokedSession.expires_at < datetime.now(timezone.utc).replace(tzinfo=None)).delete(synchronize_session=False)
        db.add(RevokedSession(token_hash=token_hash, expires_at=datetime.fromtimestamp(data['exp'], timezone.utc).replace(tzinfo=None)))
        db.commit()  # Unique hash serializes concurrent replay attempts before network changes.
        return row.device_id_fk
    except HTTPException:
        raise
    except Exception as exc:
        db.rollback()
        raise HTTPException(403, 'Подпись недействительна, запрос истёк или уже использован') from exc
