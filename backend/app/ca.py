from __future__ import annotations

import hashlib
import fcntl
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

from .config import settings


def _now() -> datetime:
    return datetime.now(timezone.utc)


class CorporateCA:
    def __init__(self, ca_dir: Path | None = None):
        self.ca_dir = ca_dir or settings.ca_dir
        self.ca_dir.mkdir(parents=True, exist_ok=True)
        self.key_path = self.ca_dir / "ca.key"
        self.cert_path = self.ca_dir / "ca.crt"
        self._ensure()

    def _ensure(self) -> None:
        # Serialize first issuance across threads/processes; never silently replace a lost CA.
        with (self.ca_dir / '.ca.lock').open('a') as lock:
            os.chmod(lock.name, 0o600)
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            if self.key_path.exists() or self.cert_path.exists():
                if not (self.key_path.exists() and self.cert_path.exists()):
                    raise RuntimeError('CA incomplete: restore its matching key and certificate from backup')
                if self.key.public_key().public_numbers() != self.cert.public_key().public_numbers():
                    raise RuntimeError('CA key/certificate mismatch')
                return
            self._generate()

    @staticmethod
    def _atomic(path, data):
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
            temp = Path(stream.name)
            try:
                os.chmod(temp, 0o600)
                stream.write(data); stream.flush(); os.fsync(stream.fileno())
                os.replace(temp, path)
            finally:
                temp.unlink(missing_ok=True)

    def _generate(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "RU"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FORTIS Corporate CA"),
                x509.NameAttribute(NameOID.COMMON_NAME, "FORTIS Device Root"),
            ]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_now() - timedelta(minutes=5))
            .not_valid_after(_now() + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )
        self._atomic(self.key_path, key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
        self._atomic(self.cert_path, cert.public_bytes(serialization.Encoding.PEM))

    @property
    def key(self):
        return serialization.load_pem_private_key(self.key_path.read_bytes(), password=None)

    @property
    def cert(self) -> x509.Certificate:
        return x509.load_pem_x509_certificate(self.cert_path.read_bytes())

    def ca_pem(self) -> str:
        return self.cert_path.read_text()

    def issue_device_cert(self, common_name: str, days: int = 730) -> tuple[str, str, str, datetime, datetime]:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "RU"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FORTIS"),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name[:64]),
            ]
        )
        nb = _now() - timedelta(minutes=1)
        na = _now() + timedelta(days=days)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(nb)
            .not_valid_after(na)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
            .sign(self.key, hashes.SHA256())
        )
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ).decode()
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        serial = format(cert.serial_number, "x")
        fingerprint = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
        return cert_pem, key_pem, serial, fingerprint, nb.replace(tzinfo=None), na.replace(tzinfo=None)

    def verify_device_cert(self, cert_pem: str) -> x509.Certificate:
        from cryptography.hazmat.primitives.asymmetric import padding

        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        self.cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        now = _now()
        if cert.not_valid_before_utc > now or cert.not_valid_after_utc < now:
            raise ValueError("Срок сертификата устройства истёк или ещё не начался")
        return cert


ca = CorporateCA
