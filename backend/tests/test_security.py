"""Regression tests for the security audit; all identities and keys are temporary."""
import json
import ssl
import unittest
from unittest.mock import patch, MagicMock
from fastapi import HTTPException
import pyotp
import test_setup as baseline
from test_setup import ADMIN, SessionLocal, User, app, setup
from app import ad
from app.models import Setting
from app.schemas import AdSettingsIn, AdSourceIn
from app.security import create_token, SESSION_COOKIE, CSRF_COOKIE
from app.api.auth import _client_ip


class SecurityTests(unittest.TestCase):
    setUp = baseline.SetupTests.setUp
    tearDown = baseline.SetupTests.tearDown

    def claim(self):
        response = self.client.post('/api/setup/admin', json=ADMIN)
        self.assertEqual(response.status_code, 200, response.text)
        return self.client.cookies[SESSION_COOKIE]

    def csrf(self):
        return {'X-Fortis-CSRF': self.client.cookies[CSRF_COOKIE]}

    def finish(self):
        with SessionLocal() as db:
            setup.write(db, 'vpn_ready', True); db.commit()
        app.state.scheduler = MagicMock()
        with patch.object(setup, 'checks', return_value={'ready': True, 'checks': [], 'notice': 'test'}):
            result = self.client.post('/api/setup/finish', json={'enabled': False}, headers=self.csrf())
        self.assertEqual(result.status_code, 200, result.text)

    def login_totp(self):
        response = self.client.post('/api/auth/login', json={'email': ADMIN['email'], 'password': ADMIN['password']})
        self.assertEqual(response.status_code, 200, response.text)
        challenge = response.json()
        with SessionLocal() as db:
            secret = db.query(User).filter_by(email=ADMIN['email']).one().totp_secret
        return self.client.post('/api/auth/totp', json={'challenge': challenge['challenge'], 'code': pyotp.TOTP(secret).now()})

    def test_setup_credential_is_scoped_and_revoked_after_finish(self):
        original = self.claim()
        self.assertEqual(self.client.get('/api/setup/network').status_code, 200)
        self.assertEqual(self.client.get('/api/auth/me').status_code, 401)
        self.finish()
        self.assertNotIn(SESSION_COOKIE, self.client.cookies)
        headers = {'Authorization': 'Bearer ' + original}
        for url in ('/api/setup/network', '/api/settings/operations'):
            self.assertEqual(self.client.get(url, headers=headers).status_code, 401)
        with SessionLocal() as db:
            self.assertFalse(db.query(User).one().totp_confirmed)

    def test_cookie_login_2fa_reload_and_logout(self):
        self.claim(); self.finish()
        response = self.login_totp()
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()['token'], 'cookie-session')
        cookies = response.headers.get_list('set-cookie')
        self.assertTrue(any('fortis_session=' in v and 'HttpOnly' in v and 'SameSite=strict' in v for v in cookies))
        original = self.client.cookies[SESSION_COOKIE]
        self.assertEqual(self.client.get('/api/settings/operations').status_code, 200)
        with SessionLocal() as db:
            user = db.query(User).one()
            unverified = create_token(user)
        self.assertEqual(self.client.get('/api/settings/operations', headers={'Authorization': 'Bearer ' + unverified}).status_code, 401)
        self.assertEqual(self.client.post('/api/auth/logout', headers=self.csrf()).status_code, 200)
        self.assertEqual(self.client.get('/api/auth/me', headers={'Authorization': 'Bearer ' + original}).status_code, 401)

    def test_cookie_mutations_require_csrf_and_valid_origin(self):
        self.claim()
        url, body = '/api/setup/ad/check', {'enabled': False}
        self.assertEqual(self.client.post(url, json=body).status_code, 403)
        self.assertEqual(self.client.post(url, json=body, headers={'X-Fortis-CSRF': 'wrong'}).status_code, 403)
        self.assertEqual(self.client.post(url, json=body, headers={**self.csrf(), 'Origin': 'https://attacker.example'}).status_code, 403)
        self.assertEqual(self.client.post(url, json=body, headers=self.csrf()).status_code, 200)
        self.assertEqual(self.client.post(url, json=body, headers={**self.csrf(), 'Origin': 'http://testserver'}).status_code, 200)

    def test_initial_login_and_claim_reject_cross_origin_and_unknown_host(self):
        self.assertEqual(self.client.post('/api/setup/admin', json=ADMIN, headers={'Origin': 'https://attacker.example'}).status_code, 403)
        self.assertEqual(self.client.post('/api/setup/admin', json=ADMIN, headers={'Host': 'attacker.example'}).status_code, 400)
        self.assertFalse(self.client.get('/api/setup/status').json()['adminCreated'])

    def test_security_headers_and_range_limit(self):
        response = self.client.get('/')
        self.assertEqual(response.headers['x-frame-options'], 'DENY')
        self.assertEqual(response.headers['x-content-type-options'], 'nosniff')
        self.assertIn("script-src 'self';", response.headers['content-security-policy'])
        self.assertEqual(self.client.get('/', headers={'Range': 'bytes=' + ','.join(['0-1'] * 17)}).status_code, 416)

    def test_https_session_cookie_is_secure(self):
        self.client.base_url = 'https://testserver'
        response = self.client.post('/api/setup/admin', json=ADMIN)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(any('fortis_session=' in value and 'Secure' in value and 'HttpOnly' in value
                            for value in response.headers.get_list('set-cookie')))
        self.assertIn('max-age=', response.headers['strict-transport-security'])

    def test_regular_login_cannot_enter_administration(self):
        from app.models import Role
        from app.security import hash_password
        self.claim(); self.finish()
        with SessionLocal() as db:
            db.add(User(full_name='Ordinary test user', email='ordinary@example.test', role=Role.USER,
                        password_hash=hash_password('Test-Only-Password-2026')))
            db.commit()
        response = self.client.post('/api/auth/login', json={'email': 'ordinary@example.test', 'password': 'Test-Only-Password-2026'})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()['token'], 'cookie-session')
        self.assertEqual(self.client.get('/api/auth/me').status_code, 200)
        for url in ('/api/settings/operations', '/api/setup/network', '/api/setup/ad'):
            self.assertEqual(self.client.get(url).status_code, 403)

    def test_ip_header_cannot_change_rate_limit_identity(self):
        request = MagicMock(); request.client.host = '127.0.0.1'
        request.headers = {'x-real-ip': '203.0.113.99', 'x-forwarded-for': '203.0.113.99'}
        self.assertEqual(_client_ip(request), '127.0.0.1')

    def test_ad_password_is_encrypted_migrated_and_publicly_redacted(self):
        password = 'TEST-ONLY-AD-PASSWORD'
        with SessionLocal() as db:
            source = AdSourceIn(host='dc.example.test', port=636, useSsl=True, bindDn='service@example.test',
                                password=password, baseDn='DC=example,DC=test')
            public = ad.save_settings(db, AdSettingsIn(sources=[source]))
            for row in db.query(Setting):
                self.assertNotIn(password, row.value)
            self.assertNotIn(password, json.dumps(public))
            self.assertEqual(ad._load_sources(db)[0]['password'], password)
            key = ad.settings.data_dir / 'secrets' / 'ad.key'
            self.assertEqual(key.stat().st_mode & 0o777, 0o600)
            legacy = ad._load_sources(db)
            ad._put(db, 'ad_sources', json.dumps(legacy)); ad._put(db, 'ad_bind_password', password); db.commit()
            ad.migrate_secret_storage(db)
            self.assertEqual(ad._load_sources(db)[0]['password'], password)
            self.assertFalse(any(password in row.value for row in db.query(Setting)))
            backup = key.with_suffix('.saved'); key.rename(backup)
            try:
                with self.assertRaises(RuntimeError): ad._load_sources(db)
                self.assertFalse(key.exists())
            finally:
                backup.rename(key)

    def test_ad_requires_verified_tls_before_credentials_and_has_no_plain_fallback(self):
        from ldap3 import AUTO_BIND_TLS_BEFORE_BIND, AUTO_BIND_NO_TLS
        from ldap3.core.exceptions import LDAPException
        source = {'host': 'dc.example.test', 'port': 636, 'useSsl': True, 'bindDn': 'service@example.test',
                  'password': 'TEST-ONLY', 'baseDn': 'DC=example,DC=test'}
        for secure in (True, False):
            with patch.object(ad, 'Server') as server, patch.object(ad, 'Connection', return_value=MagicMock()) as connect:
                ad._connect_source({**source, 'useSsl': secure})
                tls = server.call_args.kwargs['tls']
                self.assertEqual(tls.validate, ssl.CERT_REQUIRED)
                self.assertEqual(tls.valid_names, [source['host']])
                self.assertEqual(connect.call_args.kwargs['auto_bind'], AUTO_BIND_NO_TLS if secure else AUTO_BIND_TLS_BEFORE_BIND)
            with patch.object(ad, 'Connection', side_effect=LDAPException('TLS failure')) as connect:
                with self.assertRaises(HTTPException): ad._connect_source({**source, 'useSsl': secure})
                connect.assert_called_once()

    def test_actual_tls_accepts_trusted_name_and_rejects_untrusted_or_wrong_name(self):
        import socket
        import tempfile
        import threading
        from pathlib import Path
        from datetime import datetime, timedelta, timezone
        from types import SimpleNamespace
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        with tempfile.TemporaryDirectory(prefix='fortis-tls-test-') as directory:
            root = Path(directory)
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'dc.example.test')])
            now = datetime.now(timezone.utc)
            certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                           .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1))
                           .not_valid_after(now+timedelta(hours=1))
                           .add_extension(x509.SubjectAlternativeName([x509.DNSName('dc.example.test')]), critical=False)
                           .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256()))
            cert = root/'cert.pem'; private = root/'key.pem'
            cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
            private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(cert, private)
            for hostname, trusted in (('dc.example.test', True), ('wrong.example.test', True), ('dc.example.test', False)):
                with self.subTest(hostname=hostname, trusted=trusted):
                    listener = socket.socket(); listener.bind(('127.0.0.1', 0)); listener.listen(1); listener.settimeout(3)
                    def serve():
                        try:
                            connection, _ = listener.accept()
                            with connection:
                                try:
                                    with context.wrap_socket(connection, server_side=True): pass
                                except ssl.SSLError: pass
                        finally: listener.close()
                    worker = threading.Thread(target=serve); worker.start()
                    source = {'host': hostname, 'port': 636, 'useSsl': True, 'bindDn': 'service@example.test',
                              'password': 'TEST-ONLY', 'baseDn': 'DC=example,DC=test'}
                    def connect(server, **kwargs):
                        raw = socket.create_connection(listener.getsockname(), timeout=3)
                        connection = SimpleNamespace(socket=raw, server=server)
                        try:
                            server.tls.wrap_socket(connection, do_handshake=True)
                            return MagicMock()
                        finally:
                            connection.socket.close(); raw.close()
                    try:
                        with patch.object(ad.settings, 'ad_ca_file', str(cert) if trusted else ''), patch.object(ad, 'Connection', side_effect=connect):
                            if hostname == 'dc.example.test' and trusted:
                                self.assertEqual(ad._connect_source(source)[1], source['baseDn'])
                            else:
                                with self.assertRaises((HTTPException, ssl.SSLError)): ad._connect_source(source)
                    finally:
                        worker.join(timeout=4)
                        self.assertFalse(worker.is_alive())
