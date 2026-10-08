"""Regression cases for revocation, proxy trust and quarantined features."""
import asyncio
import unittest
from unittest.mock import patch, MagicMock
import pyotp
import test_security as prior
from test_setup import ADMIN, SessionLocal, User
from app.security import SESSION_COOKIE
from app.config import settings


class FollowupSecurityTests(unittest.TestCase):
    setUp = prior.SecurityTests.setUp
    tearDown = prior.SecurityTests.tearDown
    claim = prior.SecurityTests.claim
    csrf = prior.SecurityTests.csrf
    finish = prior.SecurityTests.finish
    login_totp = prior.SecurityTests.login_totp

    def test_password_change_revokes_session_and_pending_challenge(self):
        self.claim(); self.finish(); self.assertEqual(self.login_totp().status_code, 200)
        original = self.client.cookies[SESSION_COOKIE]
        challenge = self.client.post('/api/auth/login', json={'email': ADMIN['email'], 'password': ADMIN['password']}, headers=self.csrf()).json()['challenge']
        with SessionLocal() as db:
            user = db.query(User).one(); uid = user.id; secret = user.totp_secret
        response = self.client.patch('/api/users/' + uid, json={'password': 'Changed-test-password-2026'}, headers=self.csrf())
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(self.client.get('/api/auth/me', headers={'Authorization': 'Bearer ' + original}).status_code, 401)
        self.assertEqual(self.client.post('/api/auth/totp', json={'challenge': challenge, 'code': pyotp.TOTP(secret).now()}, headers=self.csrf()).status_code, 401)
        response = self.client.post('/api/auth/login', json={'email': ADMIN['email'], 'password': 'Changed-test-password-2026'}, headers=self.csrf())
        self.assertTrue(response.json()['totpRequired'])

    def test_mfa_reset_revokes_session(self):
        self.claim(); self.finish(); self.assertEqual(self.login_totp().status_code, 200)
        original = self.client.cookies[SESSION_COOKIE]
        with SessionLocal() as db:
            uid = db.query(User).one().id
        response = self.client.post('/api/users/' + uid + '/totp', json={'reset': True}, headers=self.csrf())
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(self.client.get('/api/auth/me', headers={'Authorization': 'Bearer ' + original}).status_code, 401)
        response = self.client.post('/api/auth/login', json={'email': ADMIN['email'], 'password': ADMIN['password']}, headers=self.csrf())
        self.assertTrue(response.json()['totpSetup'])

    def test_geoip_never_discloses_client_ips(self):
        from app.geo import lookup_place
        with patch('urllib.request.urlopen') as transport:
            for value in ('8.8.8.8', '172.16.0.1', '172.31.255.255', '::1', 'fd00::1', '2001:4860:4860::8888', 'invalid/path'):
                lookup_place(value)
            transport.assert_not_called()
        self.assertEqual(lookup_place('172.31.1.1'), ('LAN', ''))

    def test_agent_endpoints_remain_disabled_with_legacy_flag(self):
        self.claim(); self.finish()
        for mode in (True, False):
            with patch.object(settings, 'standard_wireguard', mode):
                self.assertEqual(self.client.get('/api/agent/ca').status_code, 410 if mode else 403)
                self.assertEqual(self.client.post('/api/device/register', json={}).status_code, 410 if mode else 403)

    def test_resource_permission_does_not_grant_all_ports(self):
        from app.models import Resource, Device, AccessPolicy, Contour, Network
        from app.nft import _cidrs_for_device
        with SessionLocal() as db:
            device = Device(name='ACL test', device_id='resource-test', contour=Contour.EMPLOYEES)
            resource = Resource(name='HTTPS only', host='192.0.2.20', port=443, contour=Contour.EMPLOYEES)
            db.add_all([device, resource]); db.flush()
            db.add(AccessPolicy(device_id_fk=device.id, resource_id=resource.id, allowed=True)); db.flush()
            self.assertEqual(_cidrs_for_device(db, device), [])
            network = Network(name='Explicit network', cidr='192.0.2.0/24', contour=Contour.EMPLOYEES)
            db.add(network); db.flush()
            db.add(AccessPolicy(device_id_fk=device.id, network_id=network.id, allowed=True)); db.flush()
            self.assertEqual(_cidrs_for_device(db, device), ['192.0.2.0/24'])
            db.rollback()

    def test_audit_ignores_forged_headers(self):
        from app.audit import client_context
        request = MagicMock(); request.client.host = '127.0.0.1'
        request.headers = {'x-real-ip': '203.0.113.99', 'user-agent': 'Firefox/100'}
        self.assertEqual(client_context(request)[0], '127.0.0.1')

    def test_proxy_requires_explicit_trust_and_single_ip(self):
        from app.http_security import ClientIpMiddleware
        recorded = []
        async def next_app(scope, receive, send):
            recorded.append(scope['client'][0])
        middleware = ClientIpMiddleware(next_app)
        async def run(peer, values):
            await middleware({'type': 'http', 'client': (peer, 1234), 'headers': [(b'x-real-ip', v.encode()) for v in values]}, None, None)
        with patch.object(settings, 'trusted_proxy_ips', ''):
            asyncio.run(run('127.0.0.1', ['203.0.113.99']))
        with patch.object(settings, 'trusted_proxy_ips', '127.0.0.1/32'):
            asyncio.run(run('127.0.0.1', ['203.0.113.99']))
            asyncio.run(run('192.0.2.2', ['203.0.113.99']))
            asyncio.run(run('127.0.0.1', ['203.0.113.99, 8.8.8.8']))
            asyncio.run(run('127.0.0.1', ['203.0.113.99', '8.8.8.8']))
        self.assertEqual(recorded, ['127.0.0.1', '203.0.113.99', '192.0.2.2', '127.0.0.1', '127.0.0.1'])

    def test_legacy_resource_flows_drop_before_established_accept(self):
        from app.models import Resource, Device, DeviceStatus, AccessPolicy, Contour, WireGuardPeer
        from app.nft import render_ruleset
        with SessionLocal() as db:
            device = Device(name='Legacy resource test', device_id='legacy-resource-test', contour=Contour.EMPLOYEES, status=DeviceStatus.ACTIVE)
            resource = Resource(name='Legacy HTTPS', host='192.0.2.20', port=443, contour=Contour.EMPLOYEES)
            db.add_all([device, resource]); db.flush()
            db.add(AccessPolicy(device_id_fk=device.id, resource_id=resource.id, allowed=True))
            db.add(WireGuardPeer(device_id_fk=device.id, contour=Contour.EMPLOYEES, public_key='test-public-key', preshared_key='test-psk', vpn_ip='10.80.0.2', enabled=True)); db.flush()
            with patch.object(settings, 'employees_enabled', True), patch.object(settings, 'employees_if', 'wg-employees'):
                rules = render_ruleset(db)
            drop = 'iifname "wg-employees" ip saddr 10.80.0.2 ip daddr 192.0.2.20 drop'
            self.assertEqual(rules.count(drop), 2)
            for chain in ('input', 'forward'):
                body = rules.split('chain ' + chain + ' {')[1].split('  }')[0]
                self.assertLess(body.index(drop), body.index('ct state established,related accept'))
            self.assertNotIn('ip daddr 192.0.2.20/32 accept', rules)
            db.rollback()

    def test_resource_requests_and_legacy_issuance_fail_closed(self):
        from fastapi import HTTPException
        from types import SimpleNamespace
        from app.api.requests import _issue_row
        self.claim(); self.finish(); self.assertEqual(self.login_totp().status_code, 200)
        with SessionLocal() as db:
            uid = db.query(User).one().id
        response = self.client.post('/api/requests', json={'userId': uid, 'deviceName': 'Test device', 'contour': 'EMPLOYEES', 'resourceIds': ['legacy-resource']}, headers=self.csrf())
        self.assertEqual(response.status_code, 422, response.text)
        with self.assertRaises(HTTPException) as denied:
            from app.models import Contour
            with SessionLocal() as db:
                _issue_row(db, SimpleNamespace(resources_json=['legacy-resource'], contour=Contour.EMPLOYEES), 'test')
        self.assertEqual(denied.exception.status_code, 422)
