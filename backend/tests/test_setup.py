"""Run with: python -m unittest discover -s tests -v (isolated storage)."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock
from types import SimpleNamespace

STORAGE = tempfile.TemporaryDirectory(prefix="kontur-setup-tests-")
os.environ["DATA_DIR"] = STORAGE.name
os.environ.pop("DATABASE_URL", None)
os.environ.pop("PANEL_GATE_ENABLED", None)
from fastapi.testclient import TestClient
from app.main import app
from app import setup
from app.db import SessionLocal
from app.models import Setting, User
from app.security import verify_password

ADMIN = {"fullName": "Test Administrator", "email": "admin@example.com", "password": "Setup-test-phrase-2026"}
CONFIG = {
    "employees": {"name": "wg-employees", "subnet": "10.80.0.0/24", "port": 51820, "uplink": "eth0", "endpoint": "127.0.0.1"},
    "sites": {"name": "wg-sites", "subnet": "10.81.0.0/24", "port": 51821, "uplink": "eth1", "endpoint": "127.0.0.1"},
}


class SetupTests(unittest.TestCase):
    def setUp(self):
        from app.models import Base
        from app.db import engine
        Base.metadata.create_all(engine)
        with SessionLocal() as db:
            db.query(Setting).delete()
            db.query(User).delete()
            db.commit()
        app.state.scheduler = None
        self.client = TestClient(app)
        self.client.__enter__()
        self.headers = {}
        self.client.post("/api/setup/network/cancel", headers=self.headers)

    def tearDown(self):
        self.client.__exit__(None, None, None)
        app.state.scheduler = None

    def create(self):
        r = self.client.post("/api/setup/admin", json=ADMIN)
        self.assertEqual(r.status_code, 200, r.text)
        self.headers = {"Authorization": "Bearer " + self.client.cookies.get("fortis_session")}
        self.client.cookies.clear()

    def save(self, config=CONFIG):
        return self.client.put("/api/setup/interfaces", json=config, headers=self.headers)

    def test_fresh_install_password_and_duplicate(self):
        state = self.client.get("/api/setup/status").json()
        self.assertFalse(state["adminCreated"])
        self.assertFalse(state["completed"])
        self.assertFalse(state["runtimeActive"])
        self.assertEqual(self.client.get("/api/dashboard").status_code, 503)
        self.create()
        with SessionLocal() as db:
            user = db.query(User).one()
            self.assertNotEqual(user.password_hash, ADMIN["password"])
            self.assertTrue(verify_password(ADMIN["password"], user.password_hash))
            self.assertEqual(user.role.value, "ADMIN")
        self.assertEqual(self.client.post("/api/setup/admin", json=ADMIN).status_code, 409)

    def test_auth_and_remote_claim(self):
        self.assertEqual(self.client.get("/api/setup/checks").status_code, 401)
        self.assertEqual(self.client.post("/api/setup/admin", json=ADMIN, headers={"X-Forwarded-For": "203.0.113.5"}).status_code, 403)
        self.assertEqual(self.client.post("/api/setup/admin", json={**ADMIN, "password": "short"}).status_code, 422)
        self.assertEqual(self.client.post("/api/setup/admin", json={**ADMIN, "password": "я" * 40}).status_code, 422)
        self.create()
        self.assertEqual(self.client.put("/api/setup/interfaces", json=CONFIG).status_code, 401)

    def test_validation_and_persistence(self):
        self.create()
        for field, value in (("port", 0), ("port", 65536), ("subnet", "10.80.0.1/24"), ("subnet", "0.0.0.0/0"), ("subnet", "127.0.0.0/24"), ("name", "wg0;reboot"), ("endpoint", "https://host")):
            cfg = json.loads(json.dumps(CONFIG)); cfg["employees"][field] = value
            self.assertEqual(self.save(cfg).status_code, 422, (field, value))
        cfg = json.loads(json.dumps(CONFIG)); cfg["sites"]["subnet"] = "10.80.0.0/25"
        self.assertEqual(self.save(cfg).status_code, 422)
        cfg = json.loads(json.dumps(CONFIG)); cfg["sites"]["port"] = 51820
        self.assertEqual(self.save(cfg).status_code, 422)
        self.assertEqual(self.save().status_code, 200)
        self.assertEqual(self.client.get("/api/setup/interfaces", headers=self.headers).json(), CONFIG)
        with SessionLocal() as db:
            setup.load_interfaces(db)
            self.assertEqual(setup.settings.employees_server_ip, "10.80.0.1")
        # Simulate a fresh process reading persisted state.
        with TestClient(app) as again:
            self.assertTrue(again.get("/api/setup/status").json()["adminCreated"])
            self.assertFalse(again.get("/api/setup/status").json()["completed"])
            self.assertEqual(again.get("/api/setup/interfaces", headers=self.headers).json(), CONFIG)

    def test_failed_preflight_does_not_change_network(self):
        self.create(); self.save()
        with patch.object(setup.platform, "system", return_value="Darwin"), patch.object(setup, "activate_interfaces") as activate:
            response = self.client.post("/api/setup/start", json={}, headers=self.headers)
            self.assertEqual(response.status_code, 200)
            self.assertFalse(response.json()["completed"])
            self.assertFalse(response.json()["ready"])
            activate.assert_not_called()
        self.assertFalse(self.client.get("/api/setup/status").json()["completed"])

    def test_completion_requires_runtime_and_firewall(self):
        self.create(); self.save()
        good = {"ready": True, "checks": [], "notice": "test"}
        with patch.object(setup, "checks", return_value=good), patch.object(setup, "activate_interfaces"), patch("app.main.start_runtime"), patch.object(setup, "run", return_value=""):
            response = self.client.post("/api/setup/start", json={}, headers=self.headers).json()
            self.assertFalse(response["completed"])
        with patch.object(setup, "checks", return_value=good), patch.object(setup, "activate_interfaces"), patch("app.main.start_runtime", side_effect=lambda app: setattr(app.state, "scheduler", MagicMock())), patch.object(setup, "run", return_value=""):
            response = self.client.post("/api/setup/start", json={}, headers=self.headers).json()
            self.assertTrue(response["serverReady"])
            self.assertFalse(response["completed"])
            finished = self.client.post("/api/setup/finish", json={"enabled": False}, headers=self.headers)
            self.assertEqual(finished.status_code, 200, finished.text)
            self.assertTrue(finished.json()["completed"])
            self.assertTrue(self.client.get("/api/setup/status").json()["completed"])
            self.assertEqual(self.save().status_code, 401)
            self.assertEqual(self.client.post("/api/setup/start", json={}, headers=self.headers).status_code, 401)
        app.state.scheduler = None

    def test_linux_preflight_detects_overlap_and_occupied_port(self):
        self.create(); self.save()
        route = [{"dev": "eth0", "dst": "192.168.5.0/24"}]
        def execute(*args):
            if args == ("wg", "show", "interfaces"):
                return ""
            if args[:5] == ("ip", "-j", "-4", "route", "show"):
                return json.dumps(route)
            return json.dumps([{"ifname": "eth0", "flags": ["UP"]}])
        with patch.object(setup.platform, "system", return_value="Linux"), patch.object(setup.os, "geteuid", return_value=0), patch.object(setup.shutil, "which", return_value="/usr/bin/tool"), patch.object(setup, "run", side_effect=execute), patch.object(setup.socket, "socket") as sock:
            with SessionLocal() as db:
                self.assertTrue(setup.checks(db)["ready"])
                route[:] = [{"dev": "eth0", "dst": "10.80.0.0/24"}]
                self.assertFalse(setup.checks(db)["ready"])
                route[:] = []
                sock.return_value.__enter__.return_value.bind.side_effect = OSError("port busy")
                self.assertFalse(setup.checks(db)["ready"])

    def test_secret_is_persistent_and_private(self):
        from app.config import local_secret
        key = Path(STORAGE.name) / "secret.key"
        self.assertEqual(key.stat().st_mode & 0o777, 0o600)
        self.assertGreater(len(local_secret()), 40)
        self.assertEqual(local_secret(), setup.settings.secret_key)

    def test_custom_subnet_and_ports_reach_client_and_firewall(self):
        self.create()
        cfg = json.loads(json.dumps(CONFIG))
        cfg["sites"]["subnet"] = "10.81.0.0/26"
        cfg["sites"]["port"] = 54321
        cfg["employees"]["port"] = 54320
        self.assertEqual(self.save(cfg).status_code, 200)
        from app.wireguard import client_config
        from app.models import Contour
        from app.nft import render_ruleset
        client = client_config(private_key="TEST", address="10.81.0.2", contour=Contour.SITES, server_public="TEST", psk="TEST")
        self.assertIn("Address = 10.81.0.2/26", client)
        self.assertIn("Endpoint = 127.0.0.1:54321", client)
        with SessionLocal() as db:
            firewall = render_ruleset(db)
            self.assertIn("udp dport 54320", firewall)
            self.assertIn("udp dport 54321", firewall)
            self.assertIn("10.81.0.0/26", firewall)
        from app import engine as runtime
        db = MagicMock()
        db.query.return_value.all.return_value = [SimpleNamespace(vpn_ip="10.80.0.2", device=SimpleNamespace(user_id="test", id="device", site_id=None))]
        db.query.return_value.filter.return_value.all.return_value = []
        flows = [{"src": "10.80.0.2", "dst": "10.81.0.2", "dport": port} for port in (53, 54320, 54321)]
        with patch.object(runtime, "_internal_targets", return_value=["test"]), patch.object(runtime, "_conntrack_flows", return_value=flows), patch.object(runtime, "_match_target") as matcher:
            runtime.record_resource_visits(db)
            matcher.assert_not_called()

    def test_wireguard_files_permissions_and_rollback(self):
        self.create(); self.save()
        directory = Path(STORAGE.name) / "wireguard"
        directory.mkdir(exist_ok=True)
        forward = Path(STORAGE.name) / "forward"
        forward.write_text("0")
        calls = []
        def execute(*args):
            calls.append(args)
            if args == ("wg", "genkey"):
                return "TEST-PRIVATE-KEY"
            if args == ("wg-quick", "up", "wg-sites"):
                raise RuntimeError("second interface failed")
            return ""
        with SessionLocal() as db, patch.object(setup, "WG_DIR", directory), patch.object(setup, "FORWARD_FILE", forward), patch.object(setup, "active", return_value=False), patch.object(setup, "run", side_effect=execute):
            with self.assertRaises(RuntimeError):
                setup.activate_interfaces(db)
        self.assertFalse(list(directory.glob("*.conf")))
        self.assertIn(("wg-quick", "down", "wg-employees"), calls)
        with SessionLocal() as db, patch.object(setup, "WG_DIR", directory), patch.object(setup, "FORWARD_FILE", forward), patch.object(setup, "active", return_value=False), patch.object(setup, "run", return_value="TEST-KEY"), patch.object(setup, "checks", return_value={"checks": []}):
            setup.activate_interfaces(db)
            self.assertEqual(set(setup.read(db, "owned")), {"wg-employees", "wg-sites"})
        for item in CONFIG.values():
            path = directory / (item["name"] + ".conf")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertIn("ListenPort = " + str(item["port"]), path.read_text())
            path.unlink()



def authenticated_admin(test):
    from app.security import create_token
    with SessionLocal() as db:
        user = db.query(User).filter(User.email == ADMIN['email']).one()
        user.totp_confirmed = True
        db.commit()
        test.headers = {'Authorization': 'Bearer ' + create_token(user, mfa=True)}
    test.client.cookies.clear()


def host_inventory(count=1):
    items = []
    for index in range(count):
        items.append({'id': f'mac-{index}', 'name': f'eth{index}', 'mac': f'02:00:00:00:00:{index:02x}', 'up': True,
                      'mtu': 1500, 'addresses': [{'address': f'192.168.{index}.10', 'prefix': 24, 'family': 4}],
                      'method': 'dhcp', 'gateway': f'192.168.{index}.1', 'dns': [], 'kind': 'ethernet',
                      'selectable': True, 'editable': True})
    return {'interfaces': items, 'canApply': True, 'manager': 'Netplan', 'message': ''}


def network_payload(roles):
    hosts, connections = [], []
    for index, role in enumerate(roles):
        hosts.append({'id': f'mac-{index}', 'originalName': f'eth{index}', 'name': f'eth{index}', 'mode': 'keep', 'purpose': role})
        if role != 'later':
            connections.append({'role': role, 'customName': 'Подрядчики' if role == 'custom' else '',
                                'name': f'wg-{index}', 'subnet': f'10.{80+index}.0.0/24', 'port': 51820+index,
                                'uplink': f'eth{index}', 'endpoint': f'192.168.{index}.10'})
    return {'hosts': {'interfaces': hosts}, 'connections': connections}


class NetworkSetupTests(unittest.TestCase):
    def setUp(self):
        SetupTests.setUp(self)
        SetupTests.create(self)
        self.network_temp = tempfile.TemporaryDirectory(prefix='fortis-network-tests-')
        self.data_patch = patch.object(setup.settings, 'data_dir', Path(self.network_temp.name))
        self.data_patch.start()

    def tearDown(self):
        SetupTests.tearDown(self)
        self.data_patch.stop()
        self.network_temp.cleanup()

    def save(self, roles):
        return self.client.put('/api/setup/network', json=network_payload(roles), headers=self.headers)

    def test_one_card_creates_one_employees_or_routers_or_custom_connection(self):
        from app.configured_interfaces import profiles
        from app.nft import render_ruleset
        from app import wireguard
        from app.models import Contour
        for role, expected in (('employees', 'employees'), ('routers', 'sites'), ('custom', 'custom.wg-0')):
            with patch.object(setup.host_network, 'discover', return_value=host_inventory(1)):
                response = self.save([role])
                self.assertEqual(response.status_code, 200, response.text)
                saved = self.client.get('/api/setup/interfaces', headers=self.headers).json()
                self.assertEqual(list(saved), [expected])
                self.assertEqual(len(profiles()), 1)
                with SessionLocal() as db:
                    rules = render_ruleset(db)
                    self.assertEqual(rules.count('udp dport 51820'), 1)
                    self.assertNotIn('eth1', rules)
                    self.assertNotIn('iifname ""', rules)
                    self.assertNotIn('oifname ""', rules)
                apply = self.client.post('/api/setup/network/apply', json={}, headers=self.headers)
                self.assertEqual(apply.json()['status'], 'unchanged')
                if role == 'employees':
                    with patch.object(wireguard.subprocess, 'run') as subprocess_run:
                        self.assertEqual(wireguard.dump(Contour.SITES), [])
                        subprocess_run.assert_not_called()

    def test_three_roles_and_fourth_card_skipped(self):
        from app.configured_interfaces import profiles
        from app.nft import render_ruleset
        with patch.object(setup.host_network, 'discover', return_value=host_inventory(4)):
            response = self.save(['employees', 'routers', 'custom', 'later'])
            self.assertEqual(response.status_code, 200, response.text)
            saved = self.client.get('/api/setup/interfaces', headers=self.headers).json()
            self.assertEqual(len(saved), 3)
            self.assertEqual(saved['custom.wg-2']['title'], 'Подрядчики')
            self.assertEqual(len(profiles()), 3)
            inventory = self.client.get('/api/setup/network', headers=self.headers).json()
            self.assertEqual(len(inventory['interfaces']), 4)
            self.assertEqual(inventory['plan'][3]['purpose'], 'later')
            with SessionLocal() as db:
                rules = render_ruleset(db)
                for port in (51820, 51821, 51822):
                    self.assertIn(f'udp dport {port} accept', rules)
                self.assertNotIn('eth3', rules)

    def test_assignment_duplicates_unknown_card_and_client_pool_overlap(self):
        with patch.object(setup.host_network, 'discover', return_value=host_inventory(3)):
            self.assertEqual(self.save(['employees', 'employees']).status_code, 422)
            self.assertEqual(self.save(['later']).status_code, 422)
            payload = network_payload(['employees', 'routers'])
            payload['connections'][1]['uplink'] = 'eth0'
            self.assertEqual(self.client.put('/api/setup/network', json=payload, headers=self.headers).status_code, 422)
            payload = network_payload(['employees'])
            payload['connections'][0]['uplink'] = 'eth9'
            self.assertEqual(self.client.put('/api/setup/network', json=payload, headers=self.headers).status_code, 422)
            payload = network_payload(['employees'])
            payload['hosts']['interfaces'][0].update(mode='static', address='10.80.0.10/24')
            self.assertEqual(self.client.put('/api/setup/network', json=payload, headers=self.headers).status_code, 422)
            payload = network_payload(['custom']); payload['connections'][0]['customName'] = ''
            self.assertEqual(self.client.put('/api/setup/network', json=payload, headers=self.headers).status_code, 422)

    def test_skipped_card_can_be_configured_later_and_active_card_is_protected(self):
        with patch.object(setup.host_network, 'discover', return_value=host_inventory(2)):
            self.assertEqual(self.save(['employees', 'later']).status_code, 200)
            with SessionLocal() as db:
                setup.write(db, 'owned', ['wg-0'])
                setup.write(db, 'completed', True)
                db.commit()
            authenticated_admin(self)
            # Existing employees settings are unchanged; a new routers role is allowed.
            response = self.save(['employees', 'routers'])
            self.assertEqual(response.status_code, 200, response.text)
            inventory = self.client.get('/api/setup/network', headers=self.headers).json()
            self.assertEqual(inventory['lockedUplinks'], ['eth0'])
            payload = network_payload(['employees', 'routers']); payload['connections'][0]['port'] = 55000
            self.assertEqual(self.client.put('/api/setup/network', json=payload, headers=self.headers).status_code, 409)
            payload = network_payload(['employees', 'routers']); payload['hosts']['interfaces'][0].update(mode='static', address='192.168.0.50/24')
            self.assertEqual(self.client.put('/api/setup/network', json=payload, headers=self.headers).status_code, 409)

    def test_later_activation_runs_network_firewall_and_sniffer_checks(self):
        with SessionLocal() as db:
            setup.write(db, 'completed', True); db.commit()
        authenticated_admin(self)
        good = {'ready': True, 'checks': [], 'notice': 'test'}
        with patch.object(setup, 'checks', return_value=good) as checks, patch.object(setup, 'activate_interfaces') as activate, patch('app.nft.apply_acl') as acl, patch('app.osdetect.start') as sniff:
            response = self.client.post('/api/setup/network/activate', json={}, headers=self.headers)
            self.assertEqual(response.status_code, 200, response.text)
            self.assertTrue(response.json()['ready'])
            activate.assert_called_once(); acl.assert_called_once(); sniff.assert_called_once()
            self.assertEqual(checks.call_args.kwargs, {'require_active': True, 'check_firewall': True})

    def test_network_configuration_requires_administrator(self):
        for method, path, body in [('get', '/api/setup/network', None), ('post', '/api/setup/network/apply', {}), ('post', '/api/setup/network/confirm', {}), ('post', '/api/setup/finish', {'enabled': False})]:
            response = getattr(self.client, method)(path, **({'json': body} if body is not None else {}))
            self.assertEqual(response.status_code, 401)

    def test_ad_credentials_and_base_dn_are_verified_and_secrets_not_returned(self):
        from app import ad
        payload = {'enabled': True, 'host': 'dc.example.com', 'port': 636, 'useSsl': True,
                   'bindDn': 'user@example.com', 'password': 'TEST-ONLY', 'baseDn': 'DC=example,DC=com'}
        connection = MagicMock()
        with patch.object(ad, '_connect_source', return_value=(connection, payload['baseDn'])), patch.object(ad, '_search_entries', return_value=[object()]):
            response = self.client.post('/api/setup/ad/check', json=payload, headers=self.headers)
            self.assertEqual(response.status_code, 200, response.text)
            self.assertNotIn('TEST-ONLY', response.text)
            connection.unbind.assert_called_once()
            self.assertEqual(self.client.get('/api/setup/ad', headers=self.headers).json()['sources'], [])
        with patch.object(ad, '_connect_source', return_value=(connection, payload['baseDn'])), patch.object(ad, '_search_entries', return_value=[]):
            self.assertEqual(self.client.post('/api/setup/ad/check', json=payload, headers=self.headers).status_code, 422)
        self.assertEqual(self.client.post('/api/setup/finish', json={'enabled': False}, headers=self.headers).status_code, 409)

    def test_ad_finish_saves_connection_and_skip_does_not_connect(self):
        from app import ad
        good = {'ready': True, 'checks': [], 'notice': 'test'}
        payload = {'enabled': True, 'host': 'dc.example.com', 'port': 636, 'useSsl': True,
                   'bindDn': 'user@example.com', 'password': 'TEST-ONLY', 'baseDn': 'DC=example,DC=com'}
        with SessionLocal() as db:
            setup.write(db, 'vpn_ready', True); db.commit()
        app.state.scheduler = MagicMock()
        with patch.object(setup, 'checks', return_value=good), patch.object(setup, 'verify_ad', return_value={'ok': True}) as verify:
            response = self.client.post('/api/setup/finish', json=payload, headers=self.headers)
            self.assertEqual(response.status_code, 200, response.text)
            verify.assert_called_once()
            authenticated_admin(self)
            public = self.client.get('/api/setup/ad', headers=self.headers).json()
            self.assertTrue(public['sources'][0]['passwordSet'])
            self.assertNotIn('TEST-ONLY', json.dumps(public))
        with SessionLocal() as db:
            setup.write(db, 'completed', False); db.commit()
        with patch.object(setup, 'checks', return_value=good), patch.object(setup, 'verify_ad') as verify:
            self.assertEqual(self.client.post('/api/setup/finish', json={'enabled': False}, headers=self.headers).status_code, 200)
            verify.assert_not_called()


class HostNetworkTests(unittest.TestCase):
    def setUp(self):
        from app import host_network
        self.host = host_network
        self.temp = tempfile.TemporaryDirectory(prefix='fortis-netplan-unit-')
        self.root = Path(self.temp.name)
        self.netplan = self.root / 'netplan'; self.netplan.mkdir()
        self.path_patch = patch.object(self.host, 'NETPLAN_DIR', self.netplan); self.path_patch.start()
        self.data = self.root / 'data'; self.data.mkdir()

    def tearDown(self):
        self.path_patch.stop(); self.temp.cleanup()

    def fixture(self):
        content = 'network:\n  version: 2\n  renderer: networkd\n  ethernets:\n    eth0:\n      dhcp4: true\n      dhcp6: true\n    eth1:\n      dhcp4: true\n'
        path = self.netplan / '50-cloud-init.yaml'; path.write_text(content)
        return path, content

    def test_detects_one_two_three_cards_and_ipv4_ipv6(self):
        import psutil, socket
        system = self.root / 'sys'
        for count in (1, 2, 3):
            addrs, stats = {}, {}
            for index in range(count):
                name = f'eth{index}'
                (system / name / 'device').mkdir(parents=True, exist_ok=True)
                addrs[name] = [SimpleNamespace(family=psutil.AF_LINK, address=f'02:00:00:00:00:{index:02x}', netmask=None),
                               SimpleNamespace(family=socket.AF_INET, address=f'192.168.{index}.10', netmask='255.255.255.0'),
                               SimpleNamespace(family=socket.AF_INET6, address='fe80::1%eth0', netmask='ffff:ffff:ffff:ffff::')]
                stats[name] = SimpleNamespace(isup=True, mtu=1500, flags='up,broadcast,running')
            with patch.object(self.host.platform, 'system', return_value='Linux'), patch.object(self.host, 'SYS_NET', system), patch('shutil.which', return_value=None), patch.object(psutil, 'net_if_addrs', return_value=addrs), patch.object(psutil, 'net_if_stats', return_value=stats):
                inventory = self.host.discover()
                self.assertEqual(len(inventory['interfaces']), count)
                self.assertTrue(all(h['selectable'] for h in inventory['interfaces']))
                self.assertEqual(inventory['interfaces'][0]['addresses'][0], {'address': '192.168.0.10', 'prefix': 24, 'family': 4})
                self.assertEqual(inventory['interfaces'][0]['addresses'][1]['prefix'], 64)

    def test_manual_ip_rename_dhcp_and_preserving_unselected_adapter(self):
        path, _ = self.fixture()
        plan = [{'id': 'mac-0', 'originalName': 'eth0', 'name': 'lan-staff', 'mode': 'static', 'address': '192.168.0.20/24', 'gateway': '192.168.0.1', 'dns': ['1.1.1.1']}]
        self.host.HostPlanIn(interfaces=plan)
        updated = self.host.build_documents(plan, host_inventory(2), self.host.documents())
        managed = updated[self.netplan / '99-kontur-first-run.yaml']['network']['ethernets']['eth0']
        self.assertEqual(managed['set-name'], 'lan-staff')
        self.assertEqual(managed['match']['macaddress'], '02:00:00:00:00:00')
        self.assertEqual(managed['addresses'], ['192.168.0.20/24'])
        self.assertFalse(managed['dhcp4']); self.assertTrue(managed['dhcp6'])
        self.assertEqual(managed['routes'], [{'to': 'default', 'via': '192.168.0.1'}])
        self.assertEqual(updated[path]['network']['ethernets']['eth1'], {'dhcp4': True})
        self.assertNotIn('eth0', updated[path]['network']['ethernets'])
        plan[0].update(mode='dhcp', address='', gateway='', dns=[])
        managed = self.host.build_documents(plan, host_inventory(2), self.host.documents())[self.netplan / '99-kontur-first-run.yaml']['network']['ethernets']['eth0']
        self.assertTrue(managed['dhcp4']); self.assertEqual(managed['addresses'], [])

    def test_invalid_static_address_gateway_and_duplicate_names(self):
        from pydantic import ValidationError
        base = {'id': 'mac-0', 'originalName': 'eth0', 'name': 'eth0', 'mode': 'static', 'address': '192.168.0.10/24', 'gateway': '192.168.0.1'}
        for value in ('192.168.0.0/24', '192.168.0.255/24', '127.0.0.1/24', '::1/128'):
            with self.assertRaises(ValidationError):
                self.host.HostInterfaceIn(**{**base, 'address': value})
        with self.assertRaises(ValidationError):
            self.host.HostInterfaceIn(**{**base, 'gateway': '192.168.1.1'})
        with self.assertRaises(ValidationError):
            self.host.HostPlanIn(interfaces=[base, {**base, 'id': 'mac-1', 'originalName': 'eth1'}])

    def test_keep_existing_dhcp_does_not_write_or_spawn(self):
        path, content = self.fixture()
        plan = network_payload(['employees'])['hosts']['interfaces']
        with patch.object(self.host, 'discover', return_value=host_inventory(1)), patch.object(self.host.subprocess, 'Popen') as process:
            self.assertEqual(self.host.apply(plan, self.data)['status'], 'unchanged')
            process.assert_not_called()
        self.assertEqual(path.read_text(), content)

    def test_failed_generate_restores_original_files(self):
        path, content = self.fixture()
        plan = [{'id': 'mac-0', 'originalName': 'eth0', 'name': 'eth0', 'mode': 'static', 'address': '192.168.0.20/24', 'gateway': '', 'dns': []}]
        def execute(*args):
            if args == ('netplan', 'generate'):
                raise RuntimeError('invalid configuration')
            return ''
        with patch.object(self.host, 'discover', return_value=host_inventory(1)), patch.object(self.host.platform, 'system', return_value='Linux'), patch.object(self.host.os, 'geteuid', return_value=0), patch.object(self.host.subprocess, 'Popen'), patch.object(self.host, 'command', side_effect=execute):
            with self.assertRaises(RuntimeError):
                self.host.apply(plan, self.data)
        self.assertEqual(path.read_text(), content)
        self.assertFalse((self.netplan / '99-kontur-first-run.yaml').exists())
        self.assertEqual(self.host.transaction(self.data)['status'], 'rolled_back')
        self.assertEqual(self.host.state_path(self.data).stat().st_mode & 0o777, 0o600)

    def test_confirmation_checks_actual_address_and_timeout(self):
        import time
        plan = [{'id': 'mac-0', 'originalName': 'eth0', 'name': 'eth0', 'mode': 'static', 'address': '192.168.0.20/24', 'gateway': '', 'dns': []}]
        state = {'status': 'pending', 'expiresAt': time.time() + 140, 'pid': 123, 'plan': plan, 'backup': {}}
        self.host.atomic_write(self.host.state_path(self.data), json.dumps(state))
        inventory = host_inventory(1)
        process = MagicMock(pid=123, returncode=0)
        with patch.object(self.host, 'discover', return_value=inventory), patch.object(self.host, '_process', process), patch.object(self.host.psutil, 'Process') as lookup, patch.object(self.host.os, 'kill') as kill:
            lookup.return_value.cmdline.return_value = ['netplan', 'try']
            with self.assertRaises(RuntimeError):
                self.host.confirm(self.data)
            kill.assert_not_called()
            inventory['interfaces'][0]['addresses'][0]['address'] = '192.168.0.20'
            self.assertEqual(self.host.confirm(self.data)['status'], 'confirmed')
            kill.assert_called_once()
            self.assertNotIn('backup', self.host.transaction(self.data))
        state['expiresAt'] = time.time() - 1
        self.host.atomic_write(self.host.state_path(self.data), json.dumps(state))
        with self.assertRaises(RuntimeError):
            self.host.confirm(self.data)

    def test_watchdog_restores_after_expiry(self):
        import time, base64
        path, content = self.fixture()
        path.write_text('changed')
        self.host.atomic_write(self.host.state_path(self.data), json.dumps({'status': 'pending', 'expiresAt': time.time() - 1, 'backup': {str(path): base64.b64encode(content.encode()).decode()}}))
        with patch.object(self.host, 'command', return_value=''):
            self.host.watch_rollback(self.data)
        self.assertEqual(path.read_text(), content)
        self.assertEqual(self.host.transaction(self.data)['status'], 'rolled_back')


class PortAndRuntimeTests(unittest.TestCase):
    def test_listener_format_and_firewall_allowance(self):
        from app import setup_ports
        output = 'udp UNCONN 0 0 0.0.0.0:51820 0.0.0.0:*\ntcp LISTEN 0 128 [::]:443 [::]:*\ntcp LISTEN 0 128 127.0.0.1:8088 0.0.0.0:*\n'
        with patch.object(setup_ports.platform, 'system', return_value='Linux'), patch.object(setup_ports.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=output)):
            result = setup_ports.read_listeners()
            self.assertTrue(result['available'])
            self.assertIn({'protocol': 'UDP', 'address': '0.0.0.0', 'port': 51820}, result['ports'])
            self.assertIn({'protocol': 'TCP', 'address': '::', 'port': 443}, result['ports'])
        rules = {'nftables': [{'rule': {'expr': [
            {'match': {'op': '==', 'left': {'meta': {'key': 'iifname'}}, 'right': 'eth0'}},
            {'match': {'op': '==', 'left': {'payload': {'protocol': 'udp', 'field': 'dport'}}, 'right': 51820}}, {'accept': None}]}}]}
        with patch.object(setup_ports.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=json.dumps(rules))):
            self.assertTrue(setup_ports.firewall_allows('eth0', 51820))
            self.assertFalse(setup_ports.firewall_allows('eth1', 51820))
            self.assertFalse(setup_ports.firewall_allows('eth0', 51821))

    def test_channel_status_reports_only_configured_cards(self):
        from app import channel_status
        profile = {'role': 'custom', 'title': 'Гости', 'name': 'wg-guests', 'subnet': '10.90.0.0/24', 'port': 53000, 'uplink': 'eth2'}
        with patch.object(channel_status, 'profiles', return_value=[profile]), patch.object(channel_status, '_interfaces', return_value=[]), patch.object(channel_status, '_wg', return_value={'available': False, 'port': None, 'peers': None, 'recentPeers': None}), patch.object(channel_status, '_route', return_value={}), patch.object(channel_status, '_counters', return_value={}), patch.object(channel_status, '_link_speed', return_value=None):
            report = channel_status.read_channel_status()
            self.assertEqual(len(report['channels']), 1)
            self.assertEqual(report['channels'][0]['name'], 'Гости')
            self.assertEqual(report['channels'][0]['physicalInterface'], 'eth2')
            self.assertEqual(report['channels'][0]['status'], 'down')

    def test_sniffer_configured_interfaces_and_later_addition(self):
        from app import osdetect
        profile = {'name': 'wg-0', 'uplink': 'eth0', 'subnet': '10.80.0.0/24'}
        with patch.object(osdetect, '_STARTED', True), patch.object(osdetect, '_SNIFFERS', set()), patch.object(osdetect, 'profiles', return_value=[profile]) as configured, patch.object(osdetect.threading, 'Thread') as thread:
            osdetect.start(); self.assertEqual(thread.call_count, 2)
            osdetect.start(); self.assertEqual(thread.call_count, 2)
            configured.return_value = [profile, {**profile, 'name': 'wg-1', 'uplink': 'eth1'}]
            osdetect.start(); self.assertEqual(thread.call_count, 4)

    def test_sniffer_recognizes_configured_vpn_pool(self):
        from app import osdetect
        connection = MagicMock()
        connection.recv.side_effect = [b'frame', OSError('stop')]
        seen = {}
        with patch.object(osdetect.socket, 'AF_PACKET', 17, create=True), patch.object(osdetect.socket, 'socket', return_value=connection), patch.object(osdetect, 'profiles', return_value=[{'subnet': '10.80.0.0/24'}]), patch.object(osdetect, '_parse', return_value=('10.80.0.2', 64, 17, b'', '')), patch.object(osdetect, '_SEEN', seen), patch.object(osdetect, '_save'):
            osdetect._sniff('wg-0', False)
        self.assertIn('10.80.0.2', seen)


if __name__ == "__main__":
    unittest.main()
