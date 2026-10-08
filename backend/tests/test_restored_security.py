"""Regression tests for service ACLs, proof of key possession and root isolation."""
import base64
import os
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import test_security as prior
from test_setup import SessionLocal, User
from app.config import settings
from app.models import AccessPolicy, Device, DeviceCertificate, DeviceStatus, Resource, Contour, WireGuardPeer
from app import network_service

class RestoredSecurityTests(unittest.TestCase):
    setUp=prior.SecurityTests.setUp
    tearDown=prior.SecurityTests.tearDown
    claim=prior.SecurityTests.claim
    csrf=prior.SecurityTests.csrf
    finish=prior.SecurityTests.finish
    login_totp=prior.SecurityTests.login_totp

    def test_protocol_and_port_are_required(self):
        self.claim();self.finish();self.login_totp()
        for protocol,port,status in [('TCP',443,201),('UDP',53,201),('ANY',443,422),('TCP',None,422),('TCP',0,422),('TCP',65536,422)]:
            r=self.client.post('/api/resources',json={'name':'Service','host':'192.0.2.10','port':port,'protocol':protocol,'contour':'EMPLOYEES'},headers=self.csrf())
            self.assertEqual(r.status_code,status,r.text)
            if status==201:
                with SessionLocal() as db:db.delete(db.get(Resource,r.json()['id']));db.commit()

    def test_tcp_udp_acl_guard_precedes_conntrack(self):
        from app.nft import render_ruleset,_cidrs_for_device
        for protocol,port in [('TCP',443),('UDP',53)]:
            with SessionLocal() as db:
                d=Device(name='Test',device_id='resource-'+protocol,contour=Contour.EMPLOYEES,status=DeviceStatus.ACTIVE)
                r=Resource(name='Service',host='192.0.2.10',port=port,protocol=protocol,contour=Contour.EMPLOYEES)
                db.add_all([d,r]);db.flush()
                db.add(AccessPolicy(device_id_fk=d.id,resource_id=r.id,allowed=True))
                db.add(WireGuardPeer(device_id_fk=d.id,contour=Contour.EMPLOYEES,public_key='test-'+protocol,preshared_key='test',vpn_ip='10.80.0.2',enabled=True));db.flush()
                with patch.object(settings,'employees_enabled',True),patch.object(settings,'employees_if','wg-test'),patch.object(settings,'employees_nic','eth0'),patch.object(settings,'sites_enabled',False):
                    rules=render_ruleset(db)
                self.assertEqual(_cidrs_for_device(db,d),[])
                network_service.validate_rules(rules)
                for chain in ('input','forward'):
                    body=rules.split('chain '+chain+' {')[1].split('  }')[0]
                    self.assertLess(body.index(protocol.lower()+' dport '+str(port)+' accept'),body.index('ip daddr 192.0.2.10 drop'))
                    self.assertLess(body.index('ip daddr 192.0.2.10 drop'),body.index('ct state established,related accept'))
                db.rollback()

    def test_helper_rejects_arbitrary_commands_paths_and_includes(self):
        with patch.object(network_service,'owned',return_value={'employees':{'name':'wg-test'}}):
            for argv in [['bash','-c','id'],['wg-quick','up','../../tmp/evil'],['wg','show','eth0','dump'],['nft','-f','/tmp/evil'],['ip','link','delete','eth0'],['wg','set','wg-test','private-key','/etc/shadow']]:
                with self.assertRaises(ValueError):network_service.validate_command(argv)
            network_service.validate_command(['wg','show','wg-test','dump'])
        for text in ['include "/etc/shadow"','table inet foreign {','add table inet fortis_filter; include "/tmp/x"','iifname "evil\\name" accept']:
            with self.assertRaises(ValueError):network_service.validate_rules(text)
        with self.assertRaises(ValueError):network_service.dispatch('exec',{'argv':['id']})

    def test_root_backend_is_refused(self):
        from app.main import startup
        with patch('platform.system',return_value='Linux'),patch('os.geteuid',return_value=0):
            with self.assertRaises(RuntimeError):startup()

    def test_private_server_key_is_not_returned(self):
        with patch.object(network_service,'owned',return_value={'employees':{'name':'wg-test'}}),patch.object(network_service,'run',return_value='private-secret\tpublic\t51820\t0'):
            output=network_service.dispatch('command',{'argv':['wg','show','wg-test','dump']})
            self.assertTrue(output.startswith('(hidden)'));self.assertNotIn('private-secret',output)

    def test_signature_tamper_replay_and_legacy_agent_request(self):
        from app.ca import CorporateCA
        from app.device_id import compute_device_id
        from app.agent_proof import canonical
        from app.schemas import DeviceVerifyIn
        self.claim();self.finish()
        cert,key,serial,fingerprint,nb,na=CorporateCA().issue_device_cert('agent-test')
        pub=base64.b64encode(os.urandom(32)).decode()
        with SessionLocal() as db:
            u=db.query(User).one()
            d=Device(name='Agent test',device_id=compute_device_id(cert,'test-system','',pub),system_identifier='test-system',user_id=u.id,contour=Contour.EMPLOYEES,status=DeviceStatus.ACTIVE,require_agent=True)
            db.add(d);db.flush()
            db.add(DeviceCertificate(device_id_fk=d.id,serial=serial,fingerprint=fingerprint,pem=cert,not_before=nb,not_after=na))
            db.add(WireGuardPeer(device_id_fk=d.id,contour=Contour.EMPLOYEES,public_key=pub,preshared_key=base64.b64encode(os.urandom(32)).decode(),vpn_ip='10.80.0.7'));db.commit();did=d.id
        self.client.base_url='https://testserver'
        with patch.object(settings,'standard_wireguard',False):
            response=self.client.post('/api/device/challenge',json={'certificatePem':cert});self.assertEqual(response.status_code,200,response.text)
            payload=DeviceVerifyIn(challenge=response.json()['challenge'],signature='',certificatePem=cert,systemIdentifier='test-system',wireguardPublicKey=pub)
            signer=serialization.load_pem_private_key(key.encode(),password=None)
            sig=signer.sign(canonical('verify',payload.model_dump(exclude={'signature'})),padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.DIGEST_LENGTH),hashes.SHA256())
            body=payload.model_dump();body['signature']=base64.b64encode(sig).decode()
            with patch('app.api.agent.engine.verify_and_authorize',return_value={'ok':True}) as authorize:
                self.assertEqual(self.client.post('/api/device/verify',json={**body,'systemIdentifier':'other'}).status_code,403);authorize.assert_not_called()
                self.assertEqual(self.client.post('/api/device/verify',json=body).status_code,200)
                self.assertEqual(self.client.post('/api/device/verify',json=body).status_code,403)
                self.assertEqual(authorize.call_count,1)
            self.assertEqual(self.client.post('/api/device/verify',json={'certificatePem':cert,'systemIdentifier':'test-system','wireguardPublicKey':pub}).status_code,422)
        with SessionLocal() as db:
            db.query(DeviceCertificate).filter_by(device_id_fk=did).delete();db.query(WireGuardPeer).filter_by(device_id_fk=did).delete();db.query(Device).filter_by(id=did).delete();db.commit()

    def test_agent_enrollment_once_expiry_routes_and_signed_lifecycle(self):
        import secrets
        from datetime import datetime, timedelta
        from app.models import AccessRequest, RequestStatus, Session as AgentSession
        from app.agent_proof import canonical
        from app.schemas import DeviceVerifyIn, HeartbeatIn
        self.claim();self.finish()
        pub=base64.b64encode(os.urandom(32)).decode()
        token=secrets.token_urlsafe(32)
        with SessionLocal() as db:
            u=db.query(User).one()
            resource=Resource(name='Agent service',host='192.0.2.88',port=443,protocol='TCP',contour=Contour.EMPLOYEES)
            db.add(resource);db.flush()
            row=AccessRequest(user_id=u.id,device_name='Agent test',contour=Contour.EMPLOYEES,status=RequestStatus.ISSUED,
                              enrollment_token=token,resources_json=[resource.id],updated_at=datetime.utcnow())
            expired=AccessRequest(user_id=u.id,device_name='Expired',contour=Contour.EMPLOYEES,status=RequestStatus.ISSUED,
                              enrollment_token=token+'-expired',updated_at=datetime.utcnow()-timedelta(days=2))
            db.add_all([row,expired]);db.commit();rid=row.id
        self.client.base_url='https://testserver'
        body={'token':token,'systemIdentifier':'agent-system','wireguardPublicKey':pub,'deviceName':'Agent test'}
        with patch.object(settings,'standard_wireguard',False),patch.object(settings,'employees_enabled',True),patch('app.api.agent.wireguard.gen_psk',return_value=base64.b64encode(os.urandom(32)).decode()),patch('app.api.agent.wireguard.server_public_key',return_value=pub),patch('app.engine.wireguard.set_peer'),patch('app.engine.apply_acl'):
            self.assertEqual(self.client.post('/api/device/register',json={**body,'token':token+'-expired'}).status_code,403)
            result=self.client.post('/api/device/register',json=body);self.assertEqual(result.status_code,200,result.text)
            result=result.json();self.assertIn('192.0.2.88/32',result['allowedIps']);self.assertNotIn('0.0.0.0/0',result['allowedIps'])
            self.assertEqual(self.client.post('/api/device/register',json=body).status_code,403)
            with SessionLocal() as db:
                row=db.get(AccessRequest,rid);self.assertIsNone(row.enrollment_token)
                device=db.get(Device,row.issued_device_id);self.assertFalse(device.peer.enabled);did=device.id
            signer=serialization.load_pem_private_key(result['certificateKeyPem'].encode(),password=None)
            cert=result['certificatePem']
            def sign(action,payload):
                challenge=self.client.post('/api/device/challenge',json={'certificatePem':cert}).json()['challenge']
                model=(DeviceVerifyIn if action=='verify' else HeartbeatIn)(challenge=challenge,signature='',**payload)
                data=model.model_dump(exclude={'signature'})
                data['signature']=base64.b64encode(signer.sign(canonical(action,data),padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.DIGEST_LENGTH),hashes.SHA256())).decode()
                return data
            verification=sign('verify',{'certificatePem':cert,'systemIdentifier':'agent-system','wireguardPublicKey':pub})
            response=self.client.post('/api/device/verify',json=verification);self.assertEqual(response.status_code,200,response.text)
            session=response.json()['session_token']
            self.assertEqual(self.client.post('/api/device/verify',json=verification).status_code,403)
            heartbeat=sign('heartbeat',{'sessionToken':session})
            self.assertEqual(self.client.post('/api/device/heartbeat',json=heartbeat).status_code,200)
            self.assertEqual(self.client.post('/api/device/heartbeat',json=heartbeat).status_code,403)
            with SessionLocal() as db:
                db.add(AgentSession(device_id_fk='another-device',token='another-token',attested_device_id='other',expires_at=datetime.utcnow()+timedelta(hours=1),active=True));db.commit()
            self.assertEqual(self.client.post('/api/device/heartbeat',json=sign('heartbeat',{'sessionToken':'another-token'})).status_code,403)
            with SessionLocal() as db:
                db.get(Device,did).access_until=datetime.utcnow()-timedelta(seconds=1);db.commit()
            with patch('app.engine.wireguard.remove_peer'):
                self.assertEqual(self.client.post('/api/device/heartbeat',json=sign('heartbeat',{'sessionToken':session})).status_code,403)
        with SessionLocal() as db:
            db.query(AccessPolicy).filter_by(device_id_fk=did).delete();db.query(AgentSession).filter(AgentSession.device_id_fk.in_([did,'another-device'])).delete()
            db.query(DeviceCertificate).filter_by(device_id_fk=did).delete();db.query(WireGuardPeer).filter_by(device_id_fk=did).delete();db.query(Device).filter_by(id=did).delete();db.query(AccessRequest).delete();db.query(Resource).delete();db.commit()

    def test_ca_first_creation_is_serialized_and_partial_ca_is_refused(self):
        import tempfile
        from pathlib import Path
        from concurrent.futures import ThreadPoolExecutor
        from app.ca import CorporateCA
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)
            with ThreadPoolExecutor(max_workers=3) as pool:
                certificates=list(pool.map(lambda _:CorporateCA(path).ca_pem(),range(3)))
            self.assertEqual(len(set(certificates)),1)
            self.assertEqual((path/'ca.key').stat().st_mode & 0o777,0o600)
            (path/'ca.crt').unlink()
            with self.assertRaises(RuntimeError):CorporateCA(path)

    def test_standard_resource_only_issuance_routes_and_final_revocation(self):
        from datetime import datetime,timedelta
        from app.api.requests import _issue_row
        from app.models import AccessRequest,RequestStatus
        from app.nft import render_ruleset
        self.claim();self.finish()
        public=base64.b64encode(os.urandom(32)).decode()
        with SessionLocal() as db:
            u=db.query(User).one()
            d=Device(name='Resource-only',device_id='resource-only',user_id=u.id,contour=Contour.EMPLOYEES,status=DeviceStatus.PENDING,require_agent=False)
            r=Resource(name='HTTPS only',host='192.0.2.42',protocol='TCP',port=443,contour=Contour.EMPLOYEES)
            db.add_all([d,r]);db.flush()
            peer=WireGuardPeer(device_id_fk=d.id,contour=Contour.EMPLOYEES,public_key=public,private_key=public,preshared_key=public,vpn_ip='10.80.0.8',client_config='previous config',enabled=False)
            row=AccessRequest(user_id=u.id,device_name=d.name,contour=Contour.EMPLOYEES,status=RequestStatus.APPROVED_SB,resources_json=[r.id],access_until=datetime.utcnow()+timedelta(days=30))
            db.add_all([peer,row]);db.flush()
            with patch.object(settings,'employees_enabled',True),patch.object(settings,'sites_enabled',False),patch.object(settings,'employees_if','wg-test'),patch.object(settings,'employees_nic','eth0'),patch.object(settings,'standard_wireguard',True),patch('app.api.requests.wireguard.set_peer'),patch('app.api.requests.engine.apply_acl'),patch('app.provision.wireguard.server_public_key',return_value=public):
                _issue_row(db,row,u.email)
                self.assertEqual(row.status,RequestStatus.ISSUED)
                self.assertIn('AllowedIPs = 192.0.2.42/32',peer.client_config)
                self.assertNotIn('10.80.0.0/24',peer.client_config)
                db.query(AccessPolicy).filter_by(device_id_fk=d.id).delete();db.flush()
                rules=render_ruleset(db);network_service.validate_rules(rules)
                forward=rules.split('chain forward {')[1]
                self.assertLess(forward.index('iifname "wg-test" ip saddr 10.80.0.8 drop'),forward.index('ct state established,related accept'))
                self.assertNotIn('192.0.2.42 tcp dport 443 accept',rules)
            db.rollback()

    def test_unprivileged_icmp_uses_bounded_helper_and_retains_rate_limit(self):
        self.claim();self.finish();self.login_totp()
        from app import network_ping
        result={'returncode':0,'stdout':'3 packets transmitted, 3 received, 0% packet loss\nrtt min/avg/max/mdev = 1.0/2.0/3.0/0.5 ms','stderr':''}
        with patch.object(settings,'network_helper_socket','/run/test.sock'),patch('app.privilege.call',return_value=result) as helper,patch.object(network_ping,'_next_run',0):
            response=self.client.post('/api/networks/ping',json={'ip':'10.3.0.8'},headers=self.csrf())
            self.assertEqual(response.status_code,200,response.text);self.assertTrue(response.json()['reachable'])
            helper.assert_called_once_with('ping',ip='10.3.0.8',interface='',count=3)
            self.assertEqual(self.client.post('/api/networks/ping',json={'ip':'10.3.0.8'},headers=self.csrf()).status_code,429)
            self.assertEqual(self.client.post('/api/networks/ping',json={'ip':'10.3.0.8;id'},headers=self.csrf()).status_code,422)
        with self.assertRaises(ValueError):network_service.dispatch('ping',{'ip':'10.3.0.8','interface':'','count':1000000})
