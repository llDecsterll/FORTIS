#!/usr/bin/env python3
"""Run isolated Linux integration tests using Docker; no host network/volumes modified.
Requires image fortis-security-linux:local containing Python requirements and Linux tools.
"""
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid

ROOT=Path(__file__).resolve().parents[1]
PREFIX='fortis-test-'+uuid.uuid4().hex[:8]
IMAGE=os.environ.get('FORTIS_TEST_IMAGE','fortis-security-linux:local')
NETWORK=PREFIX+'-net'
CONTAINERS={name:PREFIX+'-'+name for name in ('server','client','resource')}


def docker(*args,input=None,check=True):
    result=subprocess.run(['docker',*args],input=input,text=True,capture_output=True,timeout=90)
    if check and result.returncode:
        raise RuntimeError('Docker operation failed: '+result.stderr[-1800:])
    return result.stdout.strip()


def execute(role,*args,input=None,check=True,user=None,environment=None):
    cmd=['exec','-i']
    if user:cmd+=['-u',user]
    for key,value in (environment or {}).items():cmd+=['-e',key+'='+value]
    return docker(*cmd,CONTAINERS[role],*args,input=input,check=check)


def rpc(operation,**args):
    script='import json,sys;from app.privilege import call;r=json.load(sys.stdin);print(json.dumps(call(r["operation"],**r["args"])))'
    value=execute('server','python','-c',script,input=json.dumps({'operation':operation,'args':args}),user='1001:1001',environment={
        'DATA_DIR':'/tmp/fortis-user-data','NETWORK_HELPER_SOCKET':'/run/fortis-network.sock','PYTHONPATH':'/opt/fortis/backend'})
    return json.loads(value)


def rules(host,protocol,port,public,psk):
    script='''import json,sys,os,tempfile
v=json.load(sys.stdin);root=tempfile.mkdtemp();os.environ['DATA_DIR']=root
from app.config import settings
settings.employees_enabled=True;settings.sites_enabled=False;settings.employees_if='wg-test';settings.employees_nic='eth0'
from app.db import engine,SessionLocal
from app.models import Base,Device,DeviceStatus,Resource,WireGuardPeer,AccessPolicy,Contour
from app.nft import render_ruleset
Base.metadata.create_all(engine)
with SessionLocal() as db:
 d=Device(name='Linux ACL test',device_id='linux-test',contour=Contour.EMPLOYEES,status=DeviceStatus.ACTIVE,require_agent=False)
 r=Resource(name='Linux service',host=v['host'],protocol=v['protocol'],port=v['port'],contour=Contour.EMPLOYEES)
 db.add_all([d,r]);db.flush()
 db.add(AccessPolicy(device_id_fk=d.id,resource_id=r.id,allowed=v['protocol']!='REVOKED'))
 db.add(WireGuardPeer(device_id_fk=d.id,contour=Contour.EMPLOYEES,public_key=v['public'],preshared_key=v['psk'],vpn_ip='10.80.0.2',enabled=True));db.flush()
 print(render_ruleset(db))
'''
    return execute('server','python','-c',script,input=json.dumps(dict(host=host,protocol=protocol,port=port,public=public,psk=psk)),environment={'PYTHONPATH':'/opt/fortis/backend'})


def connect(host,port,udp=False):
    script='''import json,sys,socket
v=json.load(sys.stdin)
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if v['udp'] else socket.SOCK_STREAM);s.settimeout(2)
try:
 if v['udp']:s.sendto(b'test',(v['host'],v['port']));data=s.recv(20)
 else:s.connect((v['host'],v['port']));s.sendall(b'test');data=s.recv(20)
 print('allowed' if data==b'test' else 'wrong')
except (TimeoutError,OSError):print('blocked')
finally:s.close()
'''
    return execute('client','python','-c',script,input=json.dumps(dict(host=host,port=port,udp=udp)))


def main():
    temp=Path(tempfile.mkdtemp(prefix='fortis-linux-source-'))
    try:
        # Copy only application source/test code, never the host database or keys.
        for path in ('backend/app','backend/tests','deploy'):
            shutil.copytree(ROOT/path,temp/path,ignore=shutil.ignore_patterns('__pycache__','*.pyc','*.rollback-*'))
        docker('network','create','--internal',NETWORK)
        for role,name in CONTAINERS.items():
            docker('run','-d','--name',name,'--network',NETWORK,'--cap-add=NET_ADMIN','--cap-add=NET_RAW',IMAGE,'sleep','infinity')
        docker('cp',str(temp)+'/.',CONTAINERS['server']+':/opt/fortis')
        execute('server','sh','-c','chown -R root:root /opt/fortis; find /opt/fortis -type d -exec chmod 755 {} +; find /opt/fortis -type f -exec chmod 644 {} +; python -m venv --system-site-packages /opt/fortis/backend/.venv; mkdir -p /tmp/fortis-user-data /var/lib/fortis /var/lib/fortis-network /etc/wireguard; chown fortis:fortis /tmp/fortis-user-data /var/lib/fortis')
        docker('exec','-d','-e','DATA_DIR=/var/lib/fortis-network',CONTAINERS['server'],'sh','-c','exec /opt/fortis/backend/.venv/bin/python -I /opt/fortis/deploy/network-service.py > /tmp/fortis-network-test.log 2>&1')
        for _ in range(40):
            try:
                if rpc('health')=={'ready':True}:break
            except Exception:time.sleep(.25)
        else:
            print(execute('server','cat','/tmp/fortis-network-test.log',check=False))
            raise RuntimeError('Network service did not start')
        assert rpc('activate',profiles={'employees':{'name':'wg-test','subnet':'10.80.0.0/24','port':51820,'uplink':'eth0','endpoint':'server'}},mtu=1420)==['wg-test']
        public_server=rpc('command',argv=['wg','show','wg-test','public-key'])
        private_client=execute('client','wg','genkey')
        public_client=execute('client','wg','pubkey',input=private_client+'\n')
        psk=base64.b64encode(os.urandom(32)).decode()
        rpc('peer_set',interface='wg-test',public_key=public_client,psk=psk,allowed_ips='10.80.0.2/32')
        server_ip=json.loads(docker('inspect',CONTAINERS['server']))[0]['NetworkSettings']['Networks'][NETWORK]['IPAddress']
        resource_ip=json.loads(docker('inspect',CONTAINERS['resource']))[0]['NetworkSettings']['Networks'][NETWORK]['IPAddress']
        client_setup='''import json,sys,subprocess,tempfile
v=json.load(sys.stdin)
def run(*a):subprocess.run(a,check=True,stdout=subprocess.DEVNULL)
run('ip','link','add','wg-client','type','wireguard')
with tempfile.NamedTemporaryFile(mode='w') as key, tempfile.NamedTemporaryFile(mode='w') as psk:
 key.write(v['private']);key.flush();psk.write(v['psk']);psk.flush()
 run('wg','set','wg-client','private-key',key.name,'peer',v['server_public'],'preshared-key',psk.name,'endpoint',v['server_ip']+':51820','allowed-ips',v['resource_ip']+'/32')
run('ip','address','add','10.80.0.2/32','dev','wg-client');run('ip','link','set','wg-client','up');run('ip','route','replace',v['resource_ip']+'/32','dev','wg-client')
'''
        execute('client','python','-c',client_setup,input=json.dumps(dict(private=private_client,psk=psk,server_public=public_server,server_ip=server_ip,resource_ip=resource_ip)))
        echo='''import socket,threading,time

def tcp(port):
 s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',port));s.listen()
 def connection(c):
  with c:
   while True:
    data=c.recv(100)
    if not data:return
    c.sendall(data)
 while True:
  c,_=s.accept();threading.Thread(target=connection,args=(c,),daemon=True).start()

def udp(port):
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',port))
 while True:
  data,addr=s.recvfrom(100);s.sendto(data,addr)
for p in (18080,8443):threading.Thread(target=tcp,args=(p,),daemon=True).start()
threading.Thread(target=udp,args=(18080,),daemon=True).start()
while True:time.sleep(1)
'''
        docker('exec','-d',CONTAINERS['resource'],'python','-c',echo)
        rpc('acl',rules=rules(resource_ip,'TCP',18080,public_client,psk))
        assert connect(resource_ip,18080)=='allowed','TCP resource not reachable'
        assert connect(resource_ip,8443)=='blocked','Unlisted TCP port reachable'
        assert connect(resource_ip,18080,True)=='blocked','Wrong protocol reachable'
        # Keep a real established TCP flow alive while switching the permission.
        persistent="import socket,sys;s=socket.create_connection((sys.argv[1],18080),2);s.settimeout(2);s.sendall(b'first');assert s.recv(20)==b'first';print('ready',flush=True);sys.stdin.readline();s.sendall(b'second');\ntry:print('leaked' if s.recv(20)==b'second' else 'blocked',flush=True)\nexcept (TimeoutError,OSError):print('blocked',flush=True)"
        process=subprocess.Popen(['docker','exec','-i',CONTAINERS['client'],'python','-u','-c',persistent,resource_ip],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        assert process.stdout.readline().strip()=='ready'
        rpc('acl',rules=rules(resource_ip,'UDP',18080,public_client,psk))
        output,_=process.communicate('continue\n',timeout=10)
        assert output.strip()=='blocked','Established TCP bypassed revoked permission'
        assert connect(resource_ip,18080)=='blocked'
        assert connect(resource_ip,18080,True)=='allowed'
        rpc('acl',rules=rules(resource_ip,'REVOKED',18080,public_client,psk))
        assert connect(resource_ip,18080,True)=='blocked','Revoked final resource permission remained reachable'
        dump=rpc('command',argv=['wg','show','wg-test','dump']);assert dump.startswith('(hidden)')
        uid=execute('server','id','-u',user='1001:1001');assert uid=='1001'
        status=execute('server','python','-c',"from app.channel_status import _wg;import json;print(json.dumps(_wg('wg-test')))",user='1001:1001',environment={'PYTHONPATH':'/opt/fortis/backend','DATA_DIR':'/tmp/fortis-user-data','NETWORK_HELPER_SOCKET':'/run/fortis-network.sock'})
        assert json.loads(status)['available'],'Unprivileged channel diagnostics failed'
        probe=rpc('ping',ip=resource_ip,interface='',count=3);assert probe['returncode']==0,'ICMP helper failed'
        denied=execute('server','python','-c',"from pathlib import Path\ntry:Path('/etc/wireguard/wg-test.conf').read_text();print('leaked')\nexcept PermissionError:print('denied')",user='1001:1001');assert denied=='denied'
        try:rpc('command',argv=['sh','-c','id'])
        except RuntimeError:pass
        else:raise AssertionError('Arbitrary execution accepted')
        unauthorized=execute('server','python','-c',"import socket;s=socket.socket(socket.AF_UNIX);s.connect('/run/fortis-network.sock');s.sendall(b'{\"operation\":\"health\",\"args\":{}}');\ntry:s.shutdown(socket.SHUT_WR);print('denied' if not s.recv(100) else 'leaked')\nexcept (ConnectionResetError,BrokenPipeError):print('denied')",user='65534:1001')
        assert unauthorized=='denied'
        # All unit/API tests also run as an unprivileged Linux account.
        suite=execute('server','python','-m','unittest','discover','-s','/opt/fortis/backend/tests','-q',user='1001:1001',environment={'PYTHONPATH':'/opt/fortis/backend','NETWORK_HELPER_SOCKET':''})
        print('PASS: unprivileged Linux backend tests; authenticated root-only Unix service')
        print('PASS: real WireGuard, TCP/UDP service ACLs and blocked established flow after revocation')
        print('PASS: server key isolation, arbitrary command denial and unauthorized UID rejection')
        print('PASS: unprivileged channel diagnostics and bounded ICMP through the network service')
    except Exception:
        print(execute('server','cat','/tmp/fortis-network-test.log',check=False))
        raise
    finally:
        for name in CONTAINERS.values():docker('rm','-f',name,check=False)
        docker('network','rm',NETWORK,check=False)
        shutil.rmtree(temp)

if __name__=='__main__':main()
