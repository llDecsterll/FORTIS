#!/usr/bin/env python3
"""FORTIS agent v2 reference client. Requires cryptography and wireguard-tools."""
import argparse
import base64
import json
import os
from pathlib import Path
import ssl
import subprocess
import time
from urllib.request import Request, urlopen
from urllib.parse import urlparse
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def canonical(action, payload):
    return json.dumps({'protocol':'fortis-agent-v2','action':action,'payload':payload},
                      sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('command',choices=['enroll','run'])
    parser.add_argument('--server',required=True,help='https://vpn.example.com')
    parser.add_argument('--state',type=Path,required=True,help='private client directory')
    parser.add_argument('--ca-file',help='Optional trusted HTTPS CA bundle; verification is always enabled')
    parser.add_argument('--identity',help='Stable system identifier, required for enroll')
    parser.add_argument('--name',default='FORTIS agent')
    parser.add_argument('--mac',default='')
    args=parser.parse_args()
    url=args.server.rstrip('/')
    if urlparse(url).scheme!='https' or urlparse(url).username or urlparse(url).password:
        parser.error('HTTPS URL without embedded credentials required')
    if args.state.is_symlink():parser.error('State must not be a symlink')
    args.state.mkdir(mode=0o700,parents=True,exist_ok=True)
    if args.state.stat().st_uid!=os.geteuid():parser.error('State must belong to current user')
    args.state.chmod(0o700)
    context=ssl.create_default_context(cafile=args.ca_file)
    def post(path,payload):
        req=Request(url+'/api/'+path,data=json.dumps(payload).encode(),headers={'Content-Type':'application/json'})
        with urlopen(req,context=context,timeout=30) as response:return json.load(response)
    def save(name,value):
        path=args.state/name
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as stream:stream.write(value)
    record=args.state/'agent.json'
    if args.command=='enroll':
        if record.exists():parser.error('Already enrolled; use a new directory for replacement')
        if not args.identity:parser.error('--identity required')
        from getpass import getpass
        token=getpass('Single-use enrollment token: ')
        private=subprocess.run(['wg','genkey'],capture_output=True,text=True,check=True).stdout.strip()
        public=subprocess.run(['wg','pubkey'],input=private+'\n',capture_output=True,text=True,check=True).stdout.strip()
        result=post('device/register',{'token':token,'systemIdentifier':args.identity,'macEthernet':args.mac,
                    'wireguardPublicKey':public,'deviceName':args.name})
        save('device.key',result['certificateKeyPem']);save('device.crt',result['certificatePem'])
        save('fortis.conf',f"[Interface]\nPrivateKey = {private}\nAddress = {result['vpnIp']}/32\nDNS = {result['dns']}\nMTU = {result['mtu']}\n\n[Peer]\nPublicKey = {result['serverPublicKey']}\nPresharedKey = {result['presharedKey']}\nEndpoint = {result['endpoint']}\nAllowedIPs = {result['allowedIps']}\nPersistentKeepalive = 25\n")
        save('agent.json',json.dumps({'systemIdentifier':args.identity,'mac':args.mac,'wireguardPublicKey':public,
             'deviceName':args.name,'osName':'','clientVersion':'2.0.0','userEmail':''}))
        print('Enrolled. Client files saved in the private state directory. Start run, then WireGuard.')
        return
    data=json.loads(record.read_text())
    cert=(args.state/'device.crt').read_text()
    signer=serialization.load_pem_private_key((args.state/'device.key').read_bytes(),password=None)
    def signed(action,payload):
        payload['challenge']=post('device/challenge',{'certificatePem':cert})['challenge']
        payload['signature']=base64.b64encode(signer.sign(canonical(action,payload),padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.DIGEST_LENGTH),hashes.SHA256())).decode()
        return post('device/'+action,payload)
    result=signed('verify',dict(data,certificatePem=cert))
    token=result['session_token']
    print('Device authorized. Keep this process running while WireGuard is connected.')
    while True:
        time.sleep(max(1,min(15,int(result['expires_in'])//3)))
        result=signed('heartbeat',{'sessionToken':token})

if __name__=='__main__':
    try:main()
    except KeyboardInterrupt:pass
