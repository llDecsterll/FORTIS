"""Root-only network service. No HTTP, shell, pickle or caller-selected file paths."""
import base64
import grp
import ipaddress
import json
import logging
import os
from pathlib import Path
import pwd
import re
import socket
import struct
import subprocess
import tempfile
import threading

MAX_MESSAGE = 1024 * 1024
STATE = Path('/var/lib/fortis-network')
REGISTRY = STATE / 'interfaces.json'
_SOCKET = '/run/fortis-network.sock'
_LOCK = threading.RLock()


def interface(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,14}', value):
        raise ValueError('Invalid interface')
    return value


def key(value):
    if not isinstance(value, str) or len(base64.b64decode(value, validate=True)) != 32:
        raise ValueError('Invalid WireGuard key')
    return value


def owned():
    return json.loads(REGISTRY.read_text()) if REGISTRY.exists() else {}


def managed(name):
    interface(name)
    if name not in {v['name'] for v in owned().values()}:
        raise ValueError('Unmanaged interface')
    return name


def run(argv, input=None):
    proc = subprocess.run(argv, input=input, capture_output=True, text=True, timeout=25, env={
        'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'})
    if proc.returncode:
        raise RuntimeError('Network command failed')  # Never return keys/stdout/stderr on error.
    return proc.stdout.strip()


def validate_command(argv):
    if not isinstance(argv, list) or len(argv) > 16 or any(not isinstance(x, str) or len(x) > 128 or '\n' in x or '\x00' in x for x in argv):
        raise ValueError('Invalid command')
    if argv in [['wg', 'show', 'interfaces'], ['ip', '-j', '-4', 'route', 'show', 'scope', 'link'], ['ip', '-j', 'link', 'show'], ['ip', '-j', '-4', 'rule', 'show']]:
        return argv
    if len(argv) == 4 and argv[:2] == ['wg', 'show'] and argv[3] in ('dump', 'public-key', 'listen-port', 'latest-handshakes'):
        managed(argv[2]); return argv
    if len(argv) == 6 and argv[:2] == ['wg', 'set'] and argv[3] == 'peer' and argv[5] == 'remove':
        managed(argv[2]); key(argv[4]); return argv
    if len(argv) == 6 and argv[:4] in (['ip', '-j', 'address', 'show'], ['ip', '-j', 'link', 'show']) and argv[4] == 'dev':
        interface(argv[5]); return argv
    if len(argv) == 7 and argv[:6] == ['ip', '-j', '-4', 'route', 'show', 'exact']:
        net = ipaddress.ip_network(argv[6], strict=True)
        if net.version != 4 or net.prefixlen == 0: raise ValueError('route')
        return argv
    if len(argv) == 9 and argv[:4] == ['ip', '-4', 'route', 'replace'] and argv[5] == 'dev' and argv[7:] == ['proto', 'static']:
        net=ipaddress.IPv4Network(argv[4], strict=True)
        if net.prefixlen == 0: raise ValueError('route')
        managed(argv[6]); return argv
    if len(argv) == 9 and argv[:4] == ['ip', '-4', 'route', 'del'] and argv[5] == 'dev' and argv[7:] == ['proto', 'static']:
        net=ipaddress.IPv4Network(argv[4], strict=True)
        if net.prefixlen == 0: raise ValueError('route')
        managed(argv[6]); return argv
    if len(argv) == 10 and argv[:3] == ['ip', '-4', 'rule'] and argv[3] in ('add','del') and argv[4:7] == ['priority','52','to'] and argv[8:] == ['lookup','main']:
        net=ipaddress.IPv4Network(argv[7],strict=True)
        if net.prefixlen == 0: raise ValueError('route')
        return argv
    if argv in [['nft', 'list', 'table', 'inet', 'fortis_filter'], ['nft', 'list', 'table', 'ip', 'fortis_nat'], ['nft', '-j', 'list', 'chain', 'inet', 'fortis_filter', 'input']]:
        return argv
    raise ValueError('Operation not allowed')


def validate_rules(text):
    if not isinstance(text, str) or len(text.encode()) > 512 * 1024:
        raise ValueError('Rules too large')
    fixed = {'add table inet fortis_filter','delete table inet fortis_filter','add table ip fortis_nat','delete table ip fortis_nat',
             'table inet fortis_filter {','table ip fortis_nat {','chain input {','chain output {','chain forward {','chain postrouting {','}',
             'type filter hook input priority filter; policy drop;','type filter hook forward priority filter; policy drop;','type filter hook output priority filter; policy accept;',
             'type nat hook postrouting priority srcnat; policy accept;'}
    words = {'iif','iifname','oifname','ip','saddr','daddr','protocol','tcp','udp','dport','sport','icmp','type','echo-request',
             'destination-unreachable','time-exceeded','parameter-problem','ct','state','established','related','invalid',
             'accept','drop','masquerade','snat','to','meta','l4proto'}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line == '#!/usr/sbin/nft -f' or line in fixed:
            continue
        if len(line) > 32768 or any(c in line for c in ';\\\'#$'):
            raise ValueError('Invalid rule')
        tokens = re.findall(r'"[A-Za-z][A-Za-z0-9_.-]{0,14}"|!=|[{},]|[A-Za-z0-9./-]+', line)
        if ''.join(tokens) != re.sub(r'\s+', '', line):
            raise ValueError('Invalid tokens')
        for token in tokens:
            if token in words or token in ('!=','{','}',',') or token.startswith('"'):
                continue
            if token.isdecimal() and 0 <= int(token) <= 65535:
                continue
            try:
                ipaddress.IPv4Network(token, strict=False)
            except ValueError as exc:
                raise ValueError('Invalid rule token') from exc
    return text


def activate(cfg, mtu):
    from .setup import InterfaceIn, validate_connections
    values = [InterfaceIn.model_validate(v) for v in cfg.values()]
    if not values or len(values) > 16 or not isinstance(mtu,int) or not 576 <= mtu <= 9000:
        raise ValueError('Invalid interface configuration')
    validate_connections(values)
    registry=owned()
    created=[]
    try:
        for item in values:
            name=interface(item.name)
            if name in ('lo','eth0','en0') or not Path('/sys/class/net', item.uplink).exists():
                raise ValueError('Invalid interface/uplink')
            target=Path('/etc/wireguard') / (name+'.conf')
            if name not in {v['name'] for v in registry.values()}:
                if target.exists() or Path('/sys/class/net',name).exists():
                    raise ValueError('Existing unmanaged interface')
                target.parent.mkdir(mode=0o700,exist_ok=True)
                private=run(['wg','genkey'])
                network=ipaddress.IPv4Network(item.subnet)
                content=f'[Interface]\nPrivateKey = {private}\nAddress = {next(network.hosts())}/{network.prefixlen}\nListenPort = {item.port}\nMTU = {mtu}\n'
                fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                with os.fdopen(fd,'w') as stream: stream.write(content)
                created.append(target)
            # Never execute wg-quick/PostUp hooks, including in existing configuration.
            import configparser
            parser=configparser.ConfigParser(); parser.optionxform=str
            fd=os.open(target,os.O_RDONLY|os.O_NOFOLLOW)
            with os.fdopen(fd) as stream:
                info=os.fstat(stream.fileno())
                if info.st_uid != 0 or info.st_mode & 0o077:
                    raise ValueError('Unsafe server key ownership or permissions')
                parser.read_file(stream)
            if parser.sections()!=['Interface'] or set(parser['Interface'])!={'PrivateKey','Address','ListenPort','MTU'}:
                raise ValueError('Unrecognized server configuration')
            private=key(parser['Interface']['PrivateKey'])
            if not Path('/sys/class/net',name).exists(): run(['ip','link','add','dev',name,'type','wireguard'])
            with tempfile.NamedTemporaryFile(mode='w',dir=STATE) as temp:
                temp.write(private);temp.flush()
                run(['wg','set',name,'private-key',temp.name,'listen-port',str(item.port)])
            network=ipaddress.IPv4Network(item.subnet)
            run(['ip','address','replace',f'{next(network.hosts())}/{network.prefixlen}','dev',name])
            run(['ip','link','set','dev',name,'mtu',str(mtu),'up'])
        if Path('/proc/sys/net/ipv4/ip_forward').read_text().strip() != '1':
            run(['sysctl','-w','net.ipv4.ip_forward=1'])
        with tempfile.NamedTemporaryFile(mode='w',dir=STATE,delete=False) as stream:
            pending=Path(stream.name)
            try:
                stream.write(json.dumps(cfg));stream.flush();os.fsync(stream.fileno())
                os.replace(pending,REGISTRY)
            finally:
                pending.unlink(missing_ok=True)
        configure(cfg)
        return [v.name for v in values]
    except Exception:
        for target in created:
            try: run(['ip','link','delete','dev',target.stem])
            except Exception: pass
            target.unlink(missing_ok=True)
        raise


def configure(cfg):
    from .config import settings
    for contour in ('employees','sites'):
        item=cfg.get(contour)
        setattr(settings,contour+'_enabled',bool(item))
        if item:
            for suffix, field in [('if','name'),('nic','uplink'),('net','subnet'),('port','port')]:
                setattr(settings,contour+'_'+suffix,item[field])
    settings.additional_interfaces=[v for k,v in cfg.items() if k not in ('employees','sites')]
    from .osdetect import start
    start()


def dispatch(operation,args):
    from . import host_network
    if operation=='health' and not args: return {'ready':True}
    if operation=='command' and set(args)=={'argv'}:
        argv=validate_command(args['argv'])
        if argv==['wg','show','interfaces']: return ' '.join(v['name'] for v in owned().values())
        output=run(argv)
        if argv[:2]==['wg','show'] and argv[-1]=='dump' and output:
            rows=output.splitlines(); first=rows[0].split('\t');first[0]='(hidden)';rows[0]='\t'.join(first);output='\n'.join(rows)
        return output
    if operation=='activate' and set(args)=={'profiles','mtu'}: return activate(args['profiles'],args['mtu'])
    if operation=='peer_set' and set(args)=={'interface','public_key','psk','allowed_ips'}:
        name=managed(args['interface']); public=key(args['public_key']); psk=key(args['psk'])
        ips=[str(ipaddress.IPv4Network(v.strip(),strict=False)) for v in args['allowed_ips'].split(',')]
        if not 1<=len(ips)<=64 or any(ipaddress.ip_network(v).prefixlen==0 for v in ips): raise ValueError('Invalid peer addresses')
        with tempfile.NamedTemporaryFile(mode='w',dir=STATE) as temp:
            temp.write(psk);temp.flush()
            run(['wg','set',name,'peer',public,'preshared-key',temp.name,'allowed-ips',','.join(ips)])
        return True
    if operation=='acl' and set(args)=={'rules'}:
        rules=validate_rules(args['rules'])
        # nft -c is non-mutating; apply a single atomic transaction only after validation.
        run(['nft','-c','-f','-'],input=rules)
        run(['nft','-f','-'],input=rules)
        return True
    if operation=='ping' and set(args)=={'ip','interface','count'}:
        from .network_ping import ping_address
        target=ping_address(args['ip'])
        if type(args['count']) is not int or args['count'] not in (3,5): raise ValueError('count')
        argv=['/usr/bin/ping','-n','-c',str(args['count']),'-i','0.2','-W','1','-w','5']
        if args['interface']: argv += ['-I',managed(args['interface'])]
        result=subprocess.run(argv+['--',target],capture_output=True,text=True,timeout=7,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        return {'returncode':result.returncode,'stdout':result.stdout[:4096],'stderr':result.stderr[:4096]}
    if operation=='flows' and not args:
        path=Path('/proc/net/nf_conntrack')
        if not path.exists(): return ''
        with path.open(errors='ignore') as stream: return stream.read(256 * 1024)
    if operation=='discover' and not args: return host_network.discover()
    if operation=='network_apply' and set(args)=={'plan'}: return host_network.apply(args['plan'],STATE)
    if operation=='network_confirm' and not args: return host_network.confirm(STATE)
    if operation=='network_cancel' and not args: return host_network.cancel(STATE)
    if operation=='network_status' and not args: return host_network.public_transaction(STATE)
    if operation=='observe' and set(args)=={'vpn_ip','public_ip'}:
        from .osdetect import observe
        for value in args.values():
            if value: ipaddress.ip_address(value)
        return observe(**args)
    raise ValueError('Operation not allowed')


def serve(path=_SOCKET, client_user='fortis'):
    if os.geteuid()!=0 or not hasattr(socket,'SO_PEERCRED'):
        raise RuntimeError('Network service requires Linux root')
    allowed_uid=pwd.getpwnam(client_user).pw_uid
    STATE.mkdir(mode=0o700,parents=True,exist_ok=True);STATE.chmod(0o700)
    # A systemd restart also kills the old watchdog; restore any unfinished transaction.
    from . import host_network
    if host_network.transaction(STATE).get('status') in ('pending', 'applying', 'rollback_failed'):
        host_network.cancel(STATE)
        if host_network.transaction(STATE).get('status') == 'rollback_failed':
            host_network.restore(STATE)
        if host_network.transaction(STATE).get('status') == 'rollback_failed':
            raise RuntimeError('Pending network rollback requires console recovery')
    if REGISTRY.exists(): configure(owned())
    os.umask(0o077)
    if Path(path).exists():
        if not Path(path).is_socket() or Path(path).lstat().st_uid!=0: raise RuntimeError('Unsafe socket path')
        Path(path).unlink()
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
        server.bind(path);os.chown(path,0,grp.getgrnam(client_user).gr_gid);os.chmod(path,0o660);server.listen(16)
        while True:
            stream,_=server.accept()
            with stream:
                stream.settimeout(30)
                _,uid,_=struct.unpack('3i',stream.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                if uid not in (0,allowed_uid): continue
                data=bytearray()
                try:
                    while len(data)<=MAX_MESSAGE:
                        part=stream.recv(min(65536,MAX_MESSAGE+1-len(data)))
                        if not part:break
                        data.extend(part)
                    if len(data)>MAX_MESSAGE:raise ValueError('too large')
                    request=json.loads(data)
                    if set(request)!={'operation','args'} or not isinstance(request['args'],dict):raise ValueError('request')
                    with _LOCK: result=dispatch(request['operation'],request['args'])
                    response={'ok':True,'result':result}
                except Exception as exc:
                    logging.warning('Network request rejected: %s', type(exc).__name__)
                    response={'ok':False,'error':'Сетевая операция отклонена или не выполнена'}
                encoded=json.dumps(response,ensure_ascii=True).encode()
                if len(encoded)>MAX_MESSAGE:encoded=b'{"ok":false,"error":"Result too large"}'
                stream.sendall(encoded)


if __name__=='__main__':
    serve()
