"""Bounded, read-only status for the server-managed SMB backup. No credentials."""
import json
import socket
import subprocess
import re
from datetime import datetime, timezone
from pathlib import Path

CONFIG = Path('/etc/kontur-backup/status-config.json')
STATE = Path('/var/lib/kontur-backup/status.json')

def read_backup_log():
    """Only this backup unit, last 100 lines within 30 days; never credentials."""
    try:
        output = subprocess.check_output(['journalctl','--unit','kontur-backup.service',
            '--since','30 days ago','--lines','100','--output','json','--no-pager','--quiet'],
            text=True,timeout=2,stderr=subprocess.DEVNULL)
        entries=[]
        in_key=False
        for line in output.splitlines():
            row=json.loads(line)
            message=row.get('MESSAGE','')
            if not isinstance(message,str): continue
            if '-----BEGIN ' in message:
                in_key=True
                entries.append({'createdAt':None,'message':'[Секретные данные скрыты]'})
                continue
            if in_key:
                if '-----END ' in message: in_key=False
                continue
            if re.search(r'(?i)(password|passwd|secret|token|credential|private.?key|DATABASE_URL)\s*[:=]',message):
                message='[Секретные данные скрыты]'
            message=re.sub(r'(://)[^/\s:@]+:[^/\s@]+@',r'\1[скрыто]@',message)
            stamp=row.get('__REALTIME_TIMESTAMP')
            created=datetime.fromtimestamp(int(stamp)/1_000_000,timezone.utc).isoformat() if stamp else None
            entries.append({'createdAt':created,'message':message[:2000]})
        return {'available':True,'entries':entries[-100:],'error':''}
    except (OSError, subprocess.SubprocessError, ValueError, TypeError, OverflowError):
        return {'available':False,'entries':[],'error':'Не удалось прочитать лог резервного копирования.'}

def _show(unit):
    try:
        output = subprocess.check_output(['systemctl','show',unit,'-p','ActiveState','-p','Result',
            '-p','UnitFileState','-p','NextElapseUSecRealtime'],text=True,timeout=2)
        return dict(line.split('=',1) for line in output.splitlines() if '=' in line)
    except (OSError, subprocess.SubprocessError):
        return {}

def _storage(host, share):
    try:
        with socket.create_connection((host,445),timeout=1):
            pass
        output = subprocess.check_output(['findmnt','-rn','-M','/mnt/kontur-backup','-t','cifs','-o','SOURCE'],text=True,timeout=1)
        if output.strip() != f'//{host}/{share}':
            return 'not_mounted'
        # A connected TCP port alone does not prove that the SMB share responds.
        subprocess.run(['python3','-c','import os; os.stat("/mnt/kontur-backup/kontur-new-wg")'],
                       timeout=2,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        return 'connected'
    except (OSError, subprocess.SubprocessError):
        return 'unavailable'

def read_backup_status():
    try:
        config = json.loads(CONFIG.read_text())
        host, share, folder = (str(config[k]) for k in ('host','share','folder'))
    except (OSError, ValueError, KeyError, TypeError):
        return {'configured':False,'storageStatus':'not_configured','jobStatus':'unknown','lastSuccess':None}
    try:
        state=json.loads(STATE.read_text())
    except (OSError,ValueError):
        state={}
    service=_show('kontur-backup.service'); timer=_show('kontur-backup.timer')
    job = 'running' if service.get('ActiveState')=='activating' else (
        'failed' if service.get('Result') not in (None,'','success') else state.get('state','unknown'))
    last = state.get('lastSuccess')
    last = {k:last.get(k) for k in ('filename','sizeBytes','completedAt')} if isinstance(last,dict) else None
    return {'configured':True,'kind':'SMB 3.1.1','host':host,'share':share,'folder':folder,
        'storageStatus':_storage(host,share),'jobStatus':job,'lastSuccess':last,
        'automaticEnabled':timer.get('ActiveState')=='active' and timer.get('UnitFileState')=='enabled',
        'schedule':'Ежедневно в 03:30 МСК','nextRun':timer.get('NextElapseUSecRealtime',''),
        'encryption':'AES-256 / backup-private.key',
        'lastError':'Задание завершилось с ошибкой. Подробности приведены ниже в логе резервного копирования.' if job=='failed' else '',
        'log':read_backup_log()}
