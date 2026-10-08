import base64
import hashlib
import hmac
import re
from starlette.responses import Response
from starlette.concurrency import run_in_threadpool
from .config import settings
from .db import SessionLocal
from .models import User

def entry_key(user):
    # The database nonce alone cannot be used as the URL secret.
    if not user.panel_nonce:
        raise ValueError('Panel entry is not initialized')
    payload=f'panel-entry-v1:{user.id}:{user.panel_nonce}'.encode()
    signature=base64.urlsafe_b64encode(hmac.new(settings.secret_key.encode(),payload,hashlib.sha256).digest()).decode().rstrip('=')
    return f'{user.id}.{signature}'

def resolve_owner(key):
    if not re.fullmatch(r'[a-f0-9-]{36}\.[A-Za-z0-9_-]{43}',key): return None
    with SessionLocal() as db:
        user=db.get(User,key.split('.')[0])
        if not user or not user.is_active or not user.panel_nonce: return None
        return user.id if hmac.compare_digest(entry_key(user),key) else None

class PanelGateMiddleware:
    def __init__(self,app,enabled=False): self.app,self.enabled=app,enabled
    async def __call__(self,scope,receive,send):
        if scope['type']!='http' or not self.enabled:
            return await self.app(scope,receive,send)
        path=scope.get('path','')
        parts=path.split('/',2)
        key=parts[1] if len(parts)>1 else ''
        owner=await run_in_threadpool(resolve_owner,key)
        if not owner:
            # Private upstream signal: nginx intercepts it and closes the client
            # connection without sending an HTTP status line or response body.
            return await Response(status_code=444,headers={'Cache-Control':'no-store','Referrer-Policy':'no-referrer'})(scope,receive,send)
        scope=dict(scope)
        scope['state']={**scope.get('state',{}),'panel_user_id':owner,'panel_base':'/'+key}
        scope['path']='/'+parts[2] if len(parts)>2 else '/'
        scope['raw_path']=scope['path'].encode()
        return await self.app(scope,receive,send)
