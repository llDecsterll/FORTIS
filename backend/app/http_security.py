"""Browser session protections and request limits, before route execution."""
import secrets
from urllib.parse import urlsplit
from starlette.responses import JSONResponse
from .config import settings
from .security import SESSION_COOKIE, CSRF_COOKIE


def public_hosts():
    host = urlsplit(settings.public_origin).hostname
    return list(dict.fromkeys([v.strip() for v in settings.allowed_hosts.split(',') if v.strip()] + ([host] if host else [])))


class HttpSecurityMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        from starlette.requests import Request
        request = Request(scope)
        unsafe = request.method not in ('GET', 'HEAD', 'OPTIONS')
        origin = request.headers.get('origin')
        allowed = {settings.public_origin.rstrip('/'), 'http://127.0.0.1:5173', 'http://localhost:5173',
                   str(request.base_url).rstrip('/')}
        denied = unsafe and origin is not None and origin.rstrip('/') not in allowed
        cookie_auth = SESSION_COOKIE in request.cookies and not request.headers.get('authorization')
        if unsafe and cookie_auth:
            cookie = request.cookies.get(CSRF_COOKIE, '')
            header = request.headers.get('x-fortis-csrf', '')
            denied = denied or not cookie or not secrets.compare_digest(cookie.encode(), header.encode())
        if denied:
            return await JSONResponse({'error': {'message': 'Запрос отклонён защитой CSRF'}}, status_code=403)(scope, receive, send)
        ranges = request.headers.get('range', '')
        if len(ranges) > 1024 or ranges.count(',') > 15:
            return await JSONResponse({'error': {'message': 'Слишком сложный Range-запрос'}}, status_code=416)(scope, receive, send)

        async def secure_send(message):
            if message['type'] == 'http.response.start':
                headers = list(message.get('headers', []))
                csp = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                       "img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; "
                       "worker-src 'self' blob:; object-src 'none'; base-uri 'self'; "
                       "frame-ancestors 'none'; form-action 'self'")
                headers += [(b'content-security-policy', csp.encode()), (b'x-frame-options', b'DENY'),
                            (b'x-content-type-options', b'nosniff'), (b'referrer-policy', b'no-referrer'),
                            (b'permissions-policy', b'camera=(), microphone=(), geolocation=()')]
                if request.url.scheme == 'https' or urlsplit(settings.public_origin).scheme == 'https':
                    headers.append((b'strict-transport-security', b'max-age=31536000'))
                message = {**message, 'headers': headers}
            await send(message)
        await self.app(scope, receive, secure_send)


class ClientIpMiddleware:
    """Trust exactly one proxy-supplied IP only from explicitly configured peers."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        import ipaddress
        if scope['type'] == 'http' and scope.get('client'):
            try:
                peer = ipaddress.ip_address(scope['client'][0])
                trusted = [ipaddress.ip_network(v.strip()) for v in settings.trusted_proxy_ips.split(',') if v.strip()]
                if any(peer in net for net in trusted):
                    headers = [(k, v) for k, v in scope.get('headers', []) if k.lower() == b'x-real-ip']
                    if len(headers) == 1:
                        address = ipaddress.ip_address(headers[0][1].decode('ascii').strip())
                        scope = {**scope, 'client': (str(address), scope['client'][1])}
            except (ValueError, UnicodeError):
                pass  # Retain transport peer on malformed configuration/header.
        await self.app(scope, receive, send)
