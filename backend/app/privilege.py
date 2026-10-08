"""JSON-only Unix-socket client for the isolated network service."""
import json
import socket
import struct
from .config import settings

MAX_MESSAGE = 1024 * 1024


def enabled():
    return bool(settings.network_helper_socket)


def receive(stream):
    data = bytearray()
    while len(data) <= MAX_MESSAGE:
        part = stream.recv(min(65536, MAX_MESSAGE + 1 - len(data)))
        if not part:
            break
        data.extend(part)
    if not data or len(data) > MAX_MESSAGE:
        raise RuntimeError('Некорректный ответ сетевой службы')
    return json.loads(data)


def call(operation, **args):
    body = json.dumps({'operation': operation, 'args': args}, ensure_ascii=True).encode()
    if len(body) > MAX_MESSAGE:
        raise RuntimeError('Слишком большой запрос сетевой службы')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(45)
        stream.connect(settings.network_helper_socket)
        if not hasattr(socket, 'SO_PEERCRED'):
            raise RuntimeError('Сетевая служба поддерживается только на Linux')
        _, uid, _ = struct.unpack('3i', stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != 0:
            raise RuntimeError('Сетевая служба не принадлежит root')
        stream.sendall(body)
        stream.shutdown(socket.SHUT_WR)
        result = receive(stream)
    if not result.get('ok'):
        raise RuntimeError(result.get('error', 'Сетевая операция не выполнена'))
    return result.get('result')


def command(args):
    return call('command', argv=list(args))


def available():
    if not enabled():
        return False
    try:
        return call('health') == {'ready': True}
    except (OSError, RuntimeError, ValueError):
        return False
