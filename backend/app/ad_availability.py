"""Read-only TCP availability of saved AD endpoints; never attempts a bind."""
import socket
from datetime import datetime, timezone
from threading import BoundedSemaphore
from time import monotonic

from fastapi import HTTPException

_slots = BoundedSemaphore(2)


def check_availability(db, source_id):
    from .ad import _load_sources
    source = next((s for s in _load_sources(db) if s['id'] == source_id), None)
    if source is None:
        raise HTTPException(404, 'Домен AD не найден')
    if source.get('deleting'):
        raise HTTPException(409, 'Домен удаляется; проверка недоступна')
    if not _slots.acquire(blocking=False):
        raise HTTPException(429, 'Уже выполняется проверка. Повторите немного позже')
    started = monotonic()
    try:
        try:
            with socket.create_connection((source['host'], int(source['port'])), timeout=5):
                pass
            status, detail = 'AVAILABLE', 'Сервер доступен: соединение с настроенным портом LDAP/LDAPS установлено.'
        except socket.gaierror:
            status, detail = 'UNAVAILABLE', 'Не удалось определить IP-адрес домена. Проверьте DNS и имя сервера.'
        except (TimeoutError, socket.timeout):
            status, detail = 'UNAVAILABLE', 'Сервер не ответил вовремя. Проверьте маршрутизацию, порт и межсетевой экран.'
        except ConnectionRefusedError:
            status, detail = 'UNAVAILABLE', 'Соединение отклонено: порт закрыт или служба LDAP/LDAPS не запущена.'
        except OSError:
            status, detail = 'UNAVAILABLE', 'Не удалось соединиться с сервером. Проверьте сеть и выбранный порт.'
        return {'status': status, 'detail': detail,
                'checkedAt': datetime.now(timezone.utc).isoformat(),
                'durationMs': round((monotonic() - started) * 1000)}
    finally:
        _slots.release()
