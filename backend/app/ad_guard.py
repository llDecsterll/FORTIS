"""Serialize AD configuration and sync, including commits inside peer operations."""
from contextlib import contextmanager
from functools import wraps
from threading import RLock

from sqlalchemy import text

_mutex = RLock()


@contextmanager
def ad_guard(db):
    with _mutex:
        connection = None
        try:
            if db.bind.dialect.name == "postgresql":
                connection = db.bind.connect()
                connection.execute(text("SELECT pg_advisory_lock(734029)"))
            db.expire_all()
            yield
        finally:
            if connection is not None:
                try:
                    connection.execute(text("SELECT pg_advisory_unlock(734029)"))
                finally:
                    connection.close()


def serialized_ad(function):
    @wraps(function)
    def wrapped(db, *args, **kwargs):
        with ad_guard(db):
            return function(db, *args, **kwargs)
    return wrapped
