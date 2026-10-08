"""Authenticated encryption for stored AD credentials; key is outside the DB."""
import os
import tempfile
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
from .config import settings

PREFIX = 'fortis:v1:'


def cipher(create=True):
    directory = settings.data_dir / 'secrets'
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory.chmod(0o700)
    path = directory / 'ad.key'
    if path.is_symlink():
        raise RuntimeError('Ключ шифрования AD не должен быть символьной ссылкой')
    if not path.exists():
        if not create:
            raise RuntimeError('Отсутствует ключ шифрования AD: восстановите исходный ключ')
        fd, temporary = tempfile.mkstemp(dir=directory, prefix='.ad-')
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(Fernet.generate_key()); stream.flush(); os.fsync(stream.fileno())
            try:
                os.link(temporary, path)
            except FileExistsError:
                pass
        finally:
            Path(temporary).unlink(missing_ok=True)
    path.chmod(0o600)
    return Fernet(path.read_bytes())


def encrypt(value):
    if not value or value.startswith(PREFIX):
        return value
    return PREFIX + cipher().encrypt(value.encode()).decode()


def decrypt(value):
    if not value or not value.startswith(PREFIX):
        return value  # Existing installations are migrated at startup.
    try:
        return cipher(create=False).decrypt(value[len(PREFIX):].encode()).decode()
    except (InvalidToken, ValueError) as exc:
        raise RuntimeError('Не удалось расшифровать пароль AD: восстановите исходный ключ') from exc
