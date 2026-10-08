"""Operational configuration. Backup destinations are drafts, never executable commands."""
import json
import re
from typing import Literal
from pydantic import BaseModel, Field, model_validator
from .models import Setting

KEY = 'operations_v1'

class OperationsIn(BaseModel):
    employeesMbps: int = Field(default=0, ge=0, le=100000, strict=True)
    sitesMbps: int = Field(default=0, ge=0, le=100000, strict=True)
    retentionDays: int = Field(default=2, ge=2, le=30, strict=True)
    backupKind: Literal['none', 'sftp', 'smb'] = 'none'
    backupHost: str = Field(default='', max_length=253)
    backupPath: str = Field(default='', max_length=512)
    backupUser: str = Field(default='', max_length=128)

    @model_validator(mode='after')
    def validate_destination(self):
        self.backupHost = self.backupHost.strip()
        self.backupPath = self.backupPath.strip()
        self.backupUser = self.backupUser.strip()
        if self.backupKind == 'none':
            self.backupHost = self.backupPath = self.backupUser = ''
            return self
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*', self.backupHost):
            raise ValueError('Укажите IP или DNS-имя сервера без протокола и пароля')
        if not self.backupPath or not self.backupUser:
            raise ValueError('Укажите папку и пользователя хранилища')
        if any(ord(c) < 32 for c in self.backupPath + self.backupUser):
            raise ValueError('Недопустимые символы в папке или пользователе')
        if self.backupKind == 'sftp' and not self.backupPath.startswith('/'):
            raise ValueError('Папка SFTP должна начинаться с /')
        return self

def read_operations(db):
    row = db.get(Setting, KEY)
    if not row:
        return OperationsIn()
    # Fail visibly on corrupt stored configuration rather than claiming protection.
    return OperationsIn.model_validate(json.loads(row.value))

def save_operations(db, value):
    row = db.get(Setting, KEY)
    if row is None:
        row = Setting(key=KEY, value='{}')
        db.add(row)
    row.value = value.model_dump_json()
    db.flush()

def public_operations(value):
    return {**value.model_dump(), 'backupStatus': 'not_configured' if value.backupKind == 'none' else 'draft',
            'backupEnabled': False,
            'backupMessage': 'Автоматическое копирование не настроено. Сохранение назначения не подключает хранилище и не создаёт резервные копии.'}
