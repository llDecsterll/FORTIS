"""Isolated entry point: python -I ignores caller PYTHONPATH and user packages."""
import os
import stat
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
for path in (root, root/'backend', root/'backend/app', root/'backend/.venv', Path(__file__).resolve()):
    info=path.stat()
    if info.st_uid != 0 or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise RuntimeError('Network service code and venv must be root-owned and not group/world writable')
os.environ['NETWORK_HELPER_SOCKET']=''
sys.path.insert(0,str(root/'backend'))
from app.network_service import serve
serve()
