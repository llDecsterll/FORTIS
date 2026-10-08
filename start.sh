#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [ -x backend/.venv-runtime/bin/python ]; then
  kontur_python="$(pwd)/backend/.venv-runtime/bin/python"
elif [ -x backend/.venv/bin/python ] && backend/.venv/bin/python -c 'import sys; assert sys.version_info >= (3, 10)' 2>/dev/null; then
  kontur_python="$(pwd)/backend/.venv/bin/python"
else
  python3 -c 'import sys; assert sys.version_info >= (3, 10), "Нужен Python 3.10 или новее"'
  python3 -m venv backend/.venv
  kontur_python="$(pwd)/backend/.venv/bin/python"
fi
fortis_stamp="$(dirname "$kontur_python")/../.fortis-requirements-sha256"
fortis_hash="$("$kontur_python" -c 'from hashlib import sha256; from pathlib import Path; print(sha256(Path("backend/requirements.txt").read_bytes()).hexdigest())')"
if [ ! -f "$fortis_stamp" ] || [ "$(cat "$fortis_stamp")" != "$fortis_hash" ]; then
  "$kontur_python" -m pip install -r backend/requirements.txt
  printf '%s\n' "$fortis_hash" > "$fortis_stamp"
fi
(cd web && npm ci --ignore-scripts --no-audit --no-fund && npm run build)
cd backend
exec "$kontur_python" -m uvicorn app.main:app --host 127.0.0.1 --port "${FORTIS_PORT:-${KONTUR_PORT:-8088}}" --no-proxy-headers
