#!/usr/bin/env bash
set -euo pipefail
umask 077
cd "$(dirname "${BASH_SOURCE[0]}")/.."
export UV_CACHE_DIR="${UV_CACHE_DIR:-/workspace/.cache/uv}"
uv sync --frozen
if [ -z "${VIGIA_SECRET_KEY:-}" ]; then
  if [ ! -f .env ]; then
    uv run python - <<'PY'
import secrets
from pathlib import Path
with Path('.env').open('x') as f:
    f.write('VIGIA_SECRET_KEY=' + secrets.token_urlsafe(48) + '\n')
    f.write('VIGIA_DEBUG=true\nVIGIA_ALLOWED_HOSTS=localhost,127.0.0.1,testserver\n')
Path('.env').chmod(0o600)
PY
  fi
  set -a
  . ./.env
  set +a
fi
mkdir -p var/uploads
chmod 700 var/uploads
uv run python manage.py migrate --noinput
uv run python manage.py collectstatic --noinput
uv run python manage.py check
