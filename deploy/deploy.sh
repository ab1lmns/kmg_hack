#!/usr/bin/env bash
# Update the dedicated tailnet-only instance without touching server secrets.
set -euo pipefail

APP_DIR=${APP_DIR:-/opt/identity-risk}
APP_USER=${APP_USER:-identityrisk}
SERVICE=${SERVICE:-identity-risk.service}
PORT=${PORT:-8011}
TARGET_REF=${1:-origin/main}

if [[ ${EUID} -ne 0 ]]; then
  echo "Run as root for the systemd restart" >&2
  exit 1
fi
if [[ ! -d "${APP_DIR}/.git" || ! -f "${APP_DIR}/backend/.env" ]]; then
  echo "Repository or server-only backend/.env is missing" >&2
  exit 1
fi
if [[ -n "$(runuser -u "${APP_USER}" -- git -C "${APP_DIR}" status --porcelain --untracked-files=no)" ]]; then
  echo "Tracked files have local changes; refusing deployment" >&2
  exit 1
fi

runuser -u "${APP_USER}" -- git -C "${APP_DIR}" fetch origin main
TARGET_SHA=$(runuser -u "${APP_USER}" -- git -C "${APP_DIR}" rev-parse "${TARGET_REF}^{commit}")
runuser -u "${APP_USER}" -- git -C "${APP_DIR}" merge-base --is-ancestor "${TARGET_SHA}" origin/main
runuser -u "${APP_USER}" -- git -C "${APP_DIR}" checkout --detach "${TARGET_SHA}"

if [[ ! -x "${APP_DIR}/backend/.venv/bin/python" ]]; then
  runuser -u "${APP_USER}" -- python3 -m venv "${APP_DIR}/backend/.venv"
fi
runuser -u "${APP_USER}" -- "${APP_DIR}/backend/.venv/bin/python" -m pip install \
  --disable-pip-version-check -r "${APP_DIR}/backend/requirements.txt"
runuser -u "${APP_USER}" -- bash -c 'cd "$1/frontend" && npm ci --no-audit --no-fund && npm run build' _ "${APP_DIR}"

systemctl restart "${SERVICE}"
for _ in {1..30}; do
  if curl --fail --silent --max-time 2 "http://127.0.0.1:${PORT}/api/health" >/dev/null; then
    break
  fi
  sleep 1
done
runuser -u "${APP_USER}" -- python3 "${APP_DIR}/deploy/check.py" \
  --base-url "http://127.0.0.1:${PORT}" --database "${APP_DIR}/backend/data/radar.db" --scan
echo "Deployed ${TARGET_SHA}"
