#!/usr/bin/env bash
# Update the isolated gateway checkout; never restart the private analyzer.
set -euo pipefail
APP_DIR=/opt/identity-risk-gateway
APP_USER=identityrisk
TARGET_REF=${1:-origin/main}
if [[ ${EUID} -ne 0 ]]; then echo "Run as root" >&2; exit 1; fi
if [[ ! -d "${APP_DIR}/.git" || ! -f "${APP_DIR}/backend/.env" ]]; then
  echo "Gateway checkout or server-only .env missing" >&2; exit 1
fi
if [[ -n "$(runuser -u "${APP_USER}" -- git -C "${APP_DIR}" status --porcelain --untracked-files=no)" ]]; then
  echo "Tracked gateway checkout has local changes" >&2; exit 1
fi
runuser -u "${APP_USER}" -- git -C "${APP_DIR}" fetch origin main
TARGET_SHA=$(runuser -u "${APP_USER}" -- git -C "${APP_DIR}" rev-parse "${TARGET_REF}^{commit}")
runuser -u "${APP_USER}" -- git -C "${APP_DIR}" merge-base --is-ancestor "${TARGET_SHA}" origin/main
runuser -u "${APP_USER}" -- git -C "${APP_DIR}" checkout --detach "${TARGET_SHA}"
if [[ ! -x "${APP_DIR}/backend/.venv/bin/python" ]]; then
  runuser -u "${APP_USER}" -- python3 -m venv "${APP_DIR}/backend/.venv"
fi
runuser -u "${APP_USER}" -- "${APP_DIR}/backend/.venv/bin/python" -m pip install \
  --disable-pip-version-check -q -r "${APP_DIR}/backend/requirements.txt"
systemctl restart ad-gateway.service
for _ in {1..30}; do
  if systemctl is-active --quiet ad-gateway.service; then break; fi
  sleep 1
done
systemctl is-active --quiet ad-gateway.service
echo "Gateway deployed ${TARGET_SHA}"
