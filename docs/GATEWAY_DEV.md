# Local development through AD Gateway

The current private `.ts.net` deployment remains available to administrators. For team development, the developer runs their own FastAPI Risk Engine and SQLite database. Only normalized read-only AD/Event Log observations cross the public HTTPS Gateway. The Gateway does not calculate findings, scores, recommendations, or scan history.

## Developer setup

1. Clone this repository. Install Python 3.12+ and Node.js 20+.
2. `cp backend/.env.example backend/.env`.
3. Set `AD_GATEWAY_URL=https://identity-risk.46.101.134.38.sslip.io` and your **personal** `AD_GATEWAY_TOKEN` in `backend/.env`. Do not commit or send this file. Do not set LDAP or Event Log credentials locally.
4. Run `./run` (or start `backend/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000` in `backend` and `npm run dev` in `frontend`). Open `http://127.0.0.1:5173`.

Every developer has an independent local `backend/data/radar.db`. Frontend requests remain on localhost; Vite proxies `/api` to the local FastAPI instance. A local change to `analysis.py`, rules, or scoring takes effect after restarting only the local backend and starting another scan. No Tailscale installation, direct DC access, or server deployment is needed.

The Gateway has exactly three GET endpoints: `/v1/health`, `/v1/status`, `/v1/snapshot`. All require a personal bearer token. `/v1/snapshot` has a fixed schema: users, groups and nested membership, computers, domain policy, FGPP and resultant policy, SPN and delegation fields, interactive rights evaluation, normalized Security Event Log events and source status. There are no client-controlled LDAP filters, bases, searches, or AD writes.

The Gateway stores only SHA-256 hashes of high-entropy tokens, plus access audit records. Tokens can be revoked individually. The LDAP password and the dedicated Event Log reader SSH key remain on DigitalOcean. Use a secure channel to give each developer their token; never put tokens in Git, README, frontend env, URLs, or chat logs.

If the Gateway returns 401, check the personal token or ask an administrator whether it was revoked. For 429, wait before scanning again. If its source status reports `not_evaluated`, inspect the relevant collector; interactive rights use a host-specific snapshot and become stale after 60 minutes. If the public URL is unavailable, the administrative `.ts.net` frontend continues independently.

## Administrator operations

The isolated `ad-gateway.service` runs from `/opt/identity-risk-gateway` as `identityrisk` on `127.0.0.1:8012`, behind an Nginx HTTPS vhost. The original `/opt/identity-risk` checkout, `identity-risk.service`, SQLite and Tailscale Serve are not redeployed by `deploy/deploy-gateway.sh`. New tokens are generated on a trusted developer machine and sent over SSH stdin to `python -m gateway.manage_tokens create NAME` on the Droplet, so only their hashes are stored there. `python -m gateway.manage_tokens revoke NAME` immediately disables a token; `list` shows names and states only.
