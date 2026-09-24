# Vercel and shared API security status

The current private Tailscale site and public read-only AD Gateway remain separate. The Gateway is **not** the Dashboard API. A Vercel frontend needs `/api/*` on a shared FastAPI backend; `frontend/vercel.json` contains the future same-origin rewrite. Do not expose that route until server-side authentication has been enabled and verified.

## Prepared controls

- `RADAR_AUTH_REQUIRED=true` enables individual team usernames with scrypt password hashes and revocable eight-hour bearer sessions. Tokens live only in browser memory and are sent in the `Authorization` header. The frontend does not contain LDAP passwords, Gateway tokens, SSH keys, or team passwords.
- All `/api/*` data routes require a valid session. The `viewer` role reads results; `operator` is required for scan, connection test, settings changes, audit, and CSV export. `/api/health`, login, and session status are exceptions.
- Login is limited to five attempts per minute per client IP; operator actions are limited per user and path. The reverse proxy should also enforce IP limits and a 16 KiB body cap before public exposure.
- Session and API responses use `Cache-Control: no-store`; FastAPI docs are disabled when authentication is required. The login and audit records do not contain passwords or bearer tokens.
- `frontend/vercel.json` proxies `/api/*` to the existing TLS hostname. The browser sends requests to its own Vercel origin, so a broad cross-origin CORS rule is unnecessary.

## Before public launch

1. Deploy and test the authenticated backend on a private listener. Create separate operator credentials with `RADAR_AUTH_DB_PATH=... python -m app.team_auth set-user NAME`; the command prompts for a password. Keep the database and any password handoff outside Git.
2. Verify anonymous requests to every data and mutation endpoint return 401, viewer mutations return 403, revocation invalidates existing sessions, and rate limits return 429.
3. Only then add a TLS reverse-proxy route for `/api/*`, pointing to the authenticated loopback listener. Limit request size and rate at the reverse proxy. Keep the LDAP, Event Log, SSH, and RDP connections on Tailscale.
4. Deploy the frontend with `frontend` as the Vercel project root. Do not place secrets in `VITE_*` variables. Test sign-in, scan, CSV, and browser reload from a device without Tailscale.

## Current blockers

- The shared Droplet has other public listeners, including MongoDB on TCP 27018 and 27019, plus 3000, 8080, 631, and 3478. UFW is inactive and the default INPUT policy accepts connections. These belong to other applications, so they must be reviewed with their owners before firewall changes. The host cannot currently be described as having only HTTPS and SSH exposed.
- The DC VM was previously saved because its Windows host lacked memory. Do not start it solely for this rollout; a new live AD scan is unavailable until the lab is restored.
- No Vercel project is linked in this checkout. The rewrite and login code are prepared, but the shared Dashboard API has not been published and an external browser E2E test has not been completed.
