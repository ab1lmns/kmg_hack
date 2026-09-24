"""Fixed-schema, read-only gateway. No Risk Engine, scoring, history or AD writes."""

import threading
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from backend.app.collectors import CollectorError, collect_ldap
from backend.app.config import settings
from backend.app.events import WindowsEventCollector
from .security import RateLimiter, TokenStore, database_path


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
store = TokenStore(database_path())
limits = RateLimiter()
collection_lock = threading.Lock()
last_status = {"collected_at": None, "source_status": None}


@app.middleware("http")
async def protect(request: Request, call_next):
    path = request.url.path
    ip = request.client.host if request.client else "unknown"
    headers = {"Cache-Control": "no-store"}
    if path not in ("/v1/health", "/v1/status", "/v1/snapshot") or request.method != "GET":
        return JSONResponse({"detail": "Not found"}, status_code=404, headers=headers)
    if (len(str(request.url)) > 256 or request.url.query or
            request.headers.get("content-length", "0") not in ("", "0")):
        store.audit(None, ip, path, "rejected", "request_size")
        return JSONResponse({"detail": "Invalid request"}, status_code=413, headers=headers)
    if not limits.allow("ip:" + ip, 30, 60):
        return JSONResponse({"detail": "Rate limited"}, status_code=429,
                            headers={**headers, "Retry-After": "60"})
    scheme, _, token = request.headers.get("Authorization", "").partition(" ")
    name = store.identify(token) if scheme.lower() == "bearer" else None
    if not name:
        store.audit(None, ip, path, "denied")
        return JSONResponse({"detail": "Authentication required"}, status_code=401, headers=headers)
    if not limits.allow("token:" + name, 20, 3600) or (
        path == "/v1/snapshot" and not limits.allow("snapshot:" + name, 5, 600)):
        store.audit(name, ip, path, "rate_limited")
        return JSONResponse({"detail": "Rate limited"}, status_code=429,
                            headers={**headers, "Retry-After": "600"})
    request.state.token_name = name
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    store.audit(name, ip, path, str(response.status_code))
    return response


@app.get("/v1/health")
def health():
    return {"status": "ok", "role": "read_only_ad_gateway", "schema_version": 1}


@app.get("/v1/status")
def status():
    return last_status.copy()


@app.get("/v1/snapshot")
def snapshot():
    if not collection_lock.acquire(blocking=False):
        return JSONResponse({"detail": "Collection already in progress"}, status_code=429)
    try:
        raw = collect_ldap(settings, classify=False)
        events, event_status = WindowsEventCollector(settings.event_ssh_alias or None,
            settings.event_ssh_user or None,
            Path(__file__).resolve().parents[1] / "scripts" / "Export-SecurityEvents.ps1").collect()
        raw.auth_events = events
        raw.source_status["security_event_log"] = event_status
        collected_at = datetime.now(timezone.utc).isoformat()
        last_status.update({"collected_at": collected_at, "source_status": raw.source_status.copy()})
        return {"schema_version": 1, "collected_at": collected_at, "snapshot": asdict(raw)}
    except CollectorError:
        last_status.update({"collected_at": datetime.now(timezone.utc).isoformat(),
                            "source_status": {"ldap": "error"}})
        return JSONResponse({"detail": "Directory temporarily unavailable"}, status_code=503)
    finally:
        collection_lock.release()
