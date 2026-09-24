import csv
import io
import json
import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .analysis import analyze
from .collectors import CollectorError, collect_demo, collect_ldap
from .config import settings
from .storage import Storage


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("radar")
storage = Storage(settings.db_path)


class ScanRequest(BaseModel):
    source: Literal["demo", "ldap"] = "ldap" if settings.ldap_host else "demo"
    inactive_days: int = Field(default=settings.inactive_days, ge=1, le=3650)
    old_password_days: int = Field(default=settings.old_password_days, ge=1, le=3650)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    if storage.latest() is None and not settings.ldap_host:
        storage.save(analyze(collect_demo(), settings.inactive_days, settings.old_password_days,
                             {group.lower() for group in settings.critical_groups}, settings.risk_thresholds))
    yield


app = FastAPI(title="Identity Risk Analyzer API", version="0.1.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=list(settings.cors_origins),
                   allow_credentials=False, allow_methods=["GET", "POST"], allow_headers=["Content-Type"])


def latest_or_404():
    result = storage.latest()
    if not result:
        raise HTTPException(404, "Нет результатов сканирования")
    return result


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/connection/status")
def connection_status():
    latest = storage.latest()
    last_check = storage.latest_audit_event("connection_test")
    success = storage.latest_audit_event("connection_test", "success")
    last_success = success["occurred_at"] if success else None
    return {"configured": all([settings.ldap_host, settings.ldap_base_dn,
        settings.ldap_username]),
        "password_required": not bool(settings.ldap_password),
        "host": settings.ldap_host, "port": settings.ldap_port,
        "use_ssl": settings.ldap_use_ssl, "base_dn": settings.ldap_base_dn,
        "domain": ".".join(part[3:] for part in settings.ldap_base_dn.split(",") if part.lower().startswith("dc=")),
        "reader_username": settings.ldap_username,
        "read_only": True, "last_connection_success": last_success,
        "connection_test_status": last_check["status"] if last_check else "not_checked",
        "last_scan": latest["scanned_at"] if latest else None,
        "last_scan_source": latest["source"] if latest else None,
        "last_users": latest["summary"]["total_users"] if latest else None,
        "last_groups": len(latest["groups"]) if latest else None}


@app.post("/api/connection/test")
def test_connection():
    try:
        snapshot = collect_ldap(settings)
        storage.audit("connection_test", "success", {"users": len(snapshot.accounts), "groups": len(snapshot.groups)})
        logger.info("LDAP connection test succeeded: %s users, %s groups", len(snapshot.accounts), len(snapshot.groups))
        return {"success": True, "users_found": len(snapshot.accounts),
                "groups_found": len(snapshot.groups), "domain_policy": snapshot.domain_policy}
    except CollectorError as exc:
        storage.audit("connection_test", "failed", {"error_type": type(exc).__name__})
        logger.warning("LDAP connection test failed: %s", exc)
        raise HTTPException(503, str(exc)) from exc


@app.post("/api/scans")
def create_scan(request: ScanRequest):
    started = time.perf_counter()
    previous = storage.latest()
    requested_thresholds = {"inactive_days": request.inactive_days,
                            "old_password_days": request.old_password_days}
    if previous and previous.get("thresholds") != requested_thresholds:
        storage.audit("analysis_config", "changed", requested_thresholds)
    storage.audit("scan", "started", {"source": request.source})
    try:
        snapshot = collect_demo() if request.source == "demo" else collect_ldap(settings)
        result = analyze(snapshot, request.inactive_days, request.old_password_days,
                         {group.lower() for group in settings.critical_groups}, settings.risk_thresholds)
        result["duration_ms"] = round((time.perf_counter() - started) * 1000)
        scan_id = storage.save(result)
    except CollectorError as exc:
        storage.audit("scan", "failed", {"source": request.source, "error_type": type(exc).__name__})
        logger.warning("Scan collection failed: %s", exc)
        raise HTTPException(503, str(exc)) from exc
    except Exception as exc:
        storage.audit("scan", "failed", {"source": request.source, "error_type": type(exc).__name__})
        raise
    storage.audit("scan", "completed", {"scan_id": scan_id, "source": request.source,
        "users": result["summary"]["total_users"], "groups": len(result["groups"]),
        "findings": result["summary"]["finding_count"], "duration_ms": result["duration_ms"]})
    logger.info("Scan %s completed: %s users, %s findings", scan_id,
                result["summary"]["total_users"], result["summary"]["finding_count"])
    return {"scan_id": scan_id, "status": "completed", "source": request.source,
            "users_scanned": result["summary"]["total_users"],
            "groups_scanned": len(result["groups"]),
            "findings_found": result["summary"]["finding_count"],
            "duration_ms": result["duration_ms"]}


@app.post("/api/scans/demo")
def create_demo_scan():
    return create_scan(ScanRequest(source="demo"))


@app.get("/api/scans")
def scans():
    return storage.list_scans()


@app.get("/api/scans/compare")
def compare_scans():
    history = storage.list_scans()
    if not history:
        raise HTTPException(404, "Нет результатов сканирования")
    current_meta = history[0]
    previous_meta = next((row for row in history[1:] if row["source"] == current_meta["source"]), None)
    if not previous_meta:
        return {"current_scan_id": current_meta["scan_id"], "previous_scan_id": None}
    current = storage.get(current_meta["scan_id"])
    previous = storage.get(previous_meta["scan_id"])
    current_keys = {(row["account_id"], row["rule_id"]) for row in current["findings"]}
    previous_keys = {(row["account_id"], row["rule_id"]) for row in previous["findings"]}
    return {"current_scan_id": current_meta["scan_id"], "previous_scan_id": previous_meta["scan_id"],
            "previous": previous["summary"], "current": current["summary"],
            "added_findings": len(current_keys - previous_keys),
            "resolved_findings": len(previous_keys - current_keys)}


@app.get("/api/audit")
def audit_events():
    return storage.list_audit_events()


@app.get("/api/scans/{scan_id}")
def scan(scan_id: str):
    result = storage.get(scan_id)
    if not result:
        raise HTTPException(404, "Сканирование не найдено")
    return {key: value for key, value in result.items() if key not in ("accounts", "findings")}


@app.get("/api/dashboard")
def dashboard():
    result = latest_or_404()
    return {"scan_id": result["scan_id"], "source": result["source"],
            "scanned_at": result["scanned_at"], "duration_ms": result.get("duration_ms"),
            "thresholds": result["thresholds"],
            "domain_policy": result["domain_policy"],
            "domain_policy_risk_score": result.get("domain_policy_risk_score", 0),
            "domain_policy_findings": result.get("domain_policy_findings", []), **result["summary"]}


@app.get("/api/findings")
def findings(severity: Literal["critical", "high", "medium", "low"] | None = None,
             q: str = Query(default="", max_length=100)):
    rows = latest_or_404()["findings"]
    if severity:
        rows = [item for item in rows if item["severity"] == severity]
    if q:
        needle = q.casefold()
        rows = [item for item in rows if needle in item["username"].casefold()
                or needle in item["title"].casefold()]
    return rows


@app.get("/api/accounts")
@app.get("/api/users")
def accounts():
    return [{key: value for key, value in item.items() if key != "findings"}
            for item in latest_or_404()["accounts"]]


@app.get("/api/groups")
def groups():
    return latest_or_404().get("groups", [])


@app.get("/api/accounts/{account_id:path}")
@app.get("/api/users/{account_id:path}")
def account(account_id: str):
    for item in latest_or_404()["accounts"]:
        if item["id"] == account_id:
            return item
    raise HTTPException(404, "Учётная запись не найдена")


@app.get("/api/export/csv")
def export_csv():
    result = latest_or_404()
    output = io.StringIO()
    writer = csv.writer(output)
    def safe_cell(value):
        text = str(value)
        return "'" + text if text.lstrip().startswith(("=", "+", "-", "@")) else text
    writer.writerow(["Scan Date", "Source", "Account", "Account Type", "Severity",
                     "Risk Score", "Category", "Rule", "Reason", "Why It Matters", "Evidence", "Recommendation"])
    scores = {item["id"]: item["risk_score"] for item in result["accounts"]}
    scores["__domain__"] = result.get("domain_policy_risk_score", 0)
    for item in result["findings"]:
        writer.writerow([safe_cell(value) for value in [result["scanned_at"], result["source"], item["username"],
            item["account_type"], item["severity"], scores.get(item["account_id"], 0),
            item.get("category", ""), item["title"], item["reason"], item.get("why_it_matters", ""),
            json.dumps(item.get("evidence", {}), ensure_ascii=False),
            item["recommendation"]]])
    data = "\ufeff" + output.getvalue()
    storage.audit("export_csv", "completed", {"scan_id": result["scan_id"],
        "findings": len(result["findings"])})
    logger.info("CSV exported for scan %s", result["scan_id"])
    return StreamingResponse(iter([data]), media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="identity-risk-{result["scan_id"][:8]}.csv"'})


# After `npm run build`, FastAPI can serve the UI and API on one port.
frontend_dist = Path(__file__).resolve().parents[2] / "frontend" / "dist"
if (frontend_dist / "index.html").exists():
    app.mount("/assets", StaticFiles(directory=frontend_dist / "assets"), name="assets")
    app.mount("/icons", StaticFiles(directory=frontend_dist / "icons"), name="icons")

    @app.get("/", include_in_schema=False)
    def frontend_index():
        return FileResponse(frontend_dist / "index.html")
