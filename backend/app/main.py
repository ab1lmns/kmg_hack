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
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, model_validator

from .analysis import analyze
from .collectors import CollectorError, collect_demo, collect_ldap
from .events import WindowsEventCollector
from .config import settings
from .storage import Storage, StorageError


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("radar")
storage = Storage(settings.db_path)


class AnalysisConfig(BaseModel):
    inactive_days: int = Field(default=settings.inactive_days, ge=1, le=3650)
    old_password_days: int = Field(default=settings.old_password_days, ge=1, le=3650)
    inactive_computer_days: int = Field(default=settings.inactive_computer_days, ge=1, le=3650)
    brute_attempts: int = Field(default=settings.brute_attempts, ge=2, le=1000)
    spray_unique_users: int = Field(default=settings.spray_unique_users, ge=3, le=1000)
    auth_window_minutes: int = Field(default=settings.auth_window_minutes, ge=1, le=1440)
    risk_medium_threshold: int = Field(default=settings.risk_medium_threshold, ge=10, le=98)
    risk_high_threshold: int = Field(default=settings.risk_high_threshold, ge=11, le=99)
    risk_critical_threshold: int = Field(default=settings.risk_critical_threshold, ge=12, le=100)

    @model_validator(mode="after")
    def ordered_thresholds(self):
        if not self.risk_medium_threshold < self.risk_high_threshold < self.risk_critical_threshold:
            raise ValueError("Risk thresholds must satisfy Medium < High < Critical")
        return self


class ScanRequest(BaseModel):
    source: Literal["demo", "ldap"] = "ldap" if settings.ldap_host else "demo"
    inactive_days: int | None = Field(default=None, ge=1, le=3650)
    old_password_days: int | None = Field(default=None, ge=1, le=3650)
    inactive_computer_days: int | None = Field(default=None, ge=1, le=3650)
    brute_attempts: int | None = Field(default=None, ge=2, le=1000)
    spray_unique_users: int | None = Field(default=None, ge=3, le=1000)
    auth_window_minutes: int | None = Field(default=None, ge=1, le=1440)
    risk_medium_threshold: int | None = Field(default=None, ge=10, le=98)
    risk_high_threshold: int | None = Field(default=None, ge=11, le=99)
    risk_critical_threshold: int | None = Field(default=None, ge=12, le=100)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    if storage.latest() is None and not settings.ldap_host:
        storage.save(analyze(collect_demo(), settings.inactive_days, settings.old_password_days,
                             {group.lower() for group in settings.critical_groups}, settings.risk_thresholds))
    yield


app = FastAPI(title="Identity Risk Analyzer API", version="0.1.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=list(settings.cors_origins),
                   allow_credentials=False, allow_methods=["GET", "POST", "PUT"], allow_headers=["Content-Type"])


@app.exception_handler(StorageError)
def storage_failure(_request, _exc):
    logger.error("Storage operation failed")
    return JSONResponse(status_code=503, content={"detail": "База данных временно недоступна. Проверьте файл и повторите попытку."})


def latest_or_404():
    result = storage.latest()
    if not result:
        raise HTTPException(404, "Нет результатов сканирования")
    return result


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/config")
def get_config():
    return AnalysisConfig(**(storage.get_config() or {})).model_dump()


@app.put("/api/config")
def update_config(config: AnalysisConfig):
    old = storage.get_config()
    payload = config.model_dump()
    storage.save_config(payload)
    if old != payload:
        storage.audit("analysis_config", "changed", payload)
    return payload


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
    overrides = request.model_dump(exclude_none=True, exclude={"source"})
    config = AnalysisConfig(**{**(storage.get_config() or {}), **overrides})
    storage.audit("scan", "started", {"source": request.source})
    try:
        snapshot = collect_demo() if request.source == "demo" else collect_ldap(settings)
        collection_ms = round((time.perf_counter() - started) * 1000)
        event_started = time.perf_counter()
        if request.source == "ldap":
            events, event_status = WindowsEventCollector(settings.event_ssh_alias or None,
                settings.event_ssh_user or None,
                Path(__file__).resolve().parents[2] / "scripts" / "Export-SecurityEvents.ps1").collect()
            snapshot.auth_events = events
            snapshot.source_status["security_event_log"] = event_status
            storage.audit("event_collection", event_status, {"events": len(events)})
        events_ms = round((time.perf_counter() - event_started) * 1000)
        analysis_started = time.perf_counter()
        result = analyze(snapshot, config.inactive_days, config.old_password_days,
                         {group.lower() for group in settings.critical_groups},
                         (config.risk_medium_threshold, config.risk_high_threshold,
                          config.risk_critical_threshold),
                         config.inactive_computer_days, config.brute_attempts,
                         config.spray_unique_users, config.auth_window_minutes)
        analysis_ms = round((time.perf_counter() - analysis_started) * 1000)
        if request.source == "ldap":
            storage.audit("authentication_analysis", "completed" if event_status == "pass" else event_status,
                          {"findings": len(result["auth_findings"])})
        result["duration_ms"] = round((time.perf_counter() - started) * 1000)
        result["timings_ms"] = {"ldap_and_ad_collection": collection_ms,
                                "event_collection": events_ms, "analysis": analysis_ms}
        persistence_started = time.perf_counter()
        scan_id = storage.save(result)
        persistence_ms = round((time.perf_counter() - persistence_started) * 1000)
    except CollectorError as exc:
        storage.audit("scan", "failed", {"source": request.source, "error_type": type(exc).__name__})
        logger.warning("Scan collection failed: %s", exc)
        raise HTTPException(503, str(exc)) from exc
    except Exception as exc:
        storage.audit("scan", "failed", {"source": request.source, "error_type": type(exc).__name__})
        raise
    storage.audit("scan", "completed", {"scan_id": scan_id, "source": request.source,
        "users": result["summary"]["total_users"], "groups": len(result["groups"]),
        "computers": len(result.get("computers", [])),
        "findings": result["summary"]["finding_count"],
        "duration_ms": round((time.perf_counter() - started) * 1000),
        "persistence_ms": persistence_ms})
    logger.info("Scan %s completed: %s users, %s findings", scan_id,
                result["summary"]["total_users"], result["summary"]["finding_count"])
    return {"scan_id": scan_id, "status": "completed", "source": request.source,
            "users_scanned": result["summary"]["total_users"],
            "groups_scanned": len(result["groups"]),
            "computers_scanned": len(result.get("computers", [])),
            "findings_found": result["summary"]["finding_count"],
            "duration_ms": round((time.perf_counter() - started) * 1000),
            "timings_ms": {**result["timings_ms"], "persistence": persistence_ms}}


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
            "timings_ms": result.get("timings_ms", {}),
            "thresholds": result["thresholds"],
            "domain_policy": result["domain_policy"],
            "domain_policy_risk_score": result.get("domain_policy_risk_score", 0),
            "domain_policy_findings": result.get("domain_policy_findings", []),
            "fine_grained_policies": result.get("fine_grained_policies", []),
            "fine_grained_policy_findings": result.get("fine_grained_policy_findings", []),
            "source_status": result.get("source_status", {}), **result["summary"]}


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


@app.get("/api/computers")
def computers():
    return [{key: value for key, value in item.items() if key != "findings"}
            for item in latest_or_404().get("computers", [])]


@app.get("/api/computers/{computer_id:path}")
def computer(computer_id: str):
    for item in latest_or_404().get("computers", []):
        if item["id"] == computer_id:
            return item
    raise HTTPException(404, "Компьютер не найден")


@app.get("/api/authentication")
def authentication():
    result = latest_or_404()
    return {"status": result.get("source_status", {}).get("security_event_log", "not_evaluated"),
            "events": result["summary"].get("auth_events", 0),
            "failed_bad_password": result["summary"].get("failed_auth_events", 0),
            "findings": result.get("auth_findings", [])}


@app.get("/api/checks")
def checks():
    result = latest_or_404()
    return {"sources": result.get("source_status", {}),
            "interactive_logon": [{"username": row["username"],
                                   "result": row.get("interactive_logon")}
                                  for row in result["accounts"] if row.get("service_account")]}


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
    # Semicolon keeps UTF-8 Cyrillic and columns intact when Excel on this
    # locale opens the downloaded CSV directly.
    writer = csv.writer(output, delimiter=";")
    def safe_cell(value):
        text = str(value)
        return "'" + text if text.lstrip().startswith(("=", "+", "-", "@")) else text
    writer.writerow(["Scan Date", "Source", "Object", "Object Type", "Severity",
                     "Risk Score", "Category", "Rule", "Reason", "Why It Matters", "Evidence",
                     "Recommendation", "Evaluation Status", "Confidence"])
    scores = {item["id"]: item["risk_score"] for item in result["accounts"] + result.get("computers", [])}
    scores["__domain__"] = result.get("domain_policy_risk_score", 0)
    for item in result["findings"]:
        writer.writerow([safe_cell(value) for value in [result["scanned_at"], item.get("source", result["source"]), item["username"],
            item["account_type"], item["severity"], scores.get(item["account_id"], 0),
            item.get("category", ""), item["title"], item["reason"], item.get("why_it_matters", ""),
            json.dumps(item.get("evidence", {}), ensure_ascii=False),
            item["recommendation"], item.get("evaluation_status", "finding"),
            item.get("confidence", "high")]])
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
