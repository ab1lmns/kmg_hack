import csv
import io
import logging
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
    source: Literal["demo", "ldap"] = "demo"
    ldap_password: str | None = Field(default=None, repr=False)
    inactive_days: int = Field(default=settings.inactive_days, ge=1, le=3650)
    old_password_days: int = Field(default=settings.old_password_days, ge=1, le=3650)


class ConnectionTestRequest(BaseModel):
    ldap_password: str | None = Field(default=None, repr=False)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    if storage.latest() is None:
        storage.save(analyze(collect_demo(), settings.inactive_days, settings.old_password_days,
                             {group.lower() for group in settings.critical_groups}))
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
    return {"configured": all([settings.ldap_host, settings.ldap_base_dn,
        settings.ldap_username]),
        "password_required": not bool(settings.ldap_password),
        "host": settings.ldap_host, "port": settings.ldap_port,
        "use_ssl": settings.ldap_use_ssl, "base_dn": settings.ldap_base_dn}


@app.post("/api/connection/test")
def test_connection(request: ConnectionTestRequest):
    try:
        snapshot = collect_ldap(settings, request.ldap_password)
        logger.info("LDAP connection test succeeded: %s users, %s groups", len(snapshot.accounts), len(snapshot.groups))
        return {"success": True, "users_found": len(snapshot.accounts),
                "groups_found": len(snapshot.groups), "domain_policy": snapshot.domain_policy}
    except CollectorError as exc:
        logger.warning("LDAP connection test failed: %s", exc)
        raise HTTPException(503, str(exc)) from exc


@app.post("/api/scans")
def create_scan(request: ScanRequest):
    try:
        snapshot = collect_demo() if request.source == "demo" else collect_ldap(settings, request.ldap_password)
    except CollectorError as exc:
        logger.warning("Scan collection failed: %s", exc)
        raise HTTPException(503, str(exc)) from exc
    result = analyze(snapshot, request.inactive_days, request.old_password_days,
                     {group.lower() for group in settings.critical_groups})
    scan_id = storage.save(result)
    logger.info("Scan %s completed: %s users, %s findings", scan_id,
                result["summary"]["total_users"], result["summary"]["finding_count"])
    return {"scan_id": scan_id, "status": "completed", "source": request.source,
            "users_scanned": result["summary"]["total_users"],
            "findings_found": result["summary"]["finding_count"]}


@app.post("/api/scans/demo")
def create_demo_scan():
    return create_scan(ScanRequest(source="demo"))


@app.get("/api/scans")
def scans():
    return storage.list_scans()


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
            "scanned_at": result["scanned_at"], "thresholds": result["thresholds"],
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
                     "Risk Score", "Rule", "Reason", "Recommendation"])
    scores = {item["id"]: item["risk_score"] for item in result["accounts"]}
    scores["__domain__"] = result.get("domain_policy_risk_score", 0)
    for item in result["findings"]:
        writer.writerow([safe_cell(value) for value in [result["scanned_at"], result["source"], item["username"],
            item["account_type"], item["severity"], scores.get(item["account_id"], 0),
            item["title"], item["reason"], item["recommendation"]]])
    data = "\ufeff" + output.getvalue()
    logger.info("CSV exported for scan %s", result["scan_id"])
    return StreamingResponse(iter([data]), media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="identity-risk-{result["scan_id"][:8]}.csv"'})


# After `npm run build`, FastAPI can serve the UI and API on one port.
frontend_dist = Path(__file__).resolve().parents[2] / "frontend" / "dist"
if (frontend_dist / "index.html").exists():
    app.mount("/assets", StaticFiles(directory=frontend_dist / "assets"), name="assets")

    @app.get("/", include_in_schema=False)
    def frontend_index():
        return FileResponse(frontend_dist / "index.html")
