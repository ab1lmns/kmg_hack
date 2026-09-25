import csv
import io
import json
import logging
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, model_validator

from .analysis import analyze
from .ai_chat import ChatProviderError, answer as ai_answer, build_context
from .remediation import finding_context, generate_plan
from .collectors import CollectorError, collect_demo, collect_ldap
from .events import WindowsEventCollector
from .config import settings
from .gateway_client import collect_gateway
from .gateway_client import collect_gateway_infrastructure
from .infrastructure import apply_scan_source_status, collect_infrastructure, empty_infrastructure
from .storage import Storage, StorageError
from .team_auth import TeamAuth


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("radar")
storage = Storage(settings.db_path)
team_auth = TeamAuth(settings.auth_db_path) if settings.auth_required else None
rate_windows = defaultdict(deque)


def rate_allowed(key: str, limit: int, seconds: int) -> bool:
    now = time.monotonic()
    entries = rate_windows[key]
    while entries and entries[0] <= now - seconds:
        entries.popleft()
    if len(entries) >= limit:
        return False
    entries.append(now)
    return True


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
    source: Literal["demo", "ldap"] = "ldap" if settings.ldap_host or settings.ad_source == "gateway" else "demo"
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
    if storage.latest() is None and not settings.ldap_host and settings.ad_source != "gateway":
        storage.save(analyze(collect_demo(), settings.inactive_days, settings.old_password_days,
                             {group.lower() for group in settings.critical_groups}, settings.risk_thresholds))
    yield


app = FastAPI(title="Identity Risk Analyzer API", version="0.1.0", lifespan=lifespan,
              docs_url=None if settings.auth_required else "/docs",
              redoc_url=None if settings.auth_required else "/redoc",
              openapi_url=None if settings.auth_required else "/openapi.json")
app.add_middleware(CORSMiddleware, allow_origins=list(settings.cors_origins),
                   allow_credentials=False, allow_methods=["GET", "POST", "PUT"], allow_headers=["Content-Type", "Authorization"])


@app.middleware("http")
async def team_access(request: Request, call_next):
    path = request.url.path
    if not path.startswith("/api/") or request.method == "OPTIONS":
        return await call_next(request)
    length = request.headers.get("content-length", "0")
    if not length.isdecimal() or int(length) > 16_384:
        return JSONResponse(status_code=413, content={"detail": "Запрос слишком большой"})
    if not settings.auth_required or path in ("/api/health", "/api/auth/login", "/api/auth/me"):
        if path == "/api/auth/login" and settings.auth_required and not rate_allowed("login:" + (request.client.host if request.client else "unknown"), 5, 60):
            return JSONResponse(status_code=429, content={"detail": "Слишком много попыток входа"})
        response = await call_next(request)
        if path.startswith("/api/auth/"):
            response.headers["Cache-Control"] = "no-store"
        return response
    authorization = request.headers.get("authorization", "")
    token = authorization[7:] if authorization.startswith("Bearer ") else ""
    identity = team_auth.identify(token) if team_auth else None
    if not identity:
        return JSONResponse(status_code=401, content={"detail": "Требуется вход в аккаунт"}, headers={"Cache-Control": "no-store"})
    request.state.identity = identity
    if (request.method in ("POST", "PUT") and path not in ("/api/auth/logout", "/api/ai/chat", "/api/ai/remediation-plan")) or path in ("/api/export/csv", "/api/audit"):
        if identity["role"] != "operator":
            return JSONResponse(status_code=403, content={"detail": "Недостаточно прав"})
        if not rate_allowed("action:" + identity["username"] + ":" + path, 10 if path != "/api/scans" else 3, 60):
            return JSONResponse(status_code=429, content={"detail": "Слишком много запросов"})
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    return response


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class ChatMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=2000)


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=2000)
    history: list[ChatMessage] = Field(default_factory=list, max_length=12)
    page: str = Field(default="dashboard", max_length=40)


class RemediationRequest(BaseModel):
    scan_id: str = Field(min_length=1, max_length=100)
    finding_id: str = Field(min_length=1, max_length=500)


@app.post("/api/auth/login")
def team_login(payload: LoginRequest):
    if not team_auth:
        raise HTTPException(404, "Командный вход отключён")
    token = team_auth.login(payload.username, payload.password)
    if not token:
        storage.audit("team_login", "failed", {"username": payload.username})
        raise HTTPException(401, "Неверный логин или пароль")
    storage.audit("team_login", "success", {"username": payload.username})
    return {"token": token, "user": {"username": payload.username, "role": team_auth.identify(token)["role"]}}


@app.get("/api/auth/me")
def team_me(request: Request):
    if not settings.auth_required:
        return {"auth_required": False}
    authorization = request.headers.get("authorization", "")
    token = authorization[7:] if authorization.startswith("Bearer ") else ""
    user = team_auth.identify(token) if team_auth else None
    return {"auth_required": True, "user": user}


@app.post("/api/auth/logout")
def team_logout(request: Request):
    token = request.headers.get("authorization", "")[7:]
    if team_auth:
        team_auth.logout(token)
    return {"ok": True}


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


@app.get("/api/ai/status")
def ai_status():
    return {"configured": bool(settings.openai_api_key), "model": settings.openai_model}


@app.post("/api/ai/chat")
def ai_chat(payload: ChatRequest, request: Request):
    if not rate_allowed("ai:" + (request.client.host if request.client else "unknown"), 12, 60):
        raise HTTPException(429, "Слишком много вопросов. Повторите через минуту.")
    if not settings.openai_api_key:
        raise HTTPException(503, "ИИ-чат пока не настроен. Добавьте OPENAI_API_KEY в backend/.env и перезапустите проект.")
    scan = latest_or_404()
    context = build_context(scan, storage.list_scans(), payload.message, payload.page)
    messages = [item.model_dump() for item in payload.history]
    messages.append({"role": "user", "content": payload.message})
    try:
        reply = ai_answer(settings.openai_api_key, settings.openai_model, context, messages)
    except ChatProviderError as exc:
        raise HTTPException(502, str(exc)) from exc
    return {"answer": reply, "scan_id": scan["scan_id"], "scanned_at": scan["scanned_at"]}


@app.post("/api/ai/remediation-plan")
def remediation_plan(payload: RemediationRequest, request: Request):
    if not rate_allowed("ai_plan:" + (request.client.host if request.client else "unknown"), 8, 60):
        raise HTTPException(429, "Слишком много запросов. Повторите через минуту.")
    if not settings.openai_api_key:
        raise HTTPException(503, "ИИ-планы пока не настроены. Добавьте OPENAI_API_KEY в backend/.env.")
    scan = latest_or_404()
    if scan["scan_id"] != payload.scan_id:
        raise HTTPException(409, "Анализ обновился. Обновите страницу риска и повторите запрос.")
    finding = next((item for item in [*scan.get("findings", []), *scan.get("auth_findings", [])]
                    if item.get("id") == payload.finding_id), None)
    if finding is None:
        raise HTTPException(404, "Риск не найден в текущем анализе")
    try:
        plan = generate_plan(settings.openai_api_key, settings.openai_model,
                             finding_context(scan, finding))
    except ChatProviderError as exc:
        raise HTTPException(502, str(exc)) from exc
    return {"scan_id": scan["scan_id"], "finding_id": finding["id"],
            "scanned_at": scan["scanned_at"], "plan": plan.model_dump()}


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
    gateway = settings.ad_source == "gateway"
    return {"configured": bool(settings.ad_gateway_url and settings.ad_gateway_token) if gateway
            else all([settings.ldap_host, settings.ldap_base_dn, settings.ldap_username]),
        "password_required": not bool(settings.ad_gateway_token) if gateway else not bool(settings.ldap_password),
        "host": settings.ad_gateway_url if gateway else settings.ldap_host,
        "port": 443 if gateway else settings.ldap_port,
        "use_ssl": True if gateway else settings.ldap_use_ssl,
        "connection_mode": "AD Gateway" if gateway else "LDAP_DIRECT",
        "base_dn": "" if gateway else settings.ldap_base_dn,
        "domain": "infraradar.test" if gateway else ".".join(part[3:] for part in settings.ldap_base_dn.split(",") if part.lower().startswith("dc=")),
        "reader_username": "Gateway-managed" if gateway else settings.ldap_username,
        "read_only": True, "last_connection_success": last_success,
        "connection_test_status": last_check["status"] if last_check else "not_checked",
        "last_scan": latest["scanned_at"] if latest else None,
        "last_scan_source": latest["source"] if latest else None,
        "last_users": latest["summary"]["total_users"] if latest else None,
        "last_groups": len(latest["groups"]) if latest else None}


@app.get("/api/infrastructure")
def infrastructure():
    """Live read-only topology; historical scan and risk scores are untouched."""
    latest = storage.latest()
    source_status = latest.get("source_status") if latest and latest.get("source") == "ldap" else None
    if settings.ad_source == "gateway":
        return apply_scan_source_status(collect_gateway_infrastructure(settings), source_status)
    try:
        return collect_infrastructure(settings, source_status)
    except Exception:
        unavailable = empty_infrastructure()
        unavailable["diagnostics"]["LDAP_CONNECTION"] = "error"
        return unavailable


@app.post("/api/connection/test")
def test_connection():
    try:
        snapshot = collect_gateway(settings) if settings.ad_source == "gateway" else collect_ldap(settings)
        storage.audit("connection_test", "success", {"users": len(snapshot.accounts), "groups": len(snapshot.groups)})
        logger.info("LDAP connection test succeeded: %s users, %s groups", len(snapshot.accounts), len(snapshot.groups))
        return {"success": True, "users_found": len(snapshot.accounts),
                "groups_found": len(snapshot.groups), "domain_policy": snapshot.domain_policy}
    except CollectorError as exc:
        storage.audit("connection_test", "failed", {"error_type": type(exc).__name__})
        logger.warning("Directory connection test failed: %s", type(exc).__name__)
        raise HTTPException(503, "Источник каталога временно недоступен.") from exc


@app.post("/api/scans")
def create_scan(request: ScanRequest):
    started = time.perf_counter()
    overrides = request.model_dump(exclude_none=True, exclude={"source"})
    config = AnalysisConfig(**{**(storage.get_config() or {}), **overrides})
    storage.audit("scan", "started", {"source": request.source})
    try:
        snapshot = (collect_demo() if request.source == "demo" else
                    collect_gateway(settings) if settings.ad_source == "gateway" else collect_ldap(settings))
        collection_ms = round((time.perf_counter() - started) * 1000)
        event_started = time.perf_counter()
        if request.source == "ldap":
            if settings.ad_source == "gateway":
                events = snapshot.auth_events
                event_status = snapshot.source_status.get("security_event_log", "not_evaluated")
            else:
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
        logger.warning("Scan collection failed: %s", type(exc).__name__)
        raise HTTPException(503, "Источник данных временно недоступен.") from exc
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
            "risk_thresholds": result.get("risk_thresholds", {}),
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
