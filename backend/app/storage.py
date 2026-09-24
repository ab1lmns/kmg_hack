import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class Storage:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY, scanned_at TEXT NOT NULL, source TEXT NOT NULL,
                payload TEXT NOT NULL
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, occurred_at TEXT NOT NULL,
                action TEXT NOT NULL, status TEXT NOT NULL, details TEXT NOT NULL
            )""")

    @contextmanager
    def _connect(self):
        db = sqlite3.connect(self.path)
        try:
            with db:
                yield db
        finally:
            db.close()

    def save(self, result: dict[str, Any]) -> str:
        scan_id = str(uuid.uuid4())
        with self._connect() as db:
            db.execute("INSERT INTO scans VALUES (?, ?, ?, ?)",
                (scan_id, result["scanned_at"], result["source"], json.dumps(result, ensure_ascii=False)))
        return scan_id

    def latest(self) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute("SELECT id, payload FROM scans ORDER BY scanned_at DESC LIMIT 1").fetchone()
        return {"scan_id": row[0], **json.loads(row[1])} if row else None

    def get(self, scan_id: str) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute("SELECT payload FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return {"scan_id": scan_id, **json.loads(row[0])} if row else None

    def list_scans(self) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute("SELECT id, scanned_at, source, payload FROM scans ORDER BY scanned_at DESC LIMIT 30").fetchall()
        return [{"scan_id": row[0], "scanned_at": row[1], "source": row[2],
                 "summary": json.loads(row[3])["summary"]} for row in rows]

    def audit(self, action: str, status: str, details: dict[str, Any] | None = None) -> None:
        """Only caller-selected nonsecret metadata belongs in the audit trail."""
        with self._connect() as db:
            db.execute("INSERT INTO audit_events (occurred_at, action, status, details) VALUES (?, ?, ?, ?)",
                (datetime.now(timezone.utc).isoformat(), action, status,
                 json.dumps(details or {}, ensure_ascii=False)))

    def list_audit_events(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute("SELECT occurred_at, action, status, details FROM audit_events "
                              "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [{"occurred_at": row[0], "action": row[1], "status": row[2],
                 "details": json.loads(row[3])} for row in rows]

    def latest_audit_event(self, action: str, status: str | None = None) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute("SELECT occurred_at, action, status, details FROM audit_events "
                             "WHERE action = ? AND (? IS NULL OR status = ?) ORDER BY id DESC LIMIT 1",
                             (action, status, status)).fetchone()
        return {"occurred_at": row[0], "action": row[1], "status": row[2],
                "details": json.loads(row[3])} if row else None
