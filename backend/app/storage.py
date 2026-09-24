import json
import sqlite3
import uuid
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

    def _connect(self):
        return sqlite3.connect(self.path)

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

