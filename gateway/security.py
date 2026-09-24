"""Hashed individual bearer tokens, revocation, access audit and rate limits."""

import hashlib
import os
import re
import sqlite3
import threading
import time
from collections import defaultdict, deque
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


def database_path() -> Path:
    return Path(os.getenv("AD_GATEWAY_DB_PATH", str(Path(__file__).resolve().parent / "data/gateway.db")))


class TokenStore:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    @contextmanager
    def _db(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def _init(self):
        with self._db() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("""CREATE TABLE IF NOT EXISTS tokens (
                name TEXT PRIMARY KEY,
                token_hash TEXT NOT NULL UNIQUE,
                disabled INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS access_audit (
                id INTEGER PRIMARY KEY,
                at TEXT NOT NULL,
                token_name TEXT,
                source_ip TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                status TEXT NOT NULL,
                detail TEXT NOT NULL DEFAULT '')""")

    @staticmethod
    def digest(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def add(self, name: str, token: str):
        if not re.fullmatch(r"[a-zA-Z0-9._-]{3,64}", name) or len(token) < 40:
            raise ValueError("Invalid token name or length")
        with self._db() as db:
            db.execute("INSERT INTO tokens VALUES (?,?,0,?)",
                       (name, self.digest(token), datetime.now(timezone.utc).isoformat()))

    def revoke(self, name: str) -> bool:
        with self._db() as db:
            return bool(db.execute("UPDATE tokens SET disabled=1 WHERE name=?", (name,)).rowcount)

    def identify(self, token: str) -> str | None:
        if len(token) < 40 or len(token) > 256:
            return None
        with self._db() as db:
            row = db.execute("SELECT name FROM tokens WHERE token_hash=? AND disabled=0",
                             (self.digest(token),)).fetchone()
        return row["name"] if row else None

    def audit(self, name: str | None, ip: str, endpoint: str, status: str, detail: str = ""):
        with self._db() as db:
            db.execute("INSERT INTO access_audit(at,token_name,source_ip,endpoint,status,detail) VALUES(?,?,?,?,?,?)",
                       (datetime.now(timezone.utc).isoformat(), name, ip, endpoint, status, detail))

    def list_tokens(self):
        with self._db() as db:
            return [dict(row) for row in db.execute("SELECT name,disabled,created_at FROM tokens ORDER BY name")]


class RateLimiter:
    def __init__(self):
        self.events = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        now = time.monotonic()
        with self.lock:
            if len(self.events) > 10000:
                self.events = defaultdict(deque, {key: value for key, value in self.events.items()
                    if value and value[-1] > now - 3600})
            events = self.events[key]
            while events and events[0] <= now - window_seconds:
                events.popleft()
            if len(events) >= limit:
                return False
            events.append(now)
            return True
