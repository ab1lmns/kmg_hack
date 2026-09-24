"""Small, server-side team credential and session store.

Passwords and bearer tokens are never persisted in plaintext. The CLI reads
passwords from a terminal or stdin, not command-line arguments.
"""

import hashlib
import hmac
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path


def _password_hash(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1)


class TeamAuth:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._db() as db:
            db.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, salt BLOB NOT NULL, password_hash BLOB NOT NULL, role TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1)")
            db.execute("CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, expires_at INTEGER NOT NULL)")
        os.chmod(path, 0o600)

    @contextmanager
    def _db(self):
        db = sqlite3.connect(self.path, timeout=5)
        try:
            with db:
                yield db
        finally:
            db.close()

    def set_user(self, username: str, password: str, role: str = "operator") -> None:
        if not username or len(username) > 64 or not all(c.isalnum() or c in "._-" for c in username):
            raise ValueError("Invalid username")
        if role not in ("viewer", "operator") or len(password) < 16:
            raise ValueError("Role must be viewer/operator and password must have at least 16 characters")
        salt = secrets.token_bytes(16)
        with self._db() as db:
            db.execute("INSERT INTO users VALUES (?, ?, ?, ?, 1) ON CONFLICT(username) DO UPDATE SET salt=excluded.salt, password_hash=excluded.password_hash, role=excluded.role, enabled=1", (username, salt, _password_hash(password, salt), role))
            db.execute("DELETE FROM sessions WHERE username=?", (username,))

    def disable_user(self, username: str) -> None:
        with self._db() as db:
            db.execute("UPDATE users SET enabled=0 WHERE username=?", (username,))
            db.execute("DELETE FROM sessions WHERE username=?", (username,))

    def login(self, username: str, password: str) -> str | None:
        with self._db() as db:
            row = db.execute("SELECT salt, password_hash, enabled FROM users WHERE username=?", (username,)).fetchone()
            # Keep the cost similar for unknown accounts.
            salt, expected, enabled = row if row else (b"\0" * 16, b"\0" * 64, 0)
            valid = hmac.compare_digest(_password_hash(password, salt), expected)
            if not valid or not enabled:
                return None
            token = secrets.token_urlsafe(48)
            db.execute("DELETE FROM sessions WHERE expires_at<?", (int(time.time()),))
            db.execute("INSERT INTO sessions VALUES (?, ?, ?)", (hashlib.sha256(token.encode()).hexdigest(), username, int(time.time()) + 8 * 3600))
            return token

    def identify(self, token: str) -> dict | None:
        if not token or len(token) > 256:
            return None
        with self._db() as db:
            row = db.execute("SELECT u.username, u.role FROM sessions s JOIN users u ON u.username=s.username WHERE s.token_hash=? AND s.expires_at>? AND u.enabled=1", (hashlib.sha256(token.encode()).hexdigest(), int(time.time()))).fetchone()
        return {"username": row[0], "role": row[1]} if row else None

    def logout(self, token: str) -> None:
        with self._db() as db:
            db.execute("DELETE FROM sessions WHERE token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),))


if __name__ == "__main__":
    import argparse
    import getpass
    import os
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("set-user", "disable-user"))
    parser.add_argument("username")
    parser.add_argument("--role", choices=("viewer", "operator"), default="operator")
    args = parser.parse_args()
    auth = TeamAuth(Path(os.environ.get("RADAR_AUTH_DB_PATH", "./data/team_auth.db")))
    if args.action == "set-user":
        password = getpass.getpass("Password: ")
        auth.set_user(args.username, password, args.role)
    else:
        auth.disable_user(args.username)
