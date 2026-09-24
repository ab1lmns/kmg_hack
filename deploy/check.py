"""Read-only deployment checks plus one explicit live LDAP scan."""

import argparse
import csv
import io
import json
import sqlite3
import urllib.parse
import urllib.request
from pathlib import Path


def request(base: str, path: str, method: str = "GET", payload: dict | None = None):
    body = json.dumps(payload).encode() if payload is not None else None
    headers = {"Content-Type": "application/json"} if body is not None else {}
    with urllib.request.urlopen(
        urllib.request.Request(base + path, data=body, headers=headers, method=method),
        timeout=90,
    ) as response:
        return response.read(), response.headers.get_content_type()


def check(base: str, database: Path, scan: bool) -> dict:
    health, _ = request(base, "/api/health")
    assert json.loads(health)["status"] == "ok"
    frontend, content_type = request(base, "/")
    assert content_type == "text/html" and b"<html" in frontend.lower()

    connection, _ = request(base, "/api/connection/status")
    assert json.loads(connection)["configured"]
    ldap, _ = request(base, "/api/connection/test", "POST")
    assert json.loads(ldap)["success"] is True
    if scan:
        result, _ = request(base, "/api/scans", "POST", {"source": "ldap"})
        assert json.loads(result)["status"] == "completed"

    dashboard, _ = request(base, "/api/dashboard")
    dashboard = json.loads(dashboard)
    assert dashboard["source"] == "ldap"
    assert dashboard["source_status"]["ldap"] == "pass"
    assert dashboard["source_status"]["security_event_log"] == "pass"
    assert dashboard["total_users"] >= 40

    auth, _ = request(base, "/api/authentication")
    assert json.loads(auth)["status"] == "pass"
    accounts, _ = request(base, "/api/accounts")
    accounts = json.loads(accounts)
    assert len(accounts) == dashboard["total_users"]
    assert any(item["username"] == "adm.a.sadykov" for item in accounts)
    account_id = urllib.parse.quote(accounts[0]["id"], safe="")
    detail, _ = request(base, "/api/accounts/" + account_id)
    assert json.loads(detail)["id"] == accounts[0]["id"]
    findings, _ = request(base, "/api/findings")
    findings = json.loads(findings)
    high, _ = request(base, "/api/findings?severity=high")
    assert all(item["severity"] == "high" for item in json.loads(high))
    assert len(findings) == dashboard["finding_count"]
    computers, _ = request(base, "/api/computers")
    assert len(json.loads(computers)) >= 1
    assert dashboard["fine_grained_policies"]
    checks, _ = request(base, "/api/checks")
    assert json.loads(checks)
    csv_bytes, _ = request(base, "/api/export/csv")
    assert csv_bytes.startswith(b"\xef\xbb\xbf")
    rows = list(csv.DictReader(io.StringIO(csv_bytes.decode("utf-8-sig")), delimiter=";"))
    assert len(rows) == len(findings) and len(rows[0]) == 14
    with sqlite3.connect(database) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 2
        assert db.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        assert db.execute("SELECT id FROM scans ORDER BY scanned_at DESC LIMIT 1").fetchone()[0] == dashboard["scan_id"]
    return {
        "scan_id": dashboard["scan_id"],
        "users": dashboard["total_users"],
        "findings": len(findings),
        "security_score": dashboard["security_score"],
        "ldap": "pass",
        "event_log": "pass",
        "sqlite": "pass",
        "frontend": "pass",
        "csv": "pass",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--scan", action="store_true")
    args = parser.parse_args()
    print(json.dumps(check(args.base_url, args.database, args.scan), ensure_ascii=False))
