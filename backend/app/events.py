"""Read-only Windows Security Event collection and conservative auth heuristics."""

import base64
import json
import re
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path


EVENT_IDS = {4624, 4625, 4771, 4776}
BAD_PASSWORD_CODES = {"0XC000006A", "0X18"}


def normalize_event(row: dict, target_host: str) -> dict | None:
    try:
        event_id = int(row["id"])
        if event_id not in EVENT_IDS:
            return None
        data = row.get("data") or {}
        when = datetime.fromisoformat(str(row["time"]).replace("Z", "+00:00"))
        name = str(data.get("TargetUserName") or "").strip()
        if not name or name == "-" or name.endswith("$"):
            return None
        source = str(data.get("IpAddress") or data.get("Workstation") or
                     data.get("WorkstationName") or "").strip()
        if source in ("-", "::1", "127.0.0.1"):
            source = ""
        code = str(data.get("SubStatus") or data.get("FailureCode") or
                   data.get("Status") or "").upper()
        if event_id == 4771:
            # The rendered label is "Failure Code", but the XML field is Status.
            code = str(data.get("Status") or data.get("FailureCode") or "").upper()
        if event_id == 4776:
            code = str(data.get("Status") or "").upper()
        failed = event_id != 4624 and code in BAD_PASSWORD_CODES
        return {"event_id": event_id, "timestamp": when.astimezone(timezone.utc).isoformat(),
                "username": name, "source": source, "target_host": target_host,
                "logon_type": data.get("LogonType"), "failure_status": code,
                "outcome": "failed_bad_password" if failed else
                           "success" if event_id == 4624 else "other_failure",
                "record_id": row.get("record_id")}
    except (KeyError, TypeError, ValueError, OverflowError):
        return None


def detect_authentication_risks(events: list[dict], brute_attempts: int = 5,
                                spray_users: int = 5, window_minutes: int = 10,
                                spray_max_per_user: int = 2) -> list[dict]:
    failures = sorted((event for event in events
                       if event["outcome"] == "failed_bad_password" and event["source"]),
                      key=lambda event: event["timestamp"])
    # A DC can record the same attempt as 4625 and 4771/4776. Prefer the
    # authentication event in a five-second user/source bucket.
    buckets = {}
    priority = {4771: 3, 4776: 3, 4625: 2}
    for event in failures:
        stamp = datetime.fromisoformat(event["timestamp"])
        key = (event["username"].casefold(), event["source"].casefold(), int(stamp.timestamp()) // 5)
        if key not in buckets or priority.get(event["event_id"], 0) > priority.get(buckets[key]["event_id"], 0):
            buckets[key] = event
    rows = sorted(buckets.values(), key=lambda event: event["timestamp"])
    findings = []
    for kind in ("brute", "spray"):
        groups = defaultdict(list)
        for event in rows:
            key = event["username"].casefold() if kind == "brute" else event["source"].casefold()
            groups[key].append(event)
        for key, group in groups.items():
            # Report one strongest recent window per account/source, not every overlap.
            best = []
            for end in range(len(group)):
                end_time = datetime.fromisoformat(group[end]["timestamp"])
                start_time = end_time - timedelta(minutes=window_minutes)
                window = [item for item in group[:end + 1]
                          if datetime.fromisoformat(item["timestamp"]) >= start_time]
                if kind == "brute":
                    qualifies = len(window) >= brute_attempts and len({x["source"] for x in window}) <= 3
                else:
                    counts = Counter(x["username"].casefold() for x in window)
                    qualifies = len(counts) >= spray_users and max(counts.values()) <= spray_max_per_user
                if qualifies and len(window) > len(best):
                    best = window
            if not best:
                continue
            unique_users = sorted({item["username"] for item in best})
            sources = sorted({item["source"] for item in best})
            rule_id = "POSSIBLE_BRUTE_FORCE" if kind == "brute" else "POSSIBLE_PASSWORD_SPRAY"
            subject = best[-1]["username"] if kind == "brute" else best[-1]["source"]
            findings.append({"id": f"auth:{rule_id}:{key}", "account_id": f"auth:{key}",
                "username": subject, "account_type": "authentication", "rule_id": rule_id,
                "title": "Возможный Brute Force" if kind == "brute" else "Возможный Password Spray",
                "severity": "high", "category": "authentication", "score": 25,
                "reason": f"{len(best)} неудачных попыток за {window_minutes} минут; это эвристика, не доказанная атака.",
                "why_it_matters": "Повторяющиеся ошибки пароля могут указывать на подбор; нужна сверка с контекстом входов.",
                "evidence": {"attempts": len(best), "unique_users": len(unique_users),
                             "usernames": unique_users, "sources": sources,
                             "first": best[0]["timestamp"], "last": best[-1]["timestamp"],
                             "event_ids": sorted({item["event_id"] for item in best}),
                             "record_ids": [item["record_id"] for item in best]},
                "recommendation": "Проверьте источник, целевые аккаунты и смежные события до блокировки адреса или учётной записи.",
                "confidence": "medium", "evaluation_status": "finding", "source": "security_event_log"})
    return findings


class WindowsEventCollector:
    def __init__(self, ssh_alias: str | None, ssh_user: str | None, script_path: Path):
        self.ssh_alias = ssh_alias
        self.ssh_user = ssh_user
        self.script_path = script_path

    def collect(self) -> tuple[list[dict], str]:
        if not self.ssh_alias or not self.ssh_user:
            return [], "not_evaluated"
        if self.ssh_alias == "infraradar-dc" or self.ssh_user.lower() in ("administrator", "admin"):
            return [], "error"
        try:
            config = subprocess.run(["ssh", "-G", self.ssh_alias], capture_output=True,
                                    text=True, timeout=5, check=True).stdout
            actual_user = next((line.split(" ", 1)[1].strip() for line in config.splitlines()
                                if line.startswith("user ")), "")
            actual_host = next((line.split(" ", 1)[1].strip() for line in config.splitlines()
                                if line.startswith("hostname ")), "")
            if actual_user.lower() != self.ssh_user.lower() or actual_host != "100.93.42.103":
                return [], "error"
            identity = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                                       "-o", "ConnectTimeout=8", self.ssh_alias,
                                       "whoami.exe", "/groups", "/fo", "csv"],
                                      capture_output=True, text=True, timeout=15, check=False)
            privileged_sids = (r"S-1-5-32-(?:544|548|549|550|551|552)\b|"
                               r"S-1-5-21-[0-9-]+-(?:512|518|519)\b")
            if (identity.returncode or "S-1-5-32-573" not in identity.stdout or
                    re.search(privileged_sids, identity.stdout)):
                return [], "error"
            encoded = base64.b64encode(self.script_path.read_text(encoding="utf-8").encode("utf-16le")).decode("ascii")
            result = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                                     "-o", "ConnectTimeout=8",
                                     self.ssh_alias, "powershell.exe", "-NoProfile", "-NonInteractive",
                                     "-EncodedCommand", encoded], capture_output=True, text=True,
                                    timeout=45, check=False)
            if result.returncode:
                return [], "error"
            payload = json.loads(result.stdout.strip())
            if not payload.get("target_host") or not isinstance(payload.get("events"), list):
                return [], "error"
            normalized = [item for row in payload["events"]
                          if (item := normalize_event(row, payload["target_host"]))]
            return normalized, "partial" if payload.get("truncated") else "pass"
        except (OSError, ValueError, subprocess.SubprocessError):
            return [], "error"
