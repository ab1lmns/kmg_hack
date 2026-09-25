"""Read-only evaluation of Windows user-rights snapshots.

An exported policy is host-specific. A result is conclusive only when the
snapshot includes the account's complete Windows token SIDs from that host.
"""

import json
import base64
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path


RIGHTS = (
    "SeInteractiveLogonRight", "SeDenyInteractiveLogonRight",
    "SeRemoteInteractiveLogonRight", "SeDenyRemoteInteractiveLogonRight",
)


class InteractiveLogonCollector:
    REMOTE_PATH = r"C:\ProgramData\InfraRadarLab\interactive-rights.json"

    def __init__(self, path: Path | None, max_age_minutes: int = 60,
                 ssh_alias: str | None = None, ssh_user: str | None = None):
        self.path = path
        self.max_age_minutes = max_age_minutes
        self.ssh_alias = ssh_alias
        self.ssh_user = ssh_user

    def load(self) -> tuple[dict | None, str]:
        local_status = "not_evaluated"
        if self.path and self.path.exists():
            try:
                payload = json.loads(self.path.read_text(encoding="utf-8-sig"))
                snapshot, local_status = self._validate(payload)
                if local_status == "pass":
                    return snapshot, local_status
            except (OSError, ValueError, TypeError, KeyError, AttributeError):
                local_status = "error"
        if self.ssh_alias and self.ssh_user:
            return self._load_remote()
        return None, local_status

    def _validate(self, payload: dict) -> tuple[dict | None, str]:
        try:
            collected = datetime.fromisoformat(payload["collected_at"].replace("Z", "+00:00"))
            age = (datetime.now(timezone.utc) - collected.astimezone(timezone.utc)).total_seconds()
            if age < 0 or age > self.max_age_minutes * 60:
                return None, "not_evaluated"
            if payload.get("target_host", "").upper() != "INFRARADAR-DC01" or not payload.get("source_policy"):
                return None, "error"
            if not all(key in payload.get("rights", {}) for key in RIGHTS):
                return None, "error"
            if not isinstance(payload.get("token_sids"), dict):
                return None, "error"
            return payload, "pass"
        except (OSError, ValueError, TypeError, KeyError, AttributeError):
            return None, "error"

    def _load_remote(self) -> tuple[dict | None, str]:
        try:
            config = subprocess.run(["ssh", "-G", self.ssh_alias], capture_output=True,
                                    text=True, timeout=5, check=True).stdout
            entries = dict(line.split(" ", 1) for line in config.splitlines() if " " in line)
            if (entries.get("user", "").casefold() != self.ssh_user.casefold() or
                    entries.get("hostname") != "100.93.42.103" or
                    self.ssh_user.casefold() in ("administrator", "admin")):
                return None, "error"
            identity = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                                       "-o", "ConnectTimeout=8", self.ssh_alias,
                                       "whoami.exe", "/groups", "/fo", "csv"],
                                      capture_output=True, text=True, timeout=15, check=False)
            privileged_sids = (r"S-1-5-32-(?:544|548|549|550|551|552)\b|"
                               r"S-1-5-21-[0-9-]+-(?:512|518|519)\b")
            if (identity.returncode or "S-1-5-32-573" not in identity.stdout or
                    re.search(privileged_sids, identity.stdout)):
                return None, "error"
            command = (f"$ErrorActionPreference='Stop';"
                       f"Get-Content -LiteralPath '{self.REMOTE_PATH}' -Raw")
            encoded = base64.b64encode(command.encode("utf-16le")).decode("ascii")
            result = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                                     "-o", "ConnectTimeout=8", self.ssh_alias,
                                     "powershell.exe", "-NoProfile", "-NonInteractive",
                                     "-EncodedCommand", encoded], capture_output=True,
                                    text=True, timeout=15, check=False)
            if result.returncode:
                return None, "error"
            return self._validate(json.loads(result.stdout.lstrip("\ufeff").strip()))
        except (OSError, ValueError, subprocess.SubprocessError):
            return None, "error"

    @staticmethod
    def evaluate(account, payload: dict | None, source_status: str) -> dict:
        if payload is None:
            return {"status": "not_evaluated" if source_status == "not_evaluated" else "error",
                    "target_host": None, "reason": "Нет свежего полного снимка результирующих прав входа."}
        target = payload["target_host"]
        tokens = payload.get("token_sids", {}).get(account.username.lower())
        if not isinstance(tokens, list) or not tokens:
            return {"status": "not_evaluated", "target_host": target,
                    "source_policy": payload["source_policy"],
                    "reason": "Нет подтверждённого полного набора SID токена этого аккаунта на целевом хосте."}
        token_set = {sid.upper() for sid in tokens} | {account.sid.upper()}
        rights = payload["rights"]
        matches = {key: sorted(token_set & {str(sid).upper() for sid in rights[key]}) for key in RIGHTS}
        allow_local = bool(matches["SeInteractiveLogonRight"])
        deny_local = bool(matches["SeDenyInteractiveLogonRight"])
        allow_rdp = bool(matches["SeRemoteInteractiveLogonRight"])
        deny_rdp = bool(matches["SeDenyRemoteInteractiveLogonRight"])
        local_right = allow_local and not deny_local
        rdp_right = allow_rdp and not deny_rdp
        return {"status": "finding" if (local_right or rdp_right) else "pass",
                "target_host": target, "source_policy": payload["source_policy"],
                "collected_at": payload["collected_at"],
                "allow_interactive": allow_local, "deny_interactive": deny_local,
                "allow_rdp": allow_rdp, "deny_rdp": deny_rdp,
                "effective_local_right": local_right, "effective_rdp_right": rdp_right,
                "account_enabled": account.enabled, "account_expired": account.account_expired,
                "evidence": {"matched_sids": matches, "token_sids_count": len(token_set)},
                "note": "Оценены права входа по снимку политики; состояние RDP-службы и дополнительные ограничения входа требуют отдельной проверки."}
