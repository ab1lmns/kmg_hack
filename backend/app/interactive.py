"""Read-only evaluation of Windows user-rights snapshots.

An exported policy is host-specific. A result is conclusive only when the
snapshot includes the account's complete Windows token SIDs from that host.
"""

import json
from datetime import datetime, timezone
from pathlib import Path


RIGHTS = (
    "SeInteractiveLogonRight", "SeDenyInteractiveLogonRight",
    "SeRemoteInteractiveLogonRight", "SeDenyRemoteInteractiveLogonRight",
)


class InteractiveLogonCollector:
    def __init__(self, path: Path | None, max_age_minutes: int = 60):
        self.path = path
        self.max_age_minutes = max_age_minutes

    def load(self) -> tuple[dict | None, str]:
        if not self.path or not self.path.exists():
            return None, "not_evaluated"
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            collected = datetime.fromisoformat(payload["collected_at"].replace("Z", "+00:00"))
            age = (datetime.now(timezone.utc) - collected.astimezone(timezone.utc)).total_seconds()
            if age < 0 or age > self.max_age_minutes * 60:
                return None, "not_evaluated"
            if not payload.get("target_host") or not payload.get("source_policy"):
                return None, "error"
            if not all(key in payload.get("rights", {}) for key in RIGHTS):
                return None, "error"
            return payload, "pass"
        except (OSError, ValueError, TypeError, KeyError):
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
