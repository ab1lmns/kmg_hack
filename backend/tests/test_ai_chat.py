import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

from app import main
from app.ai_chat import answer, build_context
from app.storage import Storage


class FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, *_args):
        return json.dumps({"output": [{"type": "message", "content":
            [{"type": "output_text", "text": "Проверьте svc_backup."}]}]}).encode()


class AiChatTests(unittest.TestCase):
    def test_context_contains_scan_findings_and_site_guide_without_secrets(self):
        scan = {"scan_id": "scan-1", "scanned_at": "2026-09-24T12:00:00Z", "source": "ldap",
                "summary": {"security_score": 71},
                "accounts": [{"username": "svc_backup", "risk_score": 85, "password_never_expires": True,
                              "ldap_password": "must-not-leak"}],
                "findings": [{"username": "svc_backup", "rule_id": "SERVICE_PASSWORD_NEVER_EXPIRES",
                              "evidence": {"password_never_expires": True}}],
                "groups": [{"name": "Backup Operators", "member_of": ["Administrators"]}]}
        data = build_context(scan, [], "Почему svc_backup опасен?", "accounts")
        parsed = json.loads(data)
        self.assertEqual(parsed["scan"]["accounts"][0]["username"], "svc_backup")
        self.assertEqual(parsed["scan"]["findings"][0]["rule_id"], "SERVICE_PASSWORD_NEVER_EXPIRES")
        self.assertIn("History", parsed["site_guide"])
        self.assertNotIn("must-not-leak", data)

    def test_provider_request_is_stateless_and_returns_text(self):
        seen = {}
        def fake_urlopen(request, timeout):
            seen.update(json.loads(request.data))
            self.assertEqual(timeout, 45)
            return FakeResponse()
        with patch("app.ai_chat.urlopen", side_effect=fake_urlopen):
            result = answer("test-key", "gpt-4.1-mini", "{}", [{"role": "user", "content": "Что делать?"}])
        self.assertEqual(result, "Проверьте svc_backup.")
        self.assertFalse(seen["store"])
        self.assertEqual(seen["input"][-1]["content"], "Что делать?")

    def test_api_requires_key_and_uses_latest_scan(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(main, "storage", Storage(Path(temp) / "radar.db")):
                main.create_scan(main.ScanRequest(source="demo"))
                request = main.ChatRequest(message="Какие проблемы?", page="dashboard")
                fake_http_request = type("Request", (), {"client": type("Client", (), {"host": "test-ai"})()})()
                with patch.object(main, "settings", replace(main.settings, openai_api_key="")):
                    with self.assertRaises(HTTPException) as caught:
                        main.ai_chat(request, fake_http_request)
                    self.assertEqual(caught.exception.status_code, 503)
                with patch.object(main, "settings", replace(main.settings, openai_api_key="test-key")), \
                     patch.object(main, "ai_answer", return_value="Приоритет — сервисные аккаунты.") as mocked:
                    response = main.ai_chat(request, fake_http_request)
                    self.assertEqual(response["answer"], "Приоритет — сервисные аккаунты.")
                    self.assertIn("scan_id", response)
                    self.assertIn("site_guide", mocked.call_args.args[2])


if __name__ == "__main__":
    unittest.main()
