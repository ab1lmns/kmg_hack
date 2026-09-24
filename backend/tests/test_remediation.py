import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

from app import main
from app.remediation import RemediationPlan, finding_context, generate_plan
from app.storage import Storage


SAMPLE_PLAN = {
    "title": "Проверить и ограничить права сервиса",
    "summary": "У сервисного аккаунта обнаружены лишние права.",
    "before_changes": ["Согласовать изменение с владельцем сервиса."],
    "steps": [
        {"phase": phase, "title": title, "action": "Проверить данные в AD.",
         "why": "Снизить риск.", "verify": "Повторить проверку."}
        for phase, title in [("Проверить", "Уточнить назначение"),
                             ("Исправить", "Ограничить права"),
                             ("Подтвердить", "Запустить анализ")]
    ],
    "success_criteria": "Риск не обнаруживается после повторного сканирования.",
    "limitations": "Данные отражают момент сканирования.",
}


class FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, *_args):
        return json.dumps({"output": [{"type": "message", "content": [
            {"type": "output_text", "text": json.dumps(SAMPLE_PLAN, ensure_ascii=False)}]}]}).encode()


class RemediationTests(unittest.TestCase):
    def test_context_uses_selected_finding_and_related_object_without_secret(self):
        scan = {"scanned_at": "2026-09-24T12:00:00Z", "accounts": [
            {"id": "user-1", "username": "svc_backup", "privileged": True,
             "ldap_password": "do-not-include"}], "findings": [
            {"id": "finding-1", "account_id": "user-1", "title": "Лишние права", "rule_id": "SERVICE_PRIVILEGED"},
            {"id": "finding-2", "account_id": "user-1", "rule_id": "MISSING_OWNER"}]}
        context = finding_context(scan, scan["findings"][0])
        data = json.loads(context)
        self.assertEqual(data["finding"]["rule_id"], "SERVICE_PRIVILEGED")
        self.assertEqual(data["account"]["username"], "svc_backup")
        self.assertEqual(data["related_findings"][0]["rule_id"], "MISSING_OWNER")
        self.assertNotIn("do-not-include", context)

    def test_provider_uses_strict_schema_and_no_storage(self):
        seen = {}
        def fake_urlopen(request, timeout):
            seen.update(json.loads(request.data))
            self.assertEqual(timeout, 60)
            return FakeResponse()
        with patch("app.remediation.urlopen", side_effect=fake_urlopen):
            result = generate_plan("test-key", "gpt-4.1-mini", "{}")
        self.assertIsInstance(result, RemediationPlan)
        self.assertEqual(len(result.steps), 3)
        self.assertFalse(seen["store"])
        self.assertEqual(seen["text"]["format"]["type"], "json_schema")
        self.assertTrue(seen["text"]["format"]["strict"])

    def test_api_rejects_stale_scan_and_returns_selected_plan(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(main, "storage", Storage(Path(temp) / "radar.db")):
                main.create_scan(main.ScanRequest(source="demo"))
                scan = main.latest_or_404()
                finding = scan["findings"][0]
                fake_request = type("Request", (), {"client": type("Client", (), {"host": "test-plan"})()})()
                with patch.object(main, "settings", replace(main.settings, openai_api_key="test-key")):
                    with self.assertRaises(HTTPException) as caught:
                        main.remediation_plan(main.RemediationRequest(scan_id="stale", finding_id=finding["id"]), fake_request)
                    self.assertEqual(caught.exception.status_code, 409)
                    with patch.object(main, "generate_plan", return_value=RemediationPlan.model_validate(SAMPLE_PLAN)) as mock:
                        response = main.remediation_plan(main.RemediationRequest(
                            scan_id=scan["scan_id"], finding_id=finding["id"]), fake_request)
                    self.assertEqual(response["finding_id"], finding["id"])
                    self.assertEqual(len(response["plan"]["steps"]), 3)
                    self.assertIn(finding["rule_id"], mock.call_args.args[2])


if __name__ == "__main__":
    unittest.main()
