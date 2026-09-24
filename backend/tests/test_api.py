import csv
import io
import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import main
from app.storage import Storage


class ApiTests(unittest.TestCase):
    def test_demo_scan_history_export_and_audit(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(main, "storage", Storage(Path(temp) / "radar.db")):
                first = main.create_scan(main.ScanRequest(source="demo"))
                second = main.create_scan(main.ScanRequest(source="demo"))
                self.assertEqual(first["status"], "completed")
                self.assertGreater(second["findings_found"], 0)
                self.assertGreater(second["groups_scanned"], 0)
                self.assertEqual(main.dashboard()["scan_id"], second["scan_id"])
                self.assertEqual(main.dashboard()["risk_thresholds"]["critical"], main.get_config()["risk_critical_threshold"])
                self.assertIsInstance(main.computers(), list)
                self.assertIn("status", main.authentication())
                self.assertIn("sources", main.checks())
                self.assertEqual(len(main.accounts()), second["users_scanned"])
                self.assertEqual(len(main.findings(q="")), second["findings_found"])
                comparison = main.compare_scans()
                self.assertEqual(comparison["previous_scan_id"], first["scan_id"])
                self.assertEqual(comparison["added_findings"], 0)
                self.assertEqual(comparison["resolved_findings"], 0)

                response = main.export_csv()
                async def read_body():
                    return "".join([part async for part in response.body_iterator])
                data = asyncio.run(read_body())
                self.assertTrue(data.startswith("\ufeff"))
                rows = list(csv.DictReader(io.StringIO(data.lstrip("\ufeff")), delimiter=";"))
                self.assertEqual(len(rows), second["findings_found"])
                self.assertIn("Category", rows[0])
                self.assertIn("Why It Matters", rows[0])
                self.assertNotIn("LDAP_PASSWORD", data)
                actions = {(event["action"], event["status"]) for event in main.audit_events()}
                self.assertIn(("scan", "started"), actions)
                self.assertIn(("scan", "completed"), actions)
                self.assertIn(("export_csv", "completed"), actions)

    def test_config_validation_and_persistence(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(main, "storage", Storage(Path(temp) / "radar.db")):
                config = main.AnalysisConfig(inactive_days=120, risk_medium_threshold=25,
                                             risk_high_threshold=60, risk_critical_threshold=80)
                main.update_config(config)
                self.assertEqual(main.get_config()["inactive_days"], 120)
                with self.assertRaises(ValueError):
                    main.AnalysisConfig(risk_medium_threshold=70, risk_high_threshold=60)


if __name__ == "__main__":
    unittest.main()
