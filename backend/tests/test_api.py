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
                comparison = main.compare_scans()
                self.assertEqual(comparison["previous_scan_id"], first["scan_id"])
                self.assertEqual(comparison["added_findings"], 0)
                self.assertEqual(comparison["resolved_findings"], 0)

                response = main.export_csv()
                async def read_body():
                    return "".join([part async for part in response.body_iterator])
                data = asyncio.run(read_body())
                self.assertTrue(data.startswith("\ufeff"))
                rows = list(csv.DictReader(io.StringIO(data.lstrip("\ufeff"))))
                self.assertEqual(len(rows), second["findings_found"])
                self.assertIn("Category", rows[0])
                self.assertIn("Why It Matters", rows[0])
                self.assertNotIn("LDAP_PASSWORD", data)
                actions = {(event["action"], event["status"]) for event in main.audit_events()}
                self.assertIn(("scan", "started"), actions)
                self.assertIn(("scan", "completed"), actions)
                self.assertIn(("export_csv", "completed"), actions)


if __name__ == "__main__":
    unittest.main()
