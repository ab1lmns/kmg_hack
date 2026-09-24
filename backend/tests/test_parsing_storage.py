import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.collectors import _ad_interval_seconds, _date, _int, _list
from app.storage import Storage, StorageError


class ParsingTests(unittest.TestCase):
    def test_filetime_and_empty_sentinels(self):
        self.assertEqual(_date(116444736000000000), "1970-01-01T00:00:00+00:00")
        self.assertIsNone(_date(0))
        self.assertIsNone(_date(-1))
        self.assertIsNone(_date(9223372036854775807))
        self.assertIsNone(_date("invalid"))
        self.assertEqual(_date(datetime(2020, 1, 1)).split("T")[0], "2020-01-01")
        self.assertIsNone(_date(datetime(1601, 1, 1, tzinfo=timezone.utc)))
        self.assertIsNone(_date(datetime(9999, 12, 31, tzinfo=timezone.utc)))

    def test_domain_policy_intervals_and_missing_values(self):
        self.assertEqual(_ad_interval_seconds(-42 * 86400 * 10_000_000), 42 * 86400)
        self.assertEqual(_ad_interval_seconds(-30 * 60 * 10_000_000), 1800)
        self.assertEqual(_ad_interval_seconds(timedelta(days=42)), 42 * 86400)
        self.assertEqual(_ad_interval_seconds(0), 0)
        self.assertIsNone(_ad_interval_seconds(-9223372036854775808))
        self.assertIsNone(_ad_interval_seconds("bad"))
        self.assertEqual(_int("bad", None), None)
        self.assertEqual(_list(None), [])


class StorageTests(unittest.TestCase):
    def test_scan_and_audit_survive_reopen(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "radar.db"
            storage = Storage(path)
            scan_id = storage.save({"scanned_at": "2026-01-01T00:00:00+00:00",
                                    "source": "test", "summary": {"total_users": 1},
                                    "accounts": [], "findings": []})
            storage.audit("scan", "completed", {"scan_id": scan_id})
            reopened = Storage(path)
            self.assertEqual(reopened.latest()["scan_id"], scan_id)
            self.assertEqual(reopened.get(scan_id)["summary"]["total_users"], 1)
            self.assertEqual(reopened.list_scans()[0]["scan_id"], scan_id)
            self.assertEqual(reopened.list_audit_events()[0]["details"]["scan_id"], scan_id)
            self.assertEqual(reopened.latest_audit_event("scan", "completed")["details"]["scan_id"], scan_id)

    def test_corrupt_database_fails_clearly_and_scan_save_is_atomic(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "radar.db"
            path.write_bytes(b"not a sqlite database")
            with self.assertRaises(StorageError):
                Storage(path)
            path.unlink()
            storage = Storage(path)
            with self.assertRaises(TypeError):
                storage.save({"scanned_at": "x", "source": "test", "summary": {}, "bad": object()})
            self.assertEqual(storage.list_scans(), [])

    def test_concurrent_scan_writes(self):
        with tempfile.TemporaryDirectory() as temp:
            storage = Storage(Path(temp) / "radar.db")
            def save(index):
                return storage.save({"scanned_at": f"2026-01-01T00:00:{index:02d}+00:00",
                                     "source": "test", "summary": {"total_users": index}})
            with ThreadPoolExecutor(max_workers=4) as pool:
                ids = list(pool.map(save, range(12)))
            self.assertEqual(len(ids), len(set(ids)))
            self.assertEqual(len(storage.list_scans()), 12)


if __name__ == "__main__":
    unittest.main()
