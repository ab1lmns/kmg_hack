import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from fastapi.testclient import TestClient

from app.collectors import classify_snapshot
from app.models import Account, Computer, Group, Snapshot
from gateway import app as gateway_app
from gateway.security import RateLimiter, TokenStore


def raw_snapshot():
    return Snapshot(source="ldap", accounts=[Account(id="svc_sql", username="svc_sql",
        display_name="SQL service", spns=["MSSQLSvc/sql.infraradar.test"],
        object_classes=["top", "person", "user"], service_account=False)],
        groups=[Group(id="g", name="Domain Admins")],
        computers=[Computer(id="dc", name="DC01", distinguished_name="CN=DC01")],
        domain_policy={"min_password_length": 14},
        fine_grained_policies=[{"name": "LabPSO"}],
        spn_owners=[{"name": "svc_sql", "spns": ["MSSQLSvc/sql.infraradar.test"]}],
        source_status={"ldap": "pass", "interactive_rights": "not_evaluated"})


class GatewayTests(unittest.TestCase):
    def test_fixed_read_only_schema_auth_and_revocation(self):
        with tempfile.TemporaryDirectory() as temp:
            store = TokenStore(Path(temp) / "gateway.db")
            token = "A" * 48
            store.add("dev-one", token)
            self.assertNotIn(token, (Path(temp) / "gateway.db").read_bytes().decode("latin1"))
            with patch.object(gateway_app, "store", store), patch.object(gateway_app, "limits", RateLimiter()), \
                 patch.object(gateway_app, "collect_ldap", return_value=raw_snapshot()), \
                 patch.object(gateway_app.WindowsEventCollector, "collect", return_value=([], "pass")):
                client = TestClient(gateway_app.app)
                self.assertEqual(client.get("/v1/snapshot").status_code, 401)
                headers = {"Authorization": "Bearer " + token}
                self.assertEqual(client.post("/v1/snapshot", headers=headers).status_code, 404)
                self.assertEqual(client.get("/v1/snapshot?filter=anything", headers=headers).status_code, 413)
                response = client.get("/v1/snapshot", headers=headers)
                self.assertEqual(response.status_code, 200)
                payload = response.json()
                self.assertEqual(payload["schema_version"], 1)
                self.assertFalse(payload["snapshot"]["accounts"][0]["service_account"])
                self.assertEqual(payload["snapshot"]["source_status"]["security_event_log"], "pass")
                self.assertEqual(payload["snapshot"]["fine_grained_policies"][0]["name"], "LabPSO")
                self.assertTrue(store.revoke("dev-one"))
                self.assertEqual(client.get("/v1/snapshot", headers=headers).status_code, 401)

    def test_classification_runs_after_snapshot_reaches_local_analyzer(self):
        raw = raw_snapshot()
        self.assertFalse(raw.accounts[0].service_account)
        classify_snapshot(raw)
        self.assertTrue(raw.accounts[0].service_account)
        self.assertIn("SPN", raw.accounts[0].service_detection_reasons)


if __name__ == "__main__":
    unittest.main()
