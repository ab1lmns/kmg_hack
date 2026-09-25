import tempfile
import unittest
import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from app.analysis import analyze
from app.collectors import _policy_row
from app.events import detect_authentication_risks, normalize_event
from app.interactive import InteractiveLogonCollector, RIGHTS
from app.models import Account, Computer, Group, Snapshot


def user(name="lab-user", **kwargs):
    return Account(id=f"cn={name},ou=infraradarlab,dc=infraradar,dc=test",
                   username=name, display_name=name, **kwargs)


class ExtendedRulesTests(unittest.TestCase):
    def test_sid_history_and_duplicate_spn_have_named_evidence(self):
        a = user("svc-one", service_account=True, sid_history=["S-1-5-21-1-2-3-1001"],
                 spns=["HTTP/lab.test"])
        b = user("svc-two", service_account=True, spns=["http/LAB.test"])
        owners = [{"name": a.username, "distinguished_name": a.id, "spns": a.spns},
                  {"name": b.username, "distinguished_name": b.id, "spns": b.spns}]
        result = analyze(Snapshot("test", [a, b], [], spn_owners=owners))
        rows = result["accounts"][0]["findings"]
        self.assertIn("SID_HISTORY_PRESENT", {row["rule_id"] for row in rows})
        duplicate = next(row for row in rows if row["rule_id"] == "DUPLICATE_SPN")
        self.assertEqual(len(duplicate["evidence"]["duplicates"][0]["owners"]), 2)

    def test_delegation_types_and_dc_exception(self):
        a = user("svc-delegated", service_account=True,
                 delegation={"unconstrained": True, "constrained_targets": ["HTTP/app.lab"],
                             "protocol_transition": True, "rbcd_configured": True})
        computer = Computer(id="cn=dc,ou=domain controllers,dc=infraradar,dc=test",
                            name="DC$", distinguished_name="CN=DC,OU=Domain Controllers,DC=infraradar,DC=test",
                            delegation={"unconstrained": True})
        result = analyze(Snapshot("test", [a], [], computers=[computer]))
        rules = {f["rule_id"] for f in result["accounts"][0]["findings"]}
        self.assertTrue({"DELEGATION_UNCONSTRAINED", "DELEGATION_CONSTRAINED", "DELEGATION_RBCD"} <= rules)
        self.assertFalse(result["computers"][0]["findings"])

    def test_inactive_computer_and_resultant_pso(self):
        old = (datetime.now(timezone.utc) - timedelta(days=120)).isoformat()
        computer = Computer(id="pc", name="PC$", distinguished_name="CN=PC,OU=InfraRadarLab,DC=infraradar,DC=test",
                            when_created=old)
        pso = _policy_row({"cn": "LabPSO", "msDS-PasswordSettingsPrecedence": 10,
                           "msDS-MinimumPasswordLength": 8, "msDS-LockoutThreshold": 0,
                           "msDS-PSOAppliesTo": ["CN=U,OU=InfraRadarLab,DC=infraradar,DC=test"]},
                          "CN=LabPSO,CN=Password Settings Container,CN=System,DC=infraradar,DC=test")
        a = user("pso-user", resultant_pso_dn=pso["distinguished_name"])
        result = analyze(Snapshot("test", [a], [], computers=[computer], fine_grained_policies=[pso]))
        self.assertEqual(result["accounts"][0]["password_policy_source"], "fine_grained")
        self.assertEqual(result["accounts"][0]["resultant_password_policy"]["name"], "LabPSO")
        self.assertIn("INACTIVE_COMPUTER", {f["rule_id"] for f in result["computers"][0]["findings"]})
        self.assertIn("WEAK_FINE_GRAINED_POLICY", {f["rule_id"] for f in result["findings"]})

    def test_service_interactive_requires_verified_token_and_deny_precedes_allow(self):
        account = user("svc", service_account=True, sid="S-1-5-21-1-2-3-1000")
        rights = {name: [] for name in RIGHTS}
        rights["SeInteractiveLogonRight"] = [account.sid]
        payload = {"target_host": "DC", "source_policy": "secedit merged", "collected_at": datetime.now(timezone.utc).isoformat(),
                   "rights": rights, "token_sids": {"svc": [account.sid]}}
        self.assertEqual(InteractiveLogonCollector.evaluate(account, payload, "pass")["status"], "finding")
        rights["SeDenyInteractiveLogonRight"] = [account.sid]
        self.assertEqual(InteractiveLogonCollector.evaluate(account, payload, "pass")["status"], "pass")
        payload["token_sids"] = {}
        self.assertEqual(InteractiveLogonCollector.evaluate(account, payload, "pass")["status"], "not_evaluated")
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "rights.json"
            path.write_text("{bad json", encoding="utf-8")
            self.assertEqual(InteractiveLogonCollector(path).load()[1], "error")

    def test_remote_interactive_snapshot_uses_only_dedicated_reader(self):
        payload = {"target_host": "INFRARADAR-DC01", "source_policy": "secedit merged",
                   "collected_at": datetime.now(timezone.utc).isoformat(),
                   "rights": {name: [] for name in RIGHTS},
                   "token_sids": {"svc_backup": ["S-1-5-21-1-2-3-1000"]}}
        results = [
            subprocess.CompletedProcess([], 0, "user ir-event-reader@infraradar.test\nhostname 100.93.42.103\n", ""),
            subprocess.CompletedProcess([], 0, "S-1-5-32-573", ""),
            subprocess.CompletedProcess([], 0, json.dumps(payload), ""),
        ]
        collector = InteractiveLogonCollector(None, ssh_alias="infraradar-event-reader",
                                               ssh_user="ir-event-reader@infraradar.test")
        with patch("app.interactive.subprocess.run", side_effect=results) as run:
            snapshot, status = collector.load()
        self.assertEqual(status, "pass")
        self.assertEqual(snapshot["target_host"], "INFRARADAR-DC01")
        self.assertEqual(run.call_count, 3)
        bad_config = subprocess.CompletedProcess([], 0, "user Administrator\nhostname 100.93.42.103\n", "")
        with patch("app.interactive.subprocess.run", return_value=bad_config) as run:
            self.assertEqual(collector.load()[1], "error")
        self.assertEqual(run.call_count, 1)

    def test_auth_heuristics_require_bad_password_source_and_pattern(self):
        now = datetime.now(timezone.utc)
        rows = []
        for n in range(5):
            event = normalize_event({"id": 4776, "time": (now + timedelta(seconds=n * 6)).isoformat(),
                                     "record_id": n, "data": {"TargetUserName": "victim",
                                      "Workstation": "LABHOST", "Status": "0xC000006A"}}, "DC")
            rows.append(event)
        findings = detect_authentication_risks(rows)
        self.assertEqual([f["rule_id"] for f in findings], ["POSSIBLE_BRUTE_FORCE"])
        spray = []
        for n in range(5):
            spray.append(normalize_event({"id": 4771, "time": (now + timedelta(seconds=n * 6)).isoformat(),
                 "record_id": 20+n, "data": {"TargetUserName": f"user{n}", "IpAddress": "100.1.2.3",
                                                "FailureCode": "0x18"}}, "DC"))
        self.assertIn("POSSIBLE_PASSWORD_SPRAY",
                      {f["rule_id"] for f in detect_authentication_risks(spray)})
        live_4771_shape = normalize_event({"id": 4771, "time": now.isoformat(),
            "data": {"TargetUserName": "lab-user", "IpAddress": "100.1.2.3", "Status": "0x18"}}, "DC")
        self.assertEqual(live_4771_shape["outcome"], "failed_bad_password")
        self.assertEqual(detect_authentication_risks([normalize_event({"id": 4776,
            "time": now.isoformat(), "data": {"TargetUserName": "victim", "Status": "0xC000006A"}}, "DC")]), [])


if __name__ == "__main__":
    unittest.main()
