import unittest
from datetime import datetime, timedelta, timezone

from app.analysis import analyze, privilege_paths, score_findings
from app.collectors import collect_demo
from app.models import Account, Group, Snapshot


class AnalysisTests(unittest.TestCase):
    def test_nested_membership_and_cycle(self):
        account = Account(id="u", username="user", display_name="User", groups=["Team"])
        parents = {"team": ["Subteam"], "subteam": ["Team", "Domain Admins"]}
        self.assertEqual(privilege_paths(account, parents),
                         [["user", "Team", "Subteam", "Domain Admins"]])

    def test_demo_findings_are_evidence_backed(self):
        result = analyze(collect_demo())
        by_name = {account["username"]: account for account in result["accounts"]}
        self.assertTrue(by_name["alex.kim"]["privileged"])
        self.assertIn("NESTED_PRIVILEGE", {item["rule_id"] for item in by_name["alex.kim"]["findings"]})
        self.assertIn("SERVICE_PRIVILEGED", {item["rule_id"] for item in by_name["svc_backup"]["findings"]})
        self.assertEqual(by_name["maria.s"]["risk_score"], 0)
        self.assertGreater(result["summary"]["finding_count"], 10)

    def test_normal_account_is_not_privileged(self):
        account = Account(id="u", username="user", display_name="User", groups=["Finance"])
        self.assertEqual(privilege_paths(account, {"finance": []}), [])

    def test_weak_domain_policy_is_scored(self):
        snapshot = collect_demo()
        snapshot.domain_policy = {"min_password_length": 6, "password_complexity": False,
                                  "lockout_threshold": 0}
        result = analyze(snapshot)
        self.assertEqual(len(result["domain_policy_findings"]), 3)
        self.assertEqual(result["domain_policy_risk_score"], 60)
        self.assertTrue(any(item["account_id"] == "__domain__" for item in result["findings"]))

    def test_custom_critical_group(self):
        snapshot = collect_demo()
        result = analyze(snapshot, critical_groups={"finance"})
        by_name = {account["username"]: account for account in result["accounts"]}
        self.assertTrue(by_name["maria.s"]["privileged"])
        self.assertFalse(by_name["alex.kim"]["privileged"])

    def test_disabled_privileged_is_found_even_after_recent_login(self):
        snapshot = collect_demo()
        account = next(item for item in snapshot.accounts if item.username == "disabled.admin")
        account.last_logon = next(item for item in snapshot.accounts if item.username == "maria.s").last_logon
        result = analyze(snapshot)
        by_name = {item["username"]: item for item in result["accounts"]}
        rules = {item["rule_id"] for item in by_name["disabled.admin"]["findings"]}
        self.assertIn("DISABLED_PRIVILEGED", rules)

    def test_disabled_expired_and_password_flags_have_evidence(self):
        account = Account(id="u", username="disabled", display_name="Disabled", enabled=False,
                          account_expired=True, password_never_expires=True)
        result = analyze(Snapshot(source="test", accounts=[account], groups=[]))
        findings = result["accounts"][0]["findings"]
        self.assertEqual({item["rule_id"] for item in findings},
                         {"DISABLED_ACCOUNT", "EXPIRED_ACCOUNT", "PASSWORD_NEVER_EXPIRES"})
        self.assertTrue(all(item["evidence"] and item["recommendation"] for item in findings))

    def test_new_never_used_account_is_not_called_inactive(self):
        account = Account(id="u", username="new", display_name="New",
                          when_created=datetime.now(timezone.utc).isoformat())
        result = analyze(Snapshot(source="test", accounts=[account], groups=[]))
        self.assertEqual(result["accounts"][0]["risk_score"], 0)

    def test_old_never_used_account_is_inactive(self):
        account = Account(id="u", username="old", display_name="Old",
                          when_created=(datetime.now(timezone.utc) - timedelta(days=120)).isoformat())
        result = analyze(Snapshot(source="test", accounts=[account], groups=[]), inactive_days=90)
        self.assertIn("INACTIVE_ACCOUNT", {item["rule_id"] for item in result["accounts"][0]["findings"]})

    def test_old_password_uses_configured_threshold(self):
        account = Account(id="u", username="old-password", display_name="Old password",
                          password_last_set=(datetime.now(timezone.utc) - timedelta(days=100)).isoformat())
        snapshot = Snapshot(source="test", accounts=[account], groups=[])
        self.assertNotIn("OLD_PASSWORD", {item["rule_id"] for item in
                         analyze(snapshot, old_password_days=180)["accounts"][0]["findings"]})
        self.assertIn("OLD_PASSWORD", {item["rule_id"] for item in
                      analyze(snapshot, old_password_days=90)["accounts"][0]["findings"]})

    def test_service_nested_privilege_and_combined_risk(self):
        account = Account(id="svc", username="svc_backup", display_name="Backup",
                          service_account=True, service_reason="SPN", password_never_expires=True,
                          groups=["Service Ops"])
        groups = [Group(id="ops", name="Service Ops", member_of=["IR-Lab-Admins"]),
                  Group(id="admins", name="IR-Lab-Admins",
                        distinguished_name="CN=IR-Lab-Admins,OU=InfraRadarLab,DC=infraradar,DC=test")]
        result = analyze(Snapshot(source="test", accounts=[account], groups=groups),
                         critical_groups={"ir-lab-admins"})
        row = result["accounts"][0]
        self.assertIn(["svc_backup", "Service Ops", "IR-Lab-Admins"], row["privilege_paths"])
        self.assertEqual(row["risk_level"], "high")
        self.assertEqual(row["privilege_details"][0]["scope"], "delegated_ou")
        self.assertEqual(row["interactive_logon"]["status"], "not_evaluated")
        self.assertIn("SERVICE_PRIVILEGED", {item["rule_id"] for item in row["findings"]})
        self.assertIn("SERVICE_PASSWORD_NEVER_EXPIRES", {item["rule_id"] for item in row["findings"]})

    def test_score_bands_and_boundary(self):
        self.assertEqual(score_findings([]), 0)
        self.assertLess(score_findings([{"severity": "medium", "score": 10}] * 20), 60)
        self.assertLess(score_findings([{"severity": "high", "score": 25}] * 20), 80)
        self.assertLessEqual(score_findings([{"severity": "critical", "score": 40}] * 20), 100)
        self.assertEqual(score_findings([{"severity": "high", "score": 25}], (25, 50, 75)), 50)

    def test_builtin_admin_is_distinct_from_lab_delegation(self):
        account = Account(id="svc", username="svc", display_name="Service", service_account=True,
                          groups=["Domain Admins"])
        group = Group(id="admins", name="Domain Admins",
                      distinguished_name="CN=Domain Admins,CN=Users,DC=infraradar,DC=test")
        row = analyze(Snapshot(source="test", accounts=[account], groups=[group]))["accounts"][0]
        self.assertEqual(row["risk_level"], "critical")
        self.assertEqual(row["privilege_details"][0]["scope"], "domain")
        self.assertEqual(row["findings"][0]["severity"], "critical")

    def test_all_findings_explain_why(self):
        result = analyze(collect_demo())
        self.assertTrue(all(item["why_it_matters"] for item in result["findings"]))


if __name__ == "__main__":
    unittest.main()
