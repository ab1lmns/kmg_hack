import unittest

from app.analysis import analyze, privilege_paths
from app.collectors import collect_demo
from app.models import Account, Group


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


if __name__ == "__main__":
    unittest.main()
