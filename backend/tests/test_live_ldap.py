"""Opt-in read-only smoke test against the configured lab domain."""
import os
import unittest

from app.collectors import collect_ldap
from app.config import settings
from app.analysis import analyze


@unittest.skipUnless(os.getenv("RUN_LDAP_SMOKE") == "1", "Set RUN_LDAP_SMOKE=1 to test live LDAP")
class LiveLdapTests(unittest.TestCase):
    def test_read_only_account_can_collect_lab_users_and_groups(self):
        self.assertEqual(settings.ldap_username, "ir-ldap-reader@infraradar.test")
        snapshot = collect_ldap(settings)
        self.assertEqual(snapshot.source, "ldap")
        self.assertGreaterEqual(len(snapshot.accounts), 42)
        self.assertGreaterEqual(len(snapshot.groups), 9)
        names = {account.username for account in snapshot.accounts}
        self.assertIn("svc_backup", names)
        self.assertIn("adm.a.sadykov", names)
        self.assertNotIn("ir-domainadmin", names)
        self.assertEqual(sum(account.service_account for account in snapshot.accounts), 7)
        self.assertTrue({"Finance", "HR", "IT", "Information Security", "Operations", "Legal", "Sales",
                         "Procurement", "Infrastructure", "Support"}.issubset(
            {account.department for account in snapshot.accounts}))
        self.assertEqual(snapshot.domain_policy["max_password_age_days"], 42)
        self.assertEqual(snapshot.domain_policy["lockout_duration_minutes"], 30)
        result = analyze(snapshot, critical_groups={name.lower() for name in settings.critical_groups})
        self.assertTrue(all(item["evidence"] and item["recommendation"]
                            for item in result["findings"]))
