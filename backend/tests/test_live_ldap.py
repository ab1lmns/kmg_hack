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
        self.assertGreaterEqual(len(snapshot.accounts), 28)
        self.assertGreaterEqual(len(snapshot.groups), 9)
        self.assertIn("ir-svc-backup", {account.username for account in snapshot.accounts})
        self.assertEqual(snapshot.domain_policy["max_password_age_days"], 42)
        self.assertEqual(snapshot.domain_policy["lockout_duration_minutes"], 30)
        result = analyze(snapshot, critical_groups={name.lower() for name in settings.critical_groups})
        self.assertTrue(all(item["evidence"] and item["recommendation"]
                            for item in result["findings"]))
