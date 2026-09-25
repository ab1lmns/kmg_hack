import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import main
from app.infrastructure import (collect_infrastructure, dns_diagnostics, domain_from_dn,
                                empty_infrastructure, functional_level, parse_topology)
from app.storage import Storage
from app.team_auth import TeamAuth
from gateway import app as gateway_app
from gateway.security import RateLimiter, TokenStore


ROOT = {"rootDomainNamingContext": "DC=infraradar,DC=test",
        "defaultNamingContext": "DC=infraradar,DC=test",
        "dnsHostName": "INFRARADAR-DC01.infraradar.test",
        "serverName": "CN=INFRARADAR-DC01,CN=Servers,CN=Lab-Site,CN=Sites,CN=Configuration,DC=infraradar,DC=test",
        "forestFunctionality": 7, "domainFunctionality": "7"}


class InfrastructureTests(unittest.TestCase):
    def test_forest_domain_dc_and_functional_level_parsing(self):
        forest, domain, dc = parse_topology(ROOT, {"nETBIOSName": "INFRARADAR"}, "100.93.42.103")
        self.assertEqual(domain_from_dn(ROOT["defaultNamingContext"]), "infraradar.test")
        self.assertEqual(forest, {"name": "infraradar.test", "root_domain": "infraradar.test",
                                  "functional_level": "Windows2016Forest", "status": "pass"})
        self.assertEqual(domain["netbios"], "INFRARADAR")
        self.assertEqual(domain["functional_level"], "Windows2016Domain")
        self.assertEqual(domain["status"], "pass")
        self.assertEqual(dc["hostname"], "INFRARADAR-DC01")
        self.assertEqual(dc["fqdn"], ROOT["dnsHostName"])
        self.assertEqual(dc["ip"], "100.93.42.103")
        self.assertEqual(dc["site"], "Lab-Site")
        self.assertTrue(dc["is_current"])
        self.assertIsNone(functional_level("unknown", "Domain"))

    def test_dns_fixed_queries_and_missing_optional_gc(self):
        queries = []

        class Resolver:
            def __init__(self, configure=False):
                self.nameservers = []

            def resolve(self, name, kind):
                import dns.resolver
                queries.append((name, kind))
                if name.startswith("_gc."):
                    raise dns.resolver.NoAnswer
                return [object()]

        with patch("dns.resolver.Resolver", Resolver):
            result = dns_diagnostics("infraradar.test", ROOT["dnsHostName"], "100.93.42.103")
        self.assertEqual(result, {"domain_resolution": "pass", "dc_resolution": "pass",
                                  "ldap_srv": "pass", "kerberos_srv": "pass", "gc_srv": "not_evaluated"})
        self.assertIn(("_ldap._tcp.dc._msdcs.infraradar.test", "SRV"), queries)
        self.assertIn(("_kerberos._tcp.infraradar.test", "SRV"), queries)
        self.assertIn(("_gc._tcp.infraradar.test", "SRV"), queries)

    def test_unavailable_source_returns_not_evaluated(self):
        settings = SimpleNamespace(ldap_host="", ldap_username="", ldap_password="")
        result = collect_infrastructure(settings)
        self.assertEqual(result["forest"]["status"], "not_evaluated")
        self.assertEqual(result["domain"]["status"], "not_evaluated")
        self.assertEqual(result["dns"]["ldap_srv"], "not_evaluated")
        self.assertEqual(result["diagnostics"]["LDAP_CONNECTION"], "not_evaluated")
        configured = SimpleNamespace(ldap_host="192.0.2.1", ldap_port=389,
            ldap_use_ssl=False, ldap_validate_cert=True, ldap_username="reader",
            ldap_password="not-a-real-secret")
        with patch("ldap3.Connection", side_effect=OSError("connection failed")):
            failed = collect_infrastructure(configured)
        self.assertEqual(failed["forest"]["status"], "not_evaluated")
        self.assertEqual(failed["diagnostics"]["LDAP_CONNECTION"], "error")
        self.assertNotIn("not-a-real-secret", str(failed))

    def test_infrastructure_api_and_gateway_are_read_only_and_authenticated(self):
        payload = empty_infrastructure()
        payload["forest"]["name"] = "infraradar.test"
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(main, "storage", Storage(Path(temp) / "radar.db")), \
                 patch.object(main, "collect_infrastructure", return_value=payload):
                client = TestClient(main.app)
                response = client.get("/api/infrastructure")
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json()["forest"]["name"], "infraradar.test")
                self.assertEqual(client.post("/api/infrastructure").status_code, 405)
            auth = TeamAuth(Path(temp) / "team.db")
            auth.set_user("viewer", "viewer-secret-password", "viewer")
            active_settings = SimpleNamespace(auth_required=True, ad_source="ldap_direct")
            with patch.object(main, "settings", active_settings), patch.object(main, "team_auth", auth), \
                 patch.object(main, "storage", Storage(Path(temp) / "radar.db")), \
                 patch.object(main, "collect_infrastructure", return_value=payload):
                secured = TestClient(main.app)
                self.assertEqual(secured.get("/api/infrastructure").status_code, 401)
                token = secured.post("/api/auth/login", json={"username": "viewer",
                    "password": "viewer-secret-password"}).json()["token"]
                self.assertEqual(secured.get("/api/infrastructure", headers={
                    "Authorization": "Bearer " + token}).status_code, 200)
            store = TokenStore(Path(temp) / "gateway.db")
            token = "I" * 48
            store.add("dev-infra", token)
            with patch.object(gateway_app, "store", store), patch.object(gateway_app, "limits", RateLimiter()), \
                 patch.object(gateway_app, "collect_infrastructure", return_value=payload):
                gateway = TestClient(gateway_app.app)
                self.assertEqual(gateway.get("/v1/infrastructure").status_code, 401)
                self.assertEqual(gateway.post("/v1/infrastructure", headers={"Authorization": "Bearer " + token}).status_code, 404)
                result = gateway.get("/v1/infrastructure", headers={"Authorization": "Bearer " + token})
                self.assertEqual(result.status_code, 200)
                self.assertEqual(result.json()["infrastructure"]["forest"]["name"], "infraradar.test")

    def test_gateway_mode_uses_local_saved_source_status(self):
        saved = {"source": "ldap", "source_status": {"ldap": "pass",
                 "computers": "pass", "fine_grained_policies": "pass",
                 "security_event_log": "error"}}
        with patch.object(main, "settings", SimpleNamespace(ad_source="gateway")), \
             patch.object(main, "storage", SimpleNamespace(latest=lambda: saved)), \
             patch.object(main, "collect_gateway_infrastructure", return_value=empty_infrastructure()):
            result = main.infrastructure()
        self.assertEqual(result["sources"]["users"], "pass")
        self.assertEqual(result["sources"]["groups"], "pass")
        self.assertEqual(result["sources"]["fgpp"], "pass")
        self.assertEqual(result["sources"]["security_event_log"], "error")


if __name__ == "__main__":
    unittest.main()
