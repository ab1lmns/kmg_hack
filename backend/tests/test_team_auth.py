import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import main
from app.team_auth import TeamAuth


class TeamAuthTests(unittest.TestCase):
    def test_team_access_and_revocation(self):
        with tempfile.TemporaryDirectory() as directory:
            auth = TeamAuth(Path(directory) / "auth.db")
            auth.set_user("reader", "reader-secret-password", "viewer")
            auth.set_user("operator", "operator-secret-password", "operator")
            with patch.object(main, "team_auth", auth), patch.object(main, "settings", SimpleNamespace(auth_required=True)), patch.object(main, "storage", main.Storage(Path(directory) / "radar.db")):
                client = TestClient(main.app)
                self.assertEqual(client.get("/api/config").status_code, 401)
                self.assertEqual(client.get("/api/dashboard").status_code, 401)
                self.assertEqual(client.get("/api/export/csv").status_code, 401)
                self.assertEqual(client.get("/api/auth/me").json(), {"auth_required": True, "user": None})
                self.assertEqual(client.post("/api/auth/login", json={"username": "reader", "password": "wrong"}).status_code, 401)
                reader = client.post("/api/auth/login", json={"username": "reader", "password": "reader-secret-password"}).json()["token"]
                viewer_headers = {"Authorization": f"Bearer {reader}"}
                self.assertEqual(client.get("/api/config", headers=viewer_headers).status_code, 200)
                self.assertEqual(client.get("/api/audit", headers=viewer_headers).status_code, 403)
                self.assertEqual(client.put("/api/config", headers=viewer_headers, json={}).status_code, 403)
                operator = client.post("/api/auth/login", json={"username": "operator", "password": "operator-secret-password"}).json()["token"]
                admin_headers = {"Authorization": f"Bearer {operator}"}
                self.assertEqual(client.get("/api/audit", headers=admin_headers).status_code, 200)
                self.assertEqual(client.get("/api/auth/me", headers=admin_headers).json()["user"]["role"], "operator")
                auth.disable_user("operator")
                self.assertEqual(client.get("/api/audit", headers=admin_headers).status_code, 401)
                self.assertEqual(client.get("/api/config", headers=viewer_headers).headers["cache-control"], "no-store")
                main.rate_windows.clear()
                for _ in range(5):
                    self.assertEqual(client.post("/api/auth/login", json={"username": "reader", "password": "invalid"}).status_code, 401)
                self.assertEqual(client.post("/api/auth/login", json={"username": "reader", "password": "reader-secret-password"}).status_code, 429)
                main.rate_windows.clear()


if __name__ == "__main__":
    unittest.main()
