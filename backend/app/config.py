import os
from dataclasses import dataclass
from pathlib import Path


def load_dotenv() -> None:
    path = Path(__file__).resolve().parents[1] / ".env"
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        os.environ.setdefault(key, value if key == "LDAP_PASSWORD" else value.strip().strip('"').strip("'"))


load_dotenv()


@dataclass(frozen=True)
class Settings:
    db_path: Path = Path(os.getenv("RADAR_DB_PATH", "./data/radar.db"))
    ad_source: str = os.getenv("AD_SOURCE", "ldap_direct").lower()
    ad_gateway_url: str = os.getenv("AD_GATEWAY_URL", "").rstrip("/")
    ad_gateway_token: str = os.getenv("AD_GATEWAY_TOKEN", "")
    cors_origins: tuple[str, ...] = tuple(
        item.strip() for item in os.getenv(
            "RADAR_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
        ).split(",") if item.strip()
    )
    ldap_host: str = os.getenv("LDAP_HOST", "")
    ldap_port: int = int(os.getenv("LDAP_PORT", "389"))
    ldap_use_ssl: bool = os.getenv("LDAP_USE_SSL", "false").lower() == "true"
    ldap_validate_cert: bool = os.getenv("LDAP_VALIDATE_CERT", "true").lower() == "true"
    ldap_base_dn: str = os.getenv("LDAP_BASE_DN", "")
    ldap_user_base_dn: str = os.getenv("LDAP_USER_BASE_DN", os.getenv("LDAP_BASE_DN", ""))
    ldap_username: str = os.getenv("LDAP_USERNAME", "")
    ldap_password: str = os.getenv("LDAP_PASSWORD", "")
    inactive_days: int = int(os.getenv("INACTIVE_DAYS", "90"))
    old_password_days: int = int(os.getenv("OLD_PASSWORD_DAYS", "180"))
    inactive_computer_days: int = int(os.getenv("INACTIVE_COMPUTER_DAYS", "90"))
    interactive_policy_path: Path | None = ((Path(__file__).resolve().parents[1] / os.getenv("INTERACTIVE_POLICY_PATH"))
        if os.getenv("INTERACTIVE_POLICY_PATH") else None)
    owner_attribute: str = os.getenv("OWNER_ATTRIBUTE", "managedBy")
    event_ssh_alias: str = os.getenv("EVENT_SSH_ALIAS", "")
    event_ssh_user: str = os.getenv("EVENT_SSH_USER", "")
    brute_attempts: int = int(os.getenv("BRUTE_ATTEMPTS", "5"))
    spray_unique_users: int = int(os.getenv("SPRAY_UNIQUE_USERS", "5"))
    auth_window_minutes: int = int(os.getenv("AUTH_WINDOW_MINUTES", "10"))
    risk_medium_threshold: int = int(os.getenv("RISK_MEDIUM_THRESHOLD", "30"))
    risk_high_threshold: int = int(os.getenv("RISK_HIGH_THRESHOLD", "60"))
    risk_critical_threshold: int = int(os.getenv("RISK_CRITICAL_THRESHOLD", "80"))
    critical_groups: tuple[str, ...] = tuple(
        group.strip() for group in os.getenv(
            "CRITICAL_GROUPS",
            "Domain Admins,Enterprise Admins,Schema Admins,Administrators,Account Operators,Server Operators,Backup Operators,DNSAdmins",
        ).split(",") if group.strip()
    )

    @property
    def risk_thresholds(self) -> tuple[int, int, int]:
        values = (self.risk_medium_threshold, self.risk_high_threshold, self.risk_critical_threshold)
        if not 10 <= values[0] < values[1] < values[2] <= 100:
            raise ValueError("Risk thresholds must be ordered between 10 and 100")
        return values


settings = Settings()
