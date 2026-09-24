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
        if key.strip() == "LDAP_PASSWORD":
            continue
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


load_dotenv()


@dataclass(frozen=True)
class Settings:
    db_path: Path = Path(os.getenv("RADAR_DB_PATH", "./data/radar.db"))
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
    ldap_username: str = os.getenv("LDAP_USERNAME", "")
    ldap_password: str = os.getenv("LDAP_PASSWORD", "")
    inactive_days: int = int(os.getenv("INACTIVE_DAYS", "90"))
    old_password_days: int = int(os.getenv("OLD_PASSWORD_DAYS", "180"))
    critical_groups: tuple[str, ...] = tuple(
        group.strip() for group in os.getenv(
            "CRITICAL_GROUPS",
            "Domain Admins,Enterprise Admins,Schema Admins,Administrators,Account Operators,Server Operators,Backup Operators,DNSAdmins",
        ).split(",") if group.strip()
    )


settings = Settings()
