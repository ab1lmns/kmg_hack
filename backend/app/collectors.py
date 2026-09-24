import json
import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .config import Settings
from .models import Account, Group, Snapshot


class CollectorError(Exception):
    pass


def iso_days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def collect_demo() -> Snapshot:
    path = Path(__file__).resolve().parents[1] / "data" / "demo_ad_data.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    accounts = []
    for row in payload["accounts"]:
        row = row.copy()
        if "last_logon_days_ago" in row:
            row["last_logon"] = iso_days_ago(row.pop("last_logon_days_ago"))
        if "password_set_days_ago" in row:
            row["password_last_set"] = iso_days_ago(row.pop("password_set_days_ago"))
        accounts.append(Account(**row))
    return Snapshot(
        source="demo",
        accounts=accounts,
        groups=[Group(**row) for row in payload["groups"]],
        domain_policy=payload.get("domain_policy", {}),
    )


def _value(entry, key, default=None):
    try:
        value = entry[key].value
        return default if value is None else value
    except (KeyError, TypeError):
        return default


def _list(value) -> list[str]:
    if value is None:
        return []
    return [str(item) for item in (value if isinstance(value, list) else [value])]


def _date(value) -> str | None:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat()
    if value in (None, 0, "0", "", 9223372036854775807):
        return None
    try:
        raw = int(value)
        return datetime.fromtimestamp((raw - 116444736000000000) / 10_000_000, timezone.utc).isoformat()
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _first_rdn(dn: str) -> str:
    return dn.split(",", 1)[0].split("=", 1)[-1]


def collect_ldap(settings: Settings, password: str | None = None) -> Snapshot:
    bind_password = password or settings.ldap_password
    if not all([settings.ldap_host, settings.ldap_base_dn, settings.ldap_username, bind_password]):
        raise CollectorError("Укажите LDAP_HOST, LDAP_BASE_DN и LDAP_USERNAME; пароль сканера введите в интерфейсе")
    try:
        from ldap3 import ALL, SUBTREE, Connection, Server, Tls

        tls = Tls(validate=ssl.CERT_REQUIRED if settings.ldap_validate_cert else ssl.CERT_NONE)
        server = Server(
            settings.ldap_host, port=settings.ldap_port,
            use_ssl=settings.ldap_use_ssl, tls=tls, get_info=ALL,
            connect_timeout=8,
        )
        with Connection(
            server, user=settings.ldap_username, password=bind_password,
            auto_bind=True, receive_timeout=20, raise_exceptions=True,
        ) as connection:
            users = list(connection.extend.standard.paged_search(
                settings.ldap_base_dn,
                "(&(objectCategory=person)(objectClass=user))",
                search_scope=SUBTREE,
                attributes=[
                    "objectGUID", "distinguishedName", "sAMAccountName", "displayName",
                    "description", "department", "userAccountControl", "lastLogonTimestamp",
                    "pwdLastSet", "accountExpires", "lockoutTime", "memberOf",
                    "servicePrincipalName", "managedBy", "msDS-User-Account-Control-Computed",
                ],
                paged_size=500, generator=True,
            ))
            groups_raw = list(connection.extend.standard.paged_search(
                settings.ldap_base_dn, "(objectClass=group)", search_scope=SUBTREE,
                attributes=["objectGUID", "distinguishedName", "sAMAccountName", "memberOf"],
                paged_size=500, generator=True,
            ))
            policy_attrs = ["minPwdLength", "pwdProperties", "lockoutThreshold"]
            connection.search(settings.ldap_base_dn, "(objectClass=domainDNS)", attributes=policy_attrs)
            domain_entry = connection.entries[0] if connection.entries else None
            policy = {}
            if domain_entry:
                minimum = _value(domain_entry, "minPwdLength")
                properties = _value(domain_entry, "pwdProperties")
                lockout = _value(domain_entry, "lockoutThreshold")
                policy = {
                    "min_password_length": int(minimum or 0),
                    "password_complexity": bool(int(properties or 0) & 1),
                    "lockout_threshold": int(lockout or 0),
                }
    except Exception as exc:
        # Never include bind credentials or LDAP library diagnostics in API responses.
        raise CollectorError(f"Не удалось подключиться к Active Directory ({type(exc).__name__}). Проверьте сеть, LDAP и учётную запись сканера.") from exc

    groups = []
    for row in groups_raw:
        if row.get("type") != "searchResEntry":
            continue
        attrs = row["attributes"]
        dn = str(attrs.get("distinguishedName") or row.get("dn") or "")
        groups.append(Group(
            id=dn.lower(), name=str(attrs.get("sAMAccountName") or _first_rdn(dn)),
            distinguished_name=dn,
            member_of=_list(attrs.get("memberOf")),
        ))
    group_by_dn = {group.distinguished_name.lower(): group.name for group in groups}
    for group in groups:
        group.member_of = [group_by_dn.get(dn.lower(), dn) for dn in group.member_of]

    accounts = []
    now = datetime.now(timezone.utc)
    for row in users:
        if row.get("type") != "searchResEntry":
            continue
        attrs = row["attributes"]
        username = str(attrs.get("sAMAccountName") or "")
        if not username:
            continue
        dn = str(attrs.get("distinguishedName") or row.get("dn") or "")
        flags = int(attrs.get("userAccountControl") or 0)
        computed = int(attrs.get("msDS-User-Account-Control-Computed") or 0)
        expire_at = _date(attrs.get("accountExpires"))
        last_logon = _date(attrs.get("lastLogonTimestamp"))
        password_set = _date(attrs.get("pwdLastSet"))
        spns = _list(attrs.get("servicePrincipalName"))
        managed_by = str(attrs.get("managedBy") or "")
        service_markers = []
        if spns:
            service_markers.append("SPN")
        if username.lower().startswith(("svc_", "sa_", "service_")):
            service_markers.append("префикс имени")
        if "ou=service accounts" in dn.lower():
            service_markers.append("OU Service Accounts")
        accounts.append(Account(
            id=dn.lower(), username=username,
            display_name=str(attrs.get("displayName") or username),
            distinguished_name=dn,
            department=str(attrs.get("department") or ""),
            description=str(attrs.get("description") or ""),
            enabled=not bool(flags & 0x2),
            locked=bool(computed & 0x10),
            account_expired=bool(expire_at and datetime.fromisoformat(expire_at) < now),
            last_logon=last_logon, password_last_set=password_set,
            password_never_expires=bool(flags & 0x10000),
            password_not_required=bool(flags & 0x20),
            service_account=bool(service_markers), service_reason=", ".join(service_markers),
            owner=_first_rdn(managed_by) if managed_by else None,
            groups=[group_by_dn.get(name.lower(), name) for name in _list(attrs.get("memberOf"))],
            spns=spns,
        ))
    return Snapshot(source="ldap", accounts=accounts, groups=groups, domain_policy=policy)
