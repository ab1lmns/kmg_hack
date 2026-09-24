from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Account:
    id: str
    username: str
    display_name: str
    distinguished_name: str = ""
    object_guid: str = ""
    sid: str = ""
    user_principal_name: str = ""
    primary_group_id: int | None = None
    admin_count: int | None = None
    when_created: str | None = None
    department: str = ""
    description: str = ""
    enabled: bool = True
    locked: bool = False
    account_expired: bool = False
    account_expires_at: str | None = None
    last_logon: str | None = None
    exact_last_logon: str | None = None
    logon_count: int | None = None
    activity_status: str = "not_evaluated"
    password_last_set: str | None = None
    password_must_change: bool = False
    password_never_expires: bool = False
    password_not_required: bool = False
    service_account: bool = False
    service_reason: str = ""
    service_detection_reasons: list[str] = field(default_factory=list)
    owner: str | None = None
    owner_attribute: str = "managedBy"
    sid_history: list[str] = field(default_factory=list)
    delegation: dict[str, Any] = field(default_factory=dict)
    resultant_pso_dn: str | None = None
    interactive_logon: dict[str, Any] = field(default_factory=dict)
    groups: list[str] = field(default_factory=list)
    spns: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Group:
    id: str
    name: str
    distinguished_name: str = ""
    object_guid: str = ""
    sid: str = ""
    member_of: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Computer:
    id: str
    name: str
    distinguished_name: str
    dns_hostname: str = ""
    enabled: bool = True
    last_logon: str | None = None
    password_last_set: str | None = None
    operating_system: str = ""
    when_created: str | None = None
    spns: list[str] = field(default_factory=list)
    sid_history: list[str] = field(default_factory=list)
    delegation: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Snapshot:
    source: str
    accounts: list[Account]
    groups: list[Group]
    domain_policy: dict[str, Any] = field(default_factory=dict)
    computers: list[Computer] = field(default_factory=list)
    fine_grained_policies: list[dict[str, Any]] = field(default_factory=list)
    spn_owners: list[dict[str, Any]] = field(default_factory=list)
    source_status: dict[str, Any] = field(default_factory=dict)
    auth_events: list[dict[str, Any]] = field(default_factory=list)
