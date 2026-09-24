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
    last_logon: str | None = None
    password_last_set: str | None = None
    password_never_expires: bool = False
    password_not_required: bool = False
    service_account: bool = False
    service_reason: str = ""
    owner: str | None = None
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
class Snapshot:
    source: str
    accounts: list[Account]
    groups: list[Group]
    domain_policy: dict[str, Any] = field(default_factory=dict)
