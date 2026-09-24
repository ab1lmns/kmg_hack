from collections import Counter
from datetime import datetime, timezone
from typing import Any

from .models import Account, Snapshot


CRITICAL_GROUPS = {
    "domain admins", "enterprise admins", "schema admins", "administrators",
    "account operators", "server operators", "backup operators", "dnsadmins",
}
POINTS = {"critical": 40, "high": 25, "medium": 10, "low": 5}
DEFAULT_RISK_THRESHOLDS = (30, 60, 80)  # Medium, High, Critical
RULE_CATEGORIES = {
    "DISABLED_ACCOUNT": "identity", "INACTIVE_ACCOUNT": "identity",
    "EXPIRED_ACCOUNT": "identity", "LOCKED_ACCOUNT": "identity",
    "PASSWORD_NEVER_EXPIRES": "password", "SERVICE_PASSWORD_NEVER_EXPIRES": "password",
    "OLD_PASSWORD": "password", "PASSWORD_NOT_REQUIRED": "password",
    "DIRECT_PRIVILEGE": "privilege", "NESTED_PRIVILEGE": "privilege",
    "DISABLED_PRIVILEGED": "privilege", "INACTIVE_PRIVILEGED": "privilege",
    "MULTIPLE_PRIVILEGES": "privilege", "SERVICE_PRIVILEGED": "service",
    "INACTIVE_SERVICE": "service", "MISSING_OWNER": "service",
    "SHORT_MIN_PASSWORD": "domain_policy", "NO_PASSWORD_COMPLEXITY": "domain_policy",
    "NO_LOCKOUT": "domain_policy",
}


def days_since(value: str | None) -> int | None:
    if not value:
        return None
    try:
        date = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return max(0, (datetime.now(timezone.utc) - date.astimezone(timezone.utc)).days)
    except ValueError:
        return None


def risk_level(score: int, thresholds: tuple[int, int, int] = DEFAULT_RISK_THRESHOLDS) -> str:
    medium, high, critical = thresholds
    if score >= critical:
        return "critical"
    if score >= high:
        return "high"
    if score >= medium:
        return "medium"
    if score > 0:
        return "low"
    return "safe"


def score_findings(findings: list[dict[str, Any]],
                   thresholds: tuple[int, int, int] = DEFAULT_RISK_THRESHOLDS) -> int:
    """Highest severity sets the band; additional evidence raises score within it."""
    if not findings:
        return 0
    medium, high, critical = thresholds
    bands = {"low": (10, medium - 1), "medium": (medium, high - 1),
             "high": (high, critical - 1), "critical": (critical, 100)}
    highest = max(findings, key=lambda item: POINTS[item["severity"]])
    base, ceiling = bands[highest["severity"]]
    additional = sum(item["score"] for item in findings) - highest["score"]
    return min(ceiling, base + round(additional * 0.3))


def privilege_paths(account: Account, parents: dict[str, list[str]],
                    critical_groups: set[str] = CRITICAL_GROUPS) -> list[list[str]]:
    paths: list[list[str]] = []
    stack = [[account.username, group] for group in account.groups]
    while stack:
        path = stack.pop()
        group = path[-1]
        if group.lower() in critical_groups:
            paths.append(path)
            continue
        if len(path) >= 20:
            continue
        for parent in parents.get(group.lower(), []):
            if parent.lower() not in {item.lower() for item in path}:
                stack.append(path + [parent])
    return sorted(paths, key=lambda path: (len(path), path))


def finding(account: Account, rule_id: str, title: str, severity: str,
            reason: str, recommendation: str, evidence: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "id": f"{account.id}:{rule_id}", "account_id": account.id,
        "username": account.username, "account_type": "service" if account.service_account else "user",
        "rule_id": rule_id, "title": title, "severity": severity,
        "category": RULE_CATEGORIES.get(rule_id, "other"),
        "score": POINTS[severity], "reason": reason,
        "evidence": evidence or {}, "recommendation": recommendation,
    }


def analyze(snapshot: Snapshot, inactive_days: int = 90, old_password_days: int = 180,
            critical_groups: set[str] = CRITICAL_GROUPS,
            risk_thresholds: tuple[int, int, int] = DEFAULT_RISK_THRESHOLDS) -> dict[str, Any]:
    parents = {group.name.lower(): group.member_of for group in snapshot.groups}
    all_findings: list[dict[str, Any]] = []
    accounts: list[dict[str, Any]] = []

    for account in snapshot.accounts:
        paths = privilege_paths(account, parents, critical_groups)
        account_critical_groups = sorted({path[-1] for path in paths})
        privileged = bool(paths)
        login_age = days_since(account.last_logon)
        created_age = days_since(account.when_created)
        password_age = days_since(account.password_last_set)
        findings: list[dict[str, Any]] = []
        inactive = account.enabled and (login_age is not None and login_age >= inactive_days or
            login_age is None and created_age is not None and created_age >= inactive_days)

        if not account.enabled:
            findings.append(finding(account, "DISABLED_ACCOUNT", "Отключённая учётная запись",
                "low", "Учётная запись отключена, но остаётся в каталоге",
                "Проверьте срок хранения и необходимость учётной записи по внутренней процедуре.",
                {"enabled": False}))
        if inactive:
            reason = ("Не найдено записи о последнем входе" if login_age is None
                      else f"Последний вход {login_age} дней назад")
            findings.append(finding(account, "INACTIVE_ACCOUNT", "Неактивная учётная запись",
                "medium", reason, "Уточните у владельца необходимость аккаунта; отключите его, если он больше не нужен.",
                {"last_logon": account.last_logon, "days_since_login": login_age,
                 "days_since_creation": created_age, "threshold_days": inactive_days,
                 "note": "lastLogonTimestamp обновляется с задержкой и не является точным временем последнего входа."}))
        if account.password_never_expires:
            findings.append(finding(account, "SERVICE_PASSWORD_NEVER_EXPIRES" if account.service_account else "PASSWORD_NEVER_EXPIRES", "Срок действия пароля не ограничен",
                "high" if privileged or account.service_account else "medium", "Установлен флаг Password Never Expires",
                "Определите владельца и настройте контролируемую ротацию пароля.",
                {"password_never_expires": True}))
        if account.enabled and password_age is not None and password_age >= old_password_days:
            findings.append(finding(account, "OLD_PASSWORD", "Пароль давно не менялся",
                "high" if privileged else "medium", f"Пароль установлен {password_age} дней назад",
                "Согласуйте смену пароля с владельцем и проверьте связанные сервисы.",
                {"password_last_set": account.password_last_set, "password_age_days": password_age,
                 "threshold_days": old_password_days}))
        if account.password_not_required:
            findings.append(finding(account, "PASSWORD_NOT_REQUIRED", "Ослаблены требования к паролю",
                "high", "Установлен флаг Password Not Required",
                "Проверьте необходимость настройки и включите стандартные требования к паролю.",
                {"password_not_required": True}))
        if account.locked:
            findings.append(finding(account, "LOCKED_ACCOUNT", "Учётная запись заблокирована",
                "low", "Контроллер домена сообщает о блокировке",
                "Проверьте причину блокировки и события входа; разблокируйте после проверки.",
                {"locked": True}))
        if account.account_expired:
            findings.append(finding(account, "EXPIRED_ACCOUNT", "Срок учётной записи истёк",
                "low", "Дата окончания действия учётной записи прошла",
                "Уточните необходимость аккаунта и удалите или продлите его согласно процедуре.",
                {"account_expired": True}))
        if privileged:
            direct = [path for path in paths if len(path) == 2]
            nested = [path for path in paths if len(path) > 2]
            if direct:
                findings.append(finding(account, "DIRECT_PRIVILEGE", "Прямые административные права",
                    "high", f"Прямое членство в {', '.join(sorted({path[-1] for path in direct}))}",
                    "Проверьте необходимость членства в административной группе.",
                    {"paths": direct}))
            if nested:
                findings.append(finding(account, "NESTED_PRIVILEGE", "Административные права через вложенные группы",
                    "high", "Найдена цепочка вложенного членства до критической группы",
                    "Проверьте каждую связь в цепочке и удалите лишнее членство.", {"paths": nested}))
            if not account.enabled:
                findings.append(finding(account, "DISABLED_PRIVILEGED", "Отключённый аккаунт сохраняет административные права",
                    "high", "Учётная запись отключена, но остаётся в критической группе",
                    "Проверьте необходимость членства и удалите лишние права.", {"paths": paths}))
            if inactive:
                findings.append(finding(account, "INACTIVE_PRIVILEGED", "Неактивный привилегированный аккаунт",
                    "critical", "Аккаунт имеет административные права, но давно не использовался",
                    "Проверьте владельца и необходимость доступа; удалите лишние административные права.",
                    {"paths": paths, "days_since_login": login_age}))
            if len(account_critical_groups) > 1:
                findings.append(finding(account, "MULTIPLE_PRIVILEGES", "Несколько административных ролей",
                    "high", f"Доступ к {len(account_critical_groups)} критическим группам",
                    "Оставьте только права, необходимые для текущих задач.",
                    {"critical_groups": account_critical_groups, "paths": paths}))
        if account.service_account:
            if privileged:
                findings.append(finding(account, "SERVICE_PRIVILEGED", "Сервисный аккаунт с административными правами",
                    "critical", "Сервисный аккаунт имеет доступ к критической группе",
                    "Проверьте зависимости сервиса и сократите права до минимально необходимых.",
                    {"paths": paths, "service_reason": account.service_reason}))
            if inactive:
                findings.append(finding(account, "INACTIVE_SERVICE", "Неиспользуемый сервисный аккаунт",
                    "high" if account.enabled else "medium", "Сервисный аккаунт не проявлял активности",
                    "Проверьте связанные службы и владельца; отключите аккаунт, если он не нужен.",
                    {"days_since_login": login_age, "threshold_days": inactive_days}))
        if not account.owner and account.service_account:
            findings.append(finding(account, "MISSING_OWNER", "Не указан ответственный",
                "medium", "У сервисного аккаунта не заполнен ответственный в Active Directory",
                "Назначьте владельца и внесите его в инвентаризацию.",
                {"managed_by_missing": True}))

        score = score_findings(findings, risk_thresholds)
        item = account.to_dict()
        item.update({"risk_score": score, "risk_level": risk_level(score, risk_thresholds),
                     "privileged": privileged, "critical_groups": account_critical_groups,
                     "privilege_paths": paths, "findings": findings})
        accounts.append(item)
        all_findings.extend(findings)

    policy_findings = []
    policy = snapshot.domain_policy
    if policy:
        policy_rules = [
            ("SHORT_MIN_PASSWORD", "Слишком короткий минимальный пароль", "high",
             "Минимальная длина пароля менее 12 символов", "Пересмотрите минимальную длину пароля согласно политике организации.",
             "min_password_length", lambda value: value < 12),
            ("NO_PASSWORD_COMPLEXITY", "Отключена сложность паролей", "high",
             "В доменной политике не включена сложность паролей", "Проверьте настройки сложности и примените принятую парольную политику.",
             "password_complexity", lambda value: not value),
            ("NO_LOCKOUT", "Не настроена блокировка после неудачных входов", "medium",
             "Порог блокировки равен нулю", "Проверьте политику блокировки с учётом риска перебора и доступности сервисов.",
             "lockout_threshold", lambda value: value == 0),
        ]
        for rule_id, title, severity, reason, recommendation, field, check in policy_rules:
            value = policy.get(field)
            if value is not None and check(value):
                policy_findings.append({
                    "id": f"domain:{rule_id}", "account_id": "__domain__", "username": "Политика домена",
                    "account_type": "domain", "rule_id": rule_id, "title": title,
                    "severity": severity, "score": POINTS[severity], "reason": reason,
                    "category": RULE_CATEGORIES.get(rule_id, "domain_policy"),
                    "evidence": {field: value}, "recommendation": recommendation,
                })
    all_findings.extend(policy_findings)
    domain_risk_score = min(100, sum(item["score"] for item in policy_findings))
    accounts.sort(key=lambda row: (-row["risk_score"], row["username"]))
    counts = Counter(item["severity"] for item in all_findings)
    category_counts = Counter(item["rule_id"] for item in all_findings)
    scored_objects = [item["risk_score"] for item in accounts]
    if policy:
        scored_objects.append(domain_risk_score)
    avg_risk = round(sum(scored_objects) / len(scored_objects)) if scored_objects else 0
    return {
        "source": snapshot.source,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "thresholds": {"inactive_days": inactive_days, "old_password_days": old_password_days},
        "risk_thresholds": {"medium": risk_thresholds[0], "high": risk_thresholds[1],
                            "critical": risk_thresholds[2]},
        "domain_policy": snapshot.domain_policy,
        "domain_policy_risk_score": domain_risk_score,
        "domain_policy_findings": policy_findings,
        "summary": {
            "security_score": max(0, 100 - avg_risk),
            "total_users": len(accounts),
            "service_accounts": sum(item["service_account"] for item in accounts),
            "privileged_accounts": sum(item["privileged"] for item in accounts),
            "healthy_accounts": sum(item["risk_score"] == 0 for item in accounts),
            "disabled_accounts": sum(not item["enabled"] for item in accounts),
            "inactive_accounts": sum(any(finding["rule_id"] == "INACTIVE_ACCOUNT" for finding in item["findings"])
                                     for item in accounts),
            "finding_count": len(all_findings),
            "findings": {severity: counts[severity] for severity in POINTS},
            "categories": [{"rule_id": rule, "count": count} for rule, count in category_counts.most_common()],
            "top_risky_users": [{key: item[key] for key in
                ("id", "username", "display_name", "risk_score", "risk_level", "privileged", "service_account")}
                for item in accounts[:5]],
        },
        "accounts": accounts,
        "groups": [group.to_dict() for group in snapshot.groups],
        "findings": all_findings,
    }
