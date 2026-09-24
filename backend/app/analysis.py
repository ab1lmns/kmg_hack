from collections import Counter
from datetime import datetime, timezone
from typing import Any

from .models import Account, Snapshot
from .events import detect_authentication_risks


CRITICAL_GROUPS = {
    "domain admins", "enterprise admins", "schema admins", "administrators",
    "account operators", "server operators", "backup operators", "dnsadmins",
}
TIER_ZERO_GROUPS = {"domain admins", "enterprise admins", "schema admins", "administrators"}
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
    "SID_HISTORY_PRESENT": "identity", "DUPLICATE_SPN": "service",
    "DELEGATION_UNCONSTRAINED": "privilege", "DELEGATION_CONSTRAINED": "privilege",
    "DELEGATION_RBCD": "privilege", "INACTIVE_COMPUTER": "computer",
    "WEAK_FINE_GRAINED_POLICY": "domain_policy",
    "SERVICE_INTERACTIVE_LOGON": "service",
    "AUTH_TARGETED": "authentication",
}

WHY_IT_MATTERS = {
    "DISABLED_ACCOUNT": "Оставленный объект может сохранить членства и быть включён снова без проверки прав.",
    "INACTIVE_ACCOUNT": "Неиспользуемый доступ сложнее контролировать и вовремя отозвать.",
    "EXPIRED_ACCOUNT": "Истёкший объект следует проверить на лишние членства и необходимость хранения.",
    "LOCKED_ACCOUNT": "Блокировка может указывать на ошибки входа или попытки подбора; причина требует проверки журналов.",
    "PASSWORD_NEVER_EXPIRES": "Без ротации срок использования скомпрометированного пароля не ограничен.",
    "SERVICE_PASSWORD_NEVER_EXPIRES": "Долгоживущий пароль сервиса увеличивает время возможного злоупотребления.",
    "OLD_PASSWORD": "Старый пароль дольше остаётся пригодным после возможной компрометации.",
    "PASSWORD_NOT_REQUIRED": "Этот флаг ослабляет стандартную проверку требований к паролю.",
    "DIRECT_PRIVILEGE": "Прямое членство открывает права указанной группы в её фактической области.",
    "NESTED_PRIVILEGE": "Вложенное членство может скрывать путь к административным правам.",
    "DISABLED_PRIVILEGED": "При повторном включении аккаунта сохранённые права станут доступны.",
    "INACTIVE_PRIVILEGED": "Административный доступ без наблюдаемой активности требует подтверждения владельца.",
    "MULTIPLE_PRIVILEGES": "Несколько ролей увеличивают область действий при компрометации аккаунта.",
    "SERVICE_PRIVILEGED": "Компрометация сервиса может дать права в указанной группе и области.",
    "INACTIVE_SERVICE": "Неиспользуемый сервисный доступ может остаться без контроля владельца.",
    "MISSING_OWNER": "Без ответственного сложнее безопасно менять пароль и отзывать доступ.",
    "SHORT_MIN_PASSWORD": "Низкая минимальная длина допускает более слабые пароли.",
    "NO_PASSWORD_COMPLEXITY": "Отключённая сложность допускает простые комбинации.",
    "NO_LOCKOUT": "Без блокировки попытки подбора пароля не ограничены этой политикой.",
    "SID_HISTORY_PRESENT": "Перенесённые SID могут сохранять доступ через прежние идентификаторы; назначение нужно проверить.",
    "DUPLICATE_SPN": "Одинаковый SPN у разных объектов может приводить к ошибкам Kerberos и неоднозначному владельцу сервиса.",
    "DELEGATION_UNCONSTRAINED": "Неограниченная делегация расширяет возможности сервиса использовать учётные данные клиента.",
    "DELEGATION_CONSTRAINED": "Делегирование к указанным сервисам требует подтверждения необходимости и владельца.",
    "DELEGATION_RBCD": "Ресурсное делегирование следует проверить по ACL целевого объекта и владельцу сервиса.",
    "INACTIVE_COMPUTER": "Неиспользуемый компьютерный объект может сохранять доверительные связи и доступ.",
    "WEAK_FINE_GRAINED_POLICY": "Точная парольная политика может ослаблять требования для пользователей, на которых она действует.",
    "SERVICE_INTERACTIVE_LOGON": "Интерактивный вход сервисного аккаунта расширяет способы использования этой учётной записи.",
    "AUTH_TARGETED": "Повторные неудачные входы увеличивают риск для учётной записи и требуют проверки источника.",
}


def privilege_scope(group_name: str, groups_by_name: dict[str, Any]) -> dict[str, str]:
    group = groups_by_name.get(group_name.lower())
    dn = group.distinguished_name.lower() if group else ""
    if group_name.lower() == "ir-lab-admins" and "ou=infraradarlab," in dn:
        return {"group": group_name, "scope": "delegated_ou", "scope_label": "только OU=InfraRadarLab",
                "scope_dn": "OU=InfraRadarLab,DC=infraradar,DC=test",
                "source": "лабораторное делегирование, ACL проверен на DC"}
    if group_name.lower() == "ir-lab-admins":
        return {"group": group_name, "scope": "unknown", "scope_label": "область делегирования не подтверждена"}
    if group_name.lower() in {"domain admins"} and group:
        return {"group": group_name, "scope": "domain", "scope_label": "административные права домена"}
    if group_name.lower() in {"enterprise admins", "schema admins"} and group:
        return {"group": group_name, "scope": "forest", "scope_label": "административные права леса"}
    if group_name.lower() in CRITICAL_GROUPS and group:
        return {"group": group_name, "scope": "built_in", "scope_label": "встроенная административная группа AD"}
    return {"group": group_name, "scope": "unknown", "scope_label": "область прав не подтверждена"}


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
        "why_it_matters": WHY_IT_MATTERS.get(rule_id, reason),
        "evidence": evidence or {}, "recommendation": recommendation,
    }


def analyze(snapshot: Snapshot, inactive_days: int = 90, old_password_days: int = 180,
            critical_groups: set[str] = CRITICAL_GROUPS,
            risk_thresholds: tuple[int, int, int] = DEFAULT_RISK_THRESHOLDS,
            inactive_computer_days: int = 90,
            brute_attempts: int = 5, spray_unique_users: int = 5,
            auth_window_minutes: int = 10) -> dict[str, Any]:
    parents = {group.name.lower(): group.member_of for group in snapshot.groups}
    groups_by_name = {group.name.lower(): group for group in snapshot.groups}
    pso_by_dn = {row["distinguished_name"].lower(): row for row in snapshot.fine_grained_policies}
    auth_findings = detect_authentication_risks(snapshot.auth_events, brute_attempts,
                                                spray_unique_users, auth_window_minutes)
    auth_by_user: dict[str, list[dict[str, Any]]] = {}
    for auth_finding in auth_findings:
        for username in auth_finding["evidence"]["usernames"]:
            auth_by_user.setdefault(username.casefold(), []).append(auth_finding)
    spn_map: dict[str, dict[str, Any]] = {}
    for owner in snapshot.spn_owners:
        for spn in owner["spns"]:
            spn_map.setdefault(spn.casefold(), {"spn": spn, "owners": {}})["owners"][owner["distinguished_name"].lower()] = {
                "name": owner["name"], "distinguished_name": owner["distinguished_name"]}
    all_findings: list[dict[str, Any]] = []
    accounts: list[dict[str, Any]] = []
    computers: list[dict[str, Any]] = []

    def extra_findings(object_id: str, name: str, object_type: str, sid_history: list[str],
                       spns: list[str], delegation: dict, dn: str,
                       *, is_domain_controller: bool = False) -> list[dict[str, Any]]:
        def add(rule_id: str, title: str, severity: str, reason: str, recommendation: str, evidence: dict):
            return {"id": f"{object_id}:{rule_id}", "account_id": object_id,
                    "username": name, "account_type": object_type, "rule_id": rule_id,
                    "title": title, "severity": severity, "category": RULE_CATEGORIES[rule_id],
                    "score": POINTS[severity], "reason": reason,
                    "why_it_matters": WHY_IT_MATTERS[rule_id], "evidence": evidence,
                    "recommendation": recommendation}
        rows = []
        if sid_history:
            rows.append(add("SID_HISTORY_PRESENT", "SIDHistory требует проверки", "medium",
                "У объекта есть исторические SID; само наличие не доказывает атаку.",
                "Сверьте каждый SID с подтверждённой миграцией и фактическими правами.",
                {"sid_history": sid_history, "distinguished_name": dn}))
        duplicates = []
        for spn in spns:
            entry = spn_map.get(spn.casefold())
            if entry and len(entry["owners"]) > 1:
                duplicates.append({"spn": entry["spn"], "owners": list(entry["owners"].values())})
        if duplicates:
            rows.append(add("DUPLICATE_SPN", "Дублирующийся SPN", "high",
                "Один или несколько SPN назначены разным объектам.",
                "Проверьте владельцев сервисов и устраните дубликат после согласования.",
                {"duplicates": duplicates}))
        if delegation.get("unconstrained") and not is_domain_controller:
            rows.append(add("DELEGATION_UNCONSTRAINED", "Неограниченная Kerberos Delegation", "high",
                "В userAccountControl установлен TRUSTED_FOR_DELEGATION.",
                "Проверьте необходимость делегирования; предпочтите ограниченную модель при возможности.",
                {"user_account_control_flag": "TRUSTED_FOR_DELEGATION", "distinguished_name": dn}))
        targets = delegation.get("constrained_targets") or []
        if targets:
            rows.append(add("DELEGATION_CONSTRAINED", "Ограниченная Kerberos Delegation", "medium",
                "Указаны целевые сервисы делегирования; это конфигурация для проверки, а не доказанная атака.",
                "Подтвердите назначение каждого целевого SPN и необходимость protocol transition.",
                {"targets": targets, "protocol_transition": delegation.get("protocol_transition", False)}))
        if delegation.get("rbcd_configured"):
            rows.append(add("DELEGATION_RBCD", "Настроена ресурсная Kerberos Delegation", "medium",
                "На объекте есть msDS-AllowedToActOnBehalfOfOtherIdentity.",
                "Проверьте разрешённых субъектов в ACL делегирования и владельца ресурса.",
                {"rbcd_configured": True, "distinguished_name": dn}))
        return rows

    for account in snapshot.accounts:
        paths = privilege_paths(account, parents, critical_groups)
        account_critical_groups = sorted({path[-1] for path in paths})
        privilege_details = [privilege_scope(group, groups_by_name) for group in account_critical_groups]
        scope_label = "; ".join(f"{item['group']}: {item['scope_label']}" for item in privilege_details)
        has_builtin_privilege = any(item["scope"] in ("domain", "forest", "built_in")
                                    for item in privilege_details)
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
        findings.extend(extra_findings(account.id, account.username,
            "service" if account.service_account else "user", account.sid_history,
            account.spns, account.delegation, account.distinguished_name))
        if account.locked:
            findings.append(finding(account, "LOCKED_ACCOUNT", "Учётная запись заблокирована",
                "low", "Контроллер домена сообщает о блокировке",
                "Проверьте причину блокировки и события входа; разблокируйте после проверки.",
                {"locked": True}))
        for auth_finding in auth_by_user.get(account.username.casefold(), []):
            linked = finding(account, "AUTH_TARGETED", "Повторные неудачные входы",
                "high" if auth_finding["rule_id"] == "POSSIBLE_BRUTE_FORCE" else "medium",
                f"Аккаунт фигурирует в эвристике {auth_finding['title']}.",
                "Проверьте журнал аутентификации, источник попыток и состояние аккаунта.",
                {"authentication_rule": auth_finding["rule_id"],
                 "authentication_finding_id": auth_finding["id"],
                 "attempts": auth_finding["evidence"]["attempts"],
                 "sources": auth_finding["evidence"]["sources"]})
            linked["id"] += ":" + auth_finding["rule_id"]
            linked["source"] = "security_event_log"
            linked["confidence"] = "medium"
            findings.append(linked)
        if account.account_expired:
            findings.append(finding(account, "EXPIRED_ACCOUNT", "Срок учётной записи истёк",
                "low", "Дата окончания действия учётной записи прошла",
                "Уточните необходимость аккаунта и удалите или продлите его согласно процедуре.",
                {"account_expired": True}))
        if privileged:
            direct = [path for path in paths if len(path) == 2]
            nested = [path for path in paths if len(path) > 2]
            if direct:
                direct_details = [privilege_scope(group, groups_by_name) for group in sorted({path[-1] for path in direct})]
                direct_tier_zero = any(item["scope"] in ("domain", "forest", "built_in") and item["group"].lower() in TIER_ZERO_GROUPS
                                       for item in direct_details)
                findings.append(finding(account, "DIRECT_PRIVILEGE", "Прямые административные права",
                    "critical" if direct_tier_zero else "high",
                    "Прямое членство. " + "; ".join(f"{item['group']}: {item['scope_label']}" for item in direct_details),
                    "Проверьте необходимость членства в административной группе.",
                    {"paths": direct, "privilege_details": direct_details}))
            if nested:
                nested_details = [privilege_scope(group, groups_by_name) for group in sorted({path[-1] for path in nested})]
                nested_tier_zero = any(item["scope"] in ("domain", "forest", "built_in") and item["group"].lower() in TIER_ZERO_GROUPS
                                       for item in nested_details)
                findings.append(finding(account, "NESTED_PRIVILEGE", "Административные права через вложенные группы",
                    "critical" if nested_tier_zero else "high",
                    "Найдена цепочка вложенного членства. " + "; ".join(f"{item['group']}: {item['scope_label']}" for item in nested_details),
                    "Проверьте каждую связь в цепочке и удалите лишнее членство.",
                    {"paths": nested, "privilege_details": nested_details}))
            if not account.enabled:
                findings.append(finding(account, "DISABLED_PRIVILEGED", "Отключённый аккаунт сохраняет административные права",
                    "high", f"Учётная запись отключена, но сохраняет членство. {scope_label}",
                    "Проверьте необходимость членства и удалите лишние права.",
                    {"paths": paths, "privilege_details": privilege_details}))
            if inactive:
                findings.append(finding(account, "INACTIVE_PRIVILEGED", "Неактивный привилегированный аккаунт",
                    "critical" if has_builtin_privilege else "high", f"Аккаунт имеет права, но давно не использовался. {scope_label}",
                    "Проверьте владельца и необходимость доступа; удалите лишние административные права.",
                    {"paths": paths, "privilege_details": privilege_details, "days_since_login": login_age}))
            if len(account_critical_groups) > 1:
                findings.append(finding(account, "MULTIPLE_PRIVILEGES", "Несколько административных ролей",
                    "high", f"Доступ к {len(account_critical_groups)} критическим группам",
                    "Оставьте только права, необходимые для текущих задач.",
                    {"critical_groups": account_critical_groups, "paths": paths,
                     "privilege_details": privilege_details}))
        if account.service_account:
            if account.interactive_logon.get("status") == "finding" and account.enabled and not account.account_expired:
                findings.append(finding(account, "SERVICE_INTERACTIVE_LOGON",
                    "Сервисному аккаунту разрешён интерактивный вход", "high",
                    f"Результирующие права входа на {account.interactive_logon['target_host']} допускают локальный вход или RDP.",
                    "Ограничьте интерактивный вход через политику целевого хоста после проверки зависимостей сервиса.",
                    account.interactive_logon))
            if privileged:
                findings.append(finding(account, "SERVICE_PRIVILEGED", "Сервисный аккаунт с административными правами",
                    "critical" if has_builtin_privilege else "high", f"Сервисный аккаунт имеет права. {scope_label}",
                    "Проверьте зависимости сервиса и сократите права до минимально необходимых.",
                    {"paths": paths, "privilege_details": privilege_details,
                     "service_reason": account.service_reason}))
            if inactive:
                findings.append(finding(account, "INACTIVE_SERVICE", "Неиспользуемый сервисный аккаунт",
                    "high" if account.enabled else "medium", "Сервисный аккаунт не проявлял активности",
                    "Проверьте связанные службы и владельца; отключите аккаунт, если он не нужен.",
                    {"days_since_login": login_age, "threshold_days": inactive_days}))
        if not account.owner and account.service_account:
            findings.append(finding(account, "MISSING_OWNER", "Не указан ответственный",
                "medium", f"У сервисного аккаунта не заполнен атрибут {account.owner_attribute}; это поле используется как источник ответственного.",
                "Назначьте владельца и внесите его в инвентаризацию.",
                {"owner_attribute": account.owner_attribute, "attribute_missing": True}))

        score = score_findings(findings, risk_thresholds)
        item = account.to_dict()
        item.update({"risk_score": score, "risk_level": risk_level(score, risk_thresholds),
                     "privileged": privileged, "critical_groups": account_critical_groups,
                     "privilege_paths": paths, "privilege_details": privilege_details,
                     "interactive_logon": (account.interactive_logon or {"status": "not_evaluated",
                         "reason": "Нет снимка результирующих прав входа целевого хоста."})
                         if account.service_account else None,
                     "resultant_password_policy": pso_by_dn.get((account.resultant_pso_dn or "").lower()),
                     "password_policy_source": "fine_grained" if account.resultant_pso_dn and
                         account.resultant_pso_dn.lower() in pso_by_dn else
                         "not_evaluated" if account.resultant_pso_dn else "domain_default",
                     "findings": findings})
        accounts.append(item)
        all_findings.extend(findings)

    for computer in snapshot.computers:
        findings = extra_findings(computer.id, computer.name, "computer", computer.sid_history,
            computer.spns, computer.delegation, computer.distinguished_name,
            is_domain_controller="ou=domain controllers," in computer.distinguished_name.lower())
        age = days_since(computer.last_logon)
        created_age = days_since(computer.when_created)
        if computer.enabled and (age is not None and age >= inactive_computer_days or
                                 age is None and created_age is not None and created_age >= inactive_computer_days):
            findings.append({"id": f"{computer.id}:INACTIVE_COMPUTER", "account_id": computer.id,
                "username": computer.name, "account_type": "computer", "rule_id": "INACTIVE_COMPUTER",
                "title": "Неактивный компьютерный объект", "severity": "medium", "category": "identity",
                "score": POINTS["medium"], "reason": "Нет недавней активности по lastLogonTimestamp.",
                "why_it_matters": WHY_IT_MATTERS["INACTIVE_COMPUTER"],
                "evidence": {"last_logon_timestamp": computer.last_logon, "when_created": computer.when_created,
                             "threshold_days": inactive_computer_days,
                             "uncertainty": "lastLogonTimestamp обновляется с задержкой."},
                "recommendation": "Подтвердите состояние хоста перед отключением компьютерного объекта."})
        item = computer.to_dict()
        score = score_findings(findings, risk_thresholds)
        item.update({"risk_score": score, "risk_level": risk_level(score, risk_thresholds),
                     "findings": findings})
        computers.append(item)
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
                    "why_it_matters": WHY_IT_MATTERS[rule_id],
                    "evidence": {field: value}, "recommendation": recommendation,
                })
    all_findings.extend(policy_findings)
    pso_findings = []
    for pso in snapshot.fine_grained_policies:
        weak = {key: pso[key] for key in ("min_password_length", "lockout_threshold")
                if pso.get(key) is not None and (pso[key] < 12 if key == "min_password_length" else pso[key] == 0)}
        if weak:
            pso_findings.append({"id": f"{pso['distinguished_name']}:WEAK_FINE_GRAINED_POLICY",
                "account_id": pso["distinguished_name"].lower(), "username": pso["name"],
                "account_type": "policy", "rule_id": "WEAK_FINE_GRAINED_POLICY",
                "title": "Ослабленная точная парольная политика", "severity": "medium",
                "category": "domain_policy", "score": POINTS["medium"],
                "reason": "У Fine-Grained Password Policy есть параметры, требующие проверки.",
                "why_it_matters": WHY_IT_MATTERS["WEAK_FINE_GRAINED_POLICY"],
                "evidence": {"weak_fields": weak, "applies_to": pso["applies_to"],
                             "precedence": pso["precedence"]},
                "recommendation": "Сверьте параметры PSO с политикой для указанных пользователей или групп."})
    all_findings.extend(pso_findings)
    all_findings.extend(auth_findings)
    domain_risk_score = min(100, sum(item["score"] for item in policy_findings))
    accounts.sort(key=lambda row: (-row["risk_score"], row["username"]))
    counts = Counter(item["severity"] for item in all_findings)
    category_counts = Counter(item["rule_id"] for item in all_findings)
    scored_objects = [item["risk_score"] for item in accounts + computers]
    if policy:
        scored_objects.append(domain_risk_score)
    avg_risk = round(sum(scored_objects) / len(scored_objects)) if scored_objects else 0
    scanned_at = datetime.now(timezone.utc).isoformat()
    for row in all_findings:
        row.setdefault("source", "security_event_log" if row["account_type"] == "authentication" else snapshot.source)
        row.setdefault("evaluation_status", "finding")
        row.setdefault("confidence", "high" if row["account_type"] != "authentication" else "medium")
        row.setdefault("observed_at", scanned_at)
    return {
        "source": snapshot.source,
        "scanned_at": scanned_at,
        "thresholds": {"inactive_days": inactive_days, "old_password_days": old_password_days,
                       "inactive_computer_days": inactive_computer_days,
                       "brute_attempts": brute_attempts, "spray_unique_users": spray_unique_users,
                       "auth_window_minutes": auth_window_minutes},
        "risk_thresholds": {"medium": risk_thresholds[0], "high": risk_thresholds[1],
                            "critical": risk_thresholds[2]},
        "domain_policy": snapshot.domain_policy,
        "domain_policy_risk_score": domain_risk_score,
        "domain_policy_findings": policy_findings,
        "fine_grained_policy_findings": pso_findings,
        "summary": {
            "security_score": max(0, 100 - avg_risk),
            "total_users": len(accounts),
            "total_computers": len(computers),
            "inactive_computers": sum(any(f["rule_id"] == "INACTIVE_COMPUTER" for f in item["findings"])
                                      for item in computers),
            "locked_accounts": sum(item["locked"] for item in accounts),
            "expired_accounts": sum(item["account_expired"] for item in accounts),
            "service_accounts": sum(item["service_account"] for item in accounts),
            "privileged_accounts": sum(item["privileged"] for item in accounts),
            "healthy_accounts": sum(item["risk_score"] == 0 for item in accounts),
            "disabled_accounts": sum(not item["enabled"] for item in accounts),
            "inactive_accounts": sum(any(finding["rule_id"] == "INACTIVE_ACCOUNT" for finding in item["findings"])
                                     for item in accounts),
            "finding_count": len(all_findings),
            "auth_events": len(snapshot.auth_events),
            "failed_auth_events": sum(e["outcome"] == "failed_bad_password" for e in snapshot.auth_events),
            "auth_findings": len(auth_findings),
            "findings": {severity: counts[severity] for severity in POINTS},
            "categories": [{"rule_id": rule, "count": count} for rule, count in category_counts.most_common()],
            "top_risky_users": [{key: item[key] for key in
                ("id", "username", "display_name", "risk_score", "risk_level", "privileged", "service_account")}
                for item in accounts[:5]],
        },
        "accounts": accounts,
        "computers": computers,
        "groups": [group.to_dict() for group in snapshot.groups],
        "fine_grained_policies": snapshot.fine_grained_policies,
        "source_status": snapshot.source_status,
        "auth_findings": auth_findings,
        "findings": all_findings,
    }
