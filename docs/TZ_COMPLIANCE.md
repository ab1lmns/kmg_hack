# Identity Risk Analyzer — соответствие оригинальному ТЗ

Источник: `Техническое задание Hackathon Infrastructure_Risk_Radar.docx`, разделы 1, 2, 4, 5.1 и 6. Матрица создана до изменения кода и обновлена по итогам live E2E. `PASS` означает проверенную реализацию, `PARTIAL` — часть требования или отсутствие визуального подтверждения, `MISSING` — требование не реализовано, `NOT APPLICABLE / OPTIONAL` — дополнительный либо условный пункт ТЗ. Раздел 3 (Certificate Radar) относится к другому проекту. Исходный checkpoint: `5bec32f`.

## 1. Обязательный MVP (ТЗ 2.8)

| Требование ТЗ | Статус | Где реализовано | Как проверено | Что нужно исправить |
|---|---|---|---|---|
| Подключение к тестовому Active Directory | PASS | `backend/app/collectors.py` | live bind `ir-ldap-reader` к `infraradar.test` | — |
| Сбор информации об учётных записях | PASS | `collect_ldap` | live scan: 30 lab users, 57 groups | — |
| Несколько проверок риска | PASS | `backend/app/analysis.py` | 19 правил, 13 tests, live findings | — |
| Расчёт оценки риска | PASS | `score_findings`, `analyze` | scoring tests; live Security Score 62/100, lab OU отделена от Domain Admins | — |
| Web Dashboard | PASS | `frontend/src/App.jsx` | Vite build, `/api/dashboard` с live scan | Визуальная проверка недоступна в текущей сессии |
| Список проблем с причинами | PASS | `/api/findings`, экран «Риски» | API вернул 42 live findings; фильтры и сортировки в UI | — |
| Рекомендации по устранению | PASS | `finding`, account details | live test: все findings с recommendation и why_it_matters | — |
| Экспорт CSV, Excel или HTML | PASS | `/api/export/csv` | 42 строки, UTF-8 BOM, category/evidence/recommendation; Excel manual check в `VISUAL_CHECKLIST.md` | — |

## 2. Основные функциональные требования (ТЗ 2.2–2.7)

| Требование ТЗ | Статус | Где реализовано | Как проверено | Что нужно исправить |
|---|---|---|---|---|
| Выявление устаревших и неиспользуемых users | PARTIAL | `INACTIVE_ACCOUNT` | unit test старого `whenCreated`; нет live aged users | Чётко пометить live отсутствие сценария |
| Включённые users без активности за заданный период | PARTIAL | `INACTIVE_ACCOUNT` | порог в API/UI; unit test | Уточнить интерпретацию `lastLogonTimestamp` |
| Password Never Expires | PASS | `PASSWORD_NEVER_EXPIRES` | live test accounts с флагом | — |
| Давно не изменявшийся пароль | PARTIAL | `OLD_PASSWORD` | unit test порога; live старых паролей нет | Не заявлять live detection |
| Заблокированные users | PARTIAL | `LOCKED_ACCOUNT` | атрибут собирается; live locked account не создан | Добавить parsing/edge tests |
| Истёкшие users | PASS | `EXPIRED_ACCOUNT` | live expired account | — |
| Неиспользуемые service accounts | PARTIAL | `INACTIVE_SERVICE` | unit logic; live aged service нет | Явно отметить ограничение |
| Service accounts с разрешённым interactive login | MISSING | `interactive_logon.status=not_evaluated` | LDAP не содержит результирующие права входа на конкретном хосте | Нужен отдельный сбор применённых GPO и allow/deny прав на целевых компьютерах |
| Service accounts с избыточными правами | PASS | `SERVICE_PRIVILEGED`, `privilege_scope` | live nested path и ACL test OU; severity High для lab | — |
| Service accounts с Password Never Expires | PASS | `SERVICE_PASSWORD_NEVER_EXPIRES` | live findings | — |
| Прямое членство в критических группах | PASS | `privilege_paths`, `DIRECT_PRIVILEGE` | live AD, unit tests | — |
| Вложенное членство в критических группах | PASS | `privilege_paths`, `NESTED_PRIVILEGE` | live nested paths, область прав в API/UI | — |
| Domain Admins | PASS | `CRITICAL_GROUPS` | config и direct live membership | — |
| Enterprise Admins | PASS | `CRITICAL_GROUPS` | config, AD group collection | — |
| Schema Admins | PASS | `CRITICAL_GROUPS` | config, AD group collection | — |
| Administrators | PASS | `CRITICAL_GROUPS` | config, AD group collection | — |
| Account Operators | PASS | `CRITICAL_GROUPS` | config и direct live membership | — |
| Server Operators | PASS | `CRITICAL_GROUPS` | config и direct live membership | — |
| Backup Operators | PASS | `CRITICAL_GROUPS` | config, AD group collection | — |
| DNSAdmins | PASS | `CRITICAL_GROUPS` | config, AD group collection | — |
| Другие группы организаторов | PARTIAL | `CRITICAL_GROUPS` env | конфиг расширяем | Добавлять по фактическому scope/правам |
| Несколько уровней административных прав | PASS | `MULTIPLE_PRIVILEGES` | 2 live findings | — |
| Неочевидное повышение прав через nested groups | PASS | `NESTED_PRIVILEGE` | live path до делегированной lab OU; exact scope | — |
| Неактивные привилегированные users | PARTIAL | `INACTIVE_PRIVILEGED` | unit logic; нет live aged login | Не заявлять live срабатывание |
| Избыточные административные назначения | PASS | `MULTIPLE_PRIVILEGES`, direct/nested findings | live 2 accounts с несколькими ролями | — |
| Возраст пароля | PARTIAL | `OLD_PASSWORD` | `pwdLastSet` и FILETIME edge tests; live старого пароля нет | Нет live aged password без подделки времени |
| Доменная парольная политика | PASS | collector, `/api/dashboard`, DomainPolicy UI | 8 live полей сопоставлены с `Get-ADDefaultDomainPasswordPolicy` | — |
| Ослабленные требования у users | PARTIAL | `PASSWORD_NOT_REQUIRED` | UAC flag, unit path | Добавить edge tests и policy detail |
| Password Spray по журналам при наличии данных | NOT APPLICABLE / OPTIONAL | — | Security Event Log пока не источник приложения | Оценить доступность/качество событий |
| Brute Force по журналам при наличии данных | NOT APPLICABLE / OPTIONAL | — | Security Event Log пока не источник приложения | Оценить доступность/качество событий |
| Уровень риска каждого события/finding | PASS | `finding.severity`, `finding.score` | live JSON и CSV | — |
| Уровень риска каждого объекта | PASS | `risk_score`, `risk_level` | live account detail | — |
| Учёт criticality правила в score | PASS | `score_findings` | score unit tests | — |
| Учёт типа объекта в score | PARTIAL | service/privilege combo findings | live Critical service account | Сделать вес типа объекта явным в документации |
| Учёт административных прав в score | PASS | privilege findings | live Critical `ir-svc-backup` | — |
| Учёт давности активности в score | PARTIAL | inactive findings | unit tests, live aged users нет | Не заявлять live validation |
| Учёт нескольких признаков в score | PASS | `score_findings` | score tests и live multi-risk | — |
| AD Security Score 0–100 | PASS | `analyze.summary.security_score` | live 62/100 | Яснее объяснить направление шкалы |
| Counts Critical / High / Medium / Low | PASS | Dashboard/API | live 2/25/9/6 | — |
| Наиболее рискованные users | PASS | `top_risky_users` | live API | — |
| Counts stale/service/privileged | PASS | Dashboard quick stats | live API/build | — |
| Основные категории рисков | PASS | Dashboard categories | live API/build | — |
| Динамика Score при истории | PASS | history chart, `/api/scans/compare` | live previous → current, Critical/High, added/resolved = 0 | — |
| Переход к деталям каждого риска | PASS | Risks → account detail | код UI/API account detail | Визуальный проход при доступном браузере |
| Понятное описание каждого риска | PASS | `reason`, `why_it_matters`, details | все 42 live findings содержат объяснение | — |
| Рекомендованное действие каждого риска | PASS | `recommendation` | live test all findings nonempty | Пересмотреть формулировки на безопасность |
| AD через LDAP/PowerShell как источник | PASS | LDAP collector, SSH diagnostics | live scan, SSH | — |
| Security Event Log как источник | NOT APPLICABLE / OPTIONAL | — | условный источник, приложение его не читает | Оценить доступность событий |
| Автоматическое регулярное сокращение ручной работы | PARTIAL | Scan API + history | повторные live scans | Нет расписания (не обязательно для MVP) |

## 3. Дополнительные возможности (ТЗ 2.3.5, 2.9, 6)

| Требование ТЗ | Статус | Где реализовано | Как проверено | Что нужно исправить |
|---|---|---|---|---|
| Неактивные computer accounts | NOT APPLICABLE / OPTIONAL | — | дополнительная проверка | Только при надёжном live evidence |
| SIDHistory | NOT APPLICABLE / OPTIONAL | — | дополнительная проверка | Только при надёжном live evidence |
| Duplicate/misconfigured SPN | NOT APPLICABLE / OPTIONAL | — | дополнительная проверка | Оценить качество данных |
| Опасный Kerberos Delegation | NOT APPLICABLE / OPTIONAL | — | дополнительная проверка | Только при надёжном live evidence |
| Другие AD проверки | NOT APPLICABLE / OPTIONAL | — | по выбору команды | После P0/P1 |
| Уведомления администраторам | NOT APPLICABLE / OPTIONAL | — | дополнительная возможность | Не требуется MVP |
| История изменения оценки | PASS | SQLite + chart + compare API | live scan-to-scan delta и restart | — |
| Пояснение найденного риска | PASS | `reason`, `evidence`, `recommendation` | live detail JSON | Улучшить UI Why it matters |
| Расширяемость до общей Infrastructure Risk Radar | PARTIAL | collector/risk/API разделены | code review | SQLite слой пока без интерфейса под другие модули |

## 4. Безопасность (ТЗ 2.3.4, 2.6, 4.2)

| Требование ТЗ | Статус | Где реализовано | Как проверено | Что нужно исправить |
|---|---|---|---|---|
| Преимущественно Read Only | PASS | collector только search/bind | code review и live scan | Seed отделён от backend |
| Стандартный анализ без Domain Admin | PASS | `LDAP_USERNAME=ir-ldap-reader` | live bind/scan | — |
| Минимально необходимые права | PASS | reader только Domain Users | PowerShell group membership | — |
| Не получать пользовательские пароли | PASS | LDAP attributes whitelist | code review | — |
| Не отображать пользовательские пароли | PASS | API/UI | code review, live API | — |
| Не хранить plaintext пользовательские пароли | PASS | SQLite payload/schema | code review | — |
| Безопасная проверка слабых/скомпрометированных паролей | NOT APPLICABLE / OPTIONAL | — | ТЗ допускает, не требует | Не делать без безопасного метода |
| Журналирование действий системы | PASS | `storage.audit`, `/api/audit` | live connection/scan/export; unit API/storage tests | — |
| Рекомендации не изменяют AD | PASS | текст findings, нет write API | code review | — |

## 5. Нефункциональные требования (ТЗ 4, 6)

| Требование ТЗ | Статус | Где реализовано | Как проверено | Что нужно исправить |
|---|---|---|---|---|
| Модульность и расширяемость источников/правил | PARTIAL | collectors/analysis/storage/API | code review | Упростить добавление источников без rewrite |
| Понятный интерфейс sysadmin/ИБ | PARTIAL | React Dashboard | frontend build и static review; browser tool недоступен | Ручной проход `VISUAL_CHECKLIST.md` |
| Настраиваемые пороги | PASS | UI inactive/password, env score/groups | API validation, unit test | Проверить некорректные диапазоны end-to-end |
| Экспорт результатов | PASS | CSV | 42 live rows | Добавить category |
| Работающий прототип для централизованного аудита | PASS | FastAPI + React + SQLite | live E2E, restart | — |

## 6. Демонстрационный сценарий (ТЗ 5.1)

| Требование ТЗ | Статус | Где реализовано | Как проверено | Что нужно исправить |
|---|---|---|---|---|
| Подключение к тестовому DC и запуск анализа | PASS | frontend Scan, LDAP collector | live scan | — |
| Windows Server 2019+ на VM | PASS | Windows Server 2022 Hyper-V | SSH/PowerShell | — |
| AD DS, тестовый домен и объекты | PASS | `infraradar.test`, lab OU | `Get-ADDomain`, `Get-ADUser`, `Get-ADGroup` | — |
| Пример: 10 неактивных пользователей | NOT APPLICABLE / OPTIONAL | — | в ТЗ «например»; нет aged live data | Не подделывать timestamps |
| Пример: 7 сервисных с PNE | NOT APPLICABLE / OPTIONAL | — | в ТЗ «например»; live 5 service PNE | Не объявлять пример обязательным |
| Пример: 3 disabled privileged | PASS | lab OU seed | live 3 findings | — |
| Пример: 2 users с избыточными правами | PASS | lab OU seed/rule | live 2 findings | — |
| Dashboard показывает риски, причины и рекомендации | PASS | Dashboard/Details | API/build/live findings | Нужен ручной visual QA |
| Демонстрация профилактического выявления до инцидента | PASS | score/risks/history, `docs/DEMO_SCRIPT.md` | live E2E, сценарий 3–4 мин | — |

## Итог и оставшиеся приоритеты

- **P0 реализовано:** честный `not_evaluated` для interactive logon; различение Domain Admin и lab OU; структурный audit; 8 полей доменной политики; CSV category; Why it matters; FILETIME tests; live E2E и restart.
- **P1 реализовано:** scan-to-scan delta, connection diagnostics, сортировки/фильтры, unit/API/storage/CSV tests, manual visual checklist, demo script, README и итоговый аудит.
- **Открыто:** фактический interactive logon сервисных аккаунтов требует результирующей политики на целевых хостах; visual QA требует браузера; старые logon/password сценарии не подтверждены live без естественного старения. Условные/дополнительные P2: PSO, Security Event Log spray/bruteforce, inactive computers, SIDHistory, SPN/delegation, уведомления.
