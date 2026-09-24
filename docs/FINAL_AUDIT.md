# Identity Risk Analyzer — финальный продуктовый аудит

Дата: 2026-09-24. Основание: оригинальный DOCX ТЗ, полный разбор кода и live `infraradar.test`. Git checkpoint утверждённого frontend: `daeb4e1`. Подробная матрица: `docs/TZ_COMPLIANCE.md`. Работа над demo/presentation не выполнялась.

## Соответствие ТЗ

- Обязательный MVP: **8/8 PASS**.
- Основные функции и дополнительные AD/auth проверки в текущей расширенной матрице: **17 PASS, 18 PARTIAL, 0 MISSING, 1 OPTIONAL**. Это новый подробный набор строк, не сопоставимый по количеству со старой матрицей.
- Продукт/безопасность/устойчивость: **12 PASS, 3 PARTIAL**.
- Положительные live случаи не создавались для старого пароля, старого входа, SIDHistory, SPN duplication, delegation, слабой FGPP и аутентификационных атак. Их реализация проверена unit-тестами и честно оставлена PARTIAL в live статусе.

## Текущий стенд и live scan

Windows-хост `DANIKEK` через Tailscale `100.126.179.32`; VM `InfraRadar-DC01` запущена. DC `INFRARADAR-DC01.infraradar.test` через Tailscale `100.93.42.103`; домен `infraradar.test`. LDAP `100.93.42.103:389` под `ir-ldap-reader@infraradar.test`. PowerShell проверил: reader не имеет прямых дополнительных `MemberOf` (обычная primary group Domain Users). Обычный backend scan не применяет Administrator.

После перезапуска backend live scan `14898df0-5a9a-469f-a40c-5868fe4c2507`: **31 lab user, 57 groups, 1 computer, 1 FGPP, 42 findings**, Critical **1**, High **26**, Medium **9**, Low **6**, AD Security Score **65/100**, 190 мс. Состояние источников: LDAP/FGPP/computer/SPN/interactive rights = `pass`; Security Event Log = `not_evaluated`. Повторный scan без изменений AD: 0 добавленных findings. SQLite schema version 2 содержит этот scan; API details, Dashboard, Checks, CSV 42 строки с UTF-8 BOM проверены.

Путь `ir-domainadmin → Domain Admins` подтверждён как Critical. Делегирование `IR-Lab-Admins` относится только к `OU=InfraRadarLab` и было сверено с ACL lab OU, поэтому вложенный путь `ir-svc-backup` оценивается как High, а не Domain Admin. Доменная политика прочитана полностью: min length 0, complexity on, history 0, max age 42d, min age 0, lockout threshold 0. Длительность при нулевом threshold не считается защитой.

## Новые проверки и доказательства

| Проверка | Код / тест | Live результат |
|---|---|---|
| Interactive service logon | `InteractiveLogonCollector`, merged secedit rights, полный token SID, deny precedence | Снимок DC для 7 lab service users: все `pass`, права local/RDP не разрешены; позитивный finding UNIT VERIFIED, другие хосты NOT EVALUATED |
| Lockout | `LOCKED_ACCOUNT`, отдельный lab seed | `ir-lockout-lab` действительно заблокирован после 3 неверных bind; LDAP/PowerShell/finding подтвердили; затем разблокирован, сейчас `LockedOut=false` |
| FGPP | PSO inventory и `msDS-ResultantPSO` | `IR-Lab-Lockout-PSO`, 8 полей; PowerShell `Get-ADUserResultantPasswordPolicy` подтвердил threshold 3 для lab user |
| Computers | LDAP inventory, inactive rule, UI | 1 активный DC; положительный inactive finding UNIT VERIFIED |
| SIDHistory | read-only attribute, rule | 0 live значений; положительный случай UNIT VERIFIED |
| SPN duplicate | domain-wide SPN owner map, rule | 9 live владельцев, дублей нет; положительный случай UNIT VERIFIED |
| Kerberos delegation | unconstrained/constrained/RBCD rules | Live атрибуты прочитаны, lab находок нет; три позитивных случая UNIT VERIFIED; ожидаемый DC default исключён |
| Security Event Log | отдельный SSH collector, события 4624/4625/4771/4776 | Одноразовая read-only диагностика под Administrator: 1349 raw / 771 normalized за 24 ч, 49 bad-password failures, 0 консервативных brute/spray кандидатов. Это **не** обычный backend scan. Отдельный минимальный reader не настроен → backend `not_evaluated` |
| Brute force / spray | конфигурируемые окна, sources, usernames, дедупликация | UNIT VERIFIED; live положительных атак не наблюдалось |

PSO по схеме AD хранится в `CN=Password Settings Container,CN=System`, вне lab OU, но применён **только** к одному lab user; `GenericRead` reader выдан только этому PSO объекту. Другие политики, системные аккаунты и доменная политика не менялись. Созданный lab user остаётся, но разблокирован. Ручной экспорт прав DC использовал диагностический SSH Administrator вне backend и сохранил только локальный игнорируемый JSON снимок с mode 600. Снимок действует 60 минут, затем результат интерактивных прав станет `not_evaluated`, пока экспорт не повторён.

## Frontend и API

Утверждённый визуальный стиль, Dashboard/Risks/Accounts/Domain Policy/Connection сохранены. Добавлены поля в существующие панели, FGPP, настройки порогов, разделы Computers и Authentication. Старые API запросы и новые `/api/computers`, `/api/authentication`, `/api/checks`, `/api/config`, account/computer detail, CSV отработали после backend restart. Frontend build **PASS**. Chrome headless открыл семь страниц и карточку аккаунта на 1440/390 px без React exceptions и горизонтального переполнения; поиск Accounts/Risks проверен. Пустые/error/form состояния и открытие CSV в Excel **NOT VERIFIED**.

## Тесты, устойчивость и безопасность

`RUN_LDAP_SMOKE=1 .venv/bin/python -m unittest discover -s tests -v`: **27/27 PASS**. Есть тесты scoring и границ, nested cycles, новых правил, event эвристик, interactive allow/deny/unknown, FGPP/computer, config validation/persistence, corrupt DB, atomic writes, concurrent scans и live read-only LDAP. SQLite WAL, `user_version=2`, транзакционная запись и audit событий работают. Scan timing разделён на LDAP, event collection, analysis, persistence и total.

Code review: API не имеет AD write; обычный LDAP reader не администратор; пользовательские пароли не запрашиваются в LDAP и не выводятся в API/CSV/audit; `backend/.env` игнорируется Git и имеет mode 600. Приложение слушает `127.0.0.1`, удалённый доступ идёт через Tailscale. Новые lab скрипты запускаются отдельно, не как часть scan. Security Event Log collector отказывает Administrator/административному токену, пока отдельный минимально привилегированный доступ не настроен.

## Оставшиеся реальные ограничения

1. Для постоянного Event Log сбора нужна отдельная неадминистративная учётная запись с SSH и правом чтения Security log на DC. Изменения встроенных групп/политик ради этого не выполнялись.
2. Interactive rights подтверждены только на DC и только как права local/RDP входа; состояние RDP службы и все дополнительные ограничения фактической аутентификации не проверены. Положительный live сервисный сценарий не создавался из-за необходимости менять политику DC/хоста.
3. Старые logon/password сценарии и SIDHistory/SPN/delegation имеют unit положительные тесты, но нет корректного положительного live объекта. Защищённые timestamps не подделывались.
4. Веб-приложение без собственной авторизации и предназначено для локального lab запуска. Основные страницы визуально проверены в Chrome headless; пустые/error/form сценарии остаются непроверенными.
