# Identity Risk Analyzer — финальный продуктовый аудит

> **Обновление 2026-09-24:** этот отчёт фиксирует предыдущие live-проверки. Текущая доступность и свежая сверка с ТЗ находятся в [TZ_AUDIT_CURRENT.md](TZ_AUDIT_CURRENT.md). VM DC теперь `Running`; новый scan подтвердил 42 пользователя, 45 findings, Security Score 71 и `pass` для LDAP, Event Log и интерактивных прав. Свежий визуальный browser QA в этой сессии недоступен.

Дата: 2026-09-24. Основание: оригинальный DOCX ТЗ, полный разбор кода и live `infraradar.test`. Git checkpoint утверждённого frontend: `daeb4e1`. Подробная матрица: `docs/TZ_COMPLIANCE.md`. Демонстрационные AD-данные обновлены в пределах lab OU.

## Соответствие ТЗ

- Обязательный MVP: **8/8 PASS**.
- Основные функции и дополнительные AD/auth проверки в текущей расширенной матрице: **19 PASS, 16 PARTIAL, 0 MISSING, 1 OPTIONAL**. Это новый подробный набор строк, не сопоставимый по количеству со старой матрицей.
- Продукт/безопасность/устойчивость: **14 PASS, 1 PARTIAL**.
- Положительные live случаи не создавались для старого пароля, старого входа, SIDHistory, SPN duplication, delegation, слабой FGPP и аутентификационных атак. Их реализация проверена unit-тестами и честно оставлена PARTIAL в live статусе.

## Текущий стенд и live scan

Windows-хост `DANIKEK` через Tailscale `100.126.179.32`; VM `InfraRadar-DC01` запущена. DC `INFRARADAR-DC01.infraradar.test` через Tailscale `100.93.42.103`; домен `infraradar.test`. LDAP `100.93.42.103:389` под `ir-ldap-reader@infraradar.test`. PowerShell проверил: reader не имеет прямых дополнительных `MemberOf` (обычная primary group Domain Users). Обычный backend scan не применяет Administrator.

После checkpoint `cedc9cc` обновлены только объекты `OU=InfraRadarLab`: 33 вымышленных сотрудника (26 обычных и 7 `adm.*`), 7 сервисных `svc_*`, 2 технических reader. Сравнение сохранённых scan подтвердило: все 32 прежних SID, даты установки паролей, групповые членства, SPN и риск-флаги сохранены; добавлено 10 обычных сотрудников. PSO по-прежнему применяется к `m.kalayeva`. Mac live scan `66483f77-4322-4daf-a6ca-677034addb8b`: **42 lab users, 57 groups, 1 computer, 1 FGPP, 45 findings**, Critical **1**, High **28**, Medium **10**, Low **6**, AD Security Score **71/100**, около 7 с (LDAP и Event Log, 24 ч). Все источники имеют `pass`; Authentication: 1076 событий, 50 ошибок пароля, **0 brute force/password spray findings**. Кроме двух новых service Password Never Expires findings, количество по каждому правилу и severity совпадает со scan до обновления данных; изменение AD Security Score относительно исходного scan объясняется 10 новыми аккаунтами без находок и двумя новыми service Password Never Expires findings.

Путь `adm.a.sadykov → Domain Admins` подтверждён как Critical. Делегирование `IR-Lab-Admins` относится только к `OU=InfraRadarLab` и было сверено с ACL lab OU, поэтому вложенный путь `svc_backup` оценивается как High, а не Domain Admin. Доменная политика прочитана полностью: min length 0, complexity on, history 0, max age 42d, min age 0, lockout threshold 0. Длительность при нулевом threshold не считается защитой.

## Командный стенд DigitalOcean

Отдельный Ubuntu 24.04 Droplet `identity-risk-team` подключён к тому же tailnet (`100.93.111.98`). `identity-risk.service` запускает один uvicorn worker от непривилегированного `identityrisk` на `127.0.0.1:8011`; SQLite остаётся в WAL. Tailscale Serve публикует **только внутри tailnet** https://identity-risk-team.tail54a46d.ts.net/ и проксирует frontend production build и API под одним origin. Доступ к `46.101.134.38:8011` с Mac отклонён. Уже работавшие на Droplet nginx и другие приложения не перенастраивались.

Первый scan **с backend на Droplet** `d0d2d7cf-c352-468d-a8f4-1f1c03ba2630`: 42 lab users, 45 findings, score 71, LDAP и Security Event Log `pass`. После `systemctl restart` повторный scan `0b63f251-17bb-4e61-8186-eb9b8cfe73a8` дал те же 42/45/71; общая SQLite сохранила оба scan. `deploy/check.py` проверил health, живое LDAP-чтение, Event Log, account detail, Risks, Computers, Authentication, FGPP, CSV, frontend и SQLite. Тесты в серверном venv: **27/27 PASS**. С Mac через HTTPS проверены все семь страниц на 1440/390 px, карточка `adm.a.sadykov`, Risks и отсутствие React exceptions.

Секреты находятся только в серверном `backend/.env` и отдельном ключе SSH, оба mode 600; в Git/API/CSV/audit они не попали. Снимок интерактивных прав DC остаётся ручным и действует 60 минут; его последующее истечение честно даст `not_evaluated`, пока снимок не обновлён. Security Event Log collector от него не зависит.

## Новые проверки и доказательства

| Проверка | Код / тест | Live результат |
|---|---|---|
| Interactive service logon | `InteractiveLogonCollector`, merged secedit rights, полный token SID, deny precedence | Снимок DC для 7 lab service users: все `pass`, права local/RDP не разрешены; позитивный finding UNIT VERIFIED, другие хосты NOT EVALUATED |
| Lockout | `LOCKED_ACCOUNT`, отдельный lab seed | `m.kalayeva` действительно заблокирован после 3 неверных bind; LDAP/PowerShell/finding подтвердили; затем разблокирован, сейчас `LockedOut=false` |
| FGPP | PSO inventory и `msDS-ResultantPSO` | `IR-Lab-Lockout-PSO`, 8 полей; PowerShell `Get-ADUserResultantPasswordPolicy` подтвердил threshold 3 для lab user |
| Computers | LDAP inventory, inactive rule, UI | 1 активный DC; положительный inactive finding UNIT VERIFIED |
| SIDHistory | read-only attribute, rule | 0 live значений; положительный случай UNIT VERIFIED |
| SPN duplicate | domain-wide SPN owner map, rule | 9 live владельцев, дублей нет; положительный случай UNIT VERIFIED |
| Kerberos delegation | unconstrained/constrained/RBCD rules | Live атрибуты прочитаны, lab находок нет; три позитивных случая UNIT VERIFIED; ожидаемый DC default исключён |
| Security Event Log | отдельный SSH collector, события 4624/4625/4771/4776 | Обычный backend scan под `ir-event-reader`: `pass`, 1076 normalized, 0 auth findings. Прямой read-only экспорт тем же reader подтвердил live 4624/4625/4771/4776. Для 4771 включён только failure audit Kerberos Authentication Service на DC. |
| Brute force / spray | конфигурируемые окна, sources, usernames, дедупликация | UNIT VERIFIED; live положительных атак не наблюдалось |

PSO по схеме AD хранится в `CN=Password Settings Container,CN=System`, вне lab OU, но применён **только** к одному lab user; `GenericRead` reader выдан только этому PSO объекту. Другие политики, системные аккаунты и доменная политика не менялись. Созданный lab user остаётся, но разблокирован. Ручной экспорт прав DC использовал диагностический SSH Administrator вне backend и сохранил только локальный игнорируемый JSON снимок с mode 600. Снимок действует 60 минут, затем результат интерактивных прав станет `not_evaluated`, пока экспорт не повторён. Сбор Event Log работает отдельно от этого снимка.

## Frontend и API

Утверждённый визуальный стиль, Dashboard/Risks/Accounts/Domain Policy/Connection сохранены. Добавлены поля в существующие панели, FGPP, настройки порогов, разделы Computers и Authentication. Старые API запросы и новые `/api/computers`, `/api/authentication`, `/api/checks`, `/api/config`, account/computer detail, CSV отработали после backend restart. Frontend build **PASS**. Chrome headless открыл семь страниц и карточку `adm.a.sadykov` на 1440/390 px без React exceptions и горизонтального переполнения; поиск Accounts/Risks проверен. После доработок browser QA проверил no scan, пустые findings, поиск без результатов, LDAP unavailable/wrong password/timeout, Event Log unavailable/partial/not_evaluated, loading, API error и неправильные Settings на desktop/mobile без React exceptions или горизонтального переполнения. CSV с UTF-8 BOM и `;` delimiter открыт в установленном Microsoft Excel: 14 колонок, 46 строк вместе с заголовком, русский текст читается корректно. Для обычных CSV parsers нужно указать delimiter `;`.

## Тесты, устойчивость и безопасность

`RUN_LDAP_SMOKE=1 .venv/bin/python -m unittest discover -s tests -v`: **27/27 PASS**. Есть тесты scoring и границ, nested cycles, новых правил, event эвристик, interactive allow/deny/unknown, FGPP/computer, config validation/persistence, corrupt DB, atomic writes, concurrent scans и live read-only LDAP. SQLite WAL, `user_version=2`, транзакционная запись и audit событий работают. Scan timing разделён на LDAP, event collection, analysis, persistence и total.

Code review: API не имеет AD write; обычный LDAP reader не администратор; пользовательские пароли не запрашиваются в LDAP и не выводятся в API/CSV/audit; `backend/.env` игнорируется Git и имеет mode 600. Приложение слушает `127.0.0.1`, удалённый доступ идёт через Tailscale. Новые lab скрипты запускаются отдельно, не как часть scan. Security Event Log collector допускает только выделенный SSH alias на DC, сверяет username/IP и наличие Event Log Readers SID, отвергает административные SID. `ir-event-reader` находится в lab OU, состоит лишь в Event Log Readers сверх базовой Domain Users; отдельный ed25519 key и игнорируемый `.env` имеют mode 600. Пароль reader не записан на Mac и не выводился в API/log/CSV.

## Оставшиеся реальные ограничения

1. Interactive rights подтверждены только на DC и только как права local/RDP входа; состояние RDP службы и все дополнительные ограничения фактической аутентификации не проверены. Положительный live сервисный сценарий не создавался из-за необходимости менять политику DC/хоста.
2. Старые logon/password сценарии и SIDHistory/SPN/delegation имеют unit положительные тесты, но нет корректного положительного live объекта. Защищённые timestamps не подделывались.
3. Положительные live brute force/password spray находки не создавались; только безопасная одиночная неудачная Kerberos попытка подтвердила 4771, эвристики положительных атак UNIT VERIFIED.
4. Веб-приложение без собственной авторизации и предназначено для локального lab запуска; реальные outage DC и неверный LDAP пароль проверялись на локальных API fixtures, без вмешательства в стенд.

## Дополнение: полнота lab-профилей, 2026-09-24

Read-only аудит DC показал 42 lab-аккаунта: у 33 заполнены имя/фамилия, у 40 — отдел, должность и компания, у 42 — описание. `managedBy` был пуст у всех; для объектов user в текущей схеме используется `manager`. Скрипт `Set-LabOwners.ps1` после dry run заполнил `manager` у оставшихся 23, всего 42/42. SID, членства, пароли и риск-флаги этим шагом не менялись. Для 12 обычных сотрудников выполнены реальные успешные входы с новыми случайными паролями в памяти процесса: новый scan показывает 14 наблюдаемых входов и 28 без наблюдаемого входа. Исторические timestamps не менялись. Все 42 аккаунта и их пароли созданы сегодня, поэтому сценарии старого пароля и старой активности остаются UNIT VERIFIED.

Локальный live scan `a5766144-6e82-4b6e-941b-47d379fc8049`: 42 users, 57 groups, 1 computer, 38 findings, AD Security Score 72; шесть источников `pass`. Семь `MISSING_OWNER` исчезли после заполнения атрибута. Подтверждены direct/nested privilege, disabled privileged, expired и Password Never Expires. Фронтенд теперь читает и показывает имя, фамилию, должность, компанию и описание AD.

После этого в lab OU появился дополнительный disabled `adm.t.zhaksybek` с отдельным Critical-сценарием. Его SID, пароль, группы и риск-флаги оставлены без изменений; только `manager` задан на lab IT lead после dry run. Текущий состав — 43 аккаунта, 43/43 с ответственным. Числа scan `a5766144-6e82-4b6e-941b-47d379fc8049` выше относятся к состоянию до появления этого аккаунта.
