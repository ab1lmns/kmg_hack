# Соответствие Identity Risk Analyzer оригинальному ТЗ

> **Актуальное состояние 2026-09-24:** см. [TZ_AUDIT_CURRENT.md](TZ_AUDIT_CURRENT.md). VM контроллера домена работает. Свежие scan через приватный backend и локальный backend/AD Gateway подтвердили 42 пользователя, 45 findings и Security Score 71; LDAP, Event Log и обновлённые интерактивные права DC имеют статус `pass`. Приведённые ниже позитивные `UNIT VERIFIED` сценарии не переименованы в `LIVE VERIFIED`. Свежий визуальный browser QA в этой сессии не выполнен.

Источник: `Техническое задание Hackathon Infrastructure_Risk_Radar.docx`, полностью перечитано 2026-09-24. Исходный frontend сохранён checkpoint `daeb4e1` (до продуктовых изменений). Эта матрица проверена по коду, тестам и live AD; прежние документы не использованы как доказательство. `LIVE VERIFIED` означает проверку на настоящем `infraradar.test`; `UNIT VERIFIED` — только тестовые объекты/события; `NOT EVALUATED` — источник отсутствует или позитивный сценарий не наблюдался. Визуальный проход семи страниц и edge cases выполнен в Chrome headless на 1440 и 390 px после изменений; утверждённый стиль сохранён.

## Обязательный MVP (раздел 2.8)

| Требование | Статус | Доказательство |
|---|---|---|
| Подключение к тестовому AD | PASS | LIVE VERIFIED: LDAP bind `ir-ldap-reader`, 100.93.42.103:389 |
| Сбор пользователей | PASS | LIVE VERIFIED: 42 аккаунта lab OU (33 сотрудника, 7 сервисных, 2 reader), 57 групп для путей |
| Несколько проверок риска | PASS | LIVE VERIFIED: 45 находок; дополнительные положительные случаи UNIT VERIFIED |
| Risk Score | PASS | LIVE VERIFIED: аккаунты/политика/компьютер, score 71; границы UNIT VERIFIED |
| Web Dashboard | PASS | API + frontend build; LIVE BROWSER VERIFIED: Dashboard desktop/mobile |
| Список проблем с причинами | PASS | LIVE VERIFIED: 45 finding с reason/evidence, API + CSV |
| Рекомендации | PASS | LIVE VERIFIED: у каждой находки непустой recommendation |
| Экспорт CSV/Excel/HTML | PASS | LIVE VERIFIED: CSV UTF-8 BOM, 45 строк, 14 колонок; русский текст и разделение колонок подтверждены прямым открытием в Microsoft Excel |

## Пользователи, активность и пароли

| Требование | Статус | Доказательство / предел |
|---|---|---|
| Неактивные пользователи и configurable threshold | PARTIAL | UNIT VERIFIED: новый never logged in отличается от старого; в live нет старого неактивного пользователя |
| Приближённость lastLogonTimestamp / точный DC lastLogon / logonCount | PASS | LIVE VERIFIED: collector поля, UI различает «вход не наблюдался»; точный lastLogon только текущего DC |
| Password Never Expires | PASS | LIVE VERIFIED: реальные флаги и findings |
| Старый пароль и порог | PARTIAL | UNIT VERIFIED: правило и FILETIME; live старого пароля нет |
| pwdLastSet=0 / must change / отсутствие значения | PASS | UNIT VERIFIED: parsing и отдельный флаг; live положительный случай не создавался |
| Заблокированный пользователь | PASS | LIVE VERIFIED: `m.kalayeva` блокирован тремя неверными bind, LDAP/PowerShell/finding подтверждены, затем разблокирован |
| Истёкший пользователь | PASS | LIVE VERIFIED: флаг и finding в lab OU |
| Disabled account | PASS | LIVE VERIFIED: реальные lab account findings |
| PASSWORD_NOT_REQUIRED | PARTIAL | UNIT VERIFIED: UAC bit; live положительного примера нет |
| Неиспользуемый service account | PARTIAL | UNIT VERIFIED; нет старого service activity в live |
| Service с Password Never Expires | PASS | LIVE VERIFIED: все 7 разных сервисных аккаунтов; пять прежних флагов сохранены, два добавлены только в lab OU |
| Service с избыточными правами | PASS | LIVE VERIFIED: вложенная lab OU группа и фактический ACL тестовой OU |
| Service с разрешённым interactive logon | PARTIAL | LIVE VERIFIED: merged rights DC + полный token SID для 7 lab services, все 7 PASS (права не разрешены); положительный finding UNIT VERIFIED; другие целевые хосты и дополнительные ограничения входа NOT EVALUATED |
| Владелец сервиса | PASS | LIVE VERIFIED: `manager` заполнен у всех 43 текущих lab-аккаунтов; LDAP scan читает ответственных, семь прежних `MISSING_OWNER` исчезли |

## Привилегии и доменная политика

| Требование | Статус | Доказательство / предел |
|---|---|---|
| Прямые критические группы | PASS | LIVE VERIFIED: `adm.a.sadykov` → Domain Admins, Critical |
| Вложенные критические группы | PASS | LIVE VERIFIED: путь `svc_backup` → lab delegated group; циклы UNIT VERIFIED |
| Domain/Enterprise/Schema Admins, Administrators | PASS | LIVE VERIFIED: группы читаются; позитивный путь Domain Admins, остальные распознаются кодом/UNIT |
| Account/Server/Backup Operators, DNSAdmins | PASS | LIVE VERIFIED: группы читаются и есть lab примеры части ролей; остальные пути UNIT |
| Несколько административных ролей | PASS | LIVE VERIFIED: 2 находки, scope показан |
| Неактивный privileged user | PARTIAL | UNIT VERIFIED: правило; нет live старой активности |
| Domain policy: min length, complexity, history, ages, lockout | PASS | LIVE VERIFIED: LDAP значения сверены с `Get-ADDefaultDomainPasswordPolicy`; threshold 0 означает отсутствие lockout |
| Fine-Grained Password Policies (8 полей, precedence, applies-to) | PASS | LIVE VERIFIED: 1 PSO; `Get-ADUserResultantPasswordPolicy` = `IR-Lab-Lockout-PSO`; reader видит PSO после GenericRead только на этом объекте |
| Слабая FGPP finding | PARTIAL | UNIT VERIFIED: позитивное правило; live PSO удовлетворяет заданным порогам |
| Расширяемые critical groups и scope | PARTIAL | `CRITICAL_GROUPS` расширяем; scope lab delegation проверен ACL стенда, другие произвольные группы требуют отдельной проверки реальных прав |

## Дополнительные AD проверки

| Требование | Статус | Доказательство / предел |
|---|---|---|
| Computer inventory | PASS | LIVE VERIFIED: 1 DC computer, поля ОС/DNS/активности/пароля/SPN и UI |
| Inactive computers | PARTIAL | LIVE VERIFIED: collector и отсутствие находки на активном DC; позитивный случай UNIT VERIFIED |
| SIDHistory | PARTIAL | LIVE VERIFIED: сбор атрибута, 0 объектов; позитивный finding UNIT VERIFIED |
| Duplicate SPN | PARTIAL | LIVE VERIFIED: inventory 9 владельцев SPN без дублей; позитивный finding UNIT VERIFIED |
| Kerberos delegation: unconstrained/constrained/RBCD | PARTIAL | LIVE VERIFIED: сбор атрибутов, нет положительного lab случая; три правила UNIT VERIFIED; DC default unconstrained исключён |
| Уведомления | OPTIONAL | Дополнительная возможность ТЗ; не реализованы |

## Security Event Log и аутентификация

| Требование | Статус | Доказательство / предел |
|---|---|---|
| Security Event Log как отдельный источник | PASS | LIVE VERIFIED: постоянный scan через `ir-event-reader` из lab OU, только Event Log Readers; более 1000 нормализованных событий за 24 ч, source `pass` |
| Нормализация 4624/4625/4771/4776 | PASS | LIVE VERIFIED: под отдельным reader прочитаны все 4 ID, включая 4771 после включения failure Kerberos audit на DC; поле XML `Status` проверено |
| Possible Brute Force | PARTIAL | UNIT VERIFIED: окно, пользователь, source, timestamps, дедупликация; live scan `pass` без кандидата; позитивная эвристика только UNIT VERIFIED |
| Possible Password Spray | PARTIAL | UNIT VERIFIED: один source, много usernames, мало ошибок на каждого; live scan `pass` без кандидата; позитивная эвристика только UNIT VERIFIED |
| Связь auth finding с целевым account score | PARTIAL | UNIT VERIFIED; live положительной auth находки нет, тестовую атаку не создавали |
| Явные статусы PASS/FINDING/NOT_EVALUATED/ERROR | PASS | LIVE VERIFIED: все доступные источники `pass`, отсутствие auth находок отображается как «Сигналов не найдено»; error/partial/not_evaluated проверены в browser QA |

## Продукт, безопасность и устойчивость

| Требование | Статус | Доказательство / предел |
|---|---|---|
| Dashboard score, severity, counts, top, categories, history | PASS | LIVE VERIFIED API и Chrome headless на 1440/390 px; добавлены locked/expired/computers/auth source |
| Accounts filters/sorting and details | PASS | LIVE BROWSER VERIFIED: desktop/mobile, карточка, поиск в Accounts/Risks; новые поля/фильтры |
| Computers, Authentication, FGPP UI | PASS | LIVE BROWSER VERIFIED: страницы desktop/mobile, реальный Event Log `pass`, no findings и error/partial/not_evaluated состояния |
| Findings: общая схема/evidence/recommendation/source/time/confidence | PASS | LIVE VERIFIED: все 45 непустые, CSV/API |
| Настройки/валидация/сохранение | PASS | UNIT VERIFIED: границы и Medium < High < Critical, API persistence; UI build |
| Audit действий, включая Event Log/auth | PASS | LIVE VERIFIED: scan/connection/export; scan пишет event/auth status; секреты не логируются по code review |
| CSV: объект, score, severity, category, source, evidence | PASS | LIVE VERIFIED: 45 строк, 14 колонок, UTF-8 BOM, `;` delimiter; Microsoft Excel открыл русский текст и колонки корректно |
| SQLite schema/version, corruption, atomicity, concurrency | PASS | UNIT VERIFIED: schema v2, WAL, транзакции, восстановление; LIVE VERIFIED: два scan на Droplet в одной базе, история сохранилась после systemd restart |
| Производительность/batch LDAP/timings | PASS | LIVE VERIFIED: scan около 7 с на 42 user/57 groups/1 computer и 1076 Security events; timings API |
| Ошибки DC/credentials/timeout/malformed DB/settings/partial events | PARTIAL | Validation/storage/collector UNIT VERIFIED; frontend edge cases пройдены на локальных API fixtures, реальный DC outage не создавался |
| Backend read-only и минимальные права | PASS | LIVE VERIFIED: Droplet LDAP reader только Domain Users; event reader в lab OU состоит из Domain Users и builtin Event Log Readers, без admin token; оба используются обычным scan |
| Пароли/секреты не в API/SQLite/CSV/log | PASS | Code review + live response/CSV review; `.env` ignored, mode 600 |
| Только локальная веб-привязка / Tailscale | PASS | LIVE VERIFIED: Droplet uvicorn `127.0.0.1:8011`, Tailscale Serve HTTPS только внутри tailnet, публичный порт 8011 недоступен |
| Frontend build и отсутствие API regression | PASS | Vite build; E2E старых/новых API, повторный desktop/mobile browser QA; стиль/layout не менялся |
| Визуальный QA всех страниц | PASS | LIVE BROWSER VERIFIED: 7 страниц desktop/mobile, no scan/empty/search/loading/API/LDAP/event error/timeout/invalid Settings, без overflow/React exceptions |

## Вывод

Обязательный MVP остаётся **8/8 PASS**. Командный стенд на DigitalOcean проверен live scan, перезапуском и HTTPS E2E через Tailscale; один backend/SQLite для всех участников. Для интерактивного входа теперь есть проверка фактических прав на DC, но положительный live finding и остальные хосты не проверены. Event Log читает отдельная минимально привилегированная учётная запись; обычный backend показывает `pass` и ноль auth findings при отсутствии кандидатов. Сценарии старых логинов/паролей, SIDHistory, duplicate SPN и delegation не подделывались ради красивого live результата. Детали и текущий scan — в `docs/FINAL_AUDIT.md`.
