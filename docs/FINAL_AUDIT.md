# Identity Risk Analyzer — Final Audit

Дата: 2026-09-24. Исходное ТЗ: `Техническое задание Hackathon Infrastructure_Risk_Radar.docx`, раздел 2 и связанные требования разделов 4–6. Подробные статусы: `docs/TZ_COMPLIANCE.md`.

## Compliance with Hackathon TZ

Обязательный MVP (ТЗ 2.8): **8 / 8 PASS**. Дополнительные возможности ТЗ 2.3.5/2.9/6: **2 / 9 реализованы** (история оценки и пояснения рисков); расширяемость частичная, шесть дополнительных проверок/уведомлений не реализованы. Основные функциональные требования: 33 PASS, 12 PARTIAL, 1 MISSING, 3 условных/дополнительных. Единственный MISSING — подтверждение разрешённого интерактивного входа сервисного аккаунта на целевых машинах; UI/API честно показывают `not_evaluated`.

## Live environment

- Domain: `infraradar.test`; DC: `INFRARADAR-DC01.infraradar.test` (`100.93.42.103` через Tailscale).
- Windows host `DANIKEK` (`100.126.179.32`), VM `InfraRadar-DC01` запущена. На DC службы NTDS и DNS — Running; DNS домена разрешается в адреса DC.
- LDAP: `100.93.42.103:389` через Tailscale, `ir-ldap-reader@infraradar.test`; PowerShell подтверждает членство reader только в `Domain Users`.
- Scope: 30 пользователей в `OU=InfraRadarLab`, 57 групп для разрешения путей членства (9 групп в тестовой OU). Backend не использует Administrator.

## Live scan

Финальный scan после рестарта `e9ee7f91-65d2-419e-bd85-12dd4fa0f056`: AD Security Score **62/100**, Critical **1**, High **26**, Medium **9**, Low **6**, всего **42** находки, длительность **154 мс**. Проверено 30 пользователей, 57 групп. Это результат настоящего LDAP scan, сохранённый в SQLite и доступный через Dashboard/API/CSV. Повторный scan без изменений AD дал 0 новых и 0 исчезнувших находок.

Проверка Critical: `ir-domainadmin` имеет подтверждённое прямое членство в `Domain Admins` (PowerShell `Get-ADUser -Properties MemberOf`) и отдельное членство в `IR-Lab-Admins`. API показал Critical. Для `ir-svc-backup` API показал вложенный путь к `IR-Lab-Admins`, severity High и область **только test OU**. `Get-Acl AD:\OU=InfraRadarLab,...` подтвердил GenericAll именно на lab OU.

Доменная политика LDAP сверена с `Get-ADDefaultDomainPasswordPolicy`: длина 0, сложность включена, история 0, max age 42 дня, min age 0, lockout threshold 0, duration 30 минут, observation window 30 минут. При нулевом пороге длительность блокировки фактически не применяется.

## Implemented risk checks

`DISABLED_ACCOUNT`, `INACTIVE_ACCOUNT`, `EXPIRED_ACCOUNT`, `LOCKED_ACCOUNT`, `PASSWORD_NEVER_EXPIRES`, `SERVICE_PASSWORD_NEVER_EXPIRES`, `OLD_PASSWORD`, `PASSWORD_NOT_REQUIRED`, `DIRECT_PRIVILEGE`, `NESTED_PRIVILEGE`, `DISABLED_PRIVILEGED`, `INACTIVE_PRIVILEGED`, `MULTIPLE_PRIVILEGES`, `SERVICE_PRIVILEGED`, `INACTIVE_SERVICE`, `MISSING_OWNER`, `SHORT_MIN_PASSWORD`, `NO_PASSWORD_COMPLEXITY`, `NO_LOCKOUT`.

Старый вход и старый пароль проверены unit-тестами, но не заявляются как live-находки: защищённые AD timestamps не подделывались. Определение service account основано на SPN, имени или OU и остаётся эвристикой. Security Event Log не собирается, поэтому Password Spray и Brute Force не заявляются.

## Security

Collector выполняет только LDAP bind/search по белому списку атрибутов. У backend нет API изменения AD; seed script отделён и ограничен тестовой OU. Пользовательские пароли не читаются, не входят в SQLite, API или CSV. LDAP bind secret хранится локально в игнорируемом `backend/.env` с правами `600`, не записывается в application audit. Аудит в SQLite фиксирует тест соединения, начало/завершение/ошибку scan, экспорт и изменение порогов анализа. Приложение слушает только `127.0.0.1`, LDAP ходит по Tailscale; публичные порты не открывались.

## Tests

- Backend: **19/19 PASS** с `RUN_LDAP_SMOKE=1` (AD parsing, classification, group paths, scoring, API, storage, CSV, live LDAP).
- Frontend: **PASS**, `npm run build`.
- Live LDAP: **PASS**, reader прочитал 30 users / 57 groups и полную доменную политику.
- E2E: **PASS**, LDAP → analysis → SQLite → API/Dashboard → account detail → CSV (42 UTF-8 BOM строк, русские символы, category/evidence/recommendation).
- Restart: **PASS**, после перезапуска сохранились scan, Dashboard и audit; новый post-restart LDAP scan, account detail и CSV прошли; UI отдаётся на `127.0.0.1:8000`.
- Visual: инструмент браузера недоступен; build и HTTP отдача проверены, ручной список в `docs/VISUAL_CHECKLIST.md`.

## Remaining limitations

Фактическое разрешение интерактивного входа сервисных аккаунтов требует результирующих GPO и allow/deny прав на каждом целевом Windows-хосте. Fine-Grained Password Policies, события аутентификации для spray/bruteforce, inactive computers, SIDHistory, SPN/delegation и уведомления не входят в текущую проверенную реализацию. Нет авторизации веб-приложения: использовать только локально в лаборатории. Визуальная проверка в браузере остаётся ручной.

## Demo readiness

**READY для локальной защиты по 3–4-минутному сценарию** `docs/DEMO_SCRIPT.md` с честным показом ограничений. Перед выступлением выполните `docs/VISUAL_CHECKLIST.md` на целевом экране.
