# Актуальная сверка с ТЗ: проект 1 Identity Risk Analyzer

Проверено 2026-09-24 после запуска `InfraRadar-DC01`. Источник — оригинальное `Техническое задание Hackathon Infrastructure_Risk_Radar.docx`, разделы 2, 4 и 5.1. Проект 2 Certificate Radar в эту проверку не входит. Проверки ниже выполнялись на настоящем тестовом домене `infraradar.test`; AD-объекты и настройки домена не менялись.

## Итог

**Обязательный MVP раздела 2.8: 8/8 PASS.** Свежий scan на общем backend: `674707fb-1830-4da3-aa4e-1971e31aa0e2`, 42 пользователя, 57 групп, 1 компьютер, 45 находок, AD Security Score 71/100. Отдельный локальный backend через публичный HTTPS AD Gateway получил те же 42/45/71. Все доступные источники последнего scan — `pass`: LDAP, FGPP, компьютеры, SPN, интерактивные права DC и Security Event Log. Снимок интерактивных прав действует 60 минут; после этого источник честно станет `not_evaluated` до следующего read-only экспорта.

## Обязательный MVP (2.8)

| Требование | Статус | Свежая проверка |
|---|---|---|
| Подключение к тестовому AD | PASS | DC `INFRARADAR-DC01`, DNS/AD DS работают; read-only LDAP smoke прошёл |
| Сбор учётных записей | PASS | 42 пользователя lab OU, 57 групп; `Get-ADDomain`, `Get-ADForest`, `Get-ADDomainController`, `Get-ADUser`, `Get-ADGroup` сверены |
| Несколько проверок риска | PASS | 45 findings: 1 Critical, 28 High, 10 Medium, 6 Low |
| Оценка риска | PASS | AD Security Score 71; unit-тесты границ и формулы прошли |
| Web Dashboard | PASS по API/build; browser QA NOT VERIFIED | HTML, JS/CSS и 15 API-запросов отвечают 200; визуальный браузер в этой сессии недоступен |
| Проблемы с причинами | PASS | У всех 45 findings есть причина, evidence и рекомендация |
| Рекомендации | PASS | Автоматических AD write endpoints нет |
| CSV/Excel/HTML | PASS для CSV | UTF-8 BOM, 14 колонок, 45 строк; прямое открытие в Excel в этой сессии не повторялось |

## Функциональные сценарии и пределы (2.3–2.7)

- **Пользователи:** 7 `SERVICE_PASSWORD_NEVER_EXPIRES`, 3 `EXPIRED_ACCOUNT`; disabled/locked/PNE и пороги проверяются кодом и тестами. Положительные старый пароль и длительная неактивность остаются `UNIT VERIFIED`, потому что защищённые AD timestamps не подделывались.
- **Привилегии:** 7 `DIRECT_PRIVILEGE`, 6 `NESTED_PRIVILEGE`, 3 `DISABLED_PRIVILEGED`, 2 `MULTIPLE_PRIVILEGES` в live scan. Пути и циклы групп покрыты тестами.
- **Политика:** домен `infraradar.test`, 1 FGPP. Read-only PowerShell подтвердил текущие доменные значения: `MinPasswordLength=0`, `ComplexityEnabled=true`, `LockoutThreshold=0`; анализ отмечает риски политики. Положительный слабый FGPP — только unit.
- **Security Event Log:** отдельный `ir-event-reader` прочитал за 24 часа 4624: 2389, 4625: 107, 4771: 1, 4776: 100. Scan собрал 1293 нормализованных события, статус `pass`, 0 кандидатов на brute force/password spray. Положительные атаки — только unit; реальные атаки для проверки не создавались.
- **Интерактивные права сервисов:** обновлён read-only снимок применённой политики DC для 7 `svc_*`; источник `pass`, разрешённого local/RDP logon среди них не обнаружено. Данные относятся к DC и становятся неактуальными через 60 минут; состояние RDP-службы и другие хосты не проверялись.
- **Дополнительный AD-анализ:** компьютер, SPN, delegation и SIDHistory атрибуты читаются. Положительные опасные SIDHistory, duplicate SPN и delegation сценарии остаются `UNIT VERIFIED`; домен ради них не изменяли.
- **Dashboard/history/export:** общий backend сохранил новый scan в SQLite WAL; API истории, сравнения, аккаунтов, групп, компьютеров, аутентификации, аудита и CSV ответили 200. Локальный backend через Gateway независимо выполнил scan и сохранил собственную историю/CSV.

Пример раздела 5.1 с **10 неактивными пользователями** в live AD не воспроизведён. ТЗ приводит эти количества как пример демонстрации, а не обязательный критерий MVP. Сценарии 7 service PNE, 3 disabled privileged и 2 multiple-role подтверждены свежим scan.

## Безопасность и выполненные проверки (раздел 4)

- `RUN_LDAP_SMOKE=1 .venv/bin/python -m unittest discover -s tests -q`: **30/30 PASS**. `npm run build`: **PASS**.
- Tailscale, SSH хоста и DC, Hyper-V VM `Running`, AD DS, DNS и LDAP: **PASS**. Reader `ir-ldap-reader` состоит только в `Domain Users`; Event Log reader — в `Domain Users` и `Event Log Readers`. Ни один не состоит в `Domain Admins`.
- Реальные секреты из локального окружения и личные Gateway tokens сверены с ответами Dashboard/Accounts/Findings/CSV: совпадений нет. Секреты не выводились.
- Приватный backend доступен через Tailscale Serve; публичный Gateway требует личный токен и возвращает read-only snapshot. Общий Dashboard API для Vercel пока **не опубликован**.
- Визуальный desktop/mobile browser QA **NOT VERIFIED в этой сессии**: browser runtime не предоставил браузер. Предыдущие browser-проверки описаны в `TZ_COMPLIANCE.md`, но не выдаются здесь за свежие.
