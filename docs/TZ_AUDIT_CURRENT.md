# Актуальная сверка проекта 1 с ТЗ и схемой AD

Проверено 2026-09-25 по оригинальному «Техническому заданию Hackathon Infrastructure_Risk_Radar.docx» (разделы 2, 4, 5.1) и присланной схеме Active Directory. Проект 2 Certificate Radar сюда не входит. Результаты относятся к живому `infraradar.test` после восстановления тестовых данных и обновления сервисов DigitalOcean до `087ebdd`.

## Итог исправлений

| Проверка | До | Сейчас |
|---|---:|---:|
| Пользователи в `OU=InfraRadarLab` | 28, из них 12 обычных сотрудников | **42: 26 обычных, 7 `adm.*`, 7 `svc_*`, 2 reader** |
| `manager` заполнен | 19/28 | **42/42** |
| Получатели `IR-Lab-Lockout-PSO` | 0 | **1**, `m.kalayeva`; resultant PSO подтверждена PowerShell и LDAP |
| Права интерактивного входа в обычном scan | `not_evaluated` | **`pass`**, 7/7 сервисов на тестовом DC |
| Приватный backend | старый checkout, 46 находок, 7 ложных `MISSING_OWNER` | **39 находок, 0 `MISSING_OWNER`** |

Добавлены 14 вымышленных сотрудников только в lab OU, заполнены отсутствовавшие `manager` только у lab аккаунтов, существующая PSO назначена одному новому lab пользователю. Старые SID, пароли, членства, SPN, риск-флаги и защищённые AD timestamps не менялись. Пароли новых аккаунтов случайны и не выводились. Перед изменениями были dry-run и снимок состояния без секретов; `scripts/Restore-CorporateLab.ps1` по умолчанию остаётся dry-run.

## Живой scan и источники

| Источник / результат | Свежая проверка |
|---|---|
| DC, AD DS, DNS | `INFRARADAR-DC01.infraradar.test`, `100.93.42.103`; в этой сессии проверены NTDS, DNS, KDC, Netlogon, DNS A/SRV и LDAP bind |
| LDAP | 42 lab users, 57 групп, 1 DC computer, 1 FGPP; отдельный `ir-ldap-reader` |
| Security Event Log | `pass`; отдельный `ir-event-reader`, события 4624/4625/4771/4776 |
| Интерактивные права | SYSTEM-задача `InfraRadar-InteractiveRights-ReadOnlyExport` обновляет JSON каждые 15 минут; `ir-event-reader` только читает снимок; обычный scan: `pass`, 7/7 сервисов `pass` |
| Локальный Risk Engine через публичный HTTPS Gateway | 42 users, 57 groups, **39 findings, Security Score 75**, 0 `MISSING_OWNER`, 1 resultant PSO; доступные source statuses `pass` |
| Приватный backend | scan `3c7d6873-c401-4907-a76c-26ce1f6d3062`: **42 / 39 / 75**, `interactive_rights=pass`, `security_event_log=pass`, 42/42 владельцев |
| Gateway | Авторизованный HTTPS snapshot после обновления совпал с приватным scan; Risk Engine и история остаются в локальном backend |

Снимок интерактивных прав относится **только к DC**. Он оценивает права по применённой политике и полным token SID; фактическая доступность RDP и другие ограничения входа отдельно не доказаны. При остановке задачи или устаревании снимка более 60 минут результат честно станет `not_evaluated`.

## Матрица ТЗ

| Требование | Статус и предел |
|---|---|
| 2.8 Подключение, сбор пользователей, несколько правил, Risk Score, Dashboard, объяснения, рекомендации, CSV | **8/8 PASS по backend/API и build**. Свежий визуальный desktop/mobile browser QA после исправления не выполнялся |
| Неактивные, старые пароли, Password Never Expires, disabled/expired/locked | Флаги и правила работают; положительные live случаи есть для части сценариев. Старые AD timestamps не подделывались; положительные неактивность/старый пароль остаются UNIT |
| Сервисные аккаунты и права | LIVE: 7 сервисов, бессрочные пароли, вложенные привилегии, владелец и права входа DC. Положительный разрешённый interactive logon — UNIT |
| Прямые/вложенные админ-группы, несколько ролей | LIVE: реальные пути членства и находки; делегирование `IR-Lab-Admins` ограничено lab OU |
| Доменная парольная политика и FGPP | LIVE: 8 полей политики, 1 PSO с реальным resultant PSO; положительная слабая FGPP — UNIT |
| Компьютеры, SIDHistory, SPN, Kerberos delegation | Сбор и правила есть; опасные положительные SIDHistory, duplicate SPN, delegation намеренно не создавались, они UNIT |
| Brute force / password spray | LIVE: Event Log доступен и scan сообщает отсутствие сигналов; положительные эвристики UNIT, атаки не создавались |
| История, SQLite, CSV | LIVE: scan записан, история и CSV прошли deployment check; CSV с UTF-8 BOM и 14 колонками |
| Уведомления | OPTIONAL, не входят в обязательный MVP |

Положительные случаи с пометкой UNIT здесь не объявляются LIVE VERIFIED.

## Сверка с присланной схемой Active Directory

| Элемент схемы | Фактический стенд и отношение к анализатору |
|---|---|
| Лес, домен, DC и каталог | Один лес/домен `infraradar.test`, один работающий DC. Analyzer читает объекты по LDAP и события; к `ntds.dit` напрямую не обращается |
| Репликация DC1↔DC2 | На схеме пример двух DC; в тестовом стенде второго DC нет |
| DNS и поиск контроллера | A/SRV записи работают. Backend использует заданный LDAP host; автоматическое DNS SRV discovery не требуется MVP |
| Пользователи, группы, компьютеры, OU и GPO | Пользователи и группы читаются, 1 DC computer, lab OU и доменная парольная политика; произвольные GPO целиком не анализируются |
| Kerberos TGT/TGS и доступ к файловому серверу | KDC и события входа доступны. Analyzer наблюдает риски, но не выдаёт билеты и не оценивает ACL отдельного файлового сервера |

## Проверки и ограничения

- `RUN_LDAP_SMOKE=1 .venv/bin/python -m unittest discover -s tests -q`: **38/38 PASS**.
- Frontend production build: **PASS** на Mac и при обновлении приватного backend.
- Приватный deployment check: health, LDAP connection, live scan, Dashboard/Accounts/Findings/Computers/Authentication/FGPP, CSV, SQLite и frontend — **PASS**.
- Без токена Gateway запрещает snapshot; AD write endpoints отсутствуют. Приватный backend и DC остаются за Tailscale. Публичные порты других приложений на DigitalOcean и визуальный browser QA в рамках этого исправления повторно не проверялись; прежние ограничения публичного развёртывания сохраняются.
- Backend сохраняет demo-режим для тестирования. При показе реальных результатов проверяйте источник последнего scan: Active Directory.
