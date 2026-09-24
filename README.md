# Identity Risk Analyzer

Локальное приложение для аудита тестового Microsoft Active Directory `infraradar.test`. React показывает данные настоящего LDAP сканирования; FastAPI собирает объекты только на чтение, вычисляет находки и оценки, хранит историю в SQLite и выгружает CSV. Рекомендации не изменяют AD.

## Архитектура и область

```text
React/Vite → FastAPI (127.0.0.1) → LDAP (Tailscale, ir-ldap-reader)
                                  → AD users/groups/computers/PSO/SPN
                              → rules/scoring → SQLite → API/CSV
                  optional → local DC rights snapshot / Security Event Log reader
```

Сканируются пользователи `OU=InfraRadarLab,DC=infraradar,DC=test`; группы, компьютеры, PSO и владельцы SPN читаются из домена для контекста. Контроллер `INFRARADAR-DC01.infraradar.test` доступен через Tailscale `100.93.42.103:389`. Windows-хост `DANIKEK` — `100.126.179.32`. Обычный scan использует `ir-ldap-reader@infraradar.test`, который состоит только в `Domain Users`; Administrator не используется backend.

## Запуск

Нужны Python 3.11+ и Node.js 20+. Скопируйте `backend/.env.example` в игнорируемый Git `backend/.env`, задайте `LDAP_PASSWORD`, затем ограничьте права файла до `600`. Не записывайте секрет в код, HTTP-запрос или документацию.

```bash
cd backend
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
```

```bash
cd frontend
npm ci
npm run build
```

Backend отдаёт собранный frontend по `http://127.0.0.1:8000`. Для разработки используйте `npm run dev` и `http://127.0.0.1:5173`. Оба слушают loopback; открывать публичные порты не требуется. LDAP на порту 389 используется только внутри Tailscale; для иной среды предусмотрите TLS и проверку сертификата.

Для первого сканирования нажмите «Запустить анализ» с источником Active Directory либо вызовите:

```bash
curl -X POST http://127.0.0.1:8000/api/scans \
  -H 'Content-Type: application/json' -d '{"source":"ldap"}'
```

## Проверки

Существующие правила проверяют disabled/expired/locked/inactive users, бессрочные и старые пароли, PASSWORD_NOT_REQUIRED, прямые и вложенные административные группы, несколько ролей, сервисные учётные записи, отсутствие настроенного атрибута владельца и базовую доменную политику. Добавлены SIDHistory, дубли SPN среди пользователей и компьютеров, три вида Kerberos delegation, неактивные компьютеры, слабые FGPP и интерактивные права входа сервисных учётных записей. Эвристики Security Event Log выявляют возможный brute force и password spray при наличии отдельного источника событий. Finding содержит причину, evidence, рекомендацию, источник, время, confidence и статус проверки. Отсутствие доступа к источнику показывается как `not_evaluated`, а не как отсутствие риска.

`lastLogonTimestamp` приблизителен и может обновляться с задержкой. `lastLogon` относится к одному DC; отсутствие наблюдаемого входа показывается отдельно. `pwdLastSet=0` означает необходимость сменить пароль, а не старый пароль. Сервисная классификация опирается на тип объекта, имя/OU и SPN и является эвристикой. Атрибут владельца выбирается `OWNER_ATTRIBUTE` из `managedBy`, `manager`, `extensionAttribute1..15`; отсутствие значения не доказывает отсутствие реального ответственного.

Интерактивный collector читает свежий локальный JSON снимок прав DC. `scripts/Export-InteractiveRights.ps1` экспортирует применённые права через `secedit /mergedpolicy` и полный набор token SID сервисных пользователей lab OU. Для оценки нужны снимок младше 60 минут и все SID; deny имеет приоритет над allow. Результат относится только к целевому DC и правам входа: состояние RDP службы и другие ограничения требуют отдельной проверки. Экспорт выполняется вручную вне backend под диагностическим доступом; файл `backend/data/interactive-rights.json` игнорируется Git. Обычный scan использует лишь локальный снимок.

Для Security Event Log предусмотрены `scripts/Export-SecurityEvents.ps1` и `WindowsEventCollector`. Включение требует отдельного SSH alias на DC и неадминистративной учётной записи с правом читать Security log; задаются `EVENT_SSH_ALIAS` и `EVENT_SSH_USER`. Collector сверяет SSH host/user и отвергает Administrator/административный токен. Пока такой доступ не настроен, источник остаётся `not_evaluated`. Эвристики учитывают только документированные ошибки пароля и используют консервативную дедупликацию; находки формулируются как **возможные** атаки, а не доказанный инцидент.

## Лабораторные сценарии

`scripts/Seed-DemoAD.ps1` подготавливает объекты в lab OU. `scripts/Seed-LockoutLab.ps1` создал одного пользователя `ir-lockout-lab` в lab OU и `IR-Lab-Lockout-PSO`, применённую только к нему. AD требует хранить PSO в `CN=Password Settings Container,CN=System`; ACL чтения добавлен `ir-ldap-reader` только на этот PSO. В live проверке три неверных bind заблокировали lab user, collector создал `LOCKED_ACCOUNT`, затем пользователь был разблокирован. Сейчас он не заблокирован. Не запускайте тест блокировки на Administrator или reader.

Старые логины и пароли нельзя корректно создать правкой защищённых timestamps. Положительные правила для них, как и SIDHistory/duplicate SPN/delegation и атак, проверены unit-тестами; в текущем live снимке таких объектов/событий нет. Делегирование группы `IR-Lab-Admins` ограничено ACL тестовой OU и не равно Domain Admins.

## Оценка, настройки и API

Каждому правилу задана severity (Low/Medium/High/Critical) и балл. Худшая severity выбирает диапазон Risk Score, дополнительные находки повышают балл внутри него. AD Security Score = 100 минус средний Risk Score проверенных пользователей, компьютеров и политики; 100 лучше. Подробная формула: [docs/RISK_SCORING.md](docs/RISK_SCORING.md).

Пороги пользователя, компьютера, пароля, brute force, spray, временного окна и диапазонов Risk Score сохраняются через `GET/PUT /api/config` с проверкой значений. Другие endpoints: `/api/health`, `/api/connection/status`, `/api/connection/test`, `/api/scans`, `/api/dashboard`, `/api/accounts`, `/api/groups`, `/api/computers`, `/api/authentication`, `/api/checks`, `/api/findings`, `/api/export/csv`, `/api/audit`. CSV содержит UTF-8 BOM для Excel. База `backend/data/radar.db` имеет schema version 2, транзакционные scan writes и WAL.

## Проверка и ограничения

```bash
cd backend
RUN_LDAP_SMOKE=1 .venv/bin/python -m unittest discover -s tests -v
cd ../frontend && npm run build
```

Live scan 2026-09-24: 31 lab users, 57 groups, 1 computer, 1 FGPP, 42 findings, score 65/100. Подробная проверка и честные статусы в [docs/TZ_COMPLIANCE.md](docs/TZ_COMPLIANCE.md) и [docs/FINAL_AUDIT.md](docs/FINAL_AUDIT.md). Веб-приложение не имеет собственной авторизации: используйте его только локально. Security Event Log остаётся `not_evaluated` без отдельного минимального reader. Основные страницы проверены в Chrome headless на 1440/390 px; пустые и error состояния требуют отдельного прохода.
