# Identity Risk Analyzer

> **Актуальная проверка 2026-09-25:** живой lab сейчас содержит 28 пользователей, а локальный и приватный backend дают разные числа находок из-за устаревшего серверного кода. Перед демонстрацией смотрите [текущий аудит](docs/TZ_AUDIT_CURRENT.md); прежние числа ниже сохранены как история предыдущих проверок.

Приложение для аудита тестового Microsoft Active Directory `infraradar.test`. React показывает данные настоящего LDAP сканирования; FastAPI собирает объекты только на чтение, вычисляет находки и оценки, хранит историю в SQLite и выгружает CSV. Рекомендации не изменяют AD.

## Архитектура и область

```text
React/Vite → local FastAPI → HTTPS AD Gateway → Tailscale → AD/Event Log
                  ↓
              local rules/scoring → local SQLite → local API/CSV

Private fallback: Tailscale Serve → DigitalOcean FastAPI → Tailscale → AD/Event Log
```

Сканируются пользователи `OU=InfraRadarLab,DC=infraradar,DC=test`; группы, компьютеры, PSO и владельцы SPN читаются из домена для контекста. Контроллер `INFRARADAR-DC01.infraradar.test` доступен через Tailscale `100.93.42.103:389`. Windows-хост `DANIKEK` — `100.126.179.32`. Обычный scan использует `ir-ldap-reader@infraradar.test` для LDAP и `ir-event-reader@infraradar.test` для Security Event Log. Первый состоит только в `Domain Users`; второй — в `Event Log Readers` и базовой `Domain Users`. Administrator не используется backend.

## Запуск

Для обычной разработки нужны Python 3.12+ и Node.js 20+. Скопируйте `backend/.env.example` в игнорируемый Git `backend/.env` и задайте только адрес HTTPS Gateway и **личный** `AD_GATEWAY_TOKEN`. Ограничьте права файла до `600`. LDAP и Event Log credentials разработчикам не нужны; Tailscale на их компьютерах не требуется. Подробности: [docs/GATEWAY_DEV.md](docs/GATEWAY_DEV.md).

```bash
cp backend/.env.example backend/.env
# Укажите AD_GATEWAY_URL и личный AD_GATEWAY_TOKEN в backend/.env
chmod 600 backend/.env
./run
```

Для прежнего приватного режима `LDAP_DIRECT` используйте `AD_SOURCE=ldap_direct` и server-only LDAP/Event Log settings:

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

## ИИ-чат

В правом нижнем углу приложения есть кнопка «Спросить ИИ». Помощник получает данные последнего сохранённого сканирования: сводку, аккаунты, находки с подтверждениями, группы, компьютеры, парольную политику, статусы источников и краткую историю. Он также знает назначение разделов сайта. При больших объёмах подробные строки ограничиваются; итоговые числа сохраняются. Чат отвечает на общие вопросы, но выводы о вашем домене должен связывать с данными сканирования. Результаты после изменений в AD появятся только после нового анализа.

Добавьте ключ в игнорируемый Git файл `backend/.env` и перезапустите `./run`:

```dotenv
OPENAI_API_KEY=ваш_ключ
OPENAI_MODEL=gpt-4.1-mini
```

Ключ не передаётся браузеру. Данные анализа и текст вопросов отправляются из backend в OpenAI API; пароли и токены в контекст не включаются. Запросы используют `store: false`. Без ключа чат показывает сообщение о настройке, а анализ AD продолжает работать.

На странице «Риски» у каждой находки есть кнопка «План». Та же кнопка доступна в карточках аккаунтов, политики домена и сигналов аутентификации. ИИ составляет отдельный маршрут исправления по выбранной находке: что проверить до изменений, какие действия выполнить администратору, как подтвердить результат и что остаётся неизвестным. План формируется из данных конкретного сканирования и не изменяет Active Directory. Для нового анализа план генерируется заново. Требуется тот же `OPENAI_API_KEY`.

## Карта рисков

Вкладка «Карта рисков» строит интерактивный граф последнего анализа с помощью Cytoscape.js. На ней видны аккаунты, сервисы, компьютеры, группы AD, парольная политика и аутентификация. Сплошные стрелки обозначают прямое или вложенное членство в AD; пунктирные связи объединяют объекты в разделы карты и не означают прав доступа. По клику на объект открываются его находки и пути привилегий, а также кнопка ИИ-плана. Доступны поиск, фильтр критичности, показ всех объектов и переключатель отдельных узлов находок. Для больших доменов граф показывает до 150 объектов за раз, сортируя их по Risk Score; поиск поднимает подходящие объекты в показанную выборку.

## Проверки

Существующие правила проверяют disabled/expired/locked/inactive users, бессрочные и старые пароли, PASSWORD_NOT_REQUIRED, прямые и вложенные административные группы, несколько ролей, сервисные учётные записи, отсутствие настроенного атрибута владельца и базовую доменную политику. Добавлены SIDHistory, дубли SPN среди пользователей и компьютеров, три вида Kerberos delegation, неактивные компьютеры, слабые FGPP и интерактивные права входа сервисных учётных записей. Эвристики Security Event Log выявляют возможный brute force и password spray при наличии отдельного источника событий. Finding содержит причину, evidence, рекомендацию, источник, время, confidence и статус проверки. Отсутствие доступа к источнику показывается как `not_evaluated`, а не как отсутствие риска.

`lastLogonTimestamp` приблизителен и может обновляться с задержкой. `lastLogon` относится к одному DC; отсутствие наблюдаемого входа показывается отдельно. `pwdLastSet=0` означает необходимость сменить пароль, а не старый пароль. Сервисная классификация опирается на тип объекта, имя/OU и SPN и является эвристикой. Атрибут ответственного задаётся `OWNER_ATTRIBUTE` (по умолчанию `manager`); поддерживаются также `managedBy` и `extensionAttribute1..15`. Отсутствие значения не доказывает отсутствие реального ответственного.

Интерактивный collector использует свежий снимок применённых прав DC и полные token SID сервисных пользователей lab OU. `scripts/Write-InteractiveRightsSnapshot.ps1` выполняется на тестовом DC по расписанию каждые 15 минут под SYSTEM; отдельный `ir-event-reader` имеет только доступ на чтение снимка. Обычный scan сначала проверяет локальный JSON, затем читает снимок с DC по SSH. Нужен возраст не больше 60 минут; deny имеет приоритет над allow. Результат относится только к правам входа на DC: состояние RDP и другие ограничения требуют отдельной проверки.

Security Event Log собирают `scripts/Export-SecurityEvents.ps1` и `WindowsEventCollector` под отдельной учётной записью `ir-event-reader@infraradar.test` в lab OU. `scripts/Provision-EventReader.ps1` проверяет read-only ACE Security log и настраивает только Event Log Readers и SSH public key. На Mac настроен alias `infraradar-event-reader`, в закрытом `backend/.env` заданы `EVENT_SSH_ALIAS` и `EVENT_SSH_USER`. Collector сверяет SSH host/user, наличие Event Log Readers SID и отсутствие административного токена; обычный scan показывает `pass` при доступном источнике. Эвристики учитывают только документированные ошибки пароля и используют консервативную дедупликацию; находки формулируются как **возможные** атаки, а не доказанный инцидент.

## Лабораторные сценарии

Текущий lab OU содержит 42 аккаунта: 26 обычных вымышленных сотрудников, 7 отдельных `adm.*`, 7 сервисных `svc_*` и 2 технических reader. `scripts/Restore-CorporateLab.ps1` восстановил 14 обычных сотрудников и заполнил `manager` только внутри lab OU; существующие SID, пароли, членства и риск-флаги сохранены. По умолчанию скрипт выполняет только dry-run. Настоящие успешные входы ранее выполнялись для 12 сотрудников; вновь созданные аккаунты ещё могут показывать «Вход не наблюдался». Старые даты входа и пароля не подделывались. Существующая `IR-Lab-Lockout-PSO` теперь назначена `m.kalayeva`, и resultant PSO подтверждена. Исторические seed/lockout скрипты требуют отдельной проверки текущего состава перед повторным применением.

Старые логины и пароли нельзя корректно создать правкой защищённых timestamps. Положительные правила для них, как и SIDHistory/duplicate SPN/delegation и атак, проверены unit-тестами; в текущем live снимке таких объектов/событий нет. Делегирование группы `IR-Lab-Admins` ограничено ACL тестовой OU и не равно Domain Admins.

## Оценка, настройки и API

Каждому правилу задана severity (Low/Medium/High/Critical) и балл. Худшая severity выбирает диапазон Risk Score, дополнительные находки повышают балл внутри него. AD Security Score = 100 минус средний Risk Score проверенных пользователей, компьютеров и политики; 100 лучше. Подробная формула: [docs/RISK_SCORING.md](docs/RISK_SCORING.md).

Пороги пользователя, компьютера, пароля, brute force, spray, временного окна и диапазонов Risk Score сохраняются через `GET/PUT /api/config` с проверкой значений. Другие endpoints: `/api/health`, `/api/connection/status`, `/api/connection/test`, `/api/scans`, `/api/dashboard`, `/api/accounts`, `/api/groups`, `/api/computers`, `/api/authentication`, `/api/checks`, `/api/findings`, `/api/export/csv`, `/api/audit`. CSV содержит UTF-8 BOM и `;` как разделитель для корректного открытия русских полей в Excel. База `backend/data/radar.db` имеет schema version 2, транзакционные scan writes и WAL.

## Проверка и ограничения

```bash
cd backend
RUN_LDAP_SMOKE=1 .venv/bin/python -m unittest discover -s tests -v
cd ../frontend && npm run build
```

Live scan 2026-09-25: **42 lab users, 57 groups, 1 computer, 1 FGPP, 39 findings, Security Score 75/100**. LDAP, Security Event Log и интерактивные права DC имеют `pass`; 7/7 сервисных аккаунтов не имеют разрешённых прав входа на DC, 42/42 аккаунта имеют `manager`. Приватный backend и локальный Risk Engine через HTTPS Gateway дают одинаковые 42/39/75. Текущие доказательства и ограничения — в [docs/TZ_AUDIT_CURRENT.md](docs/TZ_AUDIT_CURRENT.md). Приватный frontend доступен только через Tailscale; общий публичный frontend ещё не развёрнут.

## Общий командный стенд

Существующий приватный DigitalOcean стенд остаётся резервным: backend на `127.0.0.1:8011`, Tailscale Serve и одна SQLite WAL. См. [docs/TEAM_ACCESS.md](docs/TEAM_ACCESS.md). Отдельный публичный HTTPS AD Gateway отдаёт только нормализованный read-only snapshot локальным backend разработчиков; сам Risk Engine и история сканов работают у каждого локально. См. [docs/GATEWAY_DEV.md](docs/GATEWAY_DEV.md). `deploy/deploy-gateway.sh` обновляет только отдельный gateway checkout/service и не перезапускает приватный стенд. Для будущего общего frontend на Vercel подготовлен вход команды; текущий статус безопасности и условия публичного запуска — в [docs/VERCEL_SECURITY.md](docs/VERCEL_SECURITY.md).
