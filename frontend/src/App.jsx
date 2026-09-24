import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { api } from './api.js'

const severityLabels = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', safe: 'Без риска' }
const sourceLabels = { demo: 'Демо', ldap: 'Active Directory' }

function Badge({ level }) {
  return <span className={`badge badge-${level}`}>{severityLabels[level] ?? level}</span>
}

// Google Material Icons, bundled locally under the Apache 2.0 license.
function Icon({ name, size = 20 }) {
  return <span className="icon" style={{ width: size, height: size, '--icon': `url(/icons/${name === 'radar' ? 'shield' : name}.svg)` }} aria-hidden="true" />
}

function ShieldScene() {
  return <div className="shield-scene" aria-hidden="true">
    <div className="scene-grid"/><div className="orbit orbit-one"/><div className="orbit orbit-two"/>
    <div className="shield-object">{Array.from({ length: 9 }, (_, i) => <div className="shield-layer" key={i} style={{ transform: `translateZ(${i * 2}px)` }}/>) }<div className="shield-face"><Icon name="shield" size={64}/></div></div>
    <div className="scene-cube cube-one"><i/><i/><i/></div><div className="scene-cube cube-two"><i/><i/><i/></div>
  </div>
}

function Empty({ title, body }) {
  return <div className="empty"><div className="empty-icon"><Icon name="shield" size={25}/></div><h3>{title}</h3><p>{body}</p></div>
}

function Metric({ label, value, tone, helper }) {
  return <div className={`metric metric-${label.toLowerCase()}`}><div className="metric-icon"><Icon name="shield" size={22}/></div><div className="metric-label">{label}</div><div className={`metric-value ${tone ?? ''}`}>{value}</div>{helper && <div className="metric-helper">{helper}</div>}</div>
}

function Dashboard({ dashboard, accounts, scans, comparison, onOpenAccount }) {
  const top = dashboard.top_risky_users ?? []
  const maxCategory = Math.max(...(dashboard.categories ?? []).map(item => item.count), 1)
  const history = scans.filter(item => item.source === dashboard.source).slice(0, 8).reverse()
  return <>
    <div className="dashboard-intro"><div><h1>Обзор безопасности</h1><p>Риски Active Directory и аккаунты, требующие внимания.</p></div></div>
    <div className="overview-grid">
      <section className="score-card"><div className="score-ring" title="100 означает минимальный выявленный риск. Оценка основана на среднем риске аккаунтов, компьютеров и политики домена." style={{ '--score': `${dashboard.security_score}%` }}><div><strong>{dashboard.security_score}</strong><span>/ 100</span></div></div><div className="score-copy"><span className="metric-label">Security Score</span><h2>Состояние домена</h2><p>Чем выше оценка,<br/>тем меньше рисков</p><span className="score-caption">AD SECURITY</span></div></section>
      <Metric label="Critical" value={dashboard.findings.critical} tone="danger" helper="Немедленная проверка" />
      <Metric label="High" value={dashboard.findings.high} tone="warning" helper="Высокий приоритет" />
      <Metric label="Medium" value={dashboard.findings.medium} tone="neutral" helper="Плановые проверки" />
      <Metric label="Low" value={dashboard.findings.low} tone="neutral" helper="Замечания" />
    </div>
    <div className="quick-stats"><span title="Пользователи в выбранной тестовой OU"><strong>{dashboard.total_users}</strong> аккаунтов проверено</span><span><strong>{dashboard.healthy_accounts ?? '—'}</strong> без находок</span><span title="Неактивность определяется порогом и приближённым lastLogonTimestamp"><strong>{dashboard.inactive_accounts ?? '—'}</strong> неактивных</span><span><strong>{dashboard.service_accounts}</strong> сервисных</span><span><strong>{dashboard.privileged_accounts}</strong> привилегированных</span><span><strong>{dashboard.disabled_accounts ?? '—'}</strong> отключённых</span><span><strong>{dashboard.locked_accounts ?? '—'}</strong> заблокированных</span><span><strong>{dashboard.expired_accounts ?? '—'}</strong> истёкших</span><span title="Компьютеры, прочитанные из домена"><strong>{dashboard.total_computers ?? '—'}</strong> компьютеров</span><span title={dashboard.source_status?.security_event_log === "pass" ? "Сигналы по журналу Security" : "Security Event Log не оценён"}><strong>{dashboard.source_status?.security_event_log === "pass" ? dashboard.auth_findings : "—"}</strong> сигналов входа</span><span><strong>{dashboard.finding_count}</strong> находок</span></div>
    <div className="dashboard-panels">
      <section className="panel distribution-panel"><div className="panel-head"><div><h2>Распределение рисков</h2><p>Находки по уровню критичности</p></div><span className="count-pill">{dashboard.finding_count} находок</span></div><div className="distribution-chart">{['critical', 'high', 'medium', 'low'].map(level => <div className={`distribution-column distribution-${level}`} key={level}><div className="distribution-track"><div className="distribution-bar" style={{height: `${(dashboard.findings[level] / Math.max(...['critical', 'high', 'medium', 'low'].map(key => dashboard.findings[key]), 1)) * 85}%`}}><strong>{dashboard.findings[level]}</strong></div></div><span>{severityLabels[level]}</span></div>)}</div><div className="chart-caption"> Данные последнего завершённого сканирования</div></section>
      <section className="panel"><div className="panel-head"><div><h2>Наиболее рискованные аккаунты</h2><p>Откройте карточку, чтобы увидеть причины и рекомендации.</p></div></div>
        {top.length ? <div className="top-list">{top.map(item => <button className="top-row" key={item.id} onClick={() => onOpenAccount(item.id)}><span className={`top-rank avatar-${item.risk_level}`}><Icon name="users" size={19}/></span><span className="top-person"><strong>{item.username}</strong><small>{item.display_name}</small></span><Badge level={item.risk_level}/><strong className="top-score">{item.risk_score}</strong><Icon name="arrow" size={17}/></button>)}</div> : <Empty title="Рисков нет" body="После сканирования здесь появятся аккаунты с наибольшим риском."/>}
      </section>
      <section className="panel category-panel"><div className="panel-head"><div><h2>Категории рисков</h2><p>Наиболее частые срабатывания правил.</p></div></div>
        {dashboard.categories?.length ? <div className="category-list">{dashboard.categories.slice(0, 6).map(item => <div className="category" key={item.rule_id}><div><span>{friendlyRule(item.rule_id)}</span><strong>{item.count}</strong></div><div className="category-track"><div style={{width: `${Math.max(7, item.count / maxCategory * 100)}%`}}/></div></div>)}</div> : <Empty title="Категорий нет" body="В этом сканировании проблемы не обнаружены."/>}
      </section>
    </div>
    <div className="two-col secondary-panels"><section className="panel"><div className="panel-head"><div><h2>Политика паролей домена</h2><p>Результат базовых проверок настроек.</p></div><button className="text-link" onClick={() => onOpenAccount('__domain__')}>Подробнее →</button></div><div className="policy-summary"><span>Минимальная длина: <strong>{dashboard.domain_policy?.min_password_length ?? '—'}</strong></span><span>Сложность: <strong>{dashboard.domain_policy?.password_complexity == null ? '—' : dashboard.domain_policy.password_complexity ? 'включена' : 'отключена'}</strong></span><span>Блокировка: <strong>{dashboard.domain_policy?.lockout_threshold ?? '—'}</strong></span></div><p className="policy-count">{dashboard.domain_policy_findings?.length ?? 0} проблем · Risk Score {dashboard.domain_policy_risk_score ?? 0}/100</p></section>
      <section className="panel"><div className="panel-head"><div><h2>Динамика Security Score</h2><p>Последние сканирования источника «{sourceLabels[dashboard.source]}».</p></div></div>{comparison?.previous_scan_id && <div className="scan-comparison"><span>Score: {comparison.previous.security_score} → {comparison.current.security_score}</span><span>Critical: {comparison.previous.findings.critical} → {comparison.current.findings.critical}</span><span>High: {comparison.previous.findings.high} → {comparison.current.findings.high}</span><span>Новые: {comparison.added_findings} · Устранённые: {comparison.resolved_findings}</span></div>}{history.length > 1 ? <div className="history-bars">{history.map(item => <div className="history-item" key={item.scan_id} title={`${formatDate(item.scanned_at)} — ${item.summary.security_score}/100`}><strong>{item.summary.security_score}</strong><div className="history-track"><div style={{height: `${item.summary.security_score}%`}}/></div><small>{new Date(item.scanned_at).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' })}</small></div>)}</div> : <p className="muted">Динамика появится после второго сканирования.</p>}</section></div>
    {accounts.length > 0 && <p className="footnote">Показатели относятся к последнему завершённому сканированию. Изменения в AD появятся после повторного запуска.</p>}
  </>
}

const friendlyNames = {
  DISABLED_ACCOUNT: 'Отключённые аккаунты', INACTIVE_ACCOUNT: 'Неактивные аккаунты', PASSWORD_NEVER_EXPIRES: 'Бессрочные пароли', SERVICE_PASSWORD_NEVER_EXPIRES: 'Бессрочные сервисные пароли',
  OLD_PASSWORD: 'Старые пароли', PASSWORD_NOT_REQUIRED: 'Ослабленные требования',
  LOCKED_ACCOUNT: 'Блокировки', EXPIRED_ACCOUNT: 'Истёкшие аккаунты',
  DIRECT_PRIVILEGE: 'Прямые привилегии', NESTED_PRIVILEGE: 'Вложенные привилегии',
  INACTIVE_PRIVILEGED: 'Неактивные администраторы', DISABLED_PRIVILEGED: 'Отключённые администраторы', MULTIPLE_PRIVILEGES: 'Несколько ролей',
  SERVICE_PRIVILEGED: 'Привилегии сервисных аккаунтов', INACTIVE_SERVICE: 'Неиспользуемые сервисные аккаунты',
  MISSING_OWNER: 'Нет владельца', SID_HISTORY_PRESENT: 'SIDHistory', DUPLICATE_SPN: 'Дубли SPN', DELEGATION_UNCONSTRAINED: 'Неограниченная делегация', DELEGATION_CONSTRAINED: 'Ограниченная делегация', DELEGATION_RBCD: 'Делегация RBCD', INACTIVE_COMPUTER: 'Неактивный компьютер', WEAK_FINE_GRAINED_POLICY: 'Слабая политика FGPP', SERVICE_INTERACTIVE_LOGON: 'Интерактивный вход сервиса', POSSIBLE_BRUTE_FORCE: 'Подбор пароля', POSSIBLE_PASSWORD_SPRAY: 'Password spray', AUTH_TARGETED: 'Атаки на аккаунт', SHORT_MIN_PASSWORD: 'Короткий пароль',
  NO_PASSWORD_COMPLEXITY: 'Сложность пароля отключена', NO_LOCKOUT: 'Нет блокировки',
}
function friendlyRule(rule) { return friendlyNames[rule] ?? rule }

const categoryLabels = { identity: 'Учётные записи', password: 'Пароли', privilege: 'Привилегии', service: 'Сервисы', domain_policy: 'Политика домена', computer: 'Компьютеры', authentication: 'Аутентификация' }
function Evidence({ evidence }) {
  const entries = Object.entries(evidence ?? {})
  if (!entries.length) return null
  return <div className="evidence"><span>Подтверждение</span><dl>{entries.map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{value == null ? 'Нет данных' : typeof value === 'object' ? JSON.stringify(value) : String(value)}</dd></div>)}</dl></div>
}

function Findings({ findings, accounts, onOpenAccount }) {
  const [severity, setSeverity] = useState('all')
  const [category, setCategory] = useState('all')
  const [accountType, setAccountType] = useState('all')
  const [privileged, setPrivileged] = useState('all')
  const [status, setStatus] = useState('all')
  const [search, setSearch] = useState('')
  const [sort, setSort] = useState('risk')
  const byId = useMemo(() => new Map(accounts.map(item => [item.id, item])), [accounts])
  const filtered = useMemo(() => findings.filter(item => {
    const account = byId.get(item.account_id)
    return (severity === 'all' || item.severity === severity) &&
      (category === 'all' || item.category === category) &&
      (accountType === 'all' || item.account_type === accountType) &&
      (privileged === 'all' || (account && account.privileged === (privileged === 'yes'))) &&
      (status === 'all' || (account && account.enabled === (status === 'enabled'))) &&
      `${item.username} ${item.title} ${item.reason}`.toLowerCase().includes(search.toLowerCase())
  }).sort((a, b) => {
    const aa = byId.get(a.account_id), bb = byId.get(b.account_id)
    const score = key => byId.get(key.account_id)?.risk_score ?? 0
    const severityRank = { critical: 4, high: 3, medium: 2, low: 1 }
    if (sort === 'severity') return severityRank[b.severity] - severityRank[a.severity] || score(b) - score(a)
    if (sort === 'username') return a.username.localeCompare(b.username, 'ru')
    if (sort === 'activity') return (aa?.last_logon || '').localeCompare(bb?.last_logon || '')
    if (sort === 'password') return (aa?.password_last_set || '').localeCompare(bb?.password_last_set || '')
    return score(b) - score(a) || severityRank[b.severity] - severityRank[a.severity]
  }), [findings, byId, severity, category, accountType, privileged, status, search, sort])
  return <><div className="section-head"><div><div className="eyebrow">Анализ</div><h1>Найденные риски</h1><p>Каждая строка содержит причину, подтверждение и рекомендуемое действие.</p></div><span className="count-pill">{filtered.length} из {findings.length}</span></div>
    <section className="panel table-panel"><div className="toolbar"><label className="search-field"><Icon name="search" size={18}/><input value={search} onChange={e => setSearch(e.target.value)} placeholder="Поиск по аккаунту или риску"/></label><label className="select-wrap"><span>Уровень</span><select value={severity} onChange={e => setSeverity(e.target.value)}><option value="all">Все</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label><label className="select-wrap"><span>Категория</span><select value={category} onChange={e => setCategory(e.target.value)}><option value="all">Все</option>{Object.entries(categoryLabels).map(([key, label]) => <option value={key} key={key}>{label}</option>)}</select></label><label className="select-wrap"><span>Тип</span><select value={accountType} onChange={e => setAccountType(e.target.value)}><option value="all">Все</option><option value="user">Пользователь</option><option value="service">Сервис</option><option value="computer">Компьютер</option><option value="domain">Домен</option><option value="policy">FGPP</option><option value="authentication">Аутентификация</option></select></label><label className="select-wrap"><span>Права</span><select value={privileged} onChange={e => setPrivileged(e.target.value)}><option value="all">Все</option><option value="yes">Есть</option><option value="no">Нет</option></select></label><label className="select-wrap"><span>Статус</span><select value={status} onChange={e => setStatus(e.target.value)}><option value="all">Все</option><option value="enabled">Включён</option><option value="disabled">Отключён</option></select></label><label className="select-wrap"><span>Сортировка</span><select value={sort} onChange={e => setSort(e.target.value)}><option value="risk">Risk Score</option><option value="severity">Severity</option><option value="username">Username</option><option value="activity">Последний вход</option><option value="password">Возраст пароля</option></select></label></div>
      {filtered.length ? <div className="table-scroll"><table><thead><tr><th>Уровень</th><th>Аккаунт</th><th>Проблема</th><th>Причина</th><th>Балл</th><th></th></tr></thead><tbody>{filtered.map(item => <tr key={item.id} onClick={() => onOpenAccount(item.account_id, item.account_type)} tabIndex="0" onKeyDown={e => { if (e.key === 'Enter') onOpenAccount(item.account_id, item.account_type) }}><td><Badge level={item.severity}/></td><td className="mono">{item.username}</td><td><strong>{item.title}</strong></td><td className="muted-cell">{item.reason}</td><td className="mono">+{item.score}</td><td><Icon name="arrow" size={16}/></td></tr>)}</tbody></table></div> : <Empty title="Ничего не найдено" body="Измените фильтр или поисковый запрос."/>}
    </section></>
}

function Accounts({ accounts, onOpenAccount, inactiveDays = 90 }) {
  const [search, setSearch] = useState('')
  const [kind, setKind] = useState('all')
  const [state, setState] = useState('all')
  const [severity, setSeverity] = useState('all')
  const [sort, setSort] = useState('risk')
  const filtered = accounts.filter(item => `${item.username} ${item.display_name} ${item.department}`.toLowerCase().includes(search.toLowerCase()) &&
    (kind === 'all' || (kind === 'service' ? item.service_account : kind === 'privileged' ? item.privileged : !item.service_account)) &&
    (state === 'all' || (state === 'inactive' ? item.enabled && (item.last_logon ? daysAgo(item.last_logon) >= inactiveDays : item.when_created && daysAgo(item.when_created) >= inactiveDays) : state === 'locked' ? item.locked : state === 'disabled' ? !item.enabled : item.enabled)) &&
    (severity === 'all' || item.risk_level === severity))
    .sort((a, b) => sort === 'name' ? a.username.localeCompare(b.username, 'ru') : sort === 'activity' ? (a.last_logon || '').localeCompare(b.last_logon || '') : sort === 'password' ? (a.password_last_set || '').localeCompare(b.password_last_set || '') : b.risk_score - a.risk_score)
  return <><div className="section-head"><div><div className="eyebrow">Объекты</div><h1>Учётные записи</h1><p>Пользователи и сервисные аккаунты с оценкой риска.</p></div><span className="count-pill">{accounts.length} объектов</span></div>
    <section className="panel table-panel"><div className="toolbar"><label className="search-field"><Icon name="search" size={18}/><input value={search} onChange={e => setSearch(e.target.value)} placeholder="Поиск по имени или отделу"/></label><label className="select-wrap"><span>Тип</span><select value={kind} onChange={e => setKind(e.target.value)}><option value="all">Все</option><option value="user">Пользователи</option><option value="service">Сервисные</option><option value="privileged">Привилегированные</option></select></label><label className="select-wrap"><span>Статус</span><select value={state} onChange={e => setState(e.target.value)}><option value="all">Все</option><option value="enabled">Включён</option><option value="disabled">Отключён</option><option value="locked">Заблокирован</option><option value="inactive">Неактивен</option></select></label><label className="select-wrap"><span>Уровень</span><select value={severity} onChange={e => setSeverity(e.target.value)}><option value="all">Все</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="safe">Без риска</option></select></label><label className="select-wrap"><span>Сортировка</span><select value={sort} onChange={e => setSort(e.target.value)}><option value="risk">Risk Score</option><option value="name">Имя</option><option value="activity">Последний вход</option><option value="password">Возраст пароля</option></select></label></div><div className="table-scroll"><table><thead><tr><th>Аккаунт</th><th>Тип</th><th>Состояние</th><th>Последний вход</th><th>Пароль</th><th>Права</th><th>Уровень</th><th>Risk Score</th><th></th></tr></thead><tbody>{filtered.map(item => <tr key={item.id} onClick={() => onOpenAccount(item.id)} tabIndex="0" onKeyDown={e => { if (e.key === 'Enter') onOpenAccount(item.id) }}><td><strong className="mono">{item.username}</strong><small className="table-sub">{item.display_name}</small></td><td>{item.service_account ? 'Сервисный' : 'Пользователь'}</td><td>{item.locked ? 'Заблокирован' : item.account_expired ? 'Истёк' : item.enabled ? 'Включён' : 'Отключён'}</td><td>{item.last_logon ? formatDate(item.last_logon) : item.activity_status === "never_observed" ? "Вход не наблюдался" : "Нет данных"}</td><td>{item.password_last_set ? `${daysAgo(item.password_last_set)} дн.` : 'Нет данных'}</td><td>{item.privileged ? <span className="privileged">Есть</span> : 'Нет'}</td><td><Badge level={item.risk_level}/></td><td className="score-cell">{item.risk_score}/100</td><td><Icon name="arrow" size={16}/></td></tr>)}</tbody></table></div>{!filtered.length && <Empty title="Аккаунты не найдены" body="Попробуйте другой поисковый запрос."/>}</section></>
}

function AccountDetails({ account, onBack }) {
  return <><button className="back-button" onClick={onBack}>← К списку аккаунтов</button><div className="section-head"><div><div className="eyebrow">Карточка аккаунта</div><h1>{account.username}</h1><p>{account.display_name} · {account.department || 'Отдел не указан'}</p></div><div className="detail-score"><span>Risk Score</span><strong>{account.risk_score}<small>/100</small></strong><Badge level={account.risk_level}/></div></div>
    <div className="details-grid"><section className="panel detail-panel"><h2>Сведения</h2><p title="Risk Score: больше означает выше риск">Risk Score {account.risk_score}/100 · {severityLabels[account.risk_level]}</p><dl className="facts"><div><dt>Тип</dt><dd>{account.service_account ? 'Сервисный аккаунт' : 'Пользователь'}</dd></div><div><dt>Состояние</dt><dd>{account.enabled ? 'Включён' : 'Отключён'}</dd></div><div><dt>Последний вход</dt><dd>{account.last_logon ? formatDate(account.last_logon) : account.activity_status === "never_observed" ? "Вход не наблюдался" : "Нет данных"}</dd></div><div><dt>Пароль установлен</dt><dd>{formatDate(account.password_last_set)}{account.password_last_set ? ` · ${daysAgo(account.password_last_set)} дней назад` : ''}</dd></div><div><dt>Владелец</dt><dd>{account.owner || 'Не указан'}</dd></div><div><dt>Привилегии</dt><dd>{account.privileged ? 'Есть' : 'Не найдены'}</dd></div></dl></section>
      <section className="panel detail-panel"><h2>Группы и пути доступа</h2><div className="tags">{account.groups.length ? account.groups.map(group => <span key={group}>{group}</span>) : <p className="muted">Группы не указаны</p>}</div>{account.privilege_details?.map(item => <p className="scope-note" key={item.group}><strong>{item.group}</strong>: {item.scope_label}</p>)}{account.privilege_paths.length > 0 && <><h3>Путь до административной группы</h3><div className="path-list">{account.privilege_paths.map((path, index) => <div className="privilege-path" key={index}>{path.map((part, i) => <span key={i}>{i > 0 && <b>→</b>}{part}</span>)}</div>)}</div></>}{account.service_account && <p className="scope-note"><strong>Права интерактивного входа на DC:</strong> {account.interactive_logon?.status === 'pass' ? 'Оценены' : 'Не оценены'}{account.interactive_logon?.note ? ` · ${account.interactive_logon.note}` : ''}</p>}</section></div>
    <section className="panel detail-panel"><h2>Данные AD и проверки</h2><dl className="facts"><div><dt>DN</dt><dd className="mono">{account.distinguished_name || 'Нет данных'}</dd></div><div><dt>Создан</dt><dd>{formatDate(account.when_created)}</dd></div><div><dt>Срок действия</dt><dd>{formatDate(account.account_expires_at)}</dd></div><div><dt>Активность</dt><dd>{account.activity_status === "never_observed" ? "Вход не наблюдался" : account.activity_status === "last_activity" ? "Последний вход" : "Не оценена"} · {formatDate(account.last_logon)}</dd></div><div><dt>Точный вход на DC</dt><dd>{formatDate(account.exact_last_logon)}</dd></div><div><dt>Блокировка / срок</dt><dd>{account.locked ? 'Заблокирован' : 'Нет блокировки'} · {account.account_expired ? 'Срок истёк' : 'Не истёк'}</dd></div><div><dt>Пароль</dt><dd>{account.password_must_change ? 'Требуется смена' : account.password_never_expires ? 'Не истекает' : 'Обычный срок'}{account.password_not_required ? ' · не требуется' : ''}</dd></div><div><dt>Применённая политика</dt><dd>{account.resultant_password_policy?.name || (account.password_policy_source === 'domain' ? 'Политика домена' : 'Нет данных')}</dd></div><div><dt>Тип сервиса</dt><dd>{account.service_detection_reasons?.join(', ') || 'Не классифицирован как сервисный'}</dd></div><div><dt>SIDHistory</dt><dd>{account.sid_history?.length ? account.sid_history.join(', ') : 'Нет'}</dd></div><div><dt>SPN</dt><dd>{account.spns?.length ? account.spns.join(', ') : 'Нет'}</dd></div><div><dt>Делегация</dt><dd>{Object.keys(account.delegation ?? {}).length ? delegationLabel(account.delegation) : 'Не обнаружена'}</dd></div><div><dt>Интерактивный вход</dt><dd>{account.interactive_logon?.status ?? 'Не оценён'}{account.interactive_logon?.target_host ? ` · ${account.interactive_logon.target_host}` : ''}</dd></div></dl></section>
    <section className="panel finding-detail-panel"><div className="panel-head"><div><h2>Причины риска и рекомендации</h2><p>{account.findings.length} найденных проблем</p></div></div>{account.findings.length ? <div className="finding-cards">{account.findings.map(item => <article className="finding-card" key={item.id}><div className="finding-card-top"><Badge level={item.severity}/><strong>+{item.score} баллов</strong></div><h3>{item.title}</h3><p>{item.reason}</p><p><strong>Почему важно:</strong> {item.why_it_matters || item.reason}</p><Evidence evidence={item.evidence}/><div className="recommendation"><span>Что сделать</span><p>{item.recommendation}</p></div></article>)}</div> : <Empty title="Проблемы не обнаружены" body="Для этого аккаунта правила анализа не сработали."/>}</section>
  </>
}

function DomainPolicy({ dashboard }) {
  const policy = dashboard.domain_policy ?? {}
  const findings = [...(dashboard.domain_policy_findings ?? []), ...(dashboard.fine_grained_policy_findings ?? [])]
  return <><div className="section-head"><div><div className="eyebrow">Домен</div><h1>Парольная политика</h1><p>Параметры политики домена и причины найденных рисков.</p></div><div className="detail-score"><span>Risk Score</span><strong>{dashboard.domain_policy_risk_score ?? 0}<small>/100</small></strong></div></div><div className="details-grid"><section className="panel detail-panel"><h2>Параметры</h2><dl className="facts"><div><dt>Минимальная длина</dt><dd>{policy.min_password_length ?? 'Нет данных'}</dd></div><div><dt>Сложность пароля</dt><dd>{policy.password_complexity == null ? 'Нет данных' : policy.password_complexity ? 'Включена' : 'Отключена'}</dd></div><div><dt>История паролей</dt><dd>{policy.password_history_count ?? 'Нет данных'}</dd></div><div><dt>Максимальный возраст</dt><dd>{policy.max_password_age_days == null ? 'Без ограничения / нет данных' : `${policy.max_password_age_days} дней`}</dd></div><div><dt>Минимальный возраст</dt><dd>{policy.min_password_age_days == null ? 'Нет данных' : `${policy.min_password_age_days} дней`}</dd></div><div><dt>Порог блокировки</dt><dd>{policy.lockout_threshold ?? 'Нет данных'}</dd></div><div><dt>Длительность блокировки</dt><dd>{policy.lockout_duration_minutes == null ? 'Нет данных' : `${policy.lockout_duration_minutes} мин`}</dd></div><div><dt>Окно блокировки</dt><dd>{policy.lockout_observation_minutes == null ? 'Нет данных' : `${policy.lockout_observation_minutes} мин`}</dd></div></dl></section><section className="panel detail-panel"><h2>Оценка</h2><p>Правила проверяют минимальную длину, сложность и порог блокировки. Для аккаунтов с FGPP применяется результирующая политика, указанная в карточке аккаунта.</p></section></div><section className="panel detail-panel"><h2>Fine-Grained Password Policies</h2>{dashboard.fine_grained_policies?.length ? dashboard.fine_grained_policies.map(item => <div key={item.distinguished_name}><h3>{item.name}</h3><dl className="facts"><div><dt>Приоритет</dt><dd>{item.precedence}</dd></div><div><dt>Применяется к</dt><dd>{item.applies_to?.join(', ') || 'Нет данных'}</dd></div><div><dt>Длина / история</dt><dd>{item.min_password_length} / {item.password_history_count}</dd></div><div><dt>Сложность</dt><dd>{item.password_complexity ? 'Включена' : 'Отключена'}</dd></div><div><dt>Возраст: мин / макс</dt><dd>{item.min_password_age_days ?? '—'} / {item.max_password_age_days ?? '—'} дн.</dd></div><div><dt>Блокировка: порог / срок / окно</dt><dd>{item.lockout_threshold ?? '—'} / {item.lockout_duration_minutes ?? '—'} / {item.lockout_observation_minutes ?? '—'} мин.</dd></div></dl></div>) : <p className="muted">Политики не найдены или источник не оценён.</p>}</section><section className="panel finding-detail-panel"><div className="panel-head"><div><h2>Найденные проблемы</h2><p>{findings.length} срабатываний</p></div></div>{findings.length ? <div className="finding-cards">{findings.map(item => <article className="finding-card" key={item.id}><div className="finding-card-top"><Badge level={item.severity}/><strong>+{item.score} баллов</strong></div><h3>{item.title}</h3><p>{item.reason}</p><p><strong>Почему важно:</strong> {item.why_it_matters || item.reason}</p><div className="recommendation"><span>Что сделать</span><p>{item.recommendation}</p></div></article>)}</div> : <Empty title="Рисков политики не найдено" body="Все доступные базовые проверки пройдены или данные политики отсутствуют."/>}</section></>
}

function Computers({ computers, findings }) {
  const [search, setSearch] = useState('')
  const filtered = computers.filter(item => `${item.name} ${item.dns_hostname} ${item.operating_system}`.toLowerCase().includes(search.toLowerCase()))
  return <><div className="section-head"><div><div className="eyebrow">Объекты</div><h1>Компьютеры</h1><p>Компьютеры Active Directory и связанные риски.</p></div><span className="count-pill">{computers.length} объектов</span></div><section className="panel table-panel"><div className="toolbar"><label className="search-field"><Icon name="search" size={18}/><input value={search} onChange={e => setSearch(e.target.value)} placeholder="Имя, DNS или ОС"/></label></div><div className="table-scroll"><table><thead><tr><th>Компьютер</th><th>ОС</th><th>Состояние</th><th>Последний вход</th><th>Уровень</th><th>Risk Score</th></tr></thead><tbody>{filtered.map(item => <tr key={item.id}><td><strong className="mono">{item.name}</strong><small className="table-sub">{item.dns_hostname}</small></td><td>{item.operating_system || '—'}</td><td>{item.enabled ? 'Включён' : 'Отключён'}</td><td>{formatDate(item.last_logon)}</td><td><Badge level={item.risk_level}/></td><td className="score-cell">{item.risk_score}/100</td></tr>)}</tbody></table></div>{!filtered.length && <Empty title="Компьютеры не найдены" body="Измените поисковый запрос или проверьте источник данных."/>}</section>{filtered.map(item => <section className="panel detail-panel" key={`detail-${item.id}`}><h2>{item.name}</h2><dl className="facts"><div><dt>DN</dt><dd className="mono">{item.distinguished_name}</dd></div><div><dt>Пароль учётной записи</dt><dd>{formatDate(item.password_last_set)}</dd></div><div><dt>Создан</dt><dd>{formatDate(item.when_created)}</dd></div><div><dt>SPN</dt><dd>{item.spns?.length ?? 0}</dd></div><div><dt>SIDHistory</dt><dd>{item.sid_history?.length ?? 0}</dd></div><div><dt>Делегация</dt><dd>{Object.keys(item.delegation ?? {}).length ? delegationLabel(item.delegation) : 'Не обнаружена'}</dd></div><div><dt>Находки</dt><dd>{findings.filter(finding => finding.account_id === item.id).map(finding => finding.title).join(', ') || 'Нет'}</dd></div></dl></section>)}</>
}

function Authentication({ authentication, dashboard }) {
  const status = authentication?.status ?? 'not_evaluated'
  return <><div className="section-head"><div><div className="eyebrow">События</div><h1>Аутентификация</h1><p>События Security Event Log и сигналы подбора паролей.</p></div></div><section className="panel detail-panel"><h2>Источник событий</h2><dl className="facts"><div><dt>Статус</dt><dd>{status === 'pass' ? 'Проверен' : status === 'partial' ? 'Частичные данные' : 'Не оценён'}</dd></div><div><dt>Событий</dt><dd>{authentication?.events ?? 0}</dd></div><div><dt>Ошибки пароля</dt><dd>{authentication?.failed_bad_password ?? 0}</dd></div><div><dt>Сигналы</dt><dd>{authentication?.findings?.length ?? 0}</dd></div></dl>{status !== 'pass' && <p className="scope-note">События не входят в текущую оценку, пока для backend не настроено отдельное минимальное право чтения журнала на DC.</p>}</section><section className="panel detail-panel"><h2>Источники проверки</h2><dl className="facts">{Object.entries(dashboard.source_status ?? {}).map(([name, value]) => <div key={name}><dt>{name}</dt><dd>{value === 'pass' ? 'Проверен' : value === 'not_evaluated' ? 'Не оценён' : String(value)}</dd></div>)}</dl></section><section className="panel finding-detail-panel"><h2>Обнаруженные сигналы</h2>{authentication?.findings?.length ? authentication.findings.map(item => <article className="finding-card" key={item.id}><Badge level={item.severity}/><h3>{item.title}</h3><p>{item.reason}</p><Evidence evidence={item.evidence}/></article>) : <p className="muted">{status === 'pass' ? 'Сигналов не найдено.' : 'Без доступа к журналу вывод о наличии или отсутствии атак невозможен.'}</p>}</section></>
}

function Settings({ connection, onTest, testing, thresholds, onThresholdChange, onSave, saving }) {
  return <><div className="section-head"><div><div className="eyebrow">Подключение</div><h1>Источник Active Directory</h1><p>Адрес и учётную запись backend читает из <code>backend/.env</code>. Секрет остаётся только на серверной стороне.</p></div></div>
    <section className="panel settings-panel"><div className="settings-title"><div className="server-icon"><Icon name="server" size={26}/></div><div><h2>LDAP-подключение</h2><p>{connection.configured && !connection.password_required ? 'Параметры заполнены' : 'Ожидает настройки сервера'}</p></div><span className={`status-pill ${connection.connection_test_status === 'success' ? 'ready' : ''}`}>{connection.connection_test_status === 'success' ? 'Подключено' : connection.connection_test_status === 'failed' ? 'Ошибка проверки' : 'Не проверено'}</span></div><dl className="facts"><div><dt>Сервер / DC</dt><dd>{connection.host || '—'}</dd></div><div><dt>Порт</dt><dd>{connection.port}</dd></div><div><dt>Домен</dt><dd>{connection.domain || '—'}</dd></div><div><dt>Base DN</dt><dd>{connection.base_dn || '—'}</dd></div><div><dt>Учётная запись чтения</dt><dd>{connection.reader_username || '—'}</dd></div><div><dt>Режим</dt><dd>{connection.read_only ? 'Только чтение' : 'Неизвестно'}</dd></div><div><dt>Соединение</dt><dd>{connection.use_ssl ? 'LDAPS' : 'LDAP через Tailscale'}</dd></div><div><dt>Успешная проверка</dt><dd>{formatDate(connection.last_connection_success)}</dd></div><div><dt>Последний scan</dt><dd>{formatDate(connection.last_scan)} · {connection.last_scan_source || '—'}</dd></div><div><dt>Объекты последнего scan</dt><dd>{connection.last_users ?? '—'} users / {connection.last_groups ?? '—'} groups</dd></div></dl><p className="credential-note">Пароль LDAP-чтения задаётся только через секрет окружения backend и не передаётся браузеру.</p><button className="primary-button" onClick={onTest} disabled={!connection.configured || connection.password_required || testing}>{testing ? 'Проверяем…' : 'Проверить соединение'}</button></section>
    <section className="panel settings-panel"><h2>Пороги анализа</h2><p>Сохранённые значения применятся при следующем сканировании.</p><div className="threshold-grid">{[['inactive_days', 'Неактивность, дней', 1, 3650], ['old_password_days', 'Возраст пароля, дней', 1, 3650], ['inactive_computer_days', 'Неактивный компьютер, дней', 1, 3650], ['brute_attempts', 'Попыток для brute force', 2, 1000], ['spray_unique_users', 'Аккаунтов для spray', 3, 1000], ['auth_window_minutes', 'Окно событий, минут', 1, 1440], ['risk_medium_threshold', 'Порог Medium', 10, 98], ['risk_high_threshold', 'Порог High', 11, 99], ['risk_critical_threshold', 'Порог Critical', 12, 100]].map(([key, label, min, max]) => <label key={key}>{label}<input type="number" min={min} max={max} value={thresholds[key] ?? ''} onChange={e => onThresholdChange({ ...thresholds, [key]: e.target.value === '' ? '' : Number(e.target.value) })}/></label>)}</div><p className="credential-note">Пороги риска должны возрастать: Medium &lt; High &lt; Critical.</p><button className="primary-button" onClick={onSave} disabled={saving}>{saving ? 'Сохраняем…' : 'Сохранить пороги'}</button></section>
    <section className="panel settings-panel"><h2>Как подключить сервер</h2><ol className="setup-list"><li>Скопируйте <code>backend/.env.example</code> в <code>backend/.env</code>.</li><li>Укажите адрес контроллера, Base DN и учётную запись чтения.</li><li>Задайте <code>LDAP_PASSWORD</code> в закрытом окружении backend и перезапустите его.</li><li>Проверьте соединение и запустите анализ Active Directory.</li></ol></section>
  </>
}

function delegationLabel(value) { const parts = []; if (value?.unconstrained) parts.push('Неограниченная'); if (value?.constrained_targets?.length) parts.push(`К сервисам: ${value.constrained_targets.join(', ')}`); if (value?.rbcd_configured) parts.push('RBCD'); return parts.join(' · ') || 'Не обнаружена' }

function formatDate(date) { return date ? new Intl.DateTimeFormat('ru-RU', { day: '2-digit', month: 'short', year: 'numeric' }).format(new Date(date)) : 'Нет данных' }
function daysAgo(date) { return Math.max(0, Math.floor((Date.now() - new Date(date).getTime()) / 86400000)) }

export default function App() {
  const [page, setRenderedPage] = useState('dashboard')
  const [targetPage, setTargetPage] = useState('dashboard')
  const [transition, setTransition] = useState('enter')
  const [direction, setDirection] = useState(1)
  const transitionTimer = useRef(null)
  const pageOrder = ['dashboard', 'findings', 'accounts', 'computers', 'policy', 'authentication', 'settings']
  const pageIndex = key => pageOrder.indexOf(key === 'detail' ? 'accounts' : key)

  function setPage(nextPage, nextAccountId = null) {
    clearTimeout(transitionTimer.current)
    setTargetPage(nextPage)
    setDirection(pageIndex(nextPage) >= pageIndex(page) ? 1 : -1)
    if (nextPage === page) {
      setAccountId(nextAccountId)
      setTransition('enter')
      return
    }
    const commit = () => {
      setAccountId(nextAccountId)
      setRenderedPage(nextPage)
      setTransition('enter')
    }
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      commit()
    } else {
      setTransition('exit')
      transitionTimer.current = setTimeout(commit, 140)
    }
  }

  useEffect(() => () => clearTimeout(transitionTimer.current), [])
  const [accountId, setAccountId] = useState(null)
  const [dashboard, setDashboard] = useState(null)
  const [findings, setFindings] = useState([])
  const [accounts, setAccounts] = useState([])
  const [computers, setComputers] = useState([])
  const [authentication, setAuthentication] = useState(null)
  const [scans, setScans] = useState([])
  const [comparison, setComparison] = useState(null)
  const [connection, setConnection] = useState(null)
  const [thresholds, setThresholds] = useState({})
  const [saving, setSaving] = useState(false)
  const [source, setSource] = useState('ldap')
  const [loading, setLoading] = useState(true)
  const [scanning, setScanning] = useState(false)
  const [scanStartedAt, setScanStartedAt] = useState(null)
  const [testing, setTesting] = useState(false)
  const [notice, setNotice] = useState(null)
  const [error, setError] = useState(null)

  const refresh = useCallback(async () => {
    const [summary, risks, users, machines, auth, config, ldap, history, delta] = await Promise.all([
      api('/dashboard'), api('/findings'), api('/accounts'), api('/computers'), api('/authentication'), api('/config'), api('/connection/status'), api('/scans'), api('/scans/compare'),
    ])
    setDashboard(summary); setFindings(risks); setAccounts(users); setComputers(machines); setAuthentication(auth); setConnection(ldap); setScans(history); setComparison(delta)
    setSource(current => current === 'demo' && summary.source === 'demo' ? 'demo' : summary.source === 'ldap' || ldap.configured ? 'ldap' : 'demo')
    setThresholds(config)
  }, [])

  useEffect(() => { refresh().catch(e => setError(e.message)).finally(() => setLoading(false)) }, [refresh])
  useEffect(() => { if (notice) { const timeout = setTimeout(() => setNotice(null), 5500); return () => clearTimeout(timeout) } }, [notice])

  async function runScan() {
    setScanning(true); setScanStartedAt(new Date()); setError(null)
    try {
      const result = await api('/scans', { method: 'POST', body: JSON.stringify({ source, ...thresholds }) })
      await refresh()
      setPage('dashboard')
      setNotice(`Сканирование завершено за ${result.duration_ms} мс: ${result.users_scanned} аккаунтов, ${result.groups_scanned} групп, ${result.findings_found} находок`)
    } catch (e) { setError(e.message) } finally { setScanning(false); setScanStartedAt(null) }
  }

  async function testConnection() {
    setTesting(true); setError(null)
    try { const result = await api('/connection/test', { method: 'POST' }); await refresh(); setNotice(`Соединение установлено: ${result.users_found} пользователей, ${result.groups_found} групп`) }
    catch (e) { setError(e.message) } finally { setTesting(false) }
  }

  async function saveThresholds() {
    setSaving(true); setError(null)
    try { const saved = await api('/config', { method: 'PUT', body: JSON.stringify(thresholds) }); setThresholds(saved); setNotice('Пороги анализа сохранены') }
    catch (e) { setError(e.message) } finally { setSaving(false) }
  }

  function openAccount(id, type) { if (id === '__domain__' || type === 'domain' || type === 'policy') { setPage('policy'); return } if (type === 'computer' || computers.some(item => item.id === id)) { setPage('computers'); return } if (type === 'authentication' || !accounts.some(item => item.id === id)) { setPage('authentication'); return } setPage('detail', id) }
  const selectedAccount = accounts.find(item => item.id === accountId)
  const detail = selectedAccount ? { ...selectedAccount, findings: findings.filter(item => item.account_id === accountId) } : null
  const nav = [{ key: 'dashboard', label: 'Обзор', icon: 'dashboard' }, { key: 'findings', label: 'Риски', icon: 'shield' }, { key: 'accounts', label: 'Аккаунты', icon: 'users' }, { key: 'computers', label: 'Компьютеры', icon: 'server' }, { key: 'policy', label: 'Политика домена', icon: 'shield' }, { key: 'authentication', label: 'Аутентификация', icon: 'shield' }, { key: 'settings', label: 'Подключение', icon: 'settings' }]

  return <div className="app-shell"><aside className="sidebar"><div className="brand"><div><strong>Identity Risk</strong><span>Security workspace</span></div></div><div className="nav-label">Рабочая область</div><nav aria-label="Основная навигация">{nav.map(item => <button key={item.key} onClick={() => setPage(item.key)} aria-current={targetPage === item.key || (targetPage === 'detail' && item.key === 'accounts') ? 'page' : undefined} className={`nav-link ${targetPage === item.key || (targetPage === 'detail' && item.key === 'accounts') ? 'active' : ''}`}><Icon name={item.icon} size={19}/><span>{item.label}</span></button>)}</nav><div className="sidebar-footer"><div className="sidebar-visual"><Icon name="shield" size={28}/><span>Видеть риски.<br/><strong>Защищать главное.</strong></span></div><div className="sidebar-bottom"><div><strong>{dashboard ? (dashboard.source === 'ldap' ? 'Active Directory' : 'Демо-режим') : 'Нет данных'}</strong><small>{dashboard ? 'Источник сканирования' : 'Ожидание сканирования'}</small></div><Icon name="server" size={18}/></div><div className="workspace-version">IDENTITY RISK RADAR <span>v0.1</span></div></div></aside>
    <main className="main"><header className="topbar"><div className="breadcrumb">Рабочая область <span>/</span> <strong>{page === 'detail' ? 'Карточка аккаунта' : nav.find(item => item.key === page)?.label}</strong></div><div className="top-actions"><label className="source-select"><span>Источник</span><select value={source} onChange={e => setSource(e.target.value)}><option value="demo">Демо</option><option value="ldap" disabled={!connection?.configured}>Active Directory</option></select><Icon name="chevron" size={15}/></label><button className="scan-button" disabled={scanning || (source === 'ldap' && connection?.password_required)} onClick={runScan}><Icon name="refresh" size={17}/>{scanning ? 'Чтение AD и анализ…' : 'Запустить анализ'}</button></div></header>
      <div className="content" style={{ '--page-direction': direction }}>{scanning && <div className="notice" role="status">Анализ запущен {scanStartedAt?.toLocaleTimeString('ru-RU')} · Идёт чтение каталога и расчёт рисков. Результат появится после завершения.</div>}{error && <div className="alert" role="alert"><span>{error}</span><button onClick={() => setError(null)} aria-label="Закрыть">×</button></div>}{notice && <div className="notice" role="status">{notice}</div>}{loading ? <div className="loading">Загрузка результатов…</div> : dashboard ? <>
        <div className="scan-meta"><span>{sourceLabels[dashboard.source]} · Сканирование {formatDate(dashboard.scanned_at)}{dashboard.duration_ms != null ? ` · ${dashboard.duration_ms} мс` : ''}</span><a href="/api/export/csv" className="export-link"><Icon name="download" size={17}/> Скачать CSV</a></div>
        <div className="page-stage" data-page={targetPage}>
        <div className="scene-lane" aria-hidden="true"><div className="scene-traveler" style={{ '--scene-step': pageIndex(targetPage) }}><ShieldScene/></div></div>
        <div key={page} className={`page-content page-${transition}`} inert={transition === 'exit' ? true : undefined}>
        {page === 'dashboard' && <Dashboard dashboard={dashboard} accounts={accounts} scans={scans} comparison={comparison} onOpenAccount={openAccount}/>}
        {page === 'findings' && <Findings findings={findings} accounts={accounts} onOpenAccount={openAccount}/>}
        {page === 'accounts' && <Accounts accounts={accounts} onOpenAccount={openAccount} inactiveDays={dashboard.thresholds?.inactive_days ?? 90}/>}
        {page === 'computers' && <Computers computers={computers} findings={findings}/>}
        {page === 'detail' && detail && <AccountDetails account={detail} onBack={() => setPage('accounts')}/>}
        {page === 'policy' && <DomainPolicy dashboard={dashboard}/>}
        {page === 'authentication' && <Authentication authentication={authentication} dashboard={dashboard}/>}
        {page === 'settings' && <Settings connection={connection ?? {}} onTest={testConnection} testing={testing} thresholds={thresholds} onThresholdChange={setThresholds} onSave={saveThresholds} saving={saving}/>}
        </div></div>
      </> : <Empty title="Нет результатов" body="Запустите демонстрационное сканирование, чтобы увидеть анализ."/>}</div>
    </main></div>
}
