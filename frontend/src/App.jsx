import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { api, downloadCsv, setAccessToken } from './api.js'

const severityLabels = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', safe: 'Без риска' }
const severityPlain = { critical: 'Критично', high: 'Высокий риск', medium: 'Средний риск', low: 'Низкий риск' }
const chartLabels = { critical: 'Критично', high: 'Высокий', medium: 'Средний', low: 'Низкий' }
const sourceLabels = { demo: 'Демо', ldap: 'Active Directory' }
const sourceStatusLabels = { ldap: 'Active Directory', fine_grained_policies: 'Fine-Grained Password Policies', computers: 'Компьютеры AD', spn_inventory: 'SPN', interactive_rights: 'Интерактивные права DC', security_event_log: 'Security Event Log', ad_gateway: 'AD Gateway' }
const checkStatusLabels = { pass: 'Проверен', finding: 'Найдена проблема', partial: 'Частичные данные', error: 'Ошибка чтения', not_evaluated: 'Не оценён' }

function interactiveStatus(value) {
  if (!value || value.status === 'not_evaluated') return 'Не оценён'
  if (value.status === 'error') return 'Ошибка проверки'
  if (value.status === 'finding') return 'Интерактивный вход разрешён'
  if (value.status === 'pass') return 'Права входа проверены: вход не разрешён'
  return 'Не оценён'
}

function activityDisplay(account) {
  if (account.last_logon) return `Последний вход: ${formatDate(account.last_logon)} (приблизительно)`
  if (account.exact_last_logon) return `Последний вход на DC: ${formatDate(account.exact_last_logon)}`
  return account.activity_status === 'never_observed' ? 'Вход не наблюдался' : 'Не оценена'
}

function Badge({ level }) {
  return <span className={`badge badge-${level}`}>{severityLabels[level] ?? level}</span>
}

// Google Material Icons, bundled locally under the Apache 2.0 license.
function Icon({ name, size = 20 }) {
  return <span className="icon" style={{ width: size, height: size, '--icon': `url(/icons/${name === 'radar' ? 'shield' : name}.svg)` }} aria-hidden="true" />
}

function Empty({ title, body }) {
  return <div className="empty"><div className="empty-icon"><Icon name="shield" size={25}/></div><h3>{title}</h3><p>{body}</p></div>
}

function Metric({ label, value, tone, helper }) {
  return <div className={`metric metric-${label.toLowerCase()}`}><div className="metric-icon"><Icon name="shield" size={22}/></div><div className="metric-label">{label}</div><div className={`metric-value ${tone ?? ''}`}>{value}</div>{helper && <div className="metric-helper">{helper}</div>}</div>
}

function Dashboard({ dashboard, accounts, scans, comparison, onOpenAccount }) {
  const top = dashboard.top_risky_users ?? []
  const policyAvailable = Object.keys(dashboard.domain_policy ?? {}).length > 0
  const maxCategory = Math.max(...(dashboard.categories ?? []).map(item => item.count), 1)
  const maxFinding = Math.max(...['critical', 'high', 'medium', 'low'].map(level => dashboard.findings[level] ?? 0), 1)
  const history = scans.filter(item => item.source === dashboard.source).slice(0, 8).reverse()
  return <>
    <div className="dashboard-intro"><div><h1>Обзор безопасности</h1><p>Риски Active Directory и аккаунты, требующие внимания.</p></div></div>
    <div className="overview-grid">
      <section className="score-card"><div className="score-ring" title="100 означает минимальный выявленный риск. Оценка основана на среднем риске аккаунтов, компьютеров и политики домена." style={{ '--score': `${dashboard.security_score}%` }}><div><strong>{dashboard.security_score}</strong><span>/ 100</span></div></div><div className="score-copy"><span className="metric-label">AD Security Score</span><h2>Состояние домена</h2><p>100 = лучше.<br/>Чем выше оценка, тем меньше выявленный риск.</p><span className="score-caption">AD SECURITY</span></div></section>
      <Metric label="Critical" value={dashboard.findings.critical} tone="danger" helper="Немедленная проверка" />
      <Metric label="High" value={dashboard.findings.high} tone="warning" helper="Высокий приоритет" />
      <Metric label="Medium" value={dashboard.findings.medium} tone="neutral" helper="Плановые проверки" />
      <Metric label="Low" value={dashboard.findings.low} tone="neutral" helper="Замечания" />
    </div>
    <div className="quick-stats">
      <span><strong>{dashboard.total_users}</strong> аккаунтов</span>
      <span><strong>{dashboard.finding_count}</strong> находок</span>
      <span><strong>{dashboard.privileged_accounts}</strong> с правами администратора</span>
      <span><strong>{dashboard.service_accounts}</strong> сервисных</span>
      <span><strong>{dashboard.disabled_accounts ?? '—'}</strong> отключённых</span>
      <span title={dashboard.source_status?.security_event_log === 'pass' ? 'Подозрительные паттерны в журнале Security' : 'Security Event Log не оценён'}><strong>{dashboard.source_status?.security_event_log === 'pass' ? dashboard.auth_findings : '—'}</strong> сигналов входа</span>
      <details className="more-stats"><summary>Ещё показатели</summary><div>
        <span><strong>{dashboard.healthy_accounts ?? '—'}</strong> без находок</span>
        <span><strong>{dashboard.inactive_accounts ?? '—'}</strong> неактивных</span>
        <span title="Новые аккаунты не считаются неактивными до истечения порога"><strong>{accounts.filter(item => item.activity_status === 'never_observed').length}</strong> без наблюдаемого входа</span>
        <span><strong>{dashboard.locked_accounts ?? '—'}</strong> заблокированных</span>
        <span><strong>{dashboard.expired_accounts ?? '—'}</strong> истёкших</span>
        <span><strong>{dashboard.total_computers ?? '—'}</strong> компьютеров</span>
      </div></details>
    </div>
    <div className="dashboard-panels">
      <section className="panel distribution-panel"><div className="panel-head"><div><h2>Распределение рисков</h2><p>Находки по уровню критичности</p></div><span className="count-pill">{dashboard.finding_count} находок</span></div>
        <div className="distribution-chart" role="list" aria-label="Находки по уровню риска">{['critical', 'high', 'medium', 'low'].map(level => {
          const count = dashboard.findings[level] ?? 0
          const width = count ? `${Math.max(6, count / maxFinding * 100)}%` : '0%'
          return <div className={`distribution-row distribution-${level}`} role="listitem" key={level}><span className="distribution-label">{chartLabels[level]}</span><div className="distribution-rail" aria-hidden="true"><div className="distribution-fill" style={{width}}/></div><strong>{count}</strong></div>
        })}</div>
      </section>
      <section className="panel category-panel"><div className="panel-head"><div><h2>Категории рисков</h2><p>Наиболее частые срабатывания правил.</p></div></div>
        {dashboard.categories?.length ? <div className="category-list">{dashboard.categories.slice(0, 6).map(item => <div className="category" key={item.rule_id}><div><span>{friendlyRule(item.rule_id)}</span><strong>{item.count}</strong></div><div className="category-track"><div style={{width: `${Math.max(7, item.count / maxCategory * 100)}%`}}/></div></div>)}</div> : <Empty title="Категорий нет" body="В этом сканировании проблемы не обнаружены."/>}
      </section>
      <section className="panel top-accounts-panel"><div className="panel-head"><div><h2>Наиболее рискованные аккаунты</h2><p>Откройте карточку, чтобы увидеть причины и рекомендации.</p></div></div>
        {top.length ? <div className="top-list">{top.map(item => <button className="top-row" key={item.id} onClick={() => onOpenAccount(item.id)}><span className={`top-rank avatar-${item.risk_level}`}><Icon name="users" size={19}/></span><span className="top-person"><strong>{item.username}</strong><small>{item.display_name}</small></span><Badge level={item.risk_level}/><strong className="top-score">{item.risk_score}</strong><Icon name="arrow" size={17}/></button>)}</div> : <Empty title="Рисков нет" body="После сканирования здесь появятся аккаунты с наибольшим риском."/>}
      </section>
    </div>
    <div className="two-col secondary-panels"><section className="panel"><div className="panel-head"><div><h2>Политика паролей домена</h2><p>Результат базовых проверок настроек.</p></div><button className="text-link" onClick={() => onOpenAccount('__domain__')}>Подробнее →</button></div><div className="policy-summary"><span>Минимальная длина: <strong>{dashboard.domain_policy?.min_password_length == null ? '—' : dashboard.domain_policy.min_password_length === 0 ? '0 (не задана)' : dashboard.domain_policy.min_password_length}</strong></span><span>Сложность: <strong>{dashboard.domain_policy?.password_complexity == null ? '—' : dashboard.domain_policy.password_complexity ? 'включена' : 'отключена'}</strong></span><span>Блокировка: <strong>{dashboard.domain_policy?.lockout_threshold == null ? '—' : dashboard.domain_policy.lockout_threshold === 0 ? '0 (отключена)' : dashboard.domain_policy.lockout_threshold}</strong></span></div><p className="policy-count">{policyAvailable ? dashboard.domain_policy_findings?.length ?? 0 : '—'} проблем · Risk Score {policyAvailable ? dashboard.domain_policy_risk_score ?? 0 : '—'}/100 (100 = хуже)</p></section>
      <section className="panel"><div className="panel-head"><div><h2>Динамика Security Score</h2><p>Последние сканирования источника «{sourceLabels[dashboard.source]}».</p></div></div>{comparison?.previous_scan_id && <div className="scan-comparison"><span>Score: {comparison.previous.security_score} → {comparison.current.security_score}</span><span>Critical: {comparison.previous.findings.critical} → {comparison.current.findings.critical}</span><span>High: {comparison.previous.findings.high} → {comparison.current.findings.high}</span><span>Новые: {comparison.added_findings} · Устранённые: {comparison.resolved_findings}</span></div>}{history.length > 1 ? <div className="history-bars">{history.map(item => <div className="history-item" key={item.scan_id} title={`${formatDate(item.scanned_at)} — ${item.summary.security_score}/100`}><strong>{item.summary.security_score}</strong><div className="history-track"><div style={{height: `${item.summary.security_score}%`}}/></div><small>{new Date(item.scanned_at).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' })}</small></div>)}</div> : <p className="muted">Динамика появится после второго сканирования.</p>}</section></div>
    {accounts.length > 0 && <details className="data-note"><summary>Как читать эти данные</summary><p>Показатели относятся к последнему сканированию. Изменения в AD появятся после повторного запуска. Отсутствие наблюдаемого входа само по себе не означает, что новый аккаунт неактивен.</p></details>}
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
      {filtered.length ? <div className="table-scroll"><table><thead><tr><th>Уровень</th><th>Аккаунт</th><th>Проблема</th><th>Причина</th><th>Балл</th><th></th></tr></thead><tbody>{filtered.map(item => <tr key={item.id} onClick={() => onOpenAccount(item.account_id, item.account_type)} tabIndex="0" onKeyDown={e => { if (e.key === 'Enter') onOpenAccount(item.account_id, item.account_type) }}><td><Badge level={item.severity}/></td><td className="mono">{item.username}</td><td><strong>{item.title}</strong></td><td className="muted-cell">{item.reason}</td><td className="mono">+{item.score}</td><td><Icon name="arrow" size={16}/></td></tr>)}</tbody></table></div> : <Empty title={findings.length ? "Ничего не найдено" : "Находок нет"} body={findings.length ? "Измените фильтр или поисковый запрос." : "В оценённых источниках находок нет. Статус источников показан на странице «Аутентификация»."}/>}
    </section></>
}

function Accounts({ accounts, findings, onOpenAccount }) {
  const [search, setSearch] = useState('')
  const [kind, setKind] = useState('all')
  const [state, setState] = useState('all')
  const [severity, setSeverity] = useState('all')
  const [sort, setSort] = useState('risk')
  const inactiveIds = useMemo(() => new Set(findings.filter(item => item.rule_id === 'INACTIVE_ACCOUNT').map(item => item.account_id)), [findings])
  const filtered = accounts.filter(item => `${item.username} ${item.display_name} ${item.department}`.toLowerCase().includes(search.toLowerCase()) &&
    (kind === 'all' || (kind === 'service' ? item.service_account : kind === 'privileged' ? item.privileged : !item.service_account)) &&
    (state === 'all' || (state === 'inactive' ? inactiveIds.has(item.id) : state === 'locked' ? item.locked : state === 'disabled' ? !item.enabled : item.enabled)) &&
    (severity === 'all' || item.risk_level === severity))
    .sort((a, b) => sort === 'name' ? a.username.localeCompare(b.username, 'ru') : sort === 'activity' ? (a.last_logon || '').localeCompare(b.last_logon || '') : sort === 'password' ? (a.password_last_set || '').localeCompare(b.password_last_set || '') : b.risk_score - a.risk_score)
  return <><div className="section-head"><div><div className="eyebrow">Объекты</div><h1>Учётные записи</h1><p>Пользователи и сервисные аккаунты с оценкой риска. Account Risk Score: 100 = хуже.</p></div><span className="count-pill">{accounts.length} объектов</span></div>
    <section className="panel table-panel"><div className="toolbar"><label className="search-field"><Icon name="search" size={18}/><input value={search} onChange={e => setSearch(e.target.value)} placeholder="Поиск по имени или отделу"/></label><label className="select-wrap"><span>Тип</span><select value={kind} onChange={e => setKind(e.target.value)}><option value="all">Все</option><option value="user">Пользователи</option><option value="service">Сервисные</option><option value="privileged">Привилегированные</option></select></label><label className="select-wrap"><span>Статус</span><select value={state} onChange={e => setState(e.target.value)}><option value="all">Все</option><option value="enabled">Включён</option><option value="disabled">Отключён</option><option value="locked">Заблокирован</option><option value="inactive">Неактивен</option></select></label><label className="select-wrap"><span>Уровень</span><select value={severity} onChange={e => setSeverity(e.target.value)}><option value="all">Все</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="safe">Без риска</option></select></label><label className="select-wrap"><span>Сортировка</span><select value={sort} onChange={e => setSort(e.target.value)}><option value="risk">Risk Score</option><option value="name">Имя</option><option value="activity">Последний вход</option><option value="password">Возраст пароля</option></select></label></div><div className="table-scroll"><table><thead><tr><th>Аккаунт</th><th>Тип</th><th>Состояние</th><th>Последний вход</th><th>Возраст пароля</th><th>Права</th><th>Уровень</th><th title="Account Risk Score: 100 означает максимальный выявленный риск">Risk Score</th><th></th></tr></thead><tbody>{filtered.map(item => <tr key={item.id} onClick={() => onOpenAccount(item.id)} tabIndex="0" onKeyDown={e => { if (e.key === 'Enter') onOpenAccount(item.id) }}><td><strong className="mono">{item.username}</strong><small className="table-sub">{item.display_name}</small></td><td>{item.service_account ? 'Сервисный' : 'Пользователь'}</td><td>{item.locked ? 'Заблокирован' : !item.enabled ? 'Отключён' : item.account_expired ? 'Истёк' : 'Включён'}</td><td>{item.last_logon ? formatDate(item.last_logon) : item.exact_last_logon ? `${formatDate(item.exact_last_logon)} (DC)` : item.activity_status === "never_observed" ? "Вход не наблюдался" : "Нет данных"}</td><td>{item.password_must_change ? 'Требуется смена' : item.password_last_set ? daysAgo(item.password_last_set) === 0 ? 'Сегодня' : `${daysAgo(item.password_last_set)} дн.` : 'Нет данных'}</td><td>{item.privileged ? <span className="privileged">Есть</span> : 'Нет'}</td><td><Badge level={item.risk_level}/></td><td className="score-cell">{item.risk_score}/100</td><td><Icon name="arrow" size={16}/></td></tr>)}</tbody></table></div>{!filtered.length && <Empty title="Аккаунты не найдены" body="Попробуйте другой поисковый запрос."/>}</section></>
}

function explainAccountFinding(item, account) {
  const evidence = item.evidence ?? {}
  const groups = evidence.privilege_details ?? []
  if (item.rule_id === 'DIRECT_PRIVILEGE') {
    const domain = groups.some(group => group.group === 'Domain Admins')
    const lab = groups.some(group => group.group === 'IR-Lab-Admins')
    const other = groups.filter(group => !['Domain Admins', 'IR-Lab-Admins'].includes(group.group))
    return {
      title: domain ? 'Доступ администратора домена' : 'Административный доступ',
      text: [
        domain && (account.enabled
          ? 'Аккаунт напрямую входит в Domain Admins: с ним можно управлять всем доменом.'
          : 'Аккаунт остаётся в Domain Admins. Пока он отключён, вход невозможен; после включения вернутся права управления доменом.'),
        lab && 'Также есть права в тестовом разделе InfraRadarLab.',
        ...other.map(group => `Также входит в ${group.group}: ${group.scope_label}.`),
      ].filter(Boolean).join(' ') || item.reason,
    }
  }
  if (item.rule_id === 'NESTED_PRIVILEGE') {
    const paths = (evidence.paths ?? []).map(path => path.join(' → ')).join('; ')
    return { title: 'Административный доступ через группы',
      text: `Права ${account.enabled ? 'получены' : 'сохранятся после включения'} через вложенные группы${paths ? `: ${paths}` : ''}. Их легко не заметить, если смотреть только список групп аккаунта.` }
  }
  if (item.rule_id === 'MULTIPLE_PRIVILEGES') {
    const names = evidence.critical_groups ?? []
    return { title: 'Несколько административных ролей',
      text: `Аккаунт состоит в ${names.length || 'нескольких'} административных группах${names.length ? `: ${names.join(', ')}` : ''}. ${account.enabled ? 'При компрометации будет доступно больше действий.' : 'При включении вернутся права всех этих групп.'}` }
  }
  const explanations = {
    PASSWORD_NEVER_EXPIRES: ['Пароль не истекает', 'В AD отключён срок действия пароля. Он останется действительным, пока его не сменят вручную.'],
    SERVICE_PASSWORD_NEVER_EXPIRES: ['Пароль сервиса не истекает', 'Пароль сервисной учётки не имеет срока действия. Без плановой смены им можно пользоваться долго.'],
    OLD_PASSWORD: ['Пароль давно не менялся', `Пароль установлен ${evidence.password_age_days ?? 'много'} дней назад; заданный порог — ${evidence.threshold_days ?? '—'} дней.`],
    PASSWORD_NOT_REQUIRED: ['Пароль может не требоваться', 'У аккаунта включён флаг AD, ослабляющий требование пароля.'],
    DISABLED_ACCOUNT: ['Аккаунт отключён', 'Войти сейчас нельзя, но запись и её настройки остаются в AD.'],
    DISABLED_PRIVILEGED: ['Отключённый администратор сохранил права', 'Аккаунт выключен, но остаётся в административных группах. Если его включить, права снова будут доступны.'],
    EXPIRED_ACCOUNT: ['Срок действия аккаунта истёк', 'Дата окончания действия прошла. Нужно проверить, зачем аккаунт и его права остаются в каталоге.'],
    LOCKED_ACCOUNT: ['Аккаунт заблокирован', 'AD зафиксировал блокировку. Причину следует проверить по событиям входа.'],
    INACTIVE_ACCOUNT: ['Аккаунт давно не использовался', `По доступным данным входа активность не наблюдалась дольше ${evidence.threshold_days ?? 'заданного порога'} дней.`],
    INACTIVE_PRIVILEGED: ['Неиспользуемый администратор', 'Административные права остаются у аккаунта, который давно не использовался.'],
    SERVICE_PRIVILEGED: ['Сервис имеет административные права', 'Сервисная учётка входит в административную группу. Взлом сервиса даст доступ к этим правам.'],
    INACTIVE_SERVICE: ['Сервис давно не использовался', 'Для сервисной учётки давно не наблюдалась активность; её назначение нужно подтвердить.'],
    MISSING_OWNER: ['Не указан ответственный', 'У сервисной учётки нет ответственного в AD. Неясно, кто должен менять пароль и проверять её права.'],
    SERVICE_INTERACTIVE_LOGON: ['Сервису разрешён вход на сервер', 'Сервисная учётка может использоваться для обычного входа на проверенном сервере.'],
    SID_HISTORY_PRESENT: ['Сохранены старые идентификаторы', 'SIDHistory может сохранять доступ через прежние учётные записи. Нужно подтвердить назначение.'],
    DUPLICATE_SPN: ['Один адрес сервиса у нескольких аккаунтов', 'Одинаковый SPN указан у разных объектов; Kerberos может выбрать неправильный аккаунт.'],
    DELEGATION_UNCONSTRAINED: ['Неограниченное делегирование', 'Сервис может использовать переданные ему учётные данные шире, чем требуется для одной задачи.'],
    DELEGATION_CONSTRAINED: ['Настроено делегирование', 'Аккаунту разрешено действовать от имени пользователей перед указанными сервисами; список нужно проверить.'],
    DELEGATION_RBCD: ['Ресурсное делегирование', 'Другим аккаунтам могут быть выданы права действовать от имени пользователей перед этим ресурсом.'],
    AUTH_TARGETED: ['Повторные неудачные входы', 'Этот аккаунт встречается в подозрительной серии неудачных попыток входа.'],
  }
  const explanation = explanations[item.rule_id]
  return explanation ? { title: explanation[0], text: explanation[1] } : { title: item.title, text: item.reason }
}

function AccountDetails({ account, riskThresholds, inactiveDays, onBack }) {
  const priority = { low: 1, medium: 2, high: 3, critical: 4 }
  const primary = account.findings.reduce((best, item) => !best || priority[item.severity] > priority[best.severity] ? item : best, null)
  const base = primary ? { low: 10, medium: riskThresholds?.medium ?? 30, high: riskThresholds?.high ?? 60, critical: riskThresholds?.critical ?? 80 }[primary.severity] : 0
  const extra = Math.max(0, account.risk_score - base)
  const noActivityFinding = !account.findings.some(item => item.rule_id === 'INACTIVE_ACCOUNT')
  const reasons = [...account.findings].sort((left, right) => priority[right.severity] - priority[left.severity])
  return <><button className="back-button" onClick={onBack}>← К списку аккаунтов</button><div className="section-head"><div><div className="eyebrow">Карточка аккаунта</div><h1>{account.username}</h1><p>{account.display_name} · {account.department || 'Отдел не указан'}</p></div><div className="detail-score"><span>Risk Score · 100 = хуже</span><strong>{account.risk_score}<small>/100</small></strong><span className={`badge badge-${account.risk_level}`}>{severityPlain[account.risk_level] ?? severityLabels[account.risk_level]}</span></div></div>
    <section className="panel detail-panel risk-explanation">
      <h2>Почему риск {account.risk_score}/100</h2>
      {reasons.length ? <>
        <p>Это оценка риска аккаунта, а не сообщение о взломе. Причины:</p>
        <div className="risk-reasons">{reasons.map(item => {
          const explanation = explainAccountFinding(item, account)
          return <div className="risk-reason" key={item.id}>
            <div><strong>{explanation.title}</strong><span className={`badge badge-${item.severity}`}>{severityPlain[item.severity] ?? item.severity}</span></div>
            <p>{explanation.text}</p>
          </div>
        })}</div>
        <details className="score-method"><summary>Как получился балл {account.risk_score}/100</summary>
          <p>Самая серьёзная причина задаёт начальную оценку {base}. Остальные причины добавили {extra} {extra === 1 ? 'балл' : extra >= 2 && extra <= 4 ? 'балла' : 'баллов'} с учётом их веса{account.risk_score === 100 ? '; итог ограничен 100' : ''}. Итог — {account.risk_score}/100.</p>
        </details>
      </> : <p>Проверки не нашли проблем для этого аккаунта. Оценка 0/100.</p>}
      {account.activity_status === 'never_observed' && noActivityFinding && <p className="scope-note">Вход в AD пока не зафиксирован. Аккаунт создан недавно, поэтому он не считается неактивным до истечения порога {inactiveDays ?? 90} дней.</p>}
    </section>
    <div className="details-grid"><section className="panel detail-panel"><h2>Сведения</h2><dl className="facts"><div><dt>Тип</dt><dd>{account.service_account ? 'Сервисный аккаунт' : 'Пользователь'}</dd></div><div><dt>Должность</dt><dd>{account.title || 'Не указана'}</dd></div><div><dt>Отдел</dt><dd>{account.department || 'Не указан'}</dd></div><div><dt>Компания</dt><dd>{account.company || 'Не указана'}</dd></div><div><dt>Состояние</dt><dd>{account.enabled ? 'Включён' : 'Отключён'}</dd></div><div><dt>Последний вход</dt><dd>{account.last_logon ? formatDate(account.last_logon) : account.exact_last_logon ? `${formatDate(account.exact_last_logon)} (DC)` : account.activity_status === "never_observed" ? "Вход не наблюдался" : "Нет данных"}</dd></div><div><dt>Пароль установлен</dt><dd>{formatDate(account.password_last_set)}{account.password_last_set ? daysAgo(account.password_last_set) === 0 ? ' · сегодня' : ` · ${daysAgo(account.password_last_set)} дней назад` : ''}</dd></div><div><dt>Владелец</dt><dd>{account.owner || (account.service_account ? 'Не указан — см. находки ниже' : 'Не указан — на этот score не влияет')}</dd></div><div><dt>Привилегии</dt><dd>{account.privileged ? 'Есть' : 'Не найдены'}</dd></div></dl></section>
      <section className="panel detail-panel"><h2>Группы и пути доступа</h2><div className="tags">{account.groups.length ? account.groups.map(group => <span key={group}>{group}</span>) : <p className="muted">Группы не указаны</p>}</div>{account.privilege_details?.map(item => <p className="scope-note" key={item.group}><strong>{item.group}</strong>: {item.scope_label}</p>)}{account.privilege_paths.length > 0 && <><h3>Путь до административной группы</h3><div className="path-list">{account.privilege_paths.map((path, index) => <div className="privilege-path" key={index}>{path.map((part, i) => <span key={i}>{i > 0 && <b>→</b>}{part}</span>)}</div>)}</div></>}{account.service_account && <p className="scope-note"><strong>Права интерактивного входа на DC:</strong> {interactiveStatus(account.interactive_logon)}{account.interactive_logon?.note ? ` · ${account.interactive_logon.note}` : ''}</p>}</section></div>
    <details className="panel detail-panel account-technical"><summary>Данные AD и проверки<span>Технические атрибуты аккаунта</span></summary><dl className="facts"><div><dt>DN</dt><dd className="mono">{account.distinguished_name || 'Нет данных'}</dd></div><div><dt>Имя / фамилия</dt><dd>{[account.given_name, account.surname].filter(Boolean).join(' ') || 'Не указаны'}</dd></div><div><dt>Описание AD</dt><dd>{account.description || 'Не указано'}</dd></div><div><dt>Создан</dt><dd>{formatDate(account.when_created)}</dd></div><div><dt>Срок действия</dt><dd>{account.account_expires_at ? formatDate(account.account_expires_at) : 'Не задан'}</dd></div><div><dt>Активность</dt><dd>{activityDisplay(account)}</dd></div><div><dt>Вход на текущем DC</dt><dd>{account.exact_last_logon ? formatDate(account.exact_last_logon) : 'Не зафиксирован'}</dd></div><div><dt>Блокировка / срок</dt><dd>{account.locked ? 'Заблокирован' : 'Нет блокировки'} · {account.account_expired ? 'Срок истёк' : 'Не истёк'}</dd></div><div><dt>Пароль</dt><dd>{account.password_must_change ? 'Требуется смена' : account.password_never_expires ? 'Не истекает' : 'Обычный срок'}{account.password_not_required ? ' · не требуется' : ''}</dd></div><div><dt>Применённая политика</dt><dd>{account.resultant_password_policy?.name || (account.password_policy_source === 'domain_default' || account.password_policy_source === 'domain' ? 'Политика домена (без FGPP)' : 'Нет данных')}</dd></div><div><dt>Тип сервиса</dt><dd>{account.service_detection_reasons?.join(', ') || 'Не классифицирован как сервисный'}</dd></div><div><dt>SIDHistory</dt><dd>{account.sid_history?.length ? account.sid_history.join(', ') : 'Нет'}</dd></div><div><dt>SPN</dt><dd>{account.spns?.length ? account.spns.join(', ') : 'Нет'}</dd></div><div><dt>Делегация</dt><dd>{Object.keys(account.delegation ?? {}).length ? delegationLabel(account.delegation) : 'Не обнаружена'}</dd></div><div><dt>Интерактивный вход</dt><dd>{account.service_account ? interactiveStatus(account.interactive_logon) : 'Не проверяется для обычных пользователей'}{account.interactive_logon?.target_host ? ` · ${account.interactive_logon.target_host}` : ''}</dd></div></dl></details>
    <section className="panel finding-detail-panel"><div className="panel-head"><div><h2>Что проверить и исправить</h2><p>{account.findings.length} найденных проблем</p></div></div>{account.findings.length ? <div className="finding-cards">{reasons.map(item => {
      const explanation = explainAccountFinding(item, account)
      return <article className="finding-card" key={item.id}>
        <div className="finding-card-top"><span className={`badge badge-${item.severity}`}>{severityPlain[item.severity] ?? item.severity}</span></div>
        <h3>{explanation.title}</h3><p>{explanation.text}</p>
        <div className="recommendation"><span>Что сделать</span><p>{item.recommendation}</p></div>
        <details className="finding-evidence"><summary>Технические данные</summary><Evidence evidence={item.evidence}/></details>
      </article>
    })}</div> : <Empty title="Проблемы не обнаружены" body="Для этого аккаунта правила анализа не сработали."/>}</section>
  </>
}

function DomainPolicy({ dashboard }) {
  const policy = dashboard.domain_policy ?? {}
  const policyAvailable = Object.keys(policy).length > 0
  const findings = [...(dashboard.domain_policy_findings ?? []), ...(dashboard.fine_grained_policy_findings ?? [])]
  return <><div className="section-head"><div><div className="eyebrow">Домен</div><h1>Парольная политика</h1><p>Параметры политики домена и причины найденных рисков.</p></div><div className="detail-score"><span>Risk Score · 100 = хуже</span><strong>{policyAvailable ? dashboard.domain_policy_risk_score ?? 0 : '—'}<small>/100</small></strong></div></div><div className="details-grid"><section className="panel detail-panel"><h2>Параметры</h2><dl className="facts"><div><dt>Минимальная длина</dt><dd>{policy.min_password_length == null ? 'Нет данных' : policy.min_password_length === 0 ? '0 — минимальная длина не задана' : policy.min_password_length}</dd></div><div><dt>Сложность пароля</dt><dd>{policy.password_complexity == null ? 'Нет данных' : policy.password_complexity ? 'Включена' : 'Отключена'}</dd></div><div><dt>История паролей</dt><dd>{policy.password_history_count == null ? 'Нет данных' : policy.password_history_count === 0 ? '0 — история не хранится' : policy.password_history_count}</dd></div><div><dt>Максимальный возраст</dt><dd>{policy.max_password_age_days == null ? 'Нет данных' : policy.max_password_age_days === 0 ? 'Без ограничения' : `${policy.max_password_age_days} дней`}</dd></div><div><dt>Минимальный возраст</dt><dd>{policy.min_password_age_days == null ? 'Нет данных' : `${policy.min_password_age_days} дней`}</dd></div><div><dt>Порог блокировки</dt><dd>{policy.lockout_threshold == null ? 'Нет данных' : policy.lockout_threshold === 0 ? '0 — блокировка отключена' : policy.lockout_threshold}</dd></div><div><dt>Длительность блокировки</dt><dd>{policy.lockout_duration_minutes == null ? 'Нет данных' : `${policy.lockout_duration_minutes} мин`}</dd></div><div><dt>Окно блокировки</dt><dd>{policy.lockout_observation_minutes == null ? 'Нет данных' : `${policy.lockout_observation_minutes} мин`}</dd></div></dl></section><section className="panel detail-panel"><h2>Оценка</h2><p>Правила проверяют минимальную длину, сложность и порог блокировки. Для аккаунтов с FGPP применяется результирующая политика, указанная в карточке аккаунта.</p></section></div><section className="panel detail-panel"><h2>Fine-Grained Password Policies</h2>{dashboard.fine_grained_policies?.length ? dashboard.fine_grained_policies.map(item => <div key={item.distinguished_name}><h3>{item.name}</h3><dl className="facts"><div><dt>Приоритет</dt><dd>{item.precedence}</dd></div><div><dt>Применяется к</dt><dd>{item.applies_to?.join(', ') || 'Нет данных'}</dd></div><div><dt>Длина / история</dt><dd>{item.min_password_length} / {item.password_history_count}</dd></div><div><dt>Сложность</dt><dd>{item.password_complexity ? 'Включена' : 'Отключена'}</dd></div><div><dt>Возраст: мин / макс</dt><dd>{item.min_password_age_days ?? '—'} / {item.max_password_age_days ?? '—'} дн.</dd></div><div><dt>Блокировка: порог / срок / окно</dt><dd>{item.lockout_threshold ?? '—'} / {item.lockout_duration_minutes ?? '—'} / {item.lockout_observation_minutes ?? '—'} мин.</dd></div></dl></div>) : <p className="muted">Политики не найдены или источник не оценён.</p>}</section><section className="panel finding-detail-panel"><div className="panel-head"><div><h2>Найденные проблемы</h2><p>{findings.length} срабатываний</p></div></div>{findings.length ? <div className="finding-cards">{findings.map(item => <article className="finding-card" key={item.id}><div className="finding-card-top"><Badge level={item.severity}/><strong>+{item.score} баллов</strong></div><h3>{item.title}</h3><p>{item.reason}</p><p><strong>Почему важно:</strong> {item.why_it_matters || item.reason}</p><div className="recommendation"><span>Что сделать</span><p>{item.recommendation}</p></div></article>)}</div> : <Empty title="Рисков политики не найдено" body="Все доступные базовые проверки пройдены или данные политики отсутствуют."/>}</section></>
}

function Computers({ computers, findings }) {
  const [search, setSearch] = useState('')
  const filtered = computers.filter(item => `${item.name} ${item.dns_hostname} ${item.operating_system}`.toLowerCase().includes(search.toLowerCase()))
  return <><div className="section-head"><div><div className="eyebrow">Объекты</div><h1>Компьютеры</h1><p>Компьютеры Active Directory и связанные риски.</p></div><span className="count-pill">{computers.length} объектов</span></div><section className="panel table-panel"><div className="toolbar"><label className="search-field"><Icon name="search" size={18}/><input value={search} onChange={e => setSearch(e.target.value)} placeholder="Имя, DNS или ОС"/></label></div><div className="table-scroll"><table><thead><tr><th>Компьютер</th><th>ОС</th><th>Состояние</th><th>Последний вход</th><th>Уровень</th><th title="Account Risk Score: 100 означает максимальный выявленный риск">Risk Score</th></tr></thead><tbody>{filtered.map(item => <tr key={item.id}><td><strong className="mono">{item.name}</strong><small className="table-sub">{item.dns_hostname}</small></td><td>{item.operating_system || '—'}</td><td>{item.enabled ? 'Включён' : 'Отключён'}</td><td>{formatDate(item.last_logon)}</td><td><Badge level={item.risk_level}/></td><td className="score-cell">{item.risk_score}/100</td></tr>)}</tbody></table></div>{!filtered.length && <Empty title="Компьютеры не найдены" body="Измените поисковый запрос или проверьте источник данных."/>}</section>{filtered.map(item => <section className="panel detail-panel" key={`detail-${item.id}`}><h2>{item.name}</h2><dl className="facts"><div><dt>DN</dt><dd className="mono">{item.distinguished_name}</dd></div><div><dt>Пароль установлен</dt><dd>{formatDate(item.password_last_set)}</dd></div><div><dt>Создан</dt><dd>{formatDate(item.when_created)}</dd></div><div><dt>SPN</dt><dd>{item.spns?.length ?? 0}</dd></div><div><dt>SIDHistory</dt><dd>{item.sid_history?.length ?? 0}</dd></div><div><dt>Делегация</dt><dd>{Object.keys(item.delegation ?? {}).length ? delegationLabel(item.delegation) : 'Не обнаружена'}</dd></div><div><dt>Находки</dt><dd>{findings.filter(finding => finding.account_id === item.id).map(finding => finding.title).join(', ') || 'Нет'}</dd></div></dl></section>)}</>
}

function Authentication({ authentication, dashboard }) {
  const status = authentication?.status ?? 'not_evaluated'
  return <><div className="section-head"><div><div className="eyebrow">События</div><h1>Аутентификация</h1><p>События Security Event Log и сигналы подбора паролей на момент scan {formatDateTime(dashboard.scanned_at)}.</p></div></div><section className="panel detail-panel"><h2>Источник событий</h2><dl className="facts"><div><dt>Статус</dt><dd>{status === 'pass' ? 'Проверен' : status === 'partial' ? 'Частичные данные' : status === 'error' ? 'Ошибка чтения' : 'Не оценён'}</dd></div><div><dt>Событий</dt><dd>{status === 'pass' || status === 'partial' ? authentication?.events ?? 0 : '—'}</dd></div><div><dt>Ошибки пароля после фильтрации</dt><dd>{status === 'pass' || status === 'partial' ? authentication?.failed_bad_password ?? 0 : '—'}</dd></div><div><dt>Сигналы</dt><dd>{status === 'pass' || status === 'partial' ? authentication?.findings?.length ?? 0 : '—'}</dd></div></dl>{status !== 'pass' && <p className="scope-note">{status === 'error' ? 'Не удалось прочитать Security Event Log. Проверьте подключение и права reader.' : status === 'partial' ? 'Собрана только часть журнала; выводы по атакам могут быть неполными.' : 'Источник Security Event Log не настроен или недоступен для оценки.'}</p>}</section><section className="panel detail-panel"><h2>Источники проверки</h2><dl className="facts">{Object.entries(dashboard.source_status ?? {}).map(([name, value]) => <div key={name}><dt>{sourceStatusLabels[name] ?? name}</dt><dd>{checkStatusLabels[value] ?? String(value)}</dd></div>)}</dl></section><section className="panel finding-detail-panel"><h2>Обнаруженные сигналы</h2>{authentication?.findings?.length ? authentication.findings.map(item => <article className="finding-card" key={item.id}><Badge level={item.severity}/><h3>{item.title}</h3><p>{item.reason}</p><Evidence evidence={item.evidence}/></article>) : <p className="muted">{status === 'pass' ? 'Сигналов не найдено.' : status === 'partial' ? 'В собранной части журнала сигналов не найдено; полную проверку подтвердить нельзя.' : 'Без доступа к журналу вывод о наличии или отсутствии атак невозможен.'}</p>}</section></>
}

const thresholdFields = [['inactive_days', 'Неактивность, дней', 1, 3650], ['old_password_days', 'Возраст пароля, дней', 1, 3650], ['inactive_computer_days', 'Неактивный компьютер, дней', 1, 3650], ['brute_attempts', 'Попыток для brute force', 2, 1000], ['spray_unique_users', 'Аккаунтов для spray', 3, 1000], ['auth_window_minutes', 'Окно событий, минут', 1, 1440], ['risk_medium_threshold', 'Порог Medium', 10, 98], ['risk_high_threshold', 'Порог High', 11, 99], ['risk_critical_threshold', 'Порог Critical', 12, 100]]

function Settings({ connection, onTest, testing, thresholds, onThresholdChange, onSave, saving }) {
  const [validation, setValidation] = useState('')
  function submit() {
    for (const [key, label, min, max] of thresholdFields) {
      const value = thresholds[key]
      if (!Number.isInteger(value) || value < min || value > max) {
        setValidation(`${label}: укажите целое число от ${min} до ${max}.`)
        return
      }
    }
    if (!(thresholds.risk_medium_threshold < thresholds.risk_high_threshold && thresholds.risk_high_threshold < thresholds.risk_critical_threshold)) {
      setValidation('Пороги риска должны возрастать: Medium < High < Critical.')
      return
    }
    setValidation('')
    onSave()
  }
  return <><div className="section-head"><div><div className="eyebrow">Подключение</div><h1>Источник Active Directory</h1></div></div>
    <section className="panel settings-panel"><div className="settings-title"><div className="server-icon"><Icon name="server" size={26}/></div><div><h2>{connection.connection_mode === 'AD Gateway' ? 'AD Gateway' : 'LDAP-подключение'}</h2><p>{connection.configured && !connection.password_required ? 'Параметры заполнены' : 'Ожидает настройки сервера'}</p></div><span className={`status-pill ${connection.connection_test_status === 'success' ? 'ready' : ''}`}>{connection.connection_test_status === 'success' ? 'Подключено' : connection.connection_test_status === 'failed' ? 'Ошибка проверки' : 'Не проверено'}</span></div><dl className="facts"><div><dt>Сервер / DC</dt><dd>{connection.host || '—'}</dd></div><div><dt>Порт</dt><dd>{connection.port ?? "—"}</dd></div><div><dt>Домен</dt><dd>{connection.domain || '—'}</dd></div><div><dt>Base DN</dt><dd>{connection.base_dn || '—'}</dd></div><div><dt>Учётная запись чтения</dt><dd>{connection.reader_username || '—'}</dd></div><div><dt>Режим</dt><dd>{connection.read_only ? 'Только чтение' : 'Неизвестно'}</dd></div><div><dt>Соединение</dt><dd>{connection.connection_mode === 'AD Gateway' ? 'HTTPS Gateway' : connection.use_ssl ? 'LDAPS' : 'LDAP через Tailscale'}</dd></div><div><dt>Успешная проверка</dt><dd>{formatDateTime(connection.last_connection_success)}</dd></div><div><dt>Последний scan</dt><dd>{formatDateTime(connection.last_scan)} · {sourceLabels[connection.last_scan_source] ?? connection.last_scan_source ?? '—'}</dd></div><div><dt>Объекты последнего scan</dt><dd>{connection.last_users ?? '—'} users / {connection.last_groups ?? '—'} groups</dd></div></dl><p className="credential-note">Данные для доступа к каталогу скрыты в интерфейсе.</p><button className="primary-button" onClick={onTest} disabled={!connection.configured || connection.password_required || testing}>{testing ? 'Проверяем…' : 'Проверить соединение'}</button></section>
    <section className="panel settings-panel"><h2>Пороги анализа</h2><p>Сохранённые значения применятся при следующем сканировании.</p><div className="threshold-grid">{thresholdFields.map(([key, label, min, max]) => <label key={key}>{label}<input type="number" min={min} max={max} value={thresholds[key] ?? ''} onChange={e => onThresholdChange({ ...thresholds, [key]: e.target.value === '' ? '' : Number(e.target.value) })}/></label>)}</div><p className="credential-note">Пороги риска должны возрастать: Medium &lt; High &lt; Critical.</p>{validation && <p className="alert" role="alert">{validation}</p>}<button className="primary-button" onClick={submit} disabled={saving}>{saving ? 'Сохраняем…' : 'Сохранить пороги'}</button></section>
  </>
}

function delegationLabel(value) { const parts = []; if (value?.unconstrained) parts.push('Неограниченная'); if (value?.constrained_targets?.length) parts.push(`К сервисам: ${value.constrained_targets.join(', ')}`); if (value?.rbcd_configured) parts.push('RBCD'); return parts.join(' · ') || 'Не обнаружена' }

function formatDate(date) { return date ? new Intl.DateTimeFormat('ru-RU', { day: '2-digit', month: 'short', year: 'numeric' }).format(new Date(date)) : 'Нет данных' }
function formatDateTime(date) { return date ? new Intl.DateTimeFormat('ru-RU', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(date)) : 'Нет данных' }
function daysAgo(date) { return Math.max(0, Math.floor((Date.now() - new Date(date).getTime()) / 86400000)) }

export default function App() {
  const [auth, setAuth] = useState(null)
  const [loginName, setLoginName] = useState('')
  const [loginPassword, setLoginPassword] = useState('')
  const [loginError, setLoginError] = useState('')
  const [loggingIn, setLoggingIn] = useState(false)
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
    const [config, ldap, history] = await Promise.all([api('/config'), api('/connection/status'), api('/scans')])
    setConnection(ldap); setScans(history); setThresholds(config)
    if (!history.length) {
      setDashboard(null); setFindings([]); setAccounts([]); setComputers([]); setAuthentication(null); setComparison(null)
      setSource(ldap.configured && !ldap.password_required ? 'ldap' : 'demo')
      return
    }
    const [summary, risks, users, machines, auth, delta] = await Promise.all([
      api('/dashboard'), api('/findings'), api('/accounts'), api('/computers'), api('/authentication'), api('/scans/compare'),
    ])
    setDashboard(summary); setFindings(risks); setAccounts(users); setComputers(machines); setAuthentication(auth); setComparison(delta)
    setSource(current => current === 'demo' && summary.source === 'demo' ? 'demo' : summary.source === 'ldap' || ldap.configured ? 'ldap' : 'demo')
  }, [])

  useEffect(() => {
    api('/auth/me').then(value => setAuth(value.auth_required ? 'login' : 'local'))
      .catch(e => { setAuth('error'); setLoginError(e.message) })
    const expired = () => { setAccessToken(null); setAuth('login'); setLoginError('Сессия истекла. Войдите снова.') }
    window.addEventListener('radar-session-expired', expired)
    return () => window.removeEventListener('radar-session-expired', expired)
  }, [])
  useEffect(() => { if (auth === 'local' || auth === 'signed-in') refresh().catch(e => setError(e.message)).finally(() => setLoading(false)) }, [auth, refresh])
  useEffect(() => { if (notice) { const timeout = setTimeout(() => setNotice(null), 5500); return () => clearTimeout(timeout) } }, [notice])

  async function signIn(event) {
    event.preventDefault()
    setLoggingIn(true); setLoginError('')
    try {
      const result = await api('/auth/login', { method: 'POST', body: JSON.stringify({ username: loginName, password: loginPassword }) })
      setAccessToken(result.token); setLoginPassword(''); setLoading(true); setAuth('signed-in')
    } catch (e) { setLoginError(e.message) } finally { setLoggingIn(false) }
  }

  async function signOut() {
    try { await api('/auth/logout', { method: 'POST' }) } catch { /* Session may already be expired. */ }
    setAccessToken(null); setAuth('login'); setDashboard(null); setLoginPassword('')
  }

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

  if (auth === null) return <div className="loading">Проверяем доступ…</div>
  if (auth === 'error') return <div className="login-page"><section className="panel login-panel"><h1>Сервис недоступен</h1><p>{loginError}</p></section></div>
  if (auth === 'login') return <div className="login-page"><form className="panel login-panel" onSubmit={signIn}><h1>Identity Risk</h1><p>Вход для участников команды</p><label>Логин<input autoComplete="username" value={loginName} onChange={e => setLoginName(e.target.value)} required/></label><label>Пароль<input type="password" autoComplete="current-password" value={loginPassword} onChange={e => setLoginPassword(e.target.value)} required/></label>{loginError && <p className="alert" role="alert">{loginError}</p>}<button className="primary-button" disabled={loggingIn}>{loggingIn ? 'Входим…' : 'Войти'}</button></form></div>

  return <div className="app-shell"><aside className="sidebar"><div className="brand"><div><strong>Identity Risk</strong><span>Security workspace</span></div></div><div className="nav-label">Рабочая область</div><nav aria-label="Основная навигация">{nav.map(item => <button key={item.key} onClick={() => setPage(item.key)} aria-current={targetPage === item.key || (targetPage === 'detail' && item.key === 'accounts') ? 'page' : undefined} className={`nav-link ${targetPage === item.key || (targetPage === 'detail' && item.key === 'accounts') ? 'active' : ''}`}><Icon name={item.icon} size={19}/><span>{item.label}</span></button>)}</nav></aside>
    <main className="main"><header className="topbar"><div className="breadcrumb">Рабочая область <span>/</span> <strong>{page === 'detail' ? 'Карточка аккаунта' : nav.find(item => item.key === page)?.label}</strong></div><div className="top-actions"><label className="source-select"><span>Источник</span><select value={source} onChange={e => setSource(e.target.value)}><option value="demo">Демо</option><option value="ldap" disabled={!connection?.configured}>Active Directory</option></select><Icon name="chevron" size={15}/></label><button className="scan-button" disabled={scanning || (source === 'ldap' && (!connection?.configured || connection.password_required))} onClick={runScan}><Icon name="refresh" size={17}/>{scanning ? 'Чтение AD и анализ…' : 'Запустить анализ'}</button>{auth === 'signed-in' && <button className="logout-button" onClick={signOut}>Выйти</button>}</div></header>
      <div className="content" style={{ '--page-direction': direction }}>{scanning && <div className="notice" role="status">Анализ запущен {scanStartedAt?.toLocaleTimeString('ru-RU')} · Идёт чтение каталога и расчёт рисков. Результат появится после завершения.</div>}{error && <div className="alert" role="alert"><span>{error}</span><button onClick={() => setError(null)} aria-label="Закрыть">×</button></div>}{notice && <div className="notice" role="status">{notice}</div>}{loading ? <div className="loading">Загрузка результатов…</div> : dashboard ? <>
        {dashboard.source === 'demo' && <div className="notice" role="status">Демо-данные: этот результат не отражает состояние Active Directory. Выберите Active Directory и запустите анализ для живых данных.</div>}
        <div className="scan-meta"><span>{sourceLabels[dashboard.source]} · Сканирование {formatDateTime(dashboard.scanned_at)}{dashboard.duration_ms != null ? ` · ${dashboard.duration_ms} мс` : ''}</span><button onClick={() => downloadCsv().catch(e => setError(e.message))} className="export-link"><Icon name="download" size={17}/> Скачать CSV</button></div>
        <div className="page-stage" data-page={targetPage}>
        <div key={page} className={`page-content page-${transition}`} inert={transition === 'exit' ? true : undefined}>
        {page === 'dashboard' && <Dashboard dashboard={dashboard} accounts={accounts} scans={scans} comparison={comparison} onOpenAccount={openAccount}/>}
        {page === 'findings' && <Findings findings={findings} accounts={accounts} onOpenAccount={openAccount}/>}
        {page === 'accounts' && <Accounts accounts={accounts} findings={findings} onOpenAccount={openAccount}/>}
        {page === 'computers' && <Computers computers={computers} findings={findings}/>}
        {page === 'detail' && detail && <AccountDetails account={detail} riskThresholds={dashboard.risk_thresholds} inactiveDays={dashboard.thresholds?.inactive_days} onBack={() => setPage('accounts')}/>}
        {page === 'policy' && <DomainPolicy dashboard={dashboard}/>}
        {page === 'authentication' && <Authentication authentication={authentication} dashboard={dashboard}/>}
        {page === 'settings' && <Settings connection={connection ?? {}} onTest={testConnection} testing={testing} thresholds={thresholds} onThresholdChange={setThresholds} onSave={saveThresholds} saving={saving}/>}
        </div></div>
      </> : page === 'settings' ? <div className="page-content"><Settings connection={connection ?? {}} onTest={testConnection} testing={testing} thresholds={thresholds} onThresholdChange={setThresholds} onSave={saveThresholds} saving={saving}/></div> : <Empty title="Нет результатов" body="Запустите анализ, чтобы увидеть результаты. Настройки подключения доступны в разделе «Подключение»."/>}</div>
    </main></div>
}
