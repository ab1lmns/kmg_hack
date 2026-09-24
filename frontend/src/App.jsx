import { useCallback, useEffect, useMemo, useState } from 'react'
import { api } from './api.js'

const severityLabels = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', safe: 'Без риска' }
const sourceLabels = { demo: 'Демо', ldap: 'Active Directory' }

function Badge({ level }) {
  return <span className={`badge badge-${level}`}>{severityLabels[level] ?? level}</span>
}

function Icon({ name, size = 20 }) {
  const paths = {
    radar: <><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><path d="M12 12 18.4 5.6"/><circle cx="12" cy="12" r="1" fill="currentColor" stroke="none"/></>,
    dashboard: <><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></>,
    shield: <><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/><path d="m9 12 2 2 4-4"/></>,
    users: <><circle cx="9" cy="8" r="3"/><path d="M3 20v-2a6 6 0 0 1 12 0v2"/><path d="M17 5a3 3 0 0 1 0 6M18 14a5 5 0 0 1 3 5v1"/></>,
    settings: <><path d="M4 7h16M4 17h16"/><circle cx="9" cy="7" r="2" fill="#0b1220"/><circle cx="15" cy="17" r="2" fill="#0b1220"/></>,
    arrow: <path d="m9 18 6-6-6-6"/>,
    download: <><path d="M12 3v12m0 0 4-4m-4 4-4-4M4 17v3h16v-3"/></>,
    refresh: <><path d="M20 11a8 8 0 1 0-2 6"/><path d="M20 4v7h-7"/></>,
    search: <><circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5"/></>,
    chevron: <path d="m6 9 6 6 6-6"/>,
    server: <><rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6.5h.01M7 17.5h.01" strokeWidth="3"/></>,
  }
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name]}</svg>
}

function Empty({ title, body }) {
  return <div className="empty"><div className="empty-icon"><Icon name="shield" size={25}/></div><h3>{title}</h3><p>{body}</p></div>
}

function Metric({ label, value, tone, helper }) {
  return <div className="metric"><div className="metric-label">{label}</div><div className={`metric-value ${tone ?? ''}`}>{value}</div>{helper && <div className="metric-helper">{helper}</div>}</div>
}

function Dashboard({ dashboard, accounts, scans, onOpenAccount }) {
  const top = dashboard.top_risky_users ?? []
  const maxCategory = Math.max(...(dashboard.categories ?? []).map(item => item.count), 1)
  const history = scans.filter(item => item.source === dashboard.source).slice(0, 8).reverse()
  return <>
    <div className="section-head"><div><div className="eyebrow">Обзор</div><h1>Состояние Active Directory</h1><p>Приоритеты последнего сканирования и учётные записи, требующие проверки.</p></div></div>
    <div className="overview-grid">
      <section className="score-card"><div className="score-card-top"><span>AD Security Score</span><Icon name="shield" size={23}/></div><div className="score-number">{dashboard.security_score}<span>/100</span></div><div className="score-track"><div style={{width: `${dashboard.security_score}%`}} /></div><p>100 означает минимальный выявленный риск. Оценка основана на среднем риске аккаунтов и политики домена.</p></section>
      <Metric label="Critical" value={dashboard.findings.critical} tone="danger" helper="Немедленная проверка" />
      <Metric label="High" value={dashboard.findings.high} tone="warning" helper="Высокий приоритет" />
      <Metric label="Medium" value={dashboard.findings.medium} tone="neutral" helper="Плановые проверки" />
      <Metric label="Low" value={dashboard.findings.low} tone="neutral" helper="Замечания" />
    </div>
    <div className="quick-stats"><span><strong>{dashboard.total_users}</strong> аккаунтов проверено</span><span><strong>{dashboard.inactive_accounts ?? '—'}</strong> неактивных</span><span><strong>{dashboard.service_accounts}</strong> сервисных</span><span><strong>{dashboard.privileged_accounts}</strong> привилегированных</span><span><strong>{dashboard.finding_count}</strong> находок</span></div>
    <div className="two-col">
      <section className="panel"><div className="panel-head"><div><h2>Наиболее рискованные аккаунты</h2><p>Откройте карточку, чтобы увидеть причины и рекомендации.</p></div></div>
        {top.length ? <div className="top-list">{top.map((item, index) => <button className="top-row" key={item.id} onClick={() => onOpenAccount(item.id)}><span className="top-rank">{String(index + 1).padStart(2, '0')}</span><span className="top-person"><strong>{item.username}</strong><small>{item.display_name}</small></span><Badge level={item.risk_level}/><strong className="top-score">{item.risk_score}</strong><Icon name="arrow" size={17}/></button>)}</div> : <Empty title="Рисков нет" body="После сканирования здесь появятся аккаунты с наибольшим риском."/>}
      </section>
      <section className="panel"><div className="panel-head"><div><h2>Категории рисков</h2><p>Наиболее частые срабатывания правил.</p></div></div>
        {dashboard.categories?.length ? <div className="category-list">{dashboard.categories.slice(0, 6).map(item => <div className="category" key={item.rule_id}><div><span>{friendlyRule(item.rule_id)}</span><strong>{item.count}</strong></div><div className="category-track"><div style={{width: `${Math.max(7, item.count / maxCategory * 100)}%`}}/></div></div>)}</div> : <Empty title="Категорий нет" body="В этом сканировании проблемы не обнаружены."/>}
      </section>
    </div>
    <div className="two-col secondary-panels"><section className="panel"><div className="panel-head"><div><h2>Политика паролей домена</h2><p>Результат базовых проверок настроек.</p></div><button className="text-link" onClick={() => onOpenAccount('__domain__')}>Подробнее →</button></div><div className="policy-summary"><span>Минимальная длина: <strong>{dashboard.domain_policy?.min_password_length ?? '—'}</strong></span><span>Сложность: <strong>{dashboard.domain_policy?.password_complexity == null ? '—' : dashboard.domain_policy.password_complexity ? 'включена' : 'отключена'}</strong></span><span>Блокировка: <strong>{dashboard.domain_policy?.lockout_threshold ?? '—'}</strong></span></div><p className="policy-count">{dashboard.domain_policy_findings?.length ?? 0} проблем · Risk Score {dashboard.domain_policy_risk_score ?? 0}/100</p></section>
      <section className="panel"><div className="panel-head"><div><h2>Динамика Security Score</h2><p>Последние сканирования источника «{sourceLabels[dashboard.source]}».</p></div></div>{history.length > 1 ? <div className="history-bars">{history.map(item => <div className="history-item" key={item.scan_id} title={`${formatDate(item.scanned_at)} — ${item.summary.security_score}/100`}><strong>{item.summary.security_score}</strong><div className="history-track"><div style={{height: `${item.summary.security_score}%`}}/></div><small>{new Date(item.scanned_at).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' })}</small></div>)}</div> : <p className="muted">Динамика появится после второго сканирования.</p>}</section></div>
    {accounts.length > 0 && <p className="footnote">Показатели относятся к последнему завершённому сканированию. Изменения в AD появятся после повторного запуска.</p>}
  </>
}

const friendlyNames = {
  INACTIVE_ACCOUNT: 'Неактивные аккаунты', PASSWORD_NEVER_EXPIRES: 'Бессрочные пароли',
  OLD_PASSWORD: 'Старые пароли', PASSWORD_NOT_REQUIRED: 'Ослабленные требования',
  LOCKED_ACCOUNT: 'Блокировки', EXPIRED_ACCOUNT: 'Истёкшие аккаунты',
  DIRECT_PRIVILEGE: 'Прямые привилегии', NESTED_PRIVILEGE: 'Вложенные привилегии',
  INACTIVE_PRIVILEGED: 'Неактивные администраторы', DISABLED_PRIVILEGED: 'Отключённые администраторы', MULTIPLE_PRIVILEGES: 'Несколько ролей',
  SERVICE_PRIVILEGED: 'Привилегии сервисных аккаунтов', INACTIVE_SERVICE: 'Неиспользуемые сервисные аккаунты',
  MISSING_OWNER: 'Нет владельца', SHORT_MIN_PASSWORD: 'Короткий пароль',
  NO_PASSWORD_COMPLEXITY: 'Сложность пароля отключена', NO_LOCKOUT: 'Нет блокировки',
}
function friendlyRule(rule) { return friendlyNames[rule] ?? rule }

function Findings({ findings, onOpenAccount }) {
  const [severity, setSeverity] = useState('all')
  const [search, setSearch] = useState('')
  const filtered = useMemo(() => findings.filter(item =>
    (severity === 'all' || item.severity === severity) &&
    `${item.username} ${item.title} ${item.reason}`.toLowerCase().includes(search.toLowerCase()),
  ), [findings, severity, search])
  return <><div className="section-head"><div><div className="eyebrow">Анализ</div><h1>Найденные риски</h1><p>Каждая строка содержит причину, подтверждение и рекомендуемое действие.</p></div><span className="count-pill">{filtered.length} из {findings.length}</span></div>
    <section className="panel table-panel"><div className="toolbar"><label className="search-field"><Icon name="search" size={18}/><input value={search} onChange={e => setSearch(e.target.value)} placeholder="Поиск по аккаунту или риску"/></label><label className="select-wrap"><span>Уровень</span><select value={severity} onChange={e => setSeverity(e.target.value)}><option value="all">Все</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select><Icon name="chevron" size={16}/></label></div>
      {filtered.length ? <div className="table-scroll"><table><thead><tr><th>Уровень</th><th>Аккаунт</th><th>Проблема</th><th>Причина</th><th>Балл</th><th></th></tr></thead><tbody>{filtered.map(item => <tr key={item.id} onClick={() => onOpenAccount(item.account_id)} tabIndex="0" onKeyDown={e => { if (e.key === 'Enter') onOpenAccount(item.account_id) }}><td><Badge level={item.severity}/></td><td className="mono">{item.username}</td><td><strong>{item.title}</strong></td><td className="muted-cell">{item.reason}</td><td className="mono">+{item.score}</td><td><Icon name="arrow" size={16}/></td></tr>)}</tbody></table></div> : <Empty title="Ничего не найдено" body="Измените фильтр или поисковый запрос."/>}
    </section></>
}

function Accounts({ accounts, onOpenAccount }) {
  const [search, setSearch] = useState('')
  const filtered = accounts.filter(item => `${item.username} ${item.display_name} ${item.department}`.toLowerCase().includes(search.toLowerCase()))
  return <><div className="section-head"><div><div className="eyebrow">Объекты</div><h1>Учётные записи</h1><p>Пользователи и сервисные аккаунты с оценкой риска.</p></div><span className="count-pill">{accounts.length} объектов</span></div>
    <section className="panel table-panel"><div className="toolbar"><label className="search-field"><Icon name="search" size={18}/><input value={search} onChange={e => setSearch(e.target.value)} placeholder="Поиск по имени или отделу"/></label></div><div className="table-scroll"><table><thead><tr><th>Аккаунт</th><th>Тип</th><th>Отдел</th><th>Права</th><th>Уровень</th><th>Risk Score</th><th></th></tr></thead><tbody>{filtered.map(item => <tr key={item.id} onClick={() => onOpenAccount(item.id)} tabIndex="0" onKeyDown={e => { if (e.key === 'Enter') onOpenAccount(item.id) }}><td><strong className="mono">{item.username}</strong><small className="table-sub">{item.display_name}</small></td><td>{item.service_account ? 'Сервисный' : 'Пользователь'}</td><td>{item.department || '—'}</td><td>{item.privileged ? <span className="privileged">Есть</span> : 'Нет'}</td><td><Badge level={item.risk_level}/></td><td className="score-cell">{item.risk_score}/100</td><td><Icon name="arrow" size={16}/></td></tr>)}</tbody></table></div>{!filtered.length && <Empty title="Аккаунты не найдены" body="Попробуйте другой поисковый запрос."/>}</section></>
}

function AccountDetails({ account, onBack }) {
  return <><button className="back-button" onClick={onBack}>← К списку аккаунтов</button><div className="section-head"><div><div className="eyebrow">Карточка аккаунта</div><h1>{account.username}</h1><p>{account.display_name} · {account.department || 'Отдел не указан'}</p></div><div className="detail-score"><span>Risk Score</span><strong>{account.risk_score}<small>/100</small></strong><Badge level={account.risk_level}/></div></div>
    <div className="details-grid"><section className="panel detail-panel"><h2>Сведения</h2><dl className="facts"><div><dt>Тип</dt><dd>{account.service_account ? 'Сервисный аккаунт' : 'Пользователь'}</dd></div><div><dt>Состояние</dt><dd>{account.enabled ? 'Включён' : 'Отключён'}</dd></div><div><dt>Последний вход</dt><dd>{formatDate(account.last_logon)}</dd></div><div><dt>Пароль установлен</dt><dd>{formatDate(account.password_last_set)}</dd></div><div><dt>Владелец</dt><dd>{account.owner || 'Не указан'}</dd></div><div><dt>Привилегии</dt><dd>{account.privileged ? 'Есть' : 'Не найдены'}</dd></div></dl></section>
      <section className="panel detail-panel"><h2>Группы и пути доступа</h2><div className="tags">{account.groups.length ? account.groups.map(group => <span key={group}>{group}</span>) : <p className="muted">Группы не указаны</p>}</div>{account.privilege_paths.length > 0 && <><h3>Путь до административной группы</h3><div className="path-list">{account.privilege_paths.map((path, index) => <div className="privilege-path" key={index}>{path.map((part, i) => <span key={i}>{i > 0 && <b>→</b>}{part}</span>)}</div>)}</div></>}</section></div>
    <section className="panel finding-detail-panel"><div className="panel-head"><div><h2>Причины риска и рекомендации</h2><p>{account.findings.length} найденных проблем</p></div></div>{account.findings.length ? <div className="finding-cards">{account.findings.map(item => <article className="finding-card" key={item.id}><div className="finding-card-top"><Badge level={item.severity}/><strong>+{item.score} баллов</strong></div><h3>{item.title}</h3><p>{item.reason}</p><div className="recommendation"><span>Что сделать</span><p>{item.recommendation}</p></div></article>)}</div> : <Empty title="Проблемы не обнаружены" body="Для этого аккаунта правила анализа не сработали."/>}</section>
  </>
}

function DomainPolicy({ dashboard }) {
  const policy = dashboard.domain_policy ?? {}
  const findings = dashboard.domain_policy_findings ?? []
  return <><div className="section-head"><div><div className="eyebrow">Домен</div><h1>Парольная политика</h1><p>Базовые параметры домена и причины найденных рисков.</p></div><div className="detail-score"><span>Risk Score</span><strong>{dashboard.domain_policy_risk_score ?? 0}<small>/100</small></strong></div></div><div className="details-grid"><section className="panel detail-panel"><h2>Параметры</h2><dl className="facts"><div><dt>Минимальная длина</dt><dd>{policy.min_password_length ?? 'Нет данных'}</dd></div><div><dt>Сложность пароля</dt><dd>{policy.password_complexity == null ? 'Нет данных' : policy.password_complexity ? 'Включена' : 'Отключена'}</dd></div><div><dt>Порог блокировки</dt><dd>{policy.lockout_threshold ?? 'Нет данных'}</dd></div></dl></section><section className="panel detail-panel"><h2>Оценка</h2><p>Правила выявляют минимальную длину менее 12 символов, отключённую сложность и отсутствие порога блокировки. Настройки Fine-Grained Password Policies пока не анализируются.</p></section></div><section className="panel finding-detail-panel"><div className="panel-head"><div><h2>Найденные проблемы</h2><p>{findings.length} срабатываний</p></div></div>{findings.length ? <div className="finding-cards">{findings.map(item => <article className="finding-card" key={item.id}><div className="finding-card-top"><Badge level={item.severity}/><strong>+{item.score} баллов</strong></div><h3>{item.title}</h3><p>{item.reason}</p><div className="recommendation"><span>Что сделать</span><p>{item.recommendation}</p></div></article>)}</div> : <Empty title="Рисков политики не найдено" body="Все доступные базовые проверки пройдены или данные политики отсутствуют."/>}</section></>
}

function Settings({ connection, onTest, testing, thresholds, onThresholdChange, ldapPassword, onPasswordChange }) {
  return <><div className="section-head"><div><div className="eyebrow">Подключение</div><h1>Источник Active Directory</h1><p>Адрес и логин backend читает из <code>backend/.env</code>. Пароль вводится здесь и хранится только до закрытия вкладки.</p></div></div>
    <section className="panel settings-panel"><div className="settings-title"><div className="server-icon"><Icon name="server" size={26}/></div><div><h2>LDAP-подключение</h2><p>{connection.configured ? 'Параметры заполнены' : 'Ожидает настройки сервера'}</p></div><span className={`status-pill ${connection.configured ? 'ready' : ''}`}>{connection.configured ? 'Настроено' : 'Не настроено'}</span></div><dl className="facts"><div><dt>Сервер</dt><dd>{connection.host || '—'}</dd></div><div><dt>Порт</dt><dd>{connection.port}</dd></div><div><dt>Base DN</dt><dd>{connection.base_dn || '—'}</dd></div><div><dt>Соединение</dt><dd>{connection.use_ssl ? 'LDAPS' : 'LDAP'}</dd></div></dl><label className="password-field">Пароль учётной записи сканера<input type="password" autoComplete="off" value={ldapPassword} onChange={e => onPasswordChange(e.target.value)} placeholder="Введите перед проверкой или сканированием"/></label><p className="credential-note">Пароль передаётся backend при запросе и не сохраняется в базе или файле. Для удалённого доступа к приложению нужен HTTPS.</p><button className="primary-button" onClick={onTest} disabled={!connection.configured || testing || (connection.password_required && !ldapPassword)}>{testing ? 'Проверяем…' : 'Проверить соединение'}</button></section>
    <section className="panel settings-panel"><h2>Пороги анализа</h2><p>Эти значения применятся при следующем сканировании.</p><div className="threshold-grid"><label>Неактивность, дней<input type="number" min="1" max="3650" value={thresholds.inactive_days} onChange={e => onThresholdChange({ ...thresholds, inactive_days: Number(e.target.value) })}/></label><label>Возраст пароля, дней<input type="number" min="1" max="3650" value={thresholds.old_password_days} onChange={e => onThresholdChange({ ...thresholds, old_password_days: Number(e.target.value) })}/></label></div></section>
    <section className="panel settings-panel"><h2>Как подключить сервер</h2><ol className="setup-list"><li>Скопируйте <code>backend/.env.example</code> в <code>backend/.env</code>.</li><li>Укажите адрес контроллера, Base DN и логин обычной учётной записи с правом чтения.</li><li>Перезапустите backend, введите пароль выше и проверьте соединение.</li><li>Выберите Active Directory и запустите анализ.</li></ol></section>
  </>
}

function formatDate(date) { return date ? new Intl.DateTimeFormat('ru-RU', { day: '2-digit', month: 'short', year: 'numeric' }).format(new Date(date)) : 'Нет данных' }

export default function App() {
  const [page, setPage] = useState('dashboard')
  const [accountId, setAccountId] = useState(null)
  const [dashboard, setDashboard] = useState(null)
  const [findings, setFindings] = useState([])
  const [accounts, setAccounts] = useState([])
  const [scans, setScans] = useState([])
  const [connection, setConnection] = useState(null)
  const [ldapPassword, setLdapPassword] = useState('')
  const [thresholds, setThresholds] = useState({ inactive_days: 90, old_password_days: 180 })
  const [source, setSource] = useState('demo')
  const [loading, setLoading] = useState(true)
  const [scanning, setScanning] = useState(false)
  const [testing, setTesting] = useState(false)
  const [notice, setNotice] = useState(null)
  const [error, setError] = useState(null)

  const refresh = useCallback(async () => {
    const [summary, risks, users, ldap, history] = await Promise.all([
      api('/dashboard'), api('/findings'), api('/accounts'), api('/connection/status'), api('/scans'),
    ])
    setDashboard(summary); setFindings(risks); setAccounts(users); setConnection(ldap); setScans(history)
    setThresholds(summary.thresholds ?? { inactive_days: 90, old_password_days: 180 })
  }, [])

  useEffect(() => { refresh().catch(e => setError(e.message)).finally(() => setLoading(false)) }, [refresh])
  useEffect(() => { if (notice) { const timeout = setTimeout(() => setNotice(null), 5500); return () => clearTimeout(timeout) } }, [notice])

  async function runScan() {
    setScanning(true); setError(null)
    try {
      const result = await api('/scans', { method: 'POST', body: JSON.stringify({ source, ...thresholds, ...(source === 'ldap' ? { ldap_password: ldapPassword } : {}) }) })
      await refresh()
      setPage('dashboard'); setAccountId(null)
      setNotice(`Сканирование завершено: ${result.users_scanned} аккаунтов, ${result.findings_found} находок`)
    } catch (e) { setError(e.message) } finally { setScanning(false) }
  }

  async function testConnection() {
    setTesting(true); setError(null)
    try { const result = await api('/connection/test', { method: 'POST', body: JSON.stringify({ ldap_password: ldapPassword }) }); setNotice(`Соединение установлено: ${result.users_found} пользователей, ${result.groups_found} групп`) }
    catch (e) { setError(e.message) } finally { setTesting(false) }
  }

  function openAccount(id) { if (id === '__domain__') { setPage('policy'); return } setAccountId(id); setPage('detail') }
  const selectedAccount = accounts.find(item => item.id === accountId)
  const detail = selectedAccount ? { ...selectedAccount, findings: findings.filter(item => item.account_id === accountId) } : null
  const nav = [{ key: 'dashboard', label: 'Обзор', icon: 'dashboard' }, { key: 'findings', label: 'Риски', icon: 'shield' }, { key: 'accounts', label: 'Аккаунты', icon: 'users' }, { key: 'policy', label: 'Политика домена', icon: 'shield' }, { key: 'settings', label: 'Подключение', icon: 'settings' }]

  return <div className="app-shell"><aside className="sidebar"><div className="brand"><div className="brand-mark"><Icon name="radar" size={23}/></div><div><strong>Identity Risk</strong><span>RADAR</span></div></div><div className="nav-label">Рабочая область</div><nav aria-label="Основная навигация">{nav.map(item => <button key={item.key} onClick={() => { setPage(item.key); setAccountId(null) }} className={`nav-link ${page === item.key || (page === 'detail' && item.key === 'accounts') ? 'active' : ''}`}><Icon name={item.icon} size={19}/><span>{item.label}</span></button>)}</nav><div className="sidebar-bottom"><span className="live-dot"/> {dashboard?.source === 'ldap' ? 'Данные Active Directory' : 'Демонстрационные данные'}</div></aside>
    <main className="main"><header className="topbar"><div className="breadcrumb">Infrastructure Risk Radar <span>/</span> Identity</div><div className="top-actions"><label className="source-select"><span>Источник</span><select value={source} onChange={e => setSource(e.target.value)}><option value="demo">Демо</option><option value="ldap" disabled={!connection?.configured}>Active Directory</option></select><Icon name="chevron" size={15}/></label><button className="scan-button" disabled={scanning} onClick={runScan}><Icon name="refresh" size={17}/>{scanning ? 'Сканирование…' : 'Запустить анализ'}</button></div></header>
      <div className="content">{error && <div className="alert" role="alert"><span>{error}</span><button onClick={() => setError(null)} aria-label="Закрыть">×</button></div>}{notice && <div className="notice" role="status">{notice}</div>}{loading ? <div className="loading">Загрузка результатов…</div> : dashboard ? <>
        <div className="scan-meta"><span className="meta-dot"/><span>{sourceLabels[dashboard.source]} · Сканирование {formatDate(dashboard.scanned_at)}</span><a href="/api/export/csv" className="export-link"><Icon name="download" size={17}/> Скачать CSV</a></div>
        {page === 'dashboard' && <Dashboard dashboard={dashboard} accounts={accounts} scans={scans} onOpenAccount={openAccount}/>}
        {page === 'findings' && <Findings findings={findings} onOpenAccount={openAccount}/>}
        {page === 'accounts' && <Accounts accounts={accounts} onOpenAccount={openAccount}/>}
        {page === 'detail' && detail && <AccountDetails account={detail} onBack={() => setPage('accounts')}/>}
        {page === 'policy' && <DomainPolicy dashboard={dashboard}/>}
        {page === 'settings' && <Settings connection={connection ?? {}} onTest={testConnection} testing={testing} thresholds={thresholds} onThresholdChange={setThresholds} ldapPassword={ldapPassword} onPasswordChange={setLdapPassword}/>}
      </> : <Empty title="Нет результатов" body="Запустите демонстрационное сканирование, чтобы увидеть анализ."/>}</div>
    </main></div>
}
