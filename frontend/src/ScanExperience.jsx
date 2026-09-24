import { useEffect, useState } from 'react'

const sourceLabels = { ldap: 'Active Directory', demo: 'Демо' }
const levels = [
  ['critical', 'Критично'],
  ['high', 'Высокий'],
  ['medium', 'Средний'],
  ['low', 'Низкий'],
]

export function securityScoreTone(score) {
  return score < 40 ? 'low' : score < 70 ? 'medium' : 'good'
}

function scanDate(value) {
  return value ? new Intl.DateTimeFormat('ru-RU', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value)) : 'Нет данных'
}

export function ScanProgress({ startedAt, source, active }) {
  const [seconds, setSeconds] = useState(0)
  useEffect(() => {
    if (!startedAt) return
    const update = () => setSeconds(Math.max(0, Math.floor((Date.now() - startedAt.getTime()) / 1000)))
    update()
    const timer = window.setInterval(update, 1000)
    return () => window.clearInterval(timer)
  }, [startedAt])
  const elapsed = String(Math.floor(seconds / 60)).padStart(2, '0') + ':' + String(seconds % 60).padStart(2, '0')
  return <div className={`scan-progress-drawer${active ? '' : ' is-leaving'}`}>
    <section className="scan-progress" role="status" aria-live="off">
      <div className="scan-progress-copy">
        <span className="scan-progress-eyebrow">Идёт анализ · {sourceLabels[source] ?? source}</span>
        <h2>Читаем данные и рассчитываем риски</h2>
      </div>
      <div className="scan-progress-time" aria-label={`Прошло ${Math.floor(seconds / 60)} минут ${seconds % 60} секунд`}><strong aria-hidden="true">{elapsed}</strong><span>прошло</span></div>
      <div className="scan-progress-track" aria-hidden="true"><span/></div>
    </section>
  </div>
}

export function ScanHistory({ scans, selectedScanId, onSelect, recentRun }) {
  const [filter, setFilter] = useState('all')
  const visible = scans.filter(item => filter === 'all' || item.source === filter)
  const selected = visible.find(item => item.scan_id === selectedScanId) ?? visible[0]
  const selectedIndex = selected ? scans.findIndex(item => item.scan_id === selected.scan_id) : -1
  const previous = selectedIndex >= 0 ? scans.slice(selectedIndex + 1).find(item => item.source === selected.source) : null
  const scoreChange = previous && selected ? selected.summary.security_score - previous.summary.security_score : null
  const findingChange = previous && selected ? selected.summary.finding_count - previous.summary.finding_count : null
  const completed = recentRun && (!selected || selected.scan_id === recentRun.scan_id)

  return <>
    <div className="section-head">
      <div><div className="eyebrow">Сохранённые результаты</div><h1>История анализов</h1><p>Каждый запуск сохраняется отдельно. Выберите запись, чтобы посмотреть её сводку.</p></div>
      <span className="count-pill">{scans.length} запусков</span>
    </div>
    {completed && <div className="scan-complete" role="status">
      <span className="scan-complete-mark" aria-hidden="true">✓</span>
      <div><strong>Анализ завершён</strong><p>{sourceLabels[recentRun.source] ?? recentRun.source} · {recentRun.users_scanned} аккаунтов · {recentRun.findings_found} находок · {(recentRun.duration_ms / 1000).toFixed(1)} сек.</p></div>
    </div>}
    {scans.length ? <div className="scan-history-layout">
      <section className="panel scan-history-list">
        <div className="panel-head"><div><h2>Запуски</h2><p>Последние {scans.length} результатов</p></div></div>
        <div className="history-filters" role="group" aria-label="Источник анализа">
          {[['all', 'Все'], ['ldap', 'Active Directory'], ['demo', 'Демо']].map(([key, label]) =>
            <button key={key} type="button" aria-pressed={filter === key} className={filter === key ? 'active' : ''} onClick={() => setFilter(key)}>{label}</button>)}
        </div>
        {visible.length ? <div className="scan-history-runs">{visible.map((item, index) =>
          <button type="button" className={'scan-history-run' + (selected?.scan_id === item.scan_id ? ' active' : '')} key={item.scan_id} onClick={() => onSelect(item.scan_id)} aria-current={selected?.scan_id === item.scan_id ? 'true' : undefined}>
            <span className="scan-run-index">{String(index + 1).padStart(2, '0')}</span>
            <span className="scan-run-main"><strong>{scanDate(item.scanned_at)}</strong><small>{sourceLabels[item.source] ?? item.source} · {item.summary.finding_count} находок</small></span>
            <span className={`scan-run-score score-tone-${securityScoreTone(item.summary.security_score)}`}><strong>{item.summary.security_score}</strong><small>/100</small></span>
          </button>)}</div> : <div className="history-empty">Для этого источника анализ ещё не запускали.</div>}
      </section>
      {selected && <section className="panel scan-history-detail">
        <div className="history-detail-top">
          <div><span className="eyebrow">Сводка анализа</span><h2>{scanDate(selected.scanned_at)}</h2><p>{sourceLabels[selected.source] ?? selected.source}</p></div>
          <div className={`history-detail-score score-tone-${securityScoreTone(selected.summary.security_score)}`}><strong>{selected.summary.security_score}</strong><span>/100</span><small>Security Score · выше лучше</small></div>
        </div>
        <div className="history-detail-metrics">
          <div><strong>{selected.summary.total_users}</strong><span>аккаунтов</span></div>
          <div><strong>{selected.summary.total_computers ?? '—'}</strong><span>компьютеров</span></div>
          <div><strong>{selected.summary.finding_count}</strong><span>находок</span></div>
        </div>
        <div className="history-severity"><h3>Уровни риска</h3><div>{levels.map(([level, label]) =>
          <span key={level} className={'history-severity-' + level}><b>{selected.summary.findings?.[level] ?? 0}</b>{label}</span>)}</div></div>
        <div className="history-compare">{scoreChange == null ? 'Это первый сохранённый анализ данного источника.' :
          <>К предыдущему анализу этого источника: <strong>{scoreChange > 0 ? '+' : ''}{scoreChange} к Security Score</strong> · {findingChange > 0 ? '+' : ''}{findingChange} находок</>}</div>
      </section>}
    </div> : <div className="panel history-empty">История пока пуста. Запустите анализ — результат появится здесь.</div>}
  </>
}
