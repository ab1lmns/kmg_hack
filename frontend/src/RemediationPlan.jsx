import { useEffect, useRef, useState } from 'react'
import { api } from './api.js'
import { downloadRemediationHtml } from './remediationExport.js'

const severityLabel = { critical: 'Критический риск', high: 'Высокий риск', medium: 'Средний риск', low: 'Низкий риск' }

function evidenceValue(value) {
  if (value == null) return 'Нет данных'
  if (typeof value === 'boolean') return value ? 'Да' : 'Нет'
  if (Array.isArray(value)) return value.map(evidenceValue).join(', ')
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

export default function RemediationPlan({ finding, scanId, cache, onClose }) {
  const cacheKey = `${scanId}:${finding.id}`
  const [plan, setPlan] = useState(() => cache.get(cacheKey) ?? null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(!cache.has(cacheKey))
  const [attempt, setAttempt] = useState(0)
  const closeRef = useRef(null)
  const panelRef = useRef(null)

  useEffect(() => {
    const previousOverflow = document.body.style.overflow
    const previousFocus = document.activeElement
    document.body.style.overflow = 'hidden'
    closeRef.current?.focus()
    const keydown = event => {
      if (event.key === 'Escape') { onClose(); return }
      if (event.key !== 'Tab') return
      const focusable = [...(panelRef.current?.querySelectorAll('button:not(:disabled), a[href], [tabindex]:not([tabindex="-1"])') ?? [])]
      if (!focusable.length) return
      const first = focusable[0]
      const last = focusable.at(-1)
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus() }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus() }
    }
    window.addEventListener('keydown', keydown)
    return () => { document.body.style.overflow = previousOverflow; window.removeEventListener('keydown', keydown); previousFocus?.focus?.() }
  }, [onClose])

  useEffect(() => {
    if (cache.has(cacheKey)) { setPlan(cache.get(cacheKey)); setLoading(false); return }
    let active = true
    setLoading(true); setError('')
    api('/ai/remediation-plan', { method: 'POST', body: JSON.stringify({ scan_id: scanId, finding_id: finding.id }) })
      .then(result => { cache.set(cacheKey, result.plan); if (active) setPlan(result.plan) })
      .catch(caught => { if (active) setError(caught.message) })
      .finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [cache, cacheKey, finding.id, scanId, attempt])

  const evidence = Object.entries(finding.evidence ?? {}).slice(0, 4)
  return <div className="plan-backdrop" onMouseDown={event => { if (event.target === event.currentTarget) onClose() }}>
    <section ref={panelRef} className="plan-panel" role="dialog" aria-modal="true" aria-labelledby="plan-dialog-title" aria-describedby="plan-dialog-description">
      <header className="plan-header"><div className="plan-brand"><span className="plan-brand-icon" aria-hidden="true">✦</span><span>INFRARADAR / AI REMEDIATION</span></div><button ref={closeRef} type="button" className="plan-close" onClick={onClose} aria-label="Закрыть план">×</button><div className="plan-title-block"><span className="plan-eyebrow">Персональный маршрут исправления</span><h2 id="plan-dialog-title">{finding.title}</h2><p id="plan-dialog-description">Для объекта <strong>{finding.username}</strong></p></div><div className="plan-header-meta"><span className={`plan-severity plan-severity-${finding.severity}`}>{severityLabel[finding.severity] ?? finding.severity}</span><span>Правило: {finding.rule_id}</span>{plan && <span>{plan.steps.length} шага к устранению</span>}</div></header>
      <div className="plan-scroll">
        {loading && <div className="plan-loading" role="status"><span className="plan-loading-icon">✦</span><h3>Составляю маршрут</h3><p>Учитываю настройки объекта, подтверждения и связанные находки…</p><div className="plan-loading-track"><span/></div></div>}
        {error && <div className="plan-error" role="alert"><strong>План не сформирован</strong><p>{error}</p><button type="button" onClick={() => setAttempt(value => value + 1)}>Попробовать ещё раз</button></div>}
        {plan && <div className="plan-layout"><aside className="plan-context-column">
          <div className="plan-intro"><div className="plan-intro-icon" aria-hidden="true">↗</div><div><span className="plan-small-label">Цель плана</span><h3>{plan.title}</h3><p>{plan.summary}</p></div></div>
          <div className="plan-finding-context"><div><span className="plan-small-label">Почему найден риск</span><p>{finding.reason}</p></div>{evidence.length > 0 && <details><summary>Доказательства анализа</summary><dl>{evidence.map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{evidenceValue(value)}</dd></div>)}</dl></details>}</div>
          {plan.before_changes.length > 0 && <div className="plan-before"><span className="plan-small-label">Перед изменениями</span><ul>{plan.before_changes.map((item, index) => <li key={index}>{item}</li>)}</ul></div>}
          </aside><div className="plan-route-column">
          <div className="plan-route-head"><div><span className="plan-small-label">ПОШАГОВЫЙ МАРШРУТ</span><h3>Шагов к устранению: {plan.steps.length}</h3></div><span>Администратор выполняет вручную</span></div>
          <ol className="plan-timeline">{plan.steps.map((step, index) => <li key={index}><div className="plan-step-rail"><span>{String(index + 1).padStart(2, '0')}</span></div><div className="plan-step-card"><div className="plan-step-top"><span className={`plan-phase plan-phase-${step.phase === 'Проверить' ? 'check' : step.phase === 'Исправить' ? 'fix' : 'verify'}`}>{step.phase}</span></div><h4>{step.title}</h4><p>{step.action}</p><div className="plan-step-extra"><div><strong>Зачем</strong><span>{step.why}</span></div><div><strong>Как проверить</strong><span>{step.verify}</span></div></div></div></li>)}</ol>
          <div className="plan-success"><span className="plan-success-icon" aria-hidden="true">✓</span><div><strong>Критерий успеха</strong><p>{plan.success_criteria}</p></div></div>
          <div className="plan-limit"><strong>Учтите:</strong> {plan.limitations}</div>
          </div></div>}
      </div>
      <footer className="plan-footer"><span>План основан на данных сканирования. Изменения в AD выполняются вручную.</span><div className="plan-footer-actions"><button type="button" onClick={onClose}>Закрыть</button><button type="button" disabled={!plan} onClick={() => window.print()}>Печать / PDF</button><button type="button" className="plan-save" disabled={!plan} onClick={() => downloadRemediationHtml(finding, scanId, plan)}>Скачать план</button></div></footer>
    </section>
  </div>
}
