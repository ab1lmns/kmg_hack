function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[character])
}

function evidenceValue(value) {
  if (value == null) return 'Нет данных'
  if (typeof value === 'boolean') return value ? 'Да' : 'Нет'
  if (Array.isArray(value)) return value.map(evidenceValue).join(', ')
  return typeof value === 'object' ? JSON.stringify(value) : String(value)
}

export function buildRemediationHtml(finding, scanId, plan) {
  const before = plan.before_changes.map(item => `<li>${escapeHtml(item)}</li>`).join('')
  const evidence = Object.entries(finding.evidence ?? {}).slice(0, 8)
    .map(([key, value]) => `<dt>${escapeHtml(key)}</dt><dd>${escapeHtml(evidenceValue(value))}</dd>`).join('')
  const steps = plan.steps.map((step, index) => `<article class="step">
    <div class="step-top"><span class="number">${String(index + 1).padStart(2, '0')}</span><span class="phase">${escapeHtml(step.phase)}</span></div>
    <h3>${escapeHtml(step.title)}</h3><p>${escapeHtml(step.action)}</p>
    <div class="step-details"><div><strong>Зачем</strong><p>${escapeHtml(step.why)}</p></div><div><strong>Как проверить</strong><p>${escapeHtml(step.verify)}</p></div></div>
  </article>`).join('')
  return `<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>InfraRadar — ${escapeHtml(finding.title)}</title><style>
  *{box-sizing:border-box}body{margin:0;background:#f4f8f5;color:#233e30;font:14px/1.6 Arial,sans-serif}main{max-width:900px;margin:32px auto;background:white;box-shadow:0 12px 45px #163b2520}
  header{padding:34px 42px;background:linear-gradient(135deg,#173a2a,#286a49);color:white}.brand{font-size:12px;font-weight:800;letter-spacing:2px;color:#bde8ca}h1{font-size:29px;line-height:1.2;margin:18px 0 7px}header p{margin:0;color:#d6ebdc}.meta{margin-top:18px;font-size:12px;color:#cbe6d4}
  .content{padding:30px 42px 42px}.lead{padding:20px;border:1px solid #d7e9dc;border-radius:12px;background:#f1f9f3}.lead h2{margin:4px 0 7px;color:#1f5f3e;font-size:20px}.lead p{margin:0}
  h2{margin:30px 0 12px;font-size:18px}.context,.before,.success,.limits{padding:18px 20px;border:1px solid #e0ece3;border-radius:10px;margin-top:15px}.context p,.success p,.limits p{margin:6px 0 0;white-space:pre-wrap}.before{background:#fffaf0;border-color:#efdfbd}.before ul{margin:8px 0 0;padding-left:22px}
  dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 13px;margin:12px 0 0;font-size:12px}dt{color:#6f8875}dd{margin:0;overflow-wrap:anywhere}.step{padding:20px;border:1px solid #dce9df;border-radius:11px;margin:0 0 12px;break-inside:avoid}.step-top{display:flex;align-items:center;gap:10px}.number{display:inline-grid;place-items:center;width:31px;height:31px;border-radius:50%;background:#e6f5e9;color:#247547;font-weight:800}.phase{color:#42825a;font-size:11px;font-weight:700;text-transform:uppercase}.step h3{margin:10px 0 6px;font-size:16px}.step>p{margin:0;white-space:pre-wrap}.step-details{display:grid;grid-template-columns:1fr 1fr;gap:18px;border-top:1px solid #e8eee9;margin-top:14px;padding-top:12px;font-size:12px}.step-details strong{color:#47805b}.step-details p{margin:4px 0 0;white-space:pre-wrap}.success{background:#eaf7ed;border-color:#bfe0c9}.limits{font-size:12px;color:#667c6b}.footnote{margin-top:24px;color:#718679;font-size:11px}
  @media(max-width:650px){main{margin:0}.content{padding:22px}header{padding:28px 22px}.step-details{grid-template-columns:1fr}dl{grid-template-columns:1fr;gap:0}dd{margin-bottom:7px}}
  @media print{@page{size:A4;margin:14mm}body{background:white}main{margin:0;box-shadow:none;max-width:none}.content{padding:24px 0}header{padding:24px;print-color-adjust:exact}.lead,.before,.success{print-color-adjust:exact}}
  </style></head><body><main><header><div class="brand">INFRARADAR · ПЛАН ИСПРАВЛЕНИЯ</div><h1>${escapeHtml(finding.title)}</h1>
  <p>Объект: ${escapeHtml(finding.username)} · ${escapeHtml(finding.severity)}</p>
  <div class="meta">Правило ${escapeHtml(finding.rule_id)} · Сканирование ${escapeHtml(scanId)} · Сохранено ${escapeHtml(new Date().toLocaleString('ru-RU'))}</div></header>
  <div class="content"><section class="lead"><small>ЦЕЛЬ ПЛАНА</small><h2>${escapeHtml(plan.title)}</h2><p>${escapeHtml(plan.summary)}</p></section>
  <section class="context"><strong>Почему найден риск</strong><p>${escapeHtml(finding.reason)}</p>${evidence ? `<dl>${evidence}</dl>` : ''}</section>
  ${before ? `<section class="before"><strong>Перед изменениями</strong><ul>${before}</ul></section>` : ''}
  <h2>Пошаговый маршрут · ${plan.steps.length} шагов</h2>${steps}
  <section class="success"><strong>Критерий успеха</strong><p>${escapeHtml(plan.success_criteria)}</p></section>
  <section class="limits"><strong>Ограничения</strong><p>${escapeHtml(plan.limitations)}</p></section>
  <p class="footnote">План составлен по сохранённому анализу. Изменения в Active Directory выполняет и проверяет администратор вручную.</p></div></main></body></html>`
}

export function downloadRemediationHtml(finding, scanId, plan) {
  const blobUrl = URL.createObjectURL(new Blob([buildRemediationHtml(finding, scanId, plan)], { type: 'text/html;charset=utf-8' }))
  const link = document.createElement('a')
  const name = String(finding.username ?? 'risk').replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 60)
  link.href = blobUrl
  link.download = `infraradar-plan-${name || 'risk'}.html`
  document.body.appendChild(link)
  link.click()
  link.remove()
  setTimeout(() => URL.revokeObjectURL(blobUrl), 1000)
}
