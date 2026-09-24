import { useEffect, useMemo, useRef, useState } from 'react'
import cytoscape from 'cytoscape'
import { api } from './api.js'
import { buildRiskGraph } from './riskGraphData.js'

const severityNames = { critical: 'Критично', high: 'Высокий', medium: 'Средний', low: 'Низкий', safe: 'Без находок' }
const kindNames = { domain: 'Домен', section: 'Раздел анализа', user: 'Пользователь', service: 'Сервисный аккаунт', computer: 'Компьютер', group: 'Группа AD', policy: 'Политика домена', authentication: 'Аутентификация', finding: 'Находка' }
const asList = value => Array.isArray(value) ? value : []

const graphStyle = [
  { selector: 'node', style: { 'background-color': '#e8f3ec', 'border-width': 2, 'border-color': '#a9c9b3', 'label': 'data(label)', 'color': '#244b35', 'font-size': 10, 'font-weight': 700, 'text-wrap': 'wrap', 'text-max-width': 115, 'text-valign': 'center', 'text-halign': 'center', 'overlay-opacity': 0 } },
  { selector: 'node[kind = "domain"]', style: { 'shape': 'round-rectangle', 'width': 165, 'height': 76, 'background-color': '#204b36', 'border-color': '#357453', 'color': '#fff', 'font-size': 17, 'text-max-width': 150 } },
  { selector: 'node[kind = "section"]', style: { 'shape': 'round-rectangle', 'width': 120, 'height': 46, 'background-color': '#f1f7f2', 'border-color': '#bed8c5', 'font-size': 11, 'text-max-width': 110 } },
  { selector: 'node[kind = "user"], node[kind = "service"], node[kind = "computer"]', style: { 'width': 'mapData(riskScore, 0, 100, 42, 66)', 'height': 'mapData(riskScore, 0, 100, 42, 66)', 'text-valign': 'bottom', 'text-margin-y': 9, 'text-background-color': '#ffffff', 'text-background-opacity': .92, 'text-background-padding': 3, 'font-size': 9 } },
  { selector: 'node[kind = "service"]', style: { 'shape': 'round-rectangle' } },
  { selector: 'node[kind = "computer"]', style: { 'shape': 'barrel' } },
  { selector: 'node[kind = "group"]', style: { 'width': 34, 'height': 34, 'shape': 'diamond', 'background-color': '#e9f0fa', 'border-color': '#9cb6d0', 'color': '#3e5b78', 'text-valign': 'bottom', 'text-margin-y': 9, 'text-background-color': '#ffffff', 'text-background-opacity': .9, 'text-background-padding': 2, 'font-size': 9 } },
  { selector: 'node[kind = "group"][critical = 1]', style: { 'background-color': '#ffe9da', 'border-color': '#df9266', 'color': '#89563b' } },
  { selector: 'node[kind = "policy"], node[kind = "authentication"]', style: { 'width': 75, 'height': 55, 'shape': 'round-rectangle', 'background-color': '#e9f4ef', 'font-size': 10 } },
  { selector: 'node[kind = "finding"]', style: { 'width': 22, 'height': 22, 'shape': 'hexagon', 'text-valign': 'bottom', 'text-margin-y': 8, 'font-size': 8, 'text-max-width': 105, 'text-background-color': '#fff', 'text-background-opacity': .92, 'text-background-padding': 2 } },
  { selector: 'node[severity = "critical"]', style: { 'background-color': '#fbe0e4', 'border-color': '#d85b6b', 'color': '#963b47' } },
  { selector: 'node[severity = "high"]', style: { 'background-color': '#fff0dc', 'border-color': '#df9a50', 'color': '#835a2c' } },
  { selector: 'node[severity = "medium"]', style: { 'background-color': '#fff7df', 'border-color': '#d9bc66' } },
  { selector: 'edge', style: { 'width': 1.6, 'line-color': '#a8bdb0', 'curve-style': 'bezier', 'opacity': .7, 'overlay-opacity': 0 } },
  { selector: 'edge[kind = "section"], edge[kind = "contains"]', style: { 'line-style': 'dashed', 'line-color': '#cbdccf', 'width': 1.2, 'opacity': .8 } },
  { selector: 'edge[kind = "member"], edge[kind = "nested"]', style: { 'target-arrow-shape': 'triangle', 'target-arrow-color': '#709f80', 'arrow-scale': .65, 'line-color': '#91b49d', 'width': 2.3 } },
  { selector: 'edge[kind = "finding"]', style: { 'line-color': '#dfb4a1', 'width': 1.6 } },
  { selector: '.faded', style: { 'opacity': .12, 'text-opacity': .08 } },
  { selector: 'node.focused', style: { 'border-width': 4, 'border-color': '#2c8b58', 'opacity': 1, 'text-opacity': 1, 'z-index': 10 } },
  { selector: 'edge.focused', style: { 'width': 3.8, 'line-color': '#348c5b', 'target-arrow-color': '#348c5b', 'opacity': 1, 'z-index': 9 } },
]

function FindingList({ findings, onPlan }) {
  if (!findings.length) return <p className="map-muted">В выбранном фильтре находок нет.</p>
  return <div className="map-finding-list">{findings.map(item => <article key={item.id}>
    <div className="map-finding-head"><span className={`map-level map-level-${item.severity}`}>{severityNames[item.severity] ?? item.severity}</span><strong>{item.title}</strong></div>
    <p>{item.reason}</p><button type="button" onClick={() => onPlan(item)}>✦ Сформировать план</button>
  </article>)}</div>
}

function Detail({ detail, dashboard, accounts, onOpenAccount, onPlan }) {
  if (!detail) return null
  const { kind } = detail
  if (kind === 'domain') return <><div className="map-detail-kicker">Общая картина</div><h2>Active Directory</h2><p>Данные последнего сохранённого анализа. Нажмите на объект, чтобы изучить его риски и связи.</p><div className="map-score"><strong>{dashboard.security_score}</strong><span>/100<br/>AD Security Score</span></div><div className="map-facts"><div><span>Аккаунты</span><strong>{dashboard.total_users}</strong></div><div><span>Компьютеры</span><strong>{dashboard.total_computers ?? 0}</strong></div><div><span>Находки</span><strong>{dashboard.finding_count}</strong></div><div><span>Critical / High</span><strong>{(dashboard.findings?.critical ?? 0) + (dashboard.findings?.high ?? 0)}</strong></div></div></>
  if (kind === 'section') return <><div className="map-detail-kicker">Группировка карты</div><h2>{detail.label}</h2><p>Пунктирные линии объединяют объекты для навигации по карте. Они не означают членство или права в Active Directory.</p></>
  if (['user', 'service', 'computer'].includes(kind)) {
    const object = detail.object
    return <><div className="map-detail-kicker">{kindNames[kind]}</div><h2>{object.username ?? object.name}</h2><div className="map-object-score"><span className={`map-level map-level-${object.risk_level}`}>{severityNames[object.risk_level] ?? object.risk_level}</span><strong>{object.risk_score ?? 0}/100</strong></div><div className="map-facts"><div><span>Статус</span><strong>{object.enabled ? 'Включён' : 'Отключён'}</strong></div><div><span>Находок</span><strong>{detail.findings.length}</strong></div>{kind !== 'computer' && <div><span>Привилегии</span><strong>{object.privileged ? 'Есть' : 'Не найдены'}</strong></div>}</div>
      {kind !== 'computer' && asList(object.privilege_paths).length > 0 && <><h3>Пути к привилегиям</h3><div className="map-paths">{object.privilege_paths.map((path, index) => <div key={index}>{path.join(' → ')}</div>)}</div></>}
      <h3>Найденные риски</h3><FindingList findings={detail.findings} onPlan={onPlan}/>
      <button className="map-open-button" onClick={() => onOpenAccount(object.id, kind)}>Открыть страницу объекта →</button>
    </>
  }
  if (kind === 'group') {
    const name = detail.group.name
    const members = accounts.filter(item => asList(item.groups).some(group => group.toLocaleLowerCase() === name.toLocaleLowerCase()) ||
      asList(item.privilege_paths).some(path => path.slice(1).some(group => group.toLocaleLowerCase() === name.toLocaleLowerCase())))
    return <><div className="map-detail-kicker">Группа Active Directory</div><h2>{name}</h2>{detail.critical && <span className="map-level map-level-high">Критическая группа</span>}<p>Стрелка к группе показывает прямое или вложенное членство по данным анализа.</p><h3>Связанные аккаунты · {members.length}</h3><div className="map-member-list">{members.slice(0, 12).map(item => <button key={item.id} onClick={() => onOpenAccount(item.id)}>{item.username}<span>→</span></button>)}{members.length > 12 && <small>Ещё {members.length - 12} аккаунтов</small>}</div></>
  }
  if (kind === 'policy') return <><div className="map-detail-kicker">Настройки домена</div><h2>Парольная политика</h2><div className="map-facts"><div><span>Минимальная длина</span><strong>{dashboard.domain_policy?.min_password_length ?? '—'}</strong></div><div><span>Сложность</span><strong>{dashboard.domain_policy?.password_complexity == null ? 'Не оценена' : dashboard.domain_policy.password_complexity ? 'Включена' : 'Выключена'}</strong></div><div><span>Порог блокировки</span><strong>{dashboard.domain_policy?.lockout_threshold ?? '—'}</strong></div></div><h3>Находки политики</h3><FindingList findings={detail.findings} onPlan={onPlan}/><button className="map-open-button" onClick={() => onOpenAccount('__domain__', 'domain')}>Открыть политику →</button></>
  if (kind === 'authentication') return <><div className="map-detail-kicker">Security Event Log</div><h2>Аутентификация</h2><p>Статус источника: {detail.authentication?.status === 'pass' ? 'проверен' : detail.authentication?.status === 'partial' ? 'частичные данные' : 'не оценён'}.</p><div className="map-facts"><div><span>Событий</span><strong>{detail.authentication?.events ?? '—'}</strong></div><div><span>Сигналов</span><strong>{detail.findings.length}</strong></div></div><FindingList findings={detail.findings} onPlan={onPlan}/><button className="map-open-button" onClick={() => onOpenAccount('', 'authentication')}>Открыть события →</button></>
  if (kind === 'finding') {
    const finding = detail.finding
    return <><div className="map-detail-kicker">Находка · {finding.rule_id}</div><h2>{finding.title}</h2><span className={`map-level map-level-${finding.severity}`}>{severityNames[finding.severity]}</span><p>{finding.reason}</p><h3>Рекомендация</h3><p>{finding.recommendation}</p><button className="map-open-button" onClick={() => onPlan(finding)}>✦ Сформировать план исправления</button></>
  }
  return null
}

export default function RiskMap({ dashboard, accounts, computers, findings, authentication, onOpenAccount, onPlan }) {
  const containerRef = useRef(null)
  const cyRef = useRef(null)
  const [groups, setGroups] = useState([])
  const [groupError, setGroupError] = useState('')
  const [severity, setSeverity] = useState('all')
  const [scope, setScope] = useState('risky')
  const [showFindings, setShowFindings] = useState(false)
  const [selectedId, setSelectedId] = useState('domain')
  const [search, setSearch] = useState('')
  const [searchOpen, setSearchOpen] = useState(false)
  useEffect(() => {
    let active = true
    api('/groups').then(rows => { if (active) setGroups(rows) }).catch(() => { if (active) setGroupError('Детали групп недоступны; пути из анализа остаются на карте.') })
    return () => { active = false }
  }, [dashboard.scan_id])
  const graph = useMemo(() => buildRiskGraph({ dashboard, accounts, computers, groups, findings, authentication, severity, scope, showFindings, search }),
    [dashboard, accounts, computers, groups, findings, authentication, severity, scope, showFindings, search])

  useEffect(() => {
    if (!containerRef.current) return
    const cy = cytoscape({ container: containerRef.current, elements: graph.elements, style: graphStyle,
      layout: { name: 'cose', animate: false, randomize: false, nodeRepulsion: () => 3200, idealEdgeLength: () => 68, edgeElasticity: () => 130, gravity: .8, numIter: 500 },
      minZoom: .18, maxZoom: 2.5, wheelSensitivity: .18, boxSelectionEnabled: false })
    cyRef.current = cy
    cy.on('tap', 'node', event => setSelectedId(event.target.id()))
    cy.on('tap', event => { if (event.target === cy) setSelectedId('domain') })
    cy.fit(undefined, 48)
    return () => { cyRef.current = null; cy.destroy() }
  }, [graph])

  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return
    cy.elements().removeClass('faded focused')
    const selected = cy.getElementById(selectedId)
    if (selected.empty() || selectedId === 'domain') { cy.fit(undefined, 48); return }
    cy.elements().addClass('faded')
    const focus = selected.closedNeighborhood()
    focus.removeClass('faded').addClass('focused')
    const detail = graph.details.get(selectedId)
    if (detail && ['user', 'service'].includes(detail.kind)) {
      for (const path of asList(detail.object.privilege_paths)) {
        const ids = [selectedId, ...path.slice(1).map(name => `group:${name.toLocaleLowerCase()}`)]
        for (const id of ids) cy.getElementById(id).removeClass('faded').addClass('focused')
        for (const edge of cy.edges()) {
          if (ids.includes(edge.source().id()) && ids.includes(edge.target().id())) edge.removeClass('faded').addClass('focused')
        }
      }
    }
    cy.fit(cy.elements('.focused'), 65)
  }, [selectedId, graph])

  const query = search.trim().toLocaleLowerCase()
  const searchResults = query ? [...graph.details.entries()].filter(([, detail]) => {
    const label = detail.object?.username ?? detail.object?.name ?? detail.group?.name ?? detail.finding?.title ?? detail.label ?? ''
    return String(label).toLocaleLowerCase().includes(query)
  }).slice(0, 8) : []
  const detail = graph.details.get(selectedId) ?? graph.details.get('domain')
  return <>
    <div className="section-head map-page-head"><div><div className="eyebrow">Визуализация анализа</div><h1>Карта рисков</h1><p>Объекты, находки и реальные пути привилегий из последнего сканирования.</p></div><span className="count-pill">{graph.meta.shownObjects} объектов · {graph.meta.findingCount} находок</span></div>
    <section className="map-toolbar panel"><label className="map-search"><span>Поиск объекта</span><input value={search} onFocus={() => setSearchOpen(true)} onChange={event => { setSearch(event.target.value); setSearchOpen(true) }} placeholder="Имя аккаунта, группа, риск…"/>{searchOpen && searchResults.length > 0 && <div className="map-search-results">{searchResults.map(([id, item]) => <button key={id} type="button" onClick={() => { setSelectedId(id); setSearchOpen(false); const cy = cyRef.current; if (cy) cy.center(cy.getElementById(id)) }}>{item.object?.username ?? item.object?.name ?? item.group?.name ?? item.finding?.title ?? item.label}<small>{kindNames[item.kind]}</small></button>)}</div>}</label>
      <label><span>Уровень</span><select value={severity} onChange={event => { setSeverity(event.target.value); setSelectedId('domain') }}><option value="all">Все риски</option><option value="urgent">Critical + High</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label>
      <label><span>Объекты</span><select value={scope} onChange={event => { setScope(event.target.value); setSelectedId('domain') }}><option value="risky">С находками</option><option value="all">Все объекты</option></select></label>
      <label className="map-toggle"><input type="checkbox" checked={showFindings} onChange={event => setShowFindings(event.target.checked)}/><span>Узлы находок</span></label>
    </section>
    <div className="map-layout"><section className="map-canvas-wrap panel"><div className="map-canvas-header"><div><strong>Граф текущего сканирования</strong><span>{graph.meta.nodes} узлов · {graph.meta.edges} связей</span></div><div className="map-zoom"><button onClick={() => cyRef.current?.zoom(Math.min(cyRef.current.zoom() * 1.25, 2.5))} aria-label="Увеличить граф">+</button><button onClick={() => cyRef.current?.zoom(Math.max(cyRef.current.zoom() / 1.25, .18))} aria-label="Уменьшить граф">−</button><button onClick={() => cyRef.current?.fit(undefined, 48)} aria-label="Показать весь граф">⤢</button></div></div><div ref={containerRef} className="map-canvas" role="img" aria-label="Интерактивная карта объектов и рисков Active Directory"/><div className="map-legend"><span><i className="map-dot-critical"/>Critical</span><span><i className="map-dot-high"/>High</span><span><i className="map-dot-group"/>Группа</span><span><b>→</b> Членство AD</span><span><em>┄</em> Группировка карты</span></div>{graph.meta.totalObjects > graph.meta.shownObjects && <p className="map-limit-note">Показаны первые {graph.meta.shownObjects} из {graph.meta.totalObjects} объектов по Risk Score. Используйте фильтр или поиск для работы с большим доменом.</p>}{groupError && <p className="map-limit-note">{groupError}</p>}</section>
      <aside className="map-inspector panel"><Detail detail={detail} dashboard={dashboard} accounts={accounts} onOpenAccount={onOpenAccount} onPlan={onPlan}/></aside></div>
    <p className="map-note">Карта отражает состояние на момент сканирования. Пунктир обозначает разделы интерфейса; сплошные стрелки между аккаунтами и группами — членство, обнаруженное в AD. Одна линия сама по себе не доказывает компрометацию.</p>
  </>
}
