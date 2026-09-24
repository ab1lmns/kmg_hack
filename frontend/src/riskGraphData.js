const severityRank = { critical: 4, high: 3, medium: 2, low: 1 }
const sectionNames = {
  users: 'Пользователи', services: 'Сервисные аккаунты', groups: 'Группы AD',
  computers: 'Компьютеры', policy: 'Парольная политика', authentication: 'Аутентификация',
}

const asList = value => Array.isArray(value) ? value : []
const groupId = name => `group:${String(name).toLocaleLowerCase()}`
const shortLabel = (value, limit = 27) => String(value ?? '').length > limit ? `${String(value).slice(0, limit - 1)}…` : String(value ?? '')

export function buildRiskGraph({ dashboard, accounts = [], computers = [], groups = [], findings = [], authentication, severity = 'all', scope = 'risky', showFindings = false, search = '' }) {
  const elements = []
  const details = new Map()
  const edgeIds = new Set()
  const nodeIds = new Set()
  const allFindings = [...new Map([...findings, ...asList(authentication?.findings)].map(item => [item.id, item])).values()]
  const findingsByObject = new Map()
  for (const finding of allFindings) {
    const key = String(finding.account_id ?? '')
    if (!findingsByObject.has(key)) findingsByObject.set(key, [])
    findingsByObject.get(key).push(finding)
  }
  const matches = finding => severity === 'all' || (severity === 'urgent' ? ['critical', 'high'].includes(finding.severity) : finding.severity === severity)
  const matchingFindings = allFindings.filter(matches)

  function node(id, label, kind, detail = {}, extra = {}) {
    if (nodeIds.has(id)) return
    nodeIds.add(id)
    elements.push({ data: { id, label: shortLabel(label, kind === 'finding' ? 25 : 29), kind, ...extra } })
    details.set(id, detail)
  }
  function edge(source, target, kind) {
    if (!nodeIds.has(source) || !nodeIds.has(target)) return
    const id = `${source}→${target}:${kind}`
    if (edgeIds.has(id)) return
    edgeIds.add(id)
    elements.push({ data: { id, source, target, kind } })
  }

  node('domain', dashboard.source === 'ldap' ? 'Active Directory' : 'Тестовый домен', 'domain', { kind: 'domain', dashboard }, { score: dashboard.security_score })
  const usedSections = new Set()
  function section(key) {
    const id = `section:${key}`
    if (!usedSections.has(key)) {
      usedSections.add(key)
      node(id, sectionNames[key], 'section', { kind: 'section', key, label: sectionNames[key] })
      edge('domain', id, 'section')
    }
    return id
  }
  const visibleObjects = []
  for (const account of accounts) {
    const objectFindings = asList(findingsByObject.get(String(account.id))).filter(matches)
    if (scope === 'risky' && !objectFindings.length) continue
    if (severity !== 'all' && !objectFindings.length) continue
    visibleObjects.push({ object: account, type: account.service_account ? 'service' : 'user', objectFindings })
  }
  for (const computer of computers) {
    const objectFindings = asList(findingsByObject.get(String(computer.id))).filter(matches)
    if (scope === 'risky' && !objectFindings.length) continue
    if (severity !== 'all' && !objectFindings.length) continue
    visibleObjects.push({ object: computer, type: 'computer', objectFindings })
  }
  const query = search.trim().toLocaleLowerCase()
  const matchScore = row => query && `${row.object.username ?? row.object.name ?? ''} ${row.object.display_name ?? ''}`.toLocaleLowerCase().includes(query) ? 1 : 0
  visibleObjects.sort((a, b) => matchScore(b) - matchScore(a) || (b.object.risk_score ?? 0) - (a.object.risk_score ?? 0))
  const shown = visibleObjects.slice(0, 150)
  const objectIds = new Map()
  for (const { object, type, objectFindings } of shown) {
    const id = `${type}:${object.id}`
    objectIds.set(String(object.id), id)
    node(id, object.username ?? object.name, type, { kind: type, object, findings: objectFindings },
      { severity: object.risk_level, riskScore: object.risk_score ?? 0, findingCount: objectFindings.length })
    edge(section(type === 'service' ? 'services' : type === 'user' ? 'users' : 'computers'), id, 'contains')
  }

  const groupByName = new Map(groups.map(item => [String(item.name).toLocaleLowerCase(), item]))
  const neededGroups = new Set()
  const criticalGroups = new Set()
  for (const { object, type } of shown) {
    if (type === 'computer') continue
    for (const name of asList(object.groups)) neededGroups.add(String(name))
    for (const path of asList(object.privilege_paths)) {
      for (const name of path.slice(1)) neededGroups.add(String(name))
      if (path.length > 1) criticalGroups.add(String(path.at(-1)).toLocaleLowerCase())
    }
  }
  // Include intermediate parent groups only when they are part of a known privilege path.
  for (const name of neededGroups) {
    const group = groupByName.get(name.toLocaleLowerCase())
    const id = groupId(name)
    node(id, group?.name ?? name, 'group', { kind: 'group', group: group ?? { name }, critical: criticalGroups.has(name.toLocaleLowerCase()) },
      { critical: criticalGroups.has(name.toLocaleLowerCase()) ? 1 : 0 })
    edge(section('groups'), id, 'contains')
  }
  for (const { object, type } of shown) {
    if (type === 'computer') continue
    const source = objectIds.get(String(object.id))
    for (const name of asList(object.groups)) edge(source, groupId(name), 'member')
    for (const path of asList(object.privilege_paths)) {
      if (path.length > 1) edge(source, groupId(path[1]), 'member')
      for (let index = 1; index < path.length - 1; index++) edge(groupId(path[index]), groupId(path[index + 1]), 'nested')
    }
  }
  for (const name of neededGroups) {
    const group = groupByName.get(name.toLocaleLowerCase())
    for (const parent of asList(group?.member_of)) edge(groupId(name), groupId(parent), 'nested')
  }

  const policyFindings = matchingFindings.filter(item => ['domain', 'policy'].includes(item.account_type))
  if (severity === 'all' || policyFindings.length) {
    node('policy', 'Политика домена', 'policy', { kind: 'policy', dashboard, findings: policyFindings },
      { severity: policyFindings.reduce((level, item) => severityRank[item.severity] > severityRank[level] ? item.severity : level, 'low'), findingCount: policyFindings.length })
    edge(section('policy'), 'policy', 'contains')
  }
  const authFindings = matchingFindings.filter(item => item.account_type === 'authentication')
  if (severity === 'all' || authFindings.length) {
    node('authentication', 'События входа', 'authentication', { kind: 'authentication', authentication, findings: authFindings },
      { findingCount: authFindings.length })
    edge(section('authentication'), 'authentication', 'contains')
  }

  if (showFindings) {
    for (const finding of matchingFindings) {
      const target = objectIds.get(String(finding.account_id)) ??
        (['domain', 'policy'].includes(finding.account_type) ? 'policy' : finding.account_type === 'authentication' ? 'authentication' : null)
      if (!target || !nodeIds.has(target)) continue
      const id = `finding:${finding.id}`
      node(id, finding.title, 'finding', { kind: 'finding', finding }, { severity: finding.severity })
      edge(target, id, 'finding')
    }
  }

  return {
    elements, details,
    meta: {
      shownObjects: shown.length, totalObjects: visibleObjects.length,
      shownGroups: neededGroups.size,
      findingCount: matchingFindings.length,
      nodes: nodeIds.size, edges: edgeIds.size,
    },
  }
}
