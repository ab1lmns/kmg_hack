import assert from 'node:assert/strict'
import test from 'node:test'
import { buildRiskGraph } from './riskGraphData.js'

const dashboard = { source: 'ldap', security_score: 63, findings: { critical: 1, high: 1 }, domain_policy: {} }
const account = { id: 'user-1', username: 'svc_backup', service_account: true, risk_score: 80,
  risk_level: 'critical', groups: ['Service-Ops'], privilege_paths: [['svc_backup', 'Service-Ops', 'Domain Admins']] }
const group = { name: 'Service-Ops', member_of: ['Domain Admins'] }
const finding = { id: 'finding-1', account_id: 'user-1', account_type: 'service', severity: 'critical', title: 'Лишние права' }

test('graph separates navigation links from actual AD membership and nested paths', () => {
  const graph = buildRiskGraph({ dashboard, accounts: [account], groups: [group], findings: [finding] })
  const edges = graph.elements.filter(item => item.data.source)
  assert.ok(edges.some(item => item.data.source === 'service:user-1' && item.data.target === 'group:service-ops' && item.data.kind === 'member'))
  assert.ok(edges.some(item => item.data.source === 'group:service-ops' && item.data.target === 'group:domain admins' && item.data.kind === 'nested'))
  assert.ok(edges.some(item => item.data.source === 'domain' && item.data.target === 'section:services' && item.data.kind === 'section'))
  assert.equal(graph.details.get('group:domain admins').critical, true)
})

test('severity filter removes unrelated objects and finding nodes are optional', () => {
  const lowAccount = { id: 'user-2', username: 'ordinary', service_account: false, risk_score: 10, risk_level: 'low', groups: [] }
  const lowFinding = { id: 'finding-2', account_id: 'user-2', account_type: 'user', severity: 'low', title: 'Замечание' }
  const graph = buildRiskGraph({ dashboard, accounts: [account, lowAccount], groups: [group], findings: [finding, lowFinding], severity: 'urgent', showFindings: true })
  assert.ok(graph.details.has('service:user-1'))
  assert.ok(graph.details.has('finding:finding-1'))
  assert.ok(!graph.details.has('user:user-2'))
  assert.ok(!graph.details.has('finding:finding-2'))
})

test('policy finding attaches to policy and never creates a fictitious AD membership', () => {
  const policyFinding = { id: 'policy-1', account_id: 'domain', account_type: 'domain', severity: 'high', title: 'Нет блокировки' }
  const graph = buildRiskGraph({ dashboard, findings: [policyFinding], showFindings: true })
  assert.ok(graph.elements.some(item => item.data.source === 'policy' && item.data.target === 'finding:policy-1' && item.data.kind === 'finding'))
  assert.ok(!graph.elements.some(item => item.data.kind === 'member'))
})
