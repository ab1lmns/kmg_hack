import test from 'node:test'
import assert from 'node:assert/strict'
import { buildRemediationHtml } from './remediationExport.js'

test('saved remediation plan preserves its details and escapes untrusted AD data', () => {
  const finding = {
    title: 'Old <admin> account', username: 'user"><script>alert(1)</script>',
    severity: 'high', rule_id: 'STALE', reason: 'No login for 90 days',
    evidence: { note: '<img src=x onerror=alert(1)>' },
  }
  const plan = {
    title: 'Review account', summary: 'Confirm ownership', before_changes: ['Create backup'],
    steps: [{ phase: 'Проверить', title: 'Find owner', action: 'Ask the team', why: 'Avoid disruption', verify: 'Owner confirmed' }],
    success_criteria: 'Access reviewed', limitations: 'No automatic changes',
  }
  const html = buildRemediationHtml(finding, 'scan-1', plan)
  for (const detail of ['Create backup', 'Find owner', 'Ask the team', 'Avoid disruption', 'Owner confirmed', 'Access reviewed']) {
    assert.ok(html.includes(detail))
  }
  assert.ok(html.includes('&lt;admin&gt;'))
  assert.ok(html.includes('&lt;script&gt;'))
  assert.ok(html.includes('&lt;img src=x onerror=alert(1)&gt;'))
  assert.ok(!html.includes('<script>alert(1)</script>'))
  assert.ok(!html.includes('<img src=x onerror=alert(1)>'))
})
