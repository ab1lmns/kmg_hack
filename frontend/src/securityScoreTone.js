// The domain score is 100 minus average object risk. Compare that average with
// the Risk Engine's High/Critical thresholds so the visual state has the same meaning.
export function securityScoreTone(securityScore, thresholds = {}) {
  const averageRisk = 100 - Number(securityScore)
  const high = Number(thresholds.high ?? thresholds.risk_high_threshold ?? 60)
  const critical = Number(thresholds.critical ?? thresholds.risk_critical_threshold ?? 80)
  if (averageRisk >= critical) return 'low'
  if (averageRisk >= high) return 'medium'
  return 'good'
}
