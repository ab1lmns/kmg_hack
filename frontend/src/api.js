const base = (import.meta.env.VITE_API_URL || '').replace(/\/$/, '')
let accessToken = null

export function setAccessToken(token) { accessToken = token }

export async function apiResponse(path, options = {}) {
  const response = await fetch(`${base}/api${path}`, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}), ...options.headers },
  })
  if (!response.ok) {
    if (response.status === 401 && path !== '/auth/login') window.dispatchEvent(new Event('radar-session-expired'))
    let detail = `Ошибка ${response.status}`
    try {
      const payload = await response.json()
      if (typeof payload.detail === 'string') detail = payload.detail
      else if (Array.isArray(payload.detail) && payload.detail.length) {
        const issue = payload.detail[0]
        const field = issue.loc?.at(-1)
        detail = `Некорректное значение${field ? ` (${field})` : ''}: ${issue.msg ?? 'проверьте параметры'}`
      }
    } catch { /* server did not return JSON */ }
    throw new Error(detail)
  }
  return response
}

export async function api(path, options = {}) {
  const response = await apiResponse(path, options)
  return response.json()
}

export async function downloadCsv() {
  const response = await apiResponse('/export/csv')
  const blob = await response.blob()
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = response.headers.get('Content-Disposition')?.match(/filename="?([^";]+)"?/)?.[1] || 'identity-risk.csv'
  link.click()
  URL.revokeObjectURL(url)
}
