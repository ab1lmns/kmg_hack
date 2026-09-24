export async function api(path, options = {}) {
  const response = await fetch(`/api${path}`, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...options.headers },
  })
  if (!response.ok) {
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
  return response.json()
}
