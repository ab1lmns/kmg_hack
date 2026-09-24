export async function api(path, options = {}) {
  const response = await fetch(`/api${path}`, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...options.headers },
  })
  if (!response.ok) {
    let detail = `Ошибка ${response.status}`
    try {
      const payload = await response.json()
      detail = typeof payload.detail === 'string' ? payload.detail : detail
    } catch { /* server did not return JSON */ }
    throw new Error(detail)
  }
  return response.json()
}

