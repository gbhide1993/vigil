const BASE = '/api'

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw new Error(body.detail || `Request failed: ${res.status}`)
  }
  return res.json()
}

export const api = {
  getEvents: (params = {}) => {
    const qs = new URLSearchParams(params).toString()
    return request(`/events${qs ? `?${qs}` : ''}`)
  },
  getAgents: () => request('/agents'),
  getAgentSessions: (agentId) => request(`/agents/${agentId}/sessions`),
  getAlerts: (params = {}) => {
    const qs = new URLSearchParams(params).toString()
    return request(`/alerts${qs ? `?${qs}` : ''}`)
  },
  resolveAlert: (alertId, body) =>
    request(`/alerts/${alertId}/resolve`, { method: 'POST', body: JSON.stringify(body) }),
  getStats: () => request('/stats'),
  getHealth: () => request('/health'),
  exportJsonUrl: (date) => `${BASE}/export/json?date=${date}`,
  exportPdfUrl: (date) => `${BASE}/export/pdf?date=${date}`,
}
