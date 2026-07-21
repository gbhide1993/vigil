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
  getSessions: (params = {}) => {
    const qs = new URLSearchParams(params).toString()
    return request(`/sessions${qs ? `?${qs}` : ''}`)
  },
  getSessionTopFinding: (sessionId) => request(`/sessions/${sessionId}/top-finding`),
  approveAgent: (agentId) => request(`/agents/${agentId}/approve`, { method: 'POST' }),
  blockAgent: (agentId, reason) =>
    request(`/agents/${agentId}/block`, { method: 'POST', body: JSON.stringify({ reason }) }),
  getAlerts: (params = {}) => {
    const qs = new URLSearchParams(params).toString()
    return request(`/alerts${qs ? `?${qs}` : ''}`)
  },
  resolveAlert: (alertId, body) =>
    request(`/alerts/${alertId}/resolve`, { method: 'POST', body: JSON.stringify(body) }),
  bulkDismissAlerts: (severity) =>
    request(`/alerts/bulk-dismiss?severity=${severity}`, { method: 'POST' }),
  getSessionEvents: (sessionId, agentId) => {
    const qs = new URLSearchParams({ agent: agentId, limit: 500 }).toString()
    return request(`/events?${qs}`).then((data) => ({
      events: data.events.filter((e) => e.session_id === sessionId),
    }))
  },
  getStats: () => request('/stats'),
  getHealth: () => request('/health'),
  getInsights: () => request('/insights'),
  getProofOfValue: () => request('/digest/proof-of-value'),
  getConfigAudit: () => request('/config-audit'),
  getWebhookUrl: () => request('/config/webhook-url'),
  setWebhookUrl: (url) => request('/config/webhook-url', { method: 'POST', body: JSON.stringify({ url }) }),
  sendTestWebhook: () => request('/digest/send-webhook', { method: 'POST' }),
  exportJsonUrl: (date) => `${BASE}/export/json?date=${date}`,
  exportPdfUrl: (date) => `${BASE}/export/pdf?date=${date}`,
  getAnalyticsSummary: () => request('/analytics/summary'),
  trackEvent: (event, properties = {}) => {
    // Fire and forget — never await this, never let it throw.
    fetch(`${BASE}/analytics/track`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ event, properties }),
    }).catch(() => {})
  },
}
