const BASE = '/api'
// App.jsx's stats poll runs every 3s and uses failures here to decide
// whether to show the "Backend not responding" banner -- without a
// timeout, a hung request (backend wedged but the TCP connection still
// open) never rejects, so inFlight never clears and polling stalls
// forever instead of ever reporting a failure.
const REQUEST_TIMEOUT_MS = 10000

async function request(path, options = {}) {
  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS)
  try {
    const res = await fetch(`${BASE}${path}`, {
      headers: { 'Content-Type': 'application/json' },
      ...options,
      signal: controller.signal,
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({}))
      throw new Error(body.detail || `Request failed: ${res.status}`)
    }
    return await res.json()
  } finally {
    clearTimeout(timeoutId)
  }
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
  // dryRun=true only counts; nothing is changed. Red-line alerts are skipped unless includeRedLine.
  resolveOlderAlerts: (days, { dryRun, includeRedLine }) =>
    request(`/alerts/resolve-older?days=${days}&dry_run=${dryRun}&include_red_line=${includeRedLine}`, { method: 'POST' }),
  getSessionEvents: (sessionId, agentId) => {
    const qs = new URLSearchParams({ session: sessionId, agent: agentId, limit: 2000 }).toString()
    return request(`/events?${qs}`)
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
  getEvidence: () => request('/evidence'),
  getEvidenceIncidents: () => request('/incidents'),
  trackEvent: (event, properties = {}) => {
    // Fire and forget — never await this, never let it throw.
    fetch(`${BASE}/analytics/track`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ event, properties }),
    }).catch(() => {})
  },
}
