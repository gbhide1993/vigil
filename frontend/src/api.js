const BASE = '/api'
// App.jsx's stats poll runs every 3s and uses failures here to decide
// whether to show the "Backend not responding" banner -- without a
// timeout, a hung request (backend wedged but the TCP connection still
// open) never rejects, so inFlight never clears and polling stalls
// forever instead of ever reporting a failure.
const REQUEST_TIMEOUT_MS = 10000

async function request(path, options = {}) {
  const { signal: callerSignal, ...fetchOptions } = options
  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS)
  // A caller-supplied signal (the History search cancels a request when the next
  // keystroke arrives) aborts the same controller the timeout uses.
  if (callerSignal) {
    if (callerSignal.aborted) controller.abort()
    else callerSignal.addEventListener('abort', () => controller.abort(), { once: true })
  }
  try {
    const res = await fetch(`${BASE}${path}`, {
      headers: { 'Content-Type': 'application/json' },
      ...fetchOptions,
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
  getEvents: (params = {}, signal) => {
    const qs = new URLSearchParams(params).toString()
    return request(`/events${qs ? `?${qs}` : ''}`, { signal })
  },
  // History search: matches a session id prefix (any case) or text in agent, type,
  // path or detail. The reply has total, sessions and session_count besides events.
  searchEvents: (q, { limit = 100, offset = 0 } = {}, signal) => {
    const qs = new URLSearchParams({ q, limit, offset }).toString()
    return request(`/events?${qs}`, { signal })
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
  getScope: () => request('/scope'),
  addScopeFolder: (path) => request('/scope', { method: 'POST', body: JSON.stringify({ path }) }),
  removeScopeFolder: (path) => request('/scope', { method: 'DELETE', body: JSON.stringify({ path }) }),
  getHealth: () => request('/health'),
  getInsights: () => request('/insights'),
  getProofOfValue: () => request('/digest/proof-of-value'),
  getConfigAudit: () => request('/config-audit'),
  getWebhookUrl: () => request('/config/webhook-url'),
  setWebhookUrl: (url) => request('/config/webhook-url', { method: 'POST', body: JSON.stringify({ url }) }),
  getExternalTimestamp: () => request('/config/external-timestamp'),
  setExternalTimestamp: (settings) => request('/config/external-timestamp', { method: 'POST', body: JSON.stringify(settings) }),
  sendTestWebhook: () => request('/digest/send-webhook', { method: 'POST' }),
  exportJsonUrl: (date) => `${BASE}/export/json?date=${date}`,
  // For showing the report on the page (every load and date change): the evidence check is the last one
  // made, labelled with its time. Only the download itself (exportJsonUrl, exportPdfUrl) runs a fresh check.
  exportJsonPreviewUrl: (date) => `${BASE}/export/json?date=${date}&preview=true`,
  exportBundleUrl: (start, end) => `${BASE}/export/bundle?start=${start}&end=${end}`,
  exportPdfUrl: (date) => `${BASE}/export/pdf?date=${date}`,
  sessionReportUrl: (sessionId) => `${BASE}/sessions/${encodeURIComponent(sessionId)}/report`,
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

// Sessions that count as sessions: a resumed one with no real activity (Vigil only found the agent already
// running when it started watching) comes back from /sessions with has_activity false and is left out of
// "has sessions", "recording since" and the empty state. An older backend without the field shows everything.
export function realSessions(sessions) {
  return (sessions || []).filter((s) => s.has_activity !== false)
}
