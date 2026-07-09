import { useEffect, useState } from 'react'
import { api } from '../api'

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low']
const SEVERITY_LABELS = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW' }
const DETAIL_TRUNCATE_LEN = 80

function formatRelative(ts) {
  if (!ts) return '—'
  const then = new Date(ts.replace(' ', 'T') + 'Z').getTime()
  const diffMs = Date.now() - then
  const mins = Math.floor(diffMs / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins} minute${mins !== 1 ? 's' : ''} ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours} hour${hours !== 1 ? 's' : ''} ago`
  const days = Math.floor(hours / 24)
  return `${days} day${days !== 1 ? 's' : ''} ago`
}

function DetailLine({ text }) {
  const [expanded, setExpanded] = useState(false)
  if (!text) return null
  const needsTruncation = text.length > DETAIL_TRUNCATE_LEN
  const shown = expanded || !needsTruncation ? text : `${text.slice(0, DETAIL_TRUNCATE_LEN)}…`

  return (
    <div className="alert-detail-line">
      <span className="alert-detail-text">{shown}</span>
      {needsTruncation && (
        <button className="alert-detail-toggle" onClick={() => setExpanded((v) => !v)}>
          {expanded ? 'Show less ▲' : 'Show full command ▼'}
        </button>
      )}
    </div>
  )
}

function AlertCard({ alert, onResolve, onNavigate }) {
  const [pendingAction, setPendingAction] = useState(null)
  const [note, setNote] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [errorMsg, setErrorMsg] = useState(null)

  const isOpen = alert.status === 'open' || alert.status === 'investigating'
  const isRedLine = alert.rule_type === 'red_line'

  async function submit(action) {
    if (action === 'risk_accepted' && !note.trim()) {
      setPendingAction(action)
      return
    }
    setSubmitting(true)
    setErrorMsg(null)
    try {
      await onResolve(alert.id, action, note.trim() || undefined)
      setPendingAction(null)
      setNote('')
    } catch (err) {
      setErrorMsg(err.message)
    } finally {
      setSubmitting(false)
    }
  }

  const sessionLabel = alert.session_id ? `Session #${alert.session_id.slice(0, 8)}` : null

  return (
    <div className={`alert-card-v2 severity-${alert.severity} ${isRedLine ? 'red-line' : ''}`}>
      {isRedLine && <div className="alert-card-v2-redline-badge">RED LINE</div>}
      <div className="alert-card-v2-top">
        <div className="alert-card-v2-title">{alert.title}</div>
        <span className={`feed-severity-badge ${alert.severity}`}>{SEVERITY_LABELS[alert.severity]}</span>
      </div>
      <div className="alert-card-v2-meta">
        {alert.agent_name || 'unknown agent'} · {formatRelative(alert.created_at)}
      </div>

      <DetailLine text={alert.event_path || alert.description} />

      {(sessionLabel || alert.session_summary) && (
        <div className="alert-card-v2-session">
          {sessionLabel}
          {alert.session_summary ? ` · During: "${alert.session_summary}"` : ''}
        </div>
      )}

      {alert.status !== 'open' && !isRedLine && (
        <div className="alert-card-v2-resolution">
          Status: <strong>{alert.status}</strong>
          {alert.resolved_by ? ` by ${alert.resolved_by}` : ''}
          {alert.resolution_note ? ` — "${alert.resolution_note}"` : ''}
        </div>
      )}

      {isRedLine && (
        <div className="alert-card-v2-resolution">
          This is a Red Line safety-floor alert and cannot be dismissed or resolved.
        </div>
      )}

      {isOpen && !isRedLine && (
        <>
          <div className="alert-card-v2-actions">
            <button className="btn ghost" disabled={submitting} onClick={() => submit('dismiss')}>
              Dismiss
            </button>
            <button className="btn ghost" disabled={submitting} onClick={() => setPendingAction('risk_accepted')}>
              Accept Risk
            </button>
            <button className="btn teal-outline" onClick={() => onNavigate('agents')}>
              → View Session
            </button>
          </div>

          {pendingAction === 'risk_accepted' && (
            <div className="field" style={{ marginTop: 10 }}>
              <label>Resolution note (required to accept risk)</label>
              <textarea
                rows={2}
                value={note}
                onChange={(e) => setNote(e.target.value)}
                placeholder="Explain why this is acceptable..."
              />
              <div style={{ display: 'flex', gap: 8, marginTop: 6 }}>
                <button className="btn primary" disabled={submitting || !note.trim()} onClick={() => submit('risk_accepted')}>
                  Confirm
                </button>
                <button className="btn" disabled={submitting} onClick={() => { setPendingAction(null); setNote('') }}>
                  Cancel
                </button>
              </div>
            </div>
          )}

          {errorMsg && <div style={{ color: 'var(--color-critical)', fontSize: 11, marginTop: 6 }}>{errorMsg}</div>}
        </>
      )}
    </div>
  )
}

export default function Alerts({ onNavigate }) {
  const [alerts, setAlerts] = useState([])
  const [statusFilter, setStatusFilter] = useState('open')
  const [severityFilter, setSeverityFilter] = useState('')
  const [agentFilter, setAgentFilter] = useState('')
  const [agents, setAgents] = useState([])
  const [bulkBusy, setBulkBusy] = useState(false)

  async function load() {
    try {
      const params = {}
      if (statusFilter) params.status = statusFilter
      if (severityFilter) params.severity = severityFilter
      if (agentFilter) params.agent = agentFilter
      const data = await api.getAlerts(params)
      setAlerts(data.alerts)
    } catch {
      // ignore poll failures
    }
  }

  useEffect(() => {
    load()
    const id = setInterval(load, 3000)
    return () => clearInterval(id)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [statusFilter, severityFilter, agentFilter])

  useEffect(() => {
    let cancelled = false
    async function loadAgents() {
      try {
        const data = await api.getAgents()
        if (!cancelled) setAgents(data.agents)
      } catch {
        // ignore poll failures
      }
    }
    loadAgents()
    return () => {
      cancelled = true
    }
  }, [])

  async function handleResolve(alertId, action, note) {
    await api.resolveAlert(alertId, { action, note })
    await load()
  }

  async function handleBulkDismissLow() {
    setBulkBusy(true)
    try {
      await api.bulkDismissAlerts('low')
      await load()
    } finally {
      setBulkBusy(false)
    }
  }

  const grouped = SEVERITY_ORDER.map((sev) => ({
    severity: sev,
    alerts: alerts.filter((a) => a.severity === sev),
  })).filter((g) => g.alerts.length > 0)

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">Alerts</div>
          <div className="page-subtitle">Review, dismiss, or accept risk on flagged agent activity</div>
        </div>
      </div>

      <div className="alerts-filter-bar">
        <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
          <option value="open">Open</option>
          <option value="investigating">Investigating</option>
          <option value="dismissed">Dismissed</option>
          <option value="exception_approved">Exception Approved</option>
          <option value="risk_accepted">Risk Accepted</option>
          <option value="">All statuses</option>
        </select>
        <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select value={agentFilter} onChange={(e) => setAgentFilter(e.target.value)}>
          <option value="">All agents</option>
          {agents.map((a) => (
            <option key={a.id} value={a.id}>{a.name}</option>
          ))}
        </select>

        <div className="alerts-filter-bar-spacer" />

        <button className="btn ghost" disabled={bulkBusy} onClick={handleBulkDismissLow}>
          Bulk: Dismiss all LOW
        </button>
      </div>

      {grouped.length === 0 ? (
        <div className="empty-state">No alerts match the current filters.</div>
      ) : (
        grouped.map((group) => (
          <div key={group.severity} className="alerts-severity-group">
            <div className="alerts-severity-group-label">
              {SEVERITY_LABELS[group.severity]} <span>({group.alerts.length})</span>
            </div>
            {group.alerts.map((alert) => (
              <AlertCard key={alert.id} alert={alert} onResolve={handleResolve} onNavigate={onNavigate} />
            ))}
          </div>
        ))
      )}
    </div>
  )
}
