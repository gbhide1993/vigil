import { useEffect, useState } from 'react'
import { api } from '../api'

function formatTime(ts) {
  if (!ts) return '—'
  return new Date(ts.replace(' ', 'T') + 'Z').toLocaleString()
}

const NOTE_REQUIRED = new Set(['exception_approved', 'risk_accepted'])

function AlertCard({ alert, onResolve }) {
  const [pendingAction, setPendingAction] = useState(null)
  const [note, setNote] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [errorMsg, setErrorMsg] = useState(null)

  const isOpen = alert.status === 'open' || alert.status === 'investigating'

  async function submit(action) {
    if (NOTE_REQUIRED.has(action) && !note.trim()) {
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

  return (
    <div className={`alert-card ${alert.severity}`}>
      <div className="alert-card-top">
        <div>
          <div className="alert-title">{alert.title}</div>
          <div className="alert-meta">
            {alert.agent_name || 'unknown agent'} · {formatTime(alert.created_at)}
          </div>
        </div>
        <span className={`badge ${alert.severity}`}>{alert.severity}</span>
      </div>
      <div className="alert-description">{alert.description}</div>

      {alert.status !== 'open' && (
        <div className="alert-meta">
          Status: <strong>{alert.status}</strong>
          {alert.resolved_by ? ` by ${alert.resolved_by}` : ''}
          {alert.resolution_note ? ` — "${alert.resolution_note}"` : ''}
        </div>
      )}

      {isOpen && (
        <>
          <div className="alert-actions">
            <button className="btn" disabled={submitting} onClick={() => submit('dismiss')}>
              Dismiss
            </button>
            <button className="btn" disabled={submitting} onClick={() => setPendingAction('exception_approved')}>
              Exception Approve
            </button>
            <button className="btn danger" disabled={submitting} onClick={() => setPendingAction('risk_accepted')}>
              Accept Risk
            </button>
          </div>

          {pendingAction && NOTE_REQUIRED.has(pendingAction) && (
            <div className="field" style={{ marginTop: 10 }}>
              <label>Resolution note (required for {pendingAction.replace('_', ' ')})</label>
              <textarea
                rows={2}
                value={note}
                onChange={(e) => setNote(e.target.value)}
                placeholder="Explain why this is acceptable..."
              />
              <div style={{ display: 'flex', gap: 8, marginTop: 6 }}>
                <button className="btn primary" disabled={submitting || !note.trim()} onClick={() => submit(pendingAction)}>
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

export default function Alerts() {
  const [alerts, setAlerts] = useState([])
  const [statusFilter, setStatusFilter] = useState('open')
  const [severityFilter, setSeverityFilter] = useState('')

  async function load() {
    try {
      const params = {}
      if (statusFilter) params.status = statusFilter
      if (severityFilter) params.severity = severityFilter
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
  }, [statusFilter, severityFilter])

  async function handleResolve(alertId, action, note) {
    await api.resolveAlert(alertId, { action, note })
    await load()
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">Alerts</div>
          <div className="page-subtitle">Review, dismiss, or accept risk on flagged agent activity</div>
        </div>
      </div>

      <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
        <div className="field" style={{ marginBottom: 0 }}>
          <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="dismissed">Dismissed</option>
            <option value="exception_approved">Exception Approved</option>
            <option value="risk_accepted">Risk Accepted</option>
            <option value="">All statuses</option>
          </select>
        </div>
        <div className="field" style={{ marginBottom: 0 }}>
          <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
            <option value="">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>

      {alerts.length === 0 ? (
        <div className="empty-state">No alerts match the current filters.</div>
      ) : (
        alerts.map((alert) => (
          <AlertCard key={alert.id} alert={alert} onResolve={handleResolve} />
        ))
      )}
    </div>
  )
}
