import { useEffect, useState } from 'react'
import { api } from '../api'

function formatIncidentTime(ts) {
  if (!ts) return '—'
  return new Date(ts.replace(' ', 'T') + 'Z').toLocaleString(undefined, {
    weekday: 'short',
    day: 'numeric',
    month: 'short',
    hour: 'numeric',
    minute: '2-digit',
  })
}

function severityColor(step) {
  const map = { low: 'var(--low)', medium: 'var(--medium)', high: 'var(--high)', critical: 'var(--critical)' }
  return map[step.severity] || 'var(--low)'
}

const STORY_LABELS = {
  file_read: { action: 'opened', severity: 'low' },
  cred_access: { action: 'accessed credential file', severity: 'critical' },
  proc_spawn: { action: 'spawned', severity: 'medium' },
  net_connect: { action: 'connected to', severity: 'medium' },
  mcp_connect: { action: 'opened MCP connection', severity: 'high' },
  file_write: { action: 'wrote to', severity: 'medium' },
}

function buildStory(alert, relatedEvents) {
  const story = []

  relatedEvents
    .filter((event) => {
      if (!alert.created_at) return true
      const alertTime = new Date(alert.created_at.replace(' ', 'T') + 'Z').getTime()
      const eventTime = new Date(event.created_at.replace(' ', 'T') + 'Z').getTime()
      return Math.abs(eventTime - alertTime) <= 60000
    })
    .sort((a, b) => new Date(a.created_at) - new Date(b.created_at))
    .forEach((event) => {
      const cfg = STORY_LABELS[event.event_type]
      if (!cfg) return
      const target = event.event_type === 'net_connect' ? event.path
        : event.event_type === 'proc_spawn' ? (event.detail || event.path)
        : event.path
      story.push({ action: cfg.action, target: target || '—', severity: cfg.severity })
    })

  if (alert.rule_type === 'red_line') {
    story.push({ action: 'blocked', target: alert.title, severity: 'critical', isFinal: true })
  }

  return story
}

function StoryTimeline({ story }) {
  if (story.length === 0) {
    return <div className="empty-state" style={{ padding: '16px 0' }}>No related events found for this window.</div>
  }
  return (
    <div className="story-timeline">
      {story.map((step, i) => (
        <div key={i} className="story-step">
          <div className="story-connector" />
          <div className="story-dot" style={{ background: severityColor(step), color: severityColor(step) }} />
          <div className="story-content">
            <span className="story-action mono">{step.action}</span>
            <span className="story-target">{step.target}</span>
          </div>
        </div>
      ))}
    </div>
  )
}

function IncidentCard({ alert, onNavigate, onResolved }) {
  const [story, setStory] = useState(null)
  const [expanded, setExpanded] = useState(true)
  const [busy, setBusy] = useState(false)
  const [errorMsg, setErrorMsg] = useState(null)
  const isRedLine = alert.rule_type === 'red_line'

  useEffect(() => {
    let cancelled = false
    async function load() {
      try {
        const data = await api.getSessionEvents(alert.session_id, alert.agent_id)
        if (!cancelled) setStory(buildStory(alert, data.events))
      } catch {
        if (!cancelled) setStory([])
      }
    }
    if (alert.session_id) load()
    else setStory([])
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [alert.id])

  async function handleResolve() {
    setBusy(true)
    setErrorMsg(null)
    try {
      await api.resolveAlert(alert.id, { action: 'dismiss' })
      onResolved()
    } catch (err) {
      setErrorMsg(err.message)
    } finally {
      setBusy(false)
    }
  }

  function handleExport() {
    api.trackEvent('export_clicked', { source: 'incident' })
    const today = new Date().toISOString().slice(0, 10)
    window.open(api.exportPdfUrl(today), '_blank')
  }

  return (
    <div className="incident-card">
      <div
        className="incident-header"
        onClick={() =>
          setExpanded((v) => {
            const next = !v
            if (next) {
              api.trackEvent('incident_viewed', { alert_id: alert.id, severity: alert.severity, rule_type: alert.rule_type })
            }
            return next
          })
        }
      >
        <div className={`incident-severity ${alert.severity}`}>
          {isRedLine ? '🔴 RED LINE' : alert.severity.toUpperCase()}
        </div>
        <div className="incident-time mono">{formatIncidentTime(alert.created_at)}</div>
        <div className="incident-agent">{alert.agent_name || 'unknown agent'}</div>
      </div>

      <div className="incident-title">{alert.title}</div>

      {expanded && (
        <>
          <StoryTimeline story={story || []} />

          <div className="incident-footer">
            <button className="btn ghost" onClick={() => onNavigate('agents')}>
              Full timeline →
            </button>
            <button className="btn ghost" onClick={handleExport}>
              Export PDF
            </button>
            {!isRedLine && (
              <button className="btn primary" disabled={busy} onClick={handleResolve}>
                Mark resolved
              </button>
            )}
          </div>
          {errorMsg && <div style={{ color: 'var(--color-critical)', fontSize: 11, marginTop: 6 }}>{errorMsg}</div>}
        </>
      )}
    </div>
  )
}

export default function IncidentList({ alerts, onNavigate, onResolved }) {
  if (alerts.length === 0) {
    return <div className="empty-state">No active incidents.</div>
  }
  return (
    <div className="incident-list">
      {alerts.map((alert) => (
        <IncidentCard key={alert.id} alert={alert} onNavigate={onNavigate} onResolved={onResolved} />
      ))}
    </div>
  )
}
