import { useEffect, useState } from 'react'
import { api } from '../api'
import IncidentList from './IncidentList'

const WINDOW_HOURS = 24

function formatStartDate(ts) {
  if (!ts) return '\u2014'
  return new Date(ts.replace(' ', 'T') + 'Z').toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  })
}

export default function Status({ onNavigate }) {
  const [criticalAlerts, setCriticalAlerts] = useState([])
  const [stats, setStats] = useState(null)
  const [agents, setAgents] = useState([])
  const [recordingSince, setRecordingSince] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false

    async function load() {
      try {
        // The status itself (red / amber / green) is decided by the backend
        // (core/alert_status.py, delivered as stats.status_level) so the
        // Status page, the sidebar badge and the tray tooltip cannot
        // disagree. Only alerts detected in the last 24 hours drive it;
        // older open alerts are shown as a separate quiet line.
        const [recentData, agentsData, sessionsData, statsData] = await Promise.all([
          api.getAlerts({ status: 'open', severity: 'high,critical', since_hours: WINDOW_HOURS }),
          api.getAgents(),
          api.getSessions(),
          api.getStats(),
        ])
        if (cancelled) return
        setCriticalAlerts(recentData.alerts)
        setStats(statsData)
        setAgents(agentsData.agents)
        if (sessionsData.sessions.length > 0) {
          const earliest = sessionsData.sessions.reduce((min, s) =>
            !min || (s.started_at && s.started_at < min) ? s.started_at : min, null)
          setRecordingSince(earliest)
        }
        setError(null)
      } catch (err) {
        if (!cancelled) setError(err.message)
      }
    }

    load()
    const id = setInterval(load, 3000)
    return () => {
      cancelled = true
      clearInterval(id)
    }
  }, [])

  const orbState = stats ? stats.status_level : 'green'
  const recentHigh = stats ? stats.needs_review : 0
  const recentMedium = stats ? stats.open_medium_24h : 0
  const olderOpen = stats ? stats.older_open : 0
  const activeAgentNames = agents.filter((a) => a.approved !== 2).map((a) => a.name)

  let contextLine
  if (orbState === 'red') {
    contextLine = (
      <a href="#incident-list" className="status-context-link">
        {recentHigh} open high-severity alert{recentHigh !== 1 ? 's' : ''} in the last 24 hours. Investigate &rarr;
      </a>
    )
  } else if (orbState === 'amber') {
    contextLine = (
      <a className="status-context-link" style={{ cursor: 'pointer' }} onClick={() => onNavigate('alerts')}>
        {recentMedium} open medium-severity alert{recentMedium !== 1 ? 's' : ''} in the last 24 hours. Review &rarr;
      </a>
    )
  } else {
    contextLine = <span className="status-context-text">No open high-severity alerts in the last 24 hours</span>
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">Status</div>
          <div className="page-subtitle">Vigil is observing this machine</div>
        </div>
      </div>

      {error && <div className="empty-state">Could not reach Vigil backend: {error}</div>}

      <div className="quiet-mode">
        <div className={`status-orb ${orbState}`} />
        <div className="status-text">
          {orbState === 'red' ? 'Incident Detected' : 'Vigil Running'}
        </div>
        <div className="status-agents mono">
          {activeAgentNames.length > 0 ? activeAgentNames.join(' \u00b7 ') : 'No agents detected'}
        </div>
        <div className="status-since mono">Recording since {formatStartDate(recordingSince)}</div>
        <div className="status-context">{contextLine}</div>
        {olderOpen > 0 && (
          <div className="status-older">
            <a className="status-older-link" onClick={() => onNavigate('alerts')}>
              {olderOpen} older open alert{olderOpen !== 1 ? 's' : ''}
            </a>
          </div>
        )}
      </div>

      {orbState === 'red' && (
        <div id="incident-list">
          <IncidentList alerts={criticalAlerts} onNavigate={onNavigate} onResolved={() => {
            api.getAlerts({ status: 'open', severity: 'high,critical', since_hours: WINDOW_HOURS }).then((d) => {
              setCriticalAlerts(d.alerts)
            }).catch(() => {})
          }} />
        </div>
      )}
    </div>
  )
}
