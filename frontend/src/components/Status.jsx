import { useEffect, useState } from 'react'
import { api } from '../api'
import IncidentList from './IncidentList'

function formatStartDate(ts) {
  if (!ts) return '—'
  return new Date(ts.replace(' ', 'T') + 'Z').toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  })
}

function computeOrbState(alerts, proofOfValue) {
  const unresolved = alerts.filter((a) => a.status === 'open' || a.status === 'investigating')
  const hasCritical = unresolved.some((a) => a.severity === 'high' || a.severity === 'critical')
  if (hasCritical) return 'red'
  const hasMinor = unresolved.some((a) => a.severity === 'medium' || a.severity === 'low')
  if (hasMinor || (proofOfValue && proofOfValue.days_clean === 0)) return 'amber'
  return 'green'
}

export default function Status({ onNavigate }) {
  const [alerts, setAlerts] = useState([])
  const [agents, setAgents] = useState([])
  const [proofOfValue, setProofOfValue] = useState(null)
  const [recordingSince, setRecordingSince] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false

    async function load() {
      try {
        const [alertsData, agentsData, sessionsData, proofOfValueData] = await Promise.all([
          api.getAlerts({ status: 'open' }),
          api.getAgents(),
          api.getSessions(),
          api.getProofOfValue(),
        ])
        if (cancelled) return
        setAlerts(alertsData.alerts)
        setAgents(agentsData.agents)
        setProofOfValue(proofOfValueData)
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

  const orbState = computeOrbState(alerts, proofOfValue)
  const activeAgentNames = agents.filter((a) => a.approved !== 2).map((a) => a.name)
  const criticalIncidents = alerts.filter(
    (a) => (a.status === 'open' || a.status === 'investigating') && (a.severity === 'high' || a.severity === 'critical')
  )

  let contextLine
  if (orbState === 'red') {
    contextLine = (
      <a href="#incident-list" className="status-context-link">
        {criticalIncidents.length} incident{criticalIncidents.length !== 1 ? 's' : ''} need attention. Investigate →
      </a>
    )
  } else if (orbState === 'amber') {
    contextLine = <span className="status-context-text">Nothing urgent — see History for recent activity.</span>
  } else {
    contextLine = <span className="status-context-text">Nothing to investigate.</span>
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">Status</div>
          <div className="page-subtitle">V-LAW is observing this machine</div>
        </div>
      </div>

      {error && <div className="empty-state">Could not reach V-LAW backend: {error}</div>}

      <div className="quiet-mode">
        <div className={`status-orb ${orbState}`} />
        <div className="status-text">
          {orbState === 'red' ? 'Incident Detected' : 'Vigil Running'}
        </div>
        <div className="status-agents mono">
          {activeAgentNames.length > 0 ? activeAgentNames.join(' · ') : 'No agents detected'}
        </div>
        <div className="status-since mono">Recording since {formatStartDate(recordingSince)}</div>
        <div className="status-context">{contextLine}</div>
      </div>

      {orbState === 'red' && (
        <div id="incident-list">
          <IncidentList alerts={criticalIncidents} onNavigate={onNavigate} onResolved={() => {
            api.getAlerts({ status: 'open' }).then((d) => setAlerts(d.alerts)).catch(() => {})
          }} />
        </div>
      )}
    </div>
  )
}
