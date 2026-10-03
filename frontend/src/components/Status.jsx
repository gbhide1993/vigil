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

function computeOrbState(hasCritical, hasMinor, proofOfValue) {
  if (hasCritical) return 'red'
  if (hasMinor || (proofOfValue && proofOfValue.days_clean === 0)) return 'amber'
  return 'green'
}

export default function Status({ onNavigate }) {
  const [criticalAlerts, setCriticalAlerts] = useState([])
  const [criticalTotal, setCriticalTotal] = useState(0)
  const [hasMinorAlerts, setHasMinorAlerts] = useState(false)
  const [agents, setAgents] = useState([])
  const [proofOfValue, setProofOfValue] = useState(null)
  const [recordingSince, setRecordingSince] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false

    async function load() {
      try {
        // Two separate calls, not one unfiltered fetch filtered client-side:
        // the orb needs both "is there an open high/critical alert" (red)
        // and "is there an open medium/low alert" (amber vs green), and
        // filtering severity server-side for only one of those tiers would
        // just move the same silent-miss bug this change is fixing onto
        // the other tier. The medium/low call only needs `total` (an
        // existence check), so it asks for limit: 1 rather than pulling
        // rows nothing here renders.
        const [criticalData, minorData, agentsData, sessionsData, proofOfValueData] = await Promise.all([
          api.getAlerts({ status: 'open', severity: 'high,critical' }),
          api.getAlerts({ status: 'open', severity: 'medium,low', limit: 1 }),
          api.getAgents(),
          api.getSessions(),
          api.getProofOfValue(),
        ])
        if (cancelled) return
        setCriticalAlerts(criticalData.alerts)
        setCriticalTotal(criticalData.total)
        setHasMinorAlerts(minorData.total > 0)
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

  const orbState = computeOrbState(criticalAlerts.length > 0, hasMinorAlerts, proofOfValue)
  const activeAgentNames = agents.filter((a) => a.approved !== 2).map((a) => a.name)

  let contextLine
  if (orbState === 'red') {
    contextLine = (
      <a href="#incident-list" className="status-context-link">
        {criticalTotal} incident{criticalTotal !== 1 ? 's' : ''} need attention. Investigate →
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
          <IncidentList alerts={criticalAlerts} onNavigate={onNavigate} onResolved={() => {
            api.getAlerts({ status: 'open', severity: 'high,critical' }).then((d) => {
              setCriticalAlerts(d.alerts)
              setCriticalTotal(d.total)
            }).catch(() => {})
          }} />
        </div>
      )}
    </div>
  )
}
