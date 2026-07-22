import { useEffect, useState } from 'react'
import { api } from '../api'

const DISMISSED_KEY = 'vlaw_insight_card_dismissed'

export default function SessionInsightCard() {
  const [dismissed, setDismissed] = useState(() => localStorage.getItem(DISMISSED_KEY) === '1')
  const [summary, setSummary] = useState(null)

  useEffect(() => {
    if (dismissed) return
    let cancelled = false
    async function load() {
      try {
        const sessionsData = await api.getSessions()
        const sessions = sessionsData.sessions
        if (sessions.length === 0) return
        // Sessions come back ordered most-recent-first; the first session is
        // the oldest one, which is what this card is meant to summarise.
        const firstSession = sessions[sessions.length - 1]
        if (firstSession.ended_at == null) return // still in progress — nothing to summarise yet

        // GET /alerts has no session_id filter param — fetch all and filter client-side.
        const alertsData = await api.getAlerts()
        const alerts = (alertsData.alerts || []).filter((a) => a.session_id === firstSession.id)
        const redLineFired = alerts.some((a) => a.rule_type === 'red_line')

        if (!cancelled) {
          setSummary({
            agentName: firstSession.agent_name || 'unknown agent',
            fileReads: firstSession.file_reads || 0,
            fileWrites: firstSession.file_writes || 0,
            netConnectCount: firstSession.net_connect_count || 0,
            redLineFired,
          })
        }
      } catch {
        // insight card is non-critical — silently skip if data isn't available
      }
    }
    load()
    return () => {
      cancelled = true
    }
  }, [dismissed])

  function handleDismiss() {
    localStorage.setItem(DISMISSED_KEY, '1')
    setDismissed(true)
  }

  if (dismissed || !summary) return null

  return (
    <div className="insight-card">
      <button className="insight-card-dismiss" onClick={handleDismiss} aria-label="Dismiss">
        ✕
      </button>
      <div className="insight-card-title">Your first session, at a glance</div>
      <div className="insight-card-body">
        <span className="insight-card-agent">{summary.agentName}</span> read{' '}
        <strong>{summary.fileReads}</strong> file{summary.fileReads !== 1 ? 's' : ''} and wrote{' '}
        <strong>{summary.fileWrites}</strong> file{summary.fileWrites !== 1 ? 's' : ''}, contacting{' '}
        <strong>{summary.netConnectCount}</strong> network destination{summary.netConnectCount !== 1 ? 's' : ''}.
        {summary.redLineFired ? (
          <> A <strong className="insight-card-redline">Red Line rule fired</strong> during this session.</>
        ) : (
          <> No Red Line rules fired.</>
        )}
      </div>
      <div className="insight-card-footer">
        This is your baseline. Vigil will alert you when future sessions deviate from this pattern.
      </div>
    </div>
  )
}
