import { useEffect, useState } from 'react'
import { api } from '../api'
import EvidenceIncidents from './EvidenceIncidents'
import IncidentList from './IncidentList'
import SessionInsightCard from './SessionInsightCard'

export default function Incidents({ onNavigate }) {
  const [alerts, setAlerts] = useState([])
  const [statusFilter, setStatusFilter] = useState('open')
  const [reloadTick, setReloadTick] = useState(0)

  // reloadTick lets the onResolved callback below trigger a refresh
  // through this same effect, so that request gets the same `cancelled`
  // guard as the poll and filter-change ones instead of racing them.
  useEffect(() => {
    let cancelled = false
    async function load() {
      try {
        const params = { severity: 'high,critical' }
        if (statusFilter) params.status = statusFilter
        const data = await api.getAlerts(params)
        if (cancelled) return
        setAlerts(data.alerts)
      } catch {
        // ignore poll failures
      }
    }
    load()
    const id = setInterval(load, 3000)
    return () => {
      cancelled = true
      clearInterval(id)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [statusFilter, reloadTick])

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">Incidents</div>
          <div className="page-subtitle">HIGH and CRITICAL alerts, with full story context</div>
        </div>
      </div>

      <SessionInsightCard />

      <EvidenceIncidents />

      <div className="alerts-filter-bar">
        <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
          <option value="open">Open</option>
          <option value="investigating">Investigating</option>
          <option value="dismissed">Dismissed</option>
          <option value="exception_approved">Exception Approved</option>
          <option value="risk_accepted">Risk Accepted</option>
          <option value="">All statuses</option>
        </select>
      </div>

      <IncidentList alerts={alerts} onNavigate={onNavigate} onResolved={() => setReloadTick((t) => t + 1)} />
    </div>
  )
}
