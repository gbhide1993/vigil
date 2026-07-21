import { useEffect, useState } from 'react'
import { api } from '../api'
import IncidentList from './IncidentList'

export default function Incidents({ onNavigate }) {
  const [alerts, setAlerts] = useState([])
  const [statusFilter, setStatusFilter] = useState('open')

  async function load() {
    try {
      const params = {}
      if (statusFilter) params.status = statusFilter
      const data = await api.getAlerts(params)
      setAlerts(data.alerts.filter((a) => a.severity === 'high' || a.severity === 'critical'))
    } catch {
      // ignore poll failures
    }
  }

  useEffect(() => {
    load()
    const id = setInterval(load, 3000)
    return () => clearInterval(id)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [statusFilter])

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">Incidents</div>
          <div className="page-subtitle">HIGH and CRITICAL alerts, with full story context</div>
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
      </div>

      <IncidentList alerts={alerts} onNavigate={onNavigate} onResolved={load} />
    </div>
  )
}
