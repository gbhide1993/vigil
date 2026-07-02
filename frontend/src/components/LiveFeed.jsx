import { useEffect, useState } from 'react'
import { api } from '../api'

function formatTime(ts) {
  if (!ts) return ''
  return new Date(ts.replace(' ', 'T') + 'Z').toLocaleTimeString()
}

function EventTypeBadge({ type }) {
  return <span className="badge outline">{type}</span>
}

export default function LiveFeed() {
  const [stats, setStats] = useState(null)
  const [events, setEvents] = useState([])
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false

    async function load() {
      try {
        const [statsData, eventsData] = await Promise.all([
          api.getStats(),
          api.getEvents({ limit: 50 }),
        ])
        if (cancelled) return
        setStats(statsData)
        setEvents(eventsData.events)
        setError(null)
      } catch (err) {
        if (!cancelled) setError(err.message)
      }
    }

    load()
    const id = setInterval(load, 2000)
    return () => {
      cancelled = true
      clearInterval(id)
    }
  }, [])

  const netEvents = events.filter((e) => e.event_type === 'net_connect')
  const credEvents = events.filter((e) => e.event_type === 'cred_access')

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">Live Feed</div>
          <div className="page-subtitle">Real-time agent activity on this machine</div>
        </div>
      </div>

      {error && <div className="empty-state">Could not reach V-LAW backend: {error}</div>}

      <div className="stat-grid">
        <div className="stat-card">
          <div className="stat-card-label">Active Agents</div>
          <div className="stat-card-value accent">{stats?.active_agents ?? '—'}</div>
        </div>
        <div className="stat-card">
          <div className="stat-card-label">Events Today</div>
          <div className="stat-card-value">{stats?.events_today ?? '—'}</div>
        </div>
        <div className="stat-card">
          <div className="stat-card-label">Open Alerts</div>
          <div className="stat-card-value" style={{ color: stats?.alerts_open ? 'var(--color-critical)' : undefined }}>
            {stats?.alerts_open ?? '—'}
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-card-label">Net Egress (MB)</div>
          <div className="stat-card-value">{stats?.net_egress_mb_today ?? '—'}</div>
        </div>
        <div className="stat-card">
          <div className="stat-card-label">Credential Accesses</div>
          <div className="stat-card-value" style={{ color: stats?.cred_accesses_today ? 'var(--color-high)' : undefined }}>
            {stats?.cred_accesses_today ?? '—'}
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <span>Event Stream</span>
          <span style={{ fontWeight: 400, color: 'var(--color-navy-muted)' }}>{events.length} recent</span>
        </div>
        <div className="panel-body">
          {events.length === 0 ? (
            <div className="empty-state">No events yet — waiting for agent activity.</div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Agent</th>
                  <th>Type</th>
                  <th>Path / Destination</th>
                  <th>Severity</th>
                </tr>
              </thead>
              <tbody>
                {events.map((e) => (
                  <tr key={e.id}>
                    <td>{formatTime(e.created_at)}</td>
                    <td>{e.agent_name || '—'}</td>
                    <td><EventTypeBadge type={e.event_type} /></td>
                    <td className="mono-truncate" title={e.path}>{e.path}</td>
                    <td><span className={`badge ${e.severity}`}>{e.severity}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      <div className="export-grid">
        <div className="panel" style={{ marginBottom: 0 }}>
          <div className="panel-header">Network Egress</div>
          <div className="panel-body">
            {netEvents.length === 0 ? (
              <div className="empty-state">No network activity yet.</div>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Agent</th>
                    <th>Destination</th>
                  </tr>
                </thead>
                <tbody>
                  {netEvents.map((e) => (
                    <tr key={e.id}>
                      <td>{formatTime(e.created_at)}</td>
                      <td>{e.agent_name}</td>
                      <td className="mono-truncate" title={e.path}>{e.path}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        <div className="panel" style={{ marginBottom: 0 }}>
          <div className="panel-header">Credential Access</div>
          <div className="panel-body">
            {credEvents.length === 0 ? (
              <div className="empty-state">No credential access detected.</div>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Agent</th>
                    <th>Path</th>
                  </tr>
                </thead>
                <tbody>
                  {credEvents.map((e) => (
                    <tr key={e.id}>
                      <td>{formatTime(e.created_at)}</td>
                      <td>{e.agent_name}</td>
                      <td className="mono-truncate" title={e.path}>{e.path}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
