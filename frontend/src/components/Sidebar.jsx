import { useEffect, useState } from 'react'
import { api } from '../api'

const NAV_ITEMS = [
  { key: 'status', label: 'Status' },
  { key: 'agents', label: 'Agents' },
  { key: 'incidents', label: 'Incidents' },
  { key: 'alerts', label: 'Alerts' },
  { key: 'history', label: 'History' },
  { key: 'export', label: 'Export' },
  { key: 'settings', label: 'Settings' },
]

function statusDotColor(agent) {
  if (agent.approved === 2) return 'red'
  if (agent.approved === 0) return 'amber'
  return 'green'
}

export default function Sidebar({ view, onNavigate, needsReviewCount }) {
  const [agents, setAgents] = useState([])

  useEffect(() => {
    let cancelled = false
    let inFlight = false
    async function load() {
      if (inFlight) return
      inFlight = true
      try {
        const data = await api.getAgents()
        if (!cancelled) setAgents(data.agents)
      } catch {
        // sidebar polling failures are non-fatal, silently retry next tick
      } finally {
        inFlight = false
      }
    }
    load()
    const id = setInterval(load, 3000)
    return () => {
      cancelled = true
      clearInterval(id)
    }
  }, [])

  const pendingCount = agents.filter((a) => a.approved === 0).length

  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <div className="sidebar-brand-name">Vigil</div>
        <div className="sidebar-brand-tagline">Local AI Watchdog</div>
      </div>

      <nav className="sidebar-nav">
        {NAV_ITEMS.map((item) => (
          <button
            key={item.key}
            className={`sidebar-nav-item ${view === item.key ? 'active' : ''}`}
            onClick={() => onNavigate(item.key)}
          >
            <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              {item.key === 'agents' && pendingCount > 0 && <span className="status-dot amber" />}
              {item.key === 'agents' && pendingCount > 0
                ? `${item.label} (${pendingCount} awaiting approval)`
                : item.label}
            </span>
            {item.key === 'incidents' && needsReviewCount > 0 && (
              <span className="sidebar-badge">{needsReviewCount}</span>
            )}
          </button>
        ))}
      </nav>

      <div>
        <div className="sidebar-section-title">Watching now</div>
        <div className="watching-list">
          {agents.length === 0 && (
            <div className="watching-item" style={{ color: 'var(--color-navy-muted)' }}>
              No agents detected
            </div>
          )}
          {agents.map((agent) => (
            <div className="watching-item" key={agent.id}>
              <span className={`status-dot ${statusDotColor(agent)}`} />
              <span>{agent.name}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="sidebar-version">v1.0.0</div>
    </aside>
  )
}
