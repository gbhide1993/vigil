import { useEffect, useState } from 'react'
import { api } from '../api'

const NAV_ITEMS = [
  { key: 'live', label: 'Live Feed' },
  { key: 'agents', label: 'Agent Detail' },
  { key: 'alerts', label: 'Alerts' },
  { key: 'export', label: 'Export' },
]

function statusDotColor(agent) {
  if (agent.approved === 2) return 'red'
  if (agent.approved === 0) return 'amber'
  return 'green'
}

export default function Sidebar({ view, onNavigate, openAlertCount }) {
  const [agents, setAgents] = useState([])

  useEffect(() => {
    let cancelled = false
    async function load() {
      try {
        const data = await api.getAgents()
        if (!cancelled) setAgents(data.agents)
      } catch {
        // sidebar polling failures are non-fatal, silently retry next tick
      }
    }
    load()
    const id = setInterval(load, 3000)
    return () => {
      cancelled = true
      clearInterval(id)
    }
  }, [])

  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <div className="sidebar-brand-name">V-LAW</div>
        <div className="sidebar-brand-tagline">Local AI Watchdog</div>
      </div>

      <nav className="sidebar-nav">
        {NAV_ITEMS.map((item) => (
          <button
            key={item.key}
            className={`sidebar-nav-item ${view === item.key ? 'active' : ''}`}
            onClick={() => onNavigate(item.key)}
          >
            <span>{item.label}</span>
            {item.key === 'alerts' && openAlertCount > 0 && (
              <span className="sidebar-badge">{openAlertCount}</span>
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
    </aside>
  )
}
