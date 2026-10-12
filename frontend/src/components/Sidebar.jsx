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

// The dot says whether the agent has been active just now, not whether it is approved.
// Approval is a separate word under the name. "active" means the backend saw activity
// from this agent in the last 30 seconds (api/agents.py current_status).
function statusDotColor(agent) {
  if (agent.approved === 2) return 'red'
  return agent.current_status === 'active' ? 'green' : 'idle'
}

function approvalLabel(agent) {
  if (agent.approved === 2) return 'blocked'
  if (agent.approved === 0) return 'not approved yet'
  return 'approved'
}

function activityLabel(agent) {
  if (agent.current_status === 'active') return 'active now'
  if (!agent.last_seen) return 'no activity seen'
  const seconds = Math.max(0, (Date.now() - new Date(agent.last_seen.replace(' ', 'T') + 'Z').getTime()) / 1000)
  if (seconds < 90) return 'last activity just now'
  const minutes = Math.round(seconds / 60)
  if (minutes < 60) return `last activity ${minutes} min ago`
  const hours = Math.round(minutes / 60)
  if (hours < 48) return `last activity ${hours} h ago`
  return `last activity ${Math.round(hours / 24)} d ago`
}

export default function Sidebar({ view, onNavigate, needsReviewCount, version }) {
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
  const activeNow = agents.filter((a) => a.current_status === 'active').length

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
                ? `${item.label} (${pendingCount} not approved yet)`
                : item.label}
            </span>
            {item.key === 'incidents' && needsReviewCount > 0 && (
              <span className="sidebar-badge">{needsReviewCount}</span>
            )}
          </button>
        ))}
      </nav>

      <div>
        <div className="sidebar-section-title">Recognised agents</div>
        <div className="sidebar-section-note">
          {agents.length === 0 ? 'none seen yet' : `${activeNow} active now of ${agents.length} seen`}
        </div>
        <div className="watching-list">
          {agents.length === 0 && (
            <div className="watching-item" style={{ color: 'var(--color-navy-muted)' }}>
              No agents detected
            </div>
          )}
          {agents.map((agent) => (
            <div className="watching-item agent-row" key={agent.id} title={`${agent.name}: ${approvalLabel(agent)}, ${activityLabel(agent)}`}>
              <span className={`status-dot ${statusDotColor(agent)}`} />
              <span className="agent-row-text">
                <span className="agent-row-name">{agent.name}</span>
                <span className="agent-row-sub">{activityLabel(agent)} · {approvalLabel(agent)}</span>
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* version is null until the backend has actually answered -- show
          nothing rather than a hardcoded or stale number in the meantime. */}
      {version && <div className="sidebar-version">v{version}</div>}
    </aside>
  )
}
