import { useEffect, useState } from 'react'
import { api } from '../api'
import { parseQuery } from '../queryParser'

const QUICK_FILTERS = [
  { label: 'After 6pm', query: 'after 6pm' },
  { label: 'Credentials', query: 'credentials' },
  { label: 'Secrets', query: 'secrets' },
  { label: '.env access', query: '.env' },
  { label: 'curl / wget', query: 'curl' },
  { label: 'Yesterday', query: 'yesterday' },
  { label: 'Claude only', query: 'claude' },
]

const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/

function isRawIp(value) {
  if (!value) return false
  const host = value.split(':')[0]
  return IPV4_RE.test(host)
}

function GlobeIcon() {
  return (
    <svg className="globe-icon" width="12" height="12" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
      <circle cx="8" cy="8" r="6.5" stroke="currentColor" strokeWidth="1.2" />
      <path d="M1.5 8h13M8 1.5c1.8 1.6 2.8 4 2.8 6.5s-1 4.9-2.8 6.5c-1.8-1.6-2.8-4-2.8-6.5S6.2 3.1 8 1.5z" stroke="currentColor" strokeWidth="1.2" />
    </svg>
  )
}

function formatTime(ts) {
  if (!ts) return ''
  return new Date(ts.replace(' ', 'T') + 'Z').toLocaleTimeString()
}

function TypeBadge({ type }) {
  const map = {
    net_connect: { label: 'NET_CONNECT', className: 'net-connect' },
    cred_access: { label: 'CRED_ACCESS', className: 'cred-access' },
    proc_spawn: { label: 'PROC_SPAWN', className: 'proc-spawn' },
    file_read: { label: 'FILE_READ', className: 'file-io' },
    file_write: { label: 'FILE_WRITE', className: 'file-io' },
  }
  const cfg = map[type] || { label: type.toUpperCase(), className: 'file-io' }
  return <span className={`type-badge ${cfg.className}`}>{cfg.label}</span>
}

function SeverityBadge({ severity }) {
  return <span className={`feed-severity-badge ${severity}`}>{severity}</span>
}

function FeedRow({ event }) {
  const path = event.path || ''
  const showGlobe = event.event_type === 'net_connect' && isRawIp(path)
  const severityClass = event.severity === 'high' || event.severity === 'critical' ? `severity-${event.severity}` : ''

  return (
    <div className={`feed-row ${severityClass}`}>
      <span className="feed-time">{formatTime(event.created_at)}</span>
      <span className="agent-pill">{event.agent_name || '—'}</span>
      <TypeBadge type={event.event_type} />
      <span className="feed-path" title={path}>
        {showGlobe && <GlobeIcon />}
        {path}
      </span>
      <span className="feed-severity">
        <SeverityBadge severity={event.severity} />
      </span>
    </div>
  )
}

function WelcomeState() {
  return (
    <div className="panel">
      <div className="panel-body" style={{ padding: '56px 24px', textAlign: 'center' }}>
        <div style={{ fontSize: 32, fontWeight: 700, color: 'var(--color-teal)', marginBottom: 12 }}>V</div>
        <div style={{ fontSize: 18, fontWeight: 600, color: 'var(--color-navy)', marginBottom: 16 }}>
          V-LAW is active and watching.
        </div>
        <div style={{ fontSize: 13, color: 'var(--color-navy-muted)', marginBottom: 24 }}>
          Start your AI agent (Claude Code, Cursor, or Copilot)
          <br />
          and return here. Your first session will appear automatically.
        </div>
        <div style={{ fontSize: 12.5, color: 'var(--color-navy-muted)', lineHeight: 2 }}>
          <div>● File activity</div>
          <div>● Network connections</div>
          <div>● Process spawns</div>
          <div>● MCP tool calls</div>
        </div>
        <div style={{ fontSize: 12, color: 'var(--color-navy-muted)', marginTop: 24 }}>
          All monitored. Zero data leaves this machine.
        </div>
      </div>
    </div>
  )
}

function trendArrow(delta) {
  if (delta > 0) return { symbol: '▲', className: 'trend-up' }
  if (delta < 0) return { symbol: '▼', className: 'trend-down' }
  return { symbol: '–', className: '' }
}

function StatCard({ label, value, valueClassName, today, yesterday, formatDelta }) {
  const hasYesterday = typeof yesterday === 'number'
  const delta = hasYesterday ? today - yesterday : null
  const arrow = hasYesterday ? trendArrow(delta) : null

  return (
    <div className="stat-card">
      <div className="stat-card-label">{label}</div>
      <div className={`stat-card-value ${valueClassName || ''}`}>{value}</div>
      {hasYesterday && (
        <div className="stat-card-trend">
          <span className={arrow.className}>{arrow.symbol}</span>
          <span>{formatDelta ? formatDelta(delta) : Math.abs(delta)} vs yesterday</span>
        </div>
      )}
    </div>
  )
}

export default function History() {
  const [stats, setStats] = useState(null)
  const [events, setEvents] = useState([])
  const [error, setError] = useState(null)
  const [sessions, setSessions] = useState(null)
  const [query, setQuery] = useState('')
  const [filteredEvents, setFilteredEvents] = useState([])

  useEffect(() => {
    let cancelled = false

    async function load() {
      try {
        const [statsData, eventsData, sessionsData] = await Promise.all([
          api.getStats(),
          api.getEvents({ limit: 50 }),
          api.getSessions(),
        ])
        if (cancelled) return
        setStats(statsData)
        setEvents(eventsData.events)
        setSessions(sessionsData.sessions)
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

  useEffect(() => {
    setFilteredEvents(parseQuery(query, events))
  }, [query, events])

  const netEvents = events.filter((e) => e.event_type === 'net_connect')
  const credEvents = events.filter((e) => e.event_type === 'cred_access')

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">History</div>
          <div className="page-subtitle">Real-time agent activity on this machine</div>
        </div>
      </div>

      {error && <div className="empty-state">Could not reach V-LAW backend: {error}</div>}

      <div className="stat-grid">
        <StatCard
          label="Active Agents"
          value={stats?.active_agents ?? '—'}
          valueClassName={stats ? (stats.active_agents > 0 ? 'good' : 'neutral') : ''}
        />
        <StatCard
          label="Events Today"
          value={stats?.events_today ?? '—'}
          today={stats?.events_today}
          yesterday={stats?.events_yesterday}
        />
        <StatCard
          label="Open Alerts"
          value={stats?.alerts_open ?? '—'}
          valueClassName={stats ? (stats.alerts_open > 0 ? 'bad-critical' : 'good') : ''}
          today={stats?.alerts_open}
          yesterday={stats?.alerts_open_yesterday}
        />
        <StatCard
          label="Net Egress (MB)"
          value={stats?.net_egress_mb_today ?? '—'}
          valueClassName={stats ? (stats.net_egress_mb_today > 0 ? 'bad-high' : 'good') : ''}
          today={stats?.net_egress_mb_today}
          yesterday={stats?.net_egress_mb_yesterday}
          formatDelta={(d) => `${Math.abs(d).toFixed(2)} MB`}
        />
        <StatCard
          label="Credential Accesses"
          value={stats?.cred_accesses_today ?? '—'}
          valueClassName={stats ? (stats.cred_accesses_today > 0 ? 'bad-critical' : 'good') : ''}
          today={stats?.cred_accesses_today}
          yesterday={stats?.cred_accesses_yesterday}
        />
      </div>

      {sessions !== null && sessions.length === 0 ? (
        <WelcomeState />
      ) : (
      <>
      <div className="query-bar">
        <input
          className="query-input mono"
          placeholder='Ask anything — "after 6pm", "modified .env", "curl", "claude"...'
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => e.key === 'Escape' && setQuery('')}
        />
        {query && (
          <button className="query-clear" onClick={() => setQuery('')} aria-label="Clear search">
            ✕
          </button>
        )}
        {query && (
          <div className="query-result-count mono">
            {filteredEvents.length} result{filteredEvents.length !== 1 ? 's' : ''}
          </div>
        )}
      </div>

      <div className="quick-filters">
        {QUICK_FILTERS.map((f) => (
          <button
            key={f.query}
            className={`quick-chip ${query === f.query ? 'active' : ''}`}
            onClick={() => setQuery(query === f.query ? '' : f.query)}
          >
            {f.label}
          </button>
        ))}
      </div>

      <div className="panel">
        <div className="panel-header">
          <span>Event Stream</span>
          <span style={{ fontWeight: 400, color: 'var(--color-navy-muted)' }}>
            {query ? `${filteredEvents.length} of ${events.length}` : `${events.length} recent`}
          </span>
        </div>
        <div className="panel-body">
          {filteredEvents.length === 0 ? (
            <div className="empty-state">
              {query ? 'No events match this search.' : 'No events yet — waiting for agent activity.'}
            </div>
          ) : (
            filteredEvents.map((e) => <FeedRow key={e.id} event={e} />)
          )}
        </div>
      </div>
      </>
      )}

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
                      <td className="mono-truncate" title={e.path}>
                        {isRawIp(e.path) && <GlobeIcon />} {e.path}
                      </td>
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
