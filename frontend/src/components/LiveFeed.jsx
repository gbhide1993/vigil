import { useEffect, useRef, useState } from 'react'
import { api } from '../api'

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

function FirstSessionCard({ session, topFinding, onDismiss }) {
  const alert = topFinding?.alert
  const kind = topFinding?.kind

  let borderColor = 'var(--color-green)'
  let text
  if (kind === 'red_line') {
    borderColor = 'var(--color-red)'
    text = `First session complete. ${session.agent_name} accessed ${session.file_reads + session.file_writes} files and made ${session.net_connect_count} network connections. 1 RED LINE alert caught.`
  } else if (kind === 'anomaly') {
    borderColor = 'var(--color-amber)'
    text = `First session complete. ${session.agent_name} accessed ${session.file_reads + session.file_writes} files. ${alert.title}`
  } else if (session.alert_count > 0) {
    borderColor = 'var(--color-amber)'
    text = `First session complete. ${session.agent_name} accessed ${session.file_reads + session.file_writes} files. ${session.alert_count} alert${session.alert_count !== 1 ? 's' : ''} raised.`
  } else {
    text = `First session complete. ${session.agent_name} ran clean — no alerts, ${session.file_reads + session.file_writes} files accessed. V-LAW is working.`
  }

  return (
    <div
      className="panel"
      style={{ borderLeft: `4px solid ${borderColor}` }}
    >
      <div className="panel-body" style={{ padding: '14px 16px', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 16 }}>
        <div style={{ fontSize: 14, color: 'var(--color-navy)' }}>{text}</div>
        <button
          onClick={onDismiss}
          style={{ background: 'none', border: 'none', color: 'var(--color-navy-muted)', cursor: 'pointer', fontSize: 16, lineHeight: 1, padding: 0 }}
          aria-label="Dismiss"
        >
          ×
        </button>
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

export default function LiveFeed() {
  const [stats, setStats] = useState(null)
  const [events, setEvents] = useState([])
  const [error, setError] = useState(null)
  const [baselineActive, setBaselineActive] = useState(true)
  const [insights, setInsights] = useState([])
  const [sessions, setSessions] = useState(null)
  const [firstSessionCard, setFirstSessionCard] = useState(null)
  const prevSessionCountRef = useRef(null)

  useEffect(() => {
    let cancelled = false

    async function load() {
      try {
        const [statsData, eventsData, healthData, sessionsData] = await Promise.all([
          api.getStats(),
          api.getEvents({ limit: 50 }),
          api.getHealth(),
          api.getSessions(),
        ])
        if (cancelled) return
        setStats(statsData)
        setEvents(eventsData.events)
        setBaselineActive(healthData.baseline_active)
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
    if (sessions === null) return
    const prevCount = prevSessionCountRef.current
    prevSessionCountRef.current = sessions.length

    if (prevCount === 0 && sessions.length === 1) {
      const firstSession = sessions[0]
      let cancelled = false
      async function loadTopFinding() {
        try {
          const topFinding = await api.getSessionTopFinding(firstSession.id)
          if (!cancelled) setFirstSessionCard({ session: firstSession, topFinding })
        } catch {
          if (!cancelled) setFirstSessionCard({ session: firstSession, topFinding: { kind: null, alert: null } })
        }
      }
      loadTopFinding()
      return () => {
        cancelled = true
      }
    }
  }, [sessions])

  useEffect(() => {
    if (!firstSessionCard) return
    const timer = setTimeout(() => setFirstSessionCard(null), 60000)
    return () => clearTimeout(timer)
  }, [firstSessionCard])

  useEffect(() => {
    if (baselineActive) return
    let cancelled = false

    async function loadInsights() {
      try {
        const data = await api.getInsights()
        if (!cancelled) setInsights(data.cards)
      } catch {
        // insight poll failures are non-fatal, silently retry next tick
      }
    }
    loadInsights()
    const id = setInterval(loadInsights, 10000)
    return () => {
      cancelled = true
      clearInterval(id)
    }
  }, [baselineActive])

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

      {firstSessionCard && (
        <FirstSessionCard
          session={firstSessionCard.session}
          topFinding={firstSessionCard.topFinding}
          onDismiss={() => setFirstSessionCard(null)}
        />
      )}

      {!baselineActive && insights.length > 0 && (
        <div className="panel">
          <div className="panel-header">
            <span>Today's Insights</span>
            <span style={{ fontWeight: 400, color: 'var(--color-navy-muted)' }}>
              baseline still compiling — statistical anomaly scoring isn't active yet
            </span>
          </div>
          <div className="panel-body" style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 10 }}>
            {insights.map((card) => (
              <div key={card.kind} style={{ fontSize: 12.5 }}>{card.text}</div>
            ))}
          </div>
        </div>
      )}

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
      <div className="panel">
        <div className="panel-header">
          <span>Event Stream</span>
          <span style={{ fontWeight: 400, color: 'var(--color-navy-muted)' }}>{events.length} recent</span>
        </div>
        <div className="panel-body">
          {events.length === 0 ? (
            <div className="empty-state">No events yet — waiting for agent activity.</div>
          ) : (
            events.map((e) => <FeedRow key={e.id} event={e} />)
          )}
        </div>
      </div>
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
