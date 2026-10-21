import { useCallback, useEffect, useRef, useState } from 'react'
import { api, realSessions } from '../api'
import { isIntentQuery, parseQuery } from '../queryParser'
import CopyButton from './CopyButton'

const SEARCH_DEBOUNCE_MS = 200
const SEARCH_PAGE_SIZE = 100
const INTENT_WINDOW = 2000
const SESSION_CHIPS_MAX = 5

function debounce(fn, delay) {
  let timer
  return (...args) => {
    clearTimeout(timer)
    timer = setTimeout(() => fn(...args), delay)
  }
}

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
  const d = new Date(ts.replace(' ', 'T') + 'Z')
  // Search results can span days: add the date when it is not today.
  return d.toDateString() === new Date().toDateString()
    ? d.toLocaleTimeString()
    : `${d.toLocaleDateString(undefined, { day: 'numeric', month: 'short' })} ${d.toLocaleTimeString()}`
}

function localIsoDate(d = new Date()) {
  const pad = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
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
      <span className="feed-session mono" title={event.session_id || undefined}>
        {(event.session_id || '').slice(0, 8)}
      </span>
      <span className="agent-pill" title={event.attribution_label || event.agent_name || undefined}>
        {event.agent_name || '—'}{event.attribution === 'best_guess' ? ' (best guess)' : ''}
      </span>
      <TypeBadge type={event.event_type} />
      <span className="feed-path" title={path}>
        {showGlobe && <GlobeIcon />}
        <span className="feed-path-text">{path}</span>
        <CopyButton text={path} />
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
          Vigil is active and watching.
        </div>
        <div style={{ fontSize: 13, color: 'var(--color-navy-muted)', marginBottom: 24 }}>
          Start your AI agent (Claude Code, Cursor, or Copilot)
          <br />
          and return here. Your first session will appear automatically.
        </div>
        <div style={{ fontSize: 12.5, color: 'var(--color-navy-muted)', lineHeight: 2 }}>
          <div>● File changes</div>
          <div>● Process spawns</div>
        </div>
        <div style={{ fontSize: 12, color: 'var(--color-navy-muted)', marginTop: 24 }}>
          Vigil uploads no event data.
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
  const [networkMonitoring, setNetworkMonitoring] = useState(null)
  const [query, setQuery] = useState('')
  // null while the box is empty; otherwise { mode, events, total, sessions, sessionCount, loading, loadingMore, error }
  const [search, setSearch] = useState(null)
  const moreController = useRef(null)

  useEffect(() => {
    let cancelled = false

    async function load() {
      try {
        const [statsData, eventsData, sessionsData, healthData] = await Promise.all([
          api.getStats(),
          api.getEvents({ limit: 50 }),
          api.getSessions(),
          api.getHealth(),
        ])
        if (cancelled) return
        setStats(statsData)
        setEvents(eventsData.events)
        setSessions(realSessions(sessionsData.sessions))
        setNetworkMonitoring(healthData.network_monitoring ?? null)
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

  const trackQueryDebounced = useCallback(
    debounce((q, count) => {
      if (q.trim()) {
        api.trackEvent('query_used', { query_length: q.length, result_count: count })
      }
    }, 600),
    []
  )

  // Live search: every keystroke restarts a short debounce and cancels the request
  // that is still in flight, so a slow older answer can never replace a newer one.
  useEffect(() => {
    const q = query.trim()
    if (moreController.current) moreController.current.abort()
    if (!q) {
      setSearch(null)
      return undefined
    }
    const controller = new AbortController()
    setSearch((prev) => ({ ...(prev || {}), loading: true, error: null }))
    const timer = setTimeout(async () => {
      try {
        let next
        if (isIntentQuery(q)) {
          const data = await api.getEvents({ limit: INTENT_WINDOW }, controller.signal)
          const matched = parseQuery(q, data.events)
          const ids = [...new Set(matched.map((e) => e.session_id).filter(Boolean))]
          next = {
            mode: 'intent', all: matched, shown: SEARCH_PAGE_SIZE, total: matched.length,
            sessions: ids.map((id) => ({ session_id: id })), sessionCount: ids.length,
          }
        } else {
          const data = await api.searchEvents(q, { limit: SEARCH_PAGE_SIZE, offset: 0 }, controller.signal)
          next = {
            mode: 'search', events: data.events, total: data.total,
            sessions: data.sessions, sessionCount: data.session_count,
          }
        }
        if (controller.signal.aborted) return
        setSearch({ ...next, loading: false, loadingMore: false, error: null })
        trackQueryDebounced(q, next.total)
      } catch (err) {
        if (!controller.signal.aborted) setSearch((prev) => ({ ...(prev || {}), loading: false, error: err.message }))
      }
    }, SEARCH_DEBOUNCE_MS)
    return () => {
      clearTimeout(timer)
      controller.abort()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query])

  async function loadMore() {
    if (!search || search.loadingMore) return
    if (search.mode === 'intent') {
      setSearch((prev) => ({ ...prev, shown: prev.shown + SEARCH_PAGE_SIZE }))
      return
    }
    const controller = new AbortController()
    moreController.current = controller
    setSearch((prev) => ({ ...prev, loadingMore: true }))
    try {
      const data = await api.searchEvents(query.trim(), { limit: SEARCH_PAGE_SIZE, offset: search.events.length }, controller.signal)
      if (controller.signal.aborted) return
      setSearch((prev) => ({ ...prev, events: [...prev.events, ...data.events], total: data.total, loadingMore: false }))
    } catch (err) {
      if (!controller.signal.aborted) setSearch((prev) => ({ ...prev, loadingMore: false, error: err.message }))
    }
  }

  const searching = search !== null
  const visibleEvents = !searching
    ? events
    : search.mode === 'intent'
      ? (search.all || []).slice(0, search.shown)
      : (search.events || [])
  const totalMatches = searching ? (search.total ?? 0) : events.length
  const singleSession = searching && !search.loading && search.sessionCount === 1 ? search.sessions[0] : null

  const netEvents = events.filter((e) => e.event_type === 'net_connect')
  const credEvents = events.filter((e) => e.event_type === 'cred_access')

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">History</div>
          <div className="page-subtitle">Agent activity on this machine</div>
        </div>
      </div>

      {error && <div className="empty-state">Could not reach Vigil backend: {error}</div>}

      <div className="stat-grid">
        <StatCard
          label="Approved Agents"
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
          value={networkMonitoring === 'off' ? 'off' : (stats?.net_egress_mb_today ?? '—')}
          valueClassName={stats && networkMonitoring === 'on' ? (stats.net_egress_mb_today > 0 ? 'bad-high' : 'good') : ''}
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
          placeholder='Search as you type: a session id (any start of it), a file, a command, an agent, or "after 6pm"'
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => e.key === 'Escape' && setQuery('')}
          aria-label="Search events"
          spellCheck={false}
        />
        {query && (
          <button className="query-clear" onClick={() => setQuery('')} aria-label="Clear search">
            ✕
          </button>
        )}
        {query && (
          <div className="query-result-count mono" aria-live="polite">
            {search?.error
              ? 'search failed'
              : search?.loading && search.total === undefined
                ? 'searching…'
                : `${totalMatches} result${totalMatches !== 1 ? 's' : ''}${search?.sessionCount ? ` · ${search.sessionCount} session${search.sessionCount !== 1 ? 's' : ''}` : ''}`}
          </div>
        )}
      </div>

      {searching && search.mode === 'search' && search.sessions && search.sessions.length > 0 && (
        <div className="session-chips">
          {search.sessions.slice(0, SESSION_CHIPS_MAX).map((s) => (
            <button key={s.session_id} className="session-chip mono" title={s.session_id} onClick={() => setQuery(s.session_id)}>
              {s.session_id.slice(0, 8)} · {s.agent_name || 'agent'} · {s.ended_at ? 'closed' : 'open'} · {s.matching_events} event{s.matching_events !== 1 ? 's' : ''}
            </button>
          ))}
          {search.sessionCount > SESSION_CHIPS_MAX && <span className="session-chips-more">+{search.sessionCount - SESSION_CHIPS_MAX} more</span>}
        </div>
      )}

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
            {searching ? `${visibleEvents.length} of ${totalMatches}` : `${events.length} recent`}
          </span>
        </div>
        <div className="panel-body">
          {visibleEvents.length === 0 ? (
            <div className="empty-state">
              {searching
                ? (search.loading ? 'Searching…' : search.error ? `Search failed: ${search.error}` : 'No events match this search.')
                : 'No events yet — waiting for agent activity.'}
            </div>
          ) : (
            visibleEvents.map((e) => <FeedRow key={e.id} event={e} />)
          )}
          {searching && visibleEvents.length < totalMatches && (
            <div className="feed-more">
              <button className="btn ghost" disabled={search.loadingMore} onClick={loadMore}>
                {search.loadingMore ? 'Loading…' : `Show ${Math.min(SEARCH_PAGE_SIZE, totalMatches - visibleEvents.length)} more (${totalMatches - visibleEvents.length} left)`}
              </button>
            </div>
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
              <div className="empty-state">
                {networkMonitoring === 'off'
                  ? 'Network monitoring is off in this version.'
                  : 'No network connections recorded.'}
              </div>
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
                      <td title={e.attribution_label || undefined}>{e.agent_name}{e.attribution === 'best_guess' ? ' (best guess)' : ''}</td>
                      <td className="cell-wrap" title={e.path}>
                        {isRawIp(e.path) && <GlobeIcon />} {e.path} <CopyButton text={e.path} />
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
                      <td title={e.attribution_label || undefined}>{e.agent_name}{e.attribution === 'best_guess' ? ' (best guess)' : ''}</td>
                      <td className="cell-wrap" title={e.path}>{e.path} <CopyButton text={e.path} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>

      <div className="history-export-row">
        <span className="history-export-label mono">
          {searching ? `${totalMatches} events matching "${query.trim()}"` : `${events.length} events in current view`}
        </span>
        <button
          className="btn-export-inline"
          onClick={() => {
            api.trackEvent('export_clicked', { source: 'history', session: Boolean(singleSession) })
            window.open(
              singleSession ? api.sessionReportUrl(singleSession.session_id) : api.exportPdfUrl(localIsoDate()),
              '_blank',
            )
          }}
        >
          {singleSession ? `Export session report (${singleSession.session_id.slice(0, 8)}) →` : "Export today's report →"}
        </button>
      </div>
    </div>
  )
}
