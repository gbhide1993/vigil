import { useEffect, useState } from 'react'
import { api } from '../api'

function formatTime(ts) {
  if (!ts) return '—'
  return new Date(ts.replace(' ', 'T') + 'Z').toLocaleString()
}

function formatRelative(ts) {
  if (!ts) return '—'
  const then = new Date(ts.replace(' ', 'T') + 'Z').getTime()
  const diffMs = Date.now() - then
  const mins = Math.floor(diffMs / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  return `${days}d ago`
}

function formatDate(ts) {
  if (!ts) return '—'
  return new Date(ts.replace(' ', 'T') + 'Z').toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
  })
}

function sessionMiniStats(sessions) {
  return sessions.reduce(
    (acc, s) => {
      acc.files += (s.file_reads || 0) + (s.file_writes || 0)
      acc.network += s.mcp_connects || 0
      acc.commands += s.proc_spawns || 0
      return acc
    },
    { files: 0, network: 0, commands: 0 }
  )
}

function sparklineBars(sessions) {
  const days = []
  for (let i = 6; i >= 0; i--) {
    const d = new Date()
    d.setDate(d.getDate() - i)
    days.push(d.toISOString().slice(0, 10))
  }
  const totals = Object.fromEntries(days.map((d) => [d, 0]))
  for (const s of sessions) {
    if (!s.started_at) continue
    const day = s.started_at.slice(0, 10)
    if (day in totals) {
      totals[day] += (s.file_reads || 0) + (s.file_writes || 0) + (s.proc_spawns || 0)
    }
  }
  const max = Math.max(1, ...Object.values(totals))
  return days.map((d) => ({ day: d, height: Math.max(4, Math.round((totals[d] / max) * 28)) }))
}

function Sparkline({ sessions }) {
  const bars = sparklineBars(sessions)
  return (
    <div className="agent-sparkline" title="Activity, last 7 days">
      {bars.map((b) => (
        <div key={b.day} className="agent-sparkline-bar" style={{ height: `${b.height}px` }} title={b.day} />
      ))}
    </div>
  )
}

function MiniStats({ sessions }) {
  const stats = sessionMiniStats(sessions)
  return (
    <div className="agent-card-ministats">
      <div>
        <div className="agent-ministat-label">Files accessed</div>
        <div className="agent-ministat-value">{stats.files.toLocaleString()}</div>
      </div>
      <div>
        <div className="agent-ministat-label">Network calls</div>
        <div className="agent-ministat-value">{stats.network.toLocaleString()}</div>
      </div>
      <div>
        <div className="agent-ministat-label">Commands run</div>
        <div className="agent-ministat-value">{stats.commands.toLocaleString()}</div>
      </div>
    </div>
  )
}

function PendingAgentCard({ agent, sessions, onApprove, onBlock }) {
  const [busy, setBusy] = useState(false)
  const [blocking, setBlocking] = useState(false)
  const [reason, setReason] = useState('')
  const [errorMsg, setErrorMsg] = useState(null)

  async function handleApprove() {
    setBusy(true)
    setErrorMsg(null)
    try {
      await onApprove(agent.id)
    } catch (err) {
      setErrorMsg(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function handleBlock() {
    setBusy(true)
    setErrorMsg(null)
    try {
      await onBlock(agent.id, reason.trim() || undefined)
      setBlocking(false)
      setReason('')
    } catch (err) {
      setErrorMsg(err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="agent-card pending">
      <div className="agent-card-top">
        <div className="agent-card-identity">
          <span className="status-dot amber" />
          <span className="agent-card-name">{agent.name}</span>
        </div>
        <span className="agent-card-sessions">{agent.session_count} sessions</span>
      </div>
      <div className="agent-card-meta">
        First seen {formatDate(agent.first_seen)} · Last seen {formatRelative(agent.last_seen)}
      </div>

      <MiniStats sessions={sessions} />

      {!blocking ? (
        <div className="agent-card-actions">
          <button className="btn approve-btn" disabled={busy} onClick={handleApprove}>
            Approve →
          </button>
          <button className="btn block-btn" disabled={busy} onClick={() => setBlocking(true)}>
            Block
          </button>
        </div>
      ) : (
        <div className="field" style={{ marginTop: 10, marginBottom: 0 }}>
          <label>Reason for blocking (optional)</label>
          <textarea
            rows={2}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Why is this agent being blocked?"
          />
          <div className="agent-card-actions">
            <button className="btn block-btn" disabled={busy} onClick={handleBlock}>
              Confirm Block
            </button>
            <button className="btn" disabled={busy} onClick={() => { setBlocking(false); setReason('') }}>
              Cancel
            </button>
          </div>
        </div>
      )}

      {errorMsg && <div style={{ color: 'var(--color-critical)', fontSize: 11, marginTop: 8 }}>{errorMsg}</div>}
    </div>
  )
}

function ApprovedAgentCard({ agent, sessions, onBlock }) {
  const [busy, setBusy] = useState(false)
  const [errorMsg, setErrorMsg] = useState(null)

  async function handleBlock() {
    setBusy(true)
    setErrorMsg(null)
    try {
      await onBlock(agent.id)
    } catch (err) {
      setErrorMsg(err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="agent-card approved">
      <div className="agent-card-top">
        <div className="agent-card-identity">
          <span className="status-dot green" />
          <span className="agent-card-name">{agent.name}</span>
        </div>
        <span className="agent-card-sessions">{agent.session_count} sessions</span>
      </div>
      <div className="agent-card-meta">
        First seen {formatDate(agent.first_seen)} · Last seen {formatRelative(agent.last_seen)}
      </div>

      <MiniStats sessions={sessions} />

      <Sparkline sessions={sessions} />

      <div className="agent-card-resolution">
        Approved by {agent.approved_by || 'admin'}
        {agent.approved_at ? ` on ${formatDate(agent.approved_at)}` : ''}
      </div>

      <div className="agent-card-actions">
        <button className="btn block-btn" disabled={busy} onClick={handleBlock}>
          Block
        </button>
      </div>

      {errorMsg && <div style={{ color: 'var(--color-critical)', fontSize: 11, marginTop: 8 }}>{errorMsg}</div>}
    </div>
  )
}

function BlockedAgentCard({ agent, sessions, onApprove }) {
  const [busy, setBusy] = useState(false)
  const [errorMsg, setErrorMsg] = useState(null)

  async function handleUnblock() {
    setBusy(true)
    setErrorMsg(null)
    try {
      await onApprove(agent.id)
    } catch (err) {
      setErrorMsg(err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="agent-card blocked">
      <div className="agent-card-top">
        <div className="agent-card-identity">
          <span className="status-dot red" />
          <span className="agent-card-name">{agent.name}</span>
        </div>
        <span className="agent-card-sessions">{agent.session_count} sessions</span>
      </div>
      <div className="agent-card-meta">
        First seen {formatDate(agent.first_seen)} · Last seen {formatRelative(agent.last_seen)}
      </div>

      <MiniStats sessions={sessions} />

      <div className="agent-card-resolution">
        {agent.blocked_reason ? `Reason: ${agent.blocked_reason}` : 'No reason given'}
        {agent.blocked_at ? ` — blocked ${formatDate(agent.blocked_at)}` : ''}
      </div>

      <div className="agent-card-actions">
        <button className="btn unblock-btn" disabled={busy} onClick={handleUnblock}>
          Unblock
        </button>
      </div>

      {errorMsg && <div style={{ color: 'var(--color-critical)', fontSize: 11, marginTop: 8 }}>{errorMsg}</div>}
    </div>
  )
}

export default function AgentDetail() {
  const [agents, setAgents] = useState([])
  const [sessionsByAgent, setSessionsByAgent] = useState({})

  useEffect(() => {
    let cancelled = false
    async function load() {
      try {
        const data = await api.getAgents()
        if (cancelled) return
        setAgents(data.agents)
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
  }, [])

  useEffect(() => {
    if (agents.length === 0) return
    let cancelled = false

    async function loadSessions() {
      try {
        const entries = await Promise.all(
          agents.map(async (a) => {
            const data = await api.getAgentSessions(a.id)
            return [a.id, data.sessions]
          })
        )
        if (!cancelled) setSessionsByAgent(Object.fromEntries(entries))
      } catch {
        // ignore poll failures
      }
    }
    loadSessions()
    const id = setInterval(loadSessions, 5000)
    return () => {
      cancelled = true
      clearInterval(id)
    }
  }, [agents])

  async function handleApprove(agentId) {
    await api.approveAgent(agentId)
    const data = await api.getAgents()
    setAgents(data.agents)
  }

  async function handleBlock(agentId, reason) {
    await api.blockAgent(agentId, reason)
    const data = await api.getAgents()
    setAgents(data.agents)
  }

  const pending = agents.filter((a) => a.approved === 0)
  const approved = agents.filter((a) => a.approved === 1)
  const blocked = agents.filter((a) => a.approved === 2)

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">Agent Detail</div>
          <div className="page-subtitle">Per-agent activity, directories, and sessions</div>
        </div>
      </div>

      {agents.length === 0 ? (
        <div className="empty-state">No agents detected yet.</div>
      ) : (
        <>
          <div className="panel-header" style={{ border: 'none', padding: '4px 4px 8px' }}>
            Pending Approval
            {pending.length > 0 && <span className="badge critical">{pending.length}</span>}
          </div>
          {pending.length === 0 ? (
            <div className="empty-state">No agents pending approval.</div>
          ) : (
            pending.map((a) => (
              <PendingAgentCard
                key={a.id}
                agent={a}
                sessions={sessionsByAgent[a.id] || []}
                onApprove={handleApprove}
                onBlock={handleBlock}
              />
            ))
          )}

          <div className="panel-header" style={{ border: 'none', padding: '20px 4px 8px' }}>
            Approved Agents
          </div>
          {approved.length === 0 ? (
            <div className="empty-state">No approved agents yet.</div>
          ) : (
            approved.map((a) => (
              <ApprovedAgentCard
                key={a.id}
                agent={a}
                sessions={sessionsByAgent[a.id] || []}
                onBlock={handleBlock}
              />
            ))
          )}

          <div className="panel-header" style={{ border: 'none', padding: '20px 4px 8px' }}>
            Blocked Agents
          </div>
          {blocked.length === 0 ? (
            <div className="empty-state">No blocked agents.</div>
          ) : (
            blocked.map((a) => (
              <BlockedAgentCard
                key={a.id}
                agent={a}
                sessions={sessionsByAgent[a.id] || []}
                onApprove={handleApprove}
              />
            ))
          )}
        </>
      )}
    </div>
  )
}
