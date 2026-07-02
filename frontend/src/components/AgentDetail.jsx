import { useEffect, useState } from 'react'
import { api } from '../api'

function formatTime(ts) {
  if (!ts) return '—'
  return new Date(ts.replace(' ', 'T') + 'Z').toLocaleString()
}

function approvalLabel(approved) {
  if (approved === 1) return { text: 'Approved', className: 'low' }
  if (approved === 2) return { text: 'Blocked', className: 'critical' }
  return { text: 'Pending', className: 'medium' }
}

function statusDotColor(status) {
  if (status === 'active') return 'green'
  if (status === 'idle') return 'amber'
  return 'red'
}

function AgentActions({ agent, onApprove, onBlock }) {
  const [busy, setBusy] = useState(false)
  const [errorMsg, setErrorMsg] = useState(null)

  async function run(action) {
    setBusy(true)
    setErrorMsg(null)
    try {
      await action(agent.id)
    } catch (err) {
      setErrorMsg(err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div>
      <div style={{ display: 'flex', gap: 8 }}>
        {agent.approved !== 1 && (
          <button className="btn primary" disabled={busy} onClick={() => run(onApprove)}>
            Approve
          </button>
        )}
        {agent.approved !== 2 && (
          <button className="btn danger" disabled={busy} onClick={() => run(onBlock)}>
            Block
          </button>
        )}
      </div>
      {errorMsg && <div style={{ color: 'var(--color-critical)', fontSize: 11, marginTop: 6 }}>{errorMsg}</div>}
    </div>
  )
}

function PendingAgentCard({ agent, onApprove, onBlock }) {
  return (
    <div className="panel" style={{ marginBottom: 12 }}>
      <div className="panel-body" style={{ padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
          <div>
            <div style={{ fontWeight: 700, fontSize: 13 }}>{agent.name}</div>
            <div className="alert-meta">{agent.process_name || 'unknown process'}</div>
            <div className="alert-meta" style={{ marginTop: 6 }}>
              First seen {formatTime(agent.first_seen)} · Last seen {formatTime(agent.last_seen)} · {agent.session_count} sessions
            </div>
          </div>
          <AgentActions agent={agent} onApprove={onApprove} onBlock={onBlock} />
        </div>
      </div>
    </div>
  )
}

function AgentsManagement({ agents, onApprove, onBlock }) {
  const pending = agents.filter((a) => a.approved === 0)
  const approved = agents.filter((a) => a.approved === 1)
  const blocked = agents.filter((a) => a.approved === 2)

  return (
    <div style={{ marginBottom: 28 }}>
      <div className="panel">
        <div className="panel-header">
          Pending Approval
          {pending.length > 0 && <span className="badge critical">{pending.length}</span>}
        </div>
        <div className="panel-body" style={{ padding: pending.length ? 16 : 0 }}>
          {pending.length === 0 ? (
            <div className="empty-state">No agents pending approval.</div>
          ) : (
            pending.map((a) => (
              <PendingAgentCard key={a.id} agent={a} onApprove={onApprove} onBlock={onBlock} />
            ))
          )}
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">Approved Agents</div>
        <div className="panel-body">
          {approved.length === 0 ? (
            <div className="empty-state">No approved agents yet.</div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Sessions</th>
                  <th>Last Seen</th>
                  <th>Status</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {approved.map((a) => (
                  <tr key={a.id}>
                    <td>{a.name}</td>
                    <td>{a.session_count}</td>
                    <td>{formatTime(a.last_seen)}</td>
                    <td>
                      <span className={`status-dot ${statusDotColor(a.current_status)}`} />
                    </td>
                    <td>
                      <button className="btn danger" onClick={() => onBlock(a.id)}>Block</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">Blocked Agents</div>
        <div className="panel-body">
          {blocked.length === 0 ? (
            <div className="empty-state">No blocked agents.</div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Blocked Since</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {blocked.map((a) => (
                  <tr key={a.id}>
                    <td>{a.name}</td>
                    <td>{formatTime(a.last_seen)}</td>
                    <td>
                      <button className="btn primary" onClick={() => onApprove(a.id)}>Approve</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  )
}

export default function AgentDetail() {
  const [agents, setAgents] = useState([])
  const [selectedId, setSelectedId] = useState(null)
  const [sessions, setSessions] = useState([])
  const [events, setEvents] = useState([])

  useEffect(() => {
    let cancelled = false
    async function load() {
      try {
        const data = await api.getAgents()
        if (cancelled) return
        setAgents(data.agents)
        if (!selectedId && data.agents.length > 0) {
          setSelectedId(data.agents[0].id)
        }
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
  }, [selectedId])

  async function handleApprove(agentId) {
    await api.approveAgent(agentId)
    const data = await api.getAgents()
    setAgents(data.agents)
  }

  async function handleBlock(agentId) {
    await api.blockAgent(agentId)
    const data = await api.getAgents()
    setAgents(data.agents)
  }

  useEffect(() => {
    if (!selectedId) return
    let cancelled = false

    async function load() {
      try {
        const [sessionData, eventData] = await Promise.all([
          api.getAgentSessions(selectedId),
          api.getEvents({ agent: selectedId, limit: 100 }),
        ])
        if (cancelled) return
        setSessions(sessionData.sessions)
        setEvents(eventData.events)
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
  }, [selectedId])

  const selectedAgent = agents.find((a) => a.id === selectedId)

  const dirCounts = {}
  for (const e of events) {
    if (e.event_type === 'file_read' || e.event_type === 'file_write') {
      dirCounts[e.path] = (dirCounts[e.path] || 0) + (e.file_count || 1)
    }
  }
  const topDirs = Object.entries(dirCounts).sort((a, b) => b[1] - a[1]).slice(0, 10)

  const netConnections = events.filter((e) => e.event_type === 'net_connect')

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">Agent Detail</div>
          <div className="page-subtitle">Per-agent activity, directories, and sessions</div>
        </div>
      </div>

      <AgentsManagement agents={agents} onApprove={handleApprove} onBlock={handleBlock} />

      {agents.length === 0 ? (
        <div className="empty-state">No agents detected yet.</div>
      ) : (
        <>
          <div style={{ display: 'flex', gap: 8, marginBottom: 20, flexWrap: 'wrap' }}>
            {agents.map((a) => (
              <button
                key={a.id}
                className={`btn ${selectedId === a.id ? 'primary' : ''}`}
                onClick={() => setSelectedId(a.id)}
              >
                {a.name}
              </button>
            ))}
          </div>

          {selectedAgent && (
            <>
              <div className="stat-grid">
                <div className="stat-card">
                  <div className="stat-card-label">Status</div>
                  <div className="stat-card-value">
                    <span className={`badge ${approvalLabel(selectedAgent.approved).className}`}>
                      {approvalLabel(selectedAgent.approved).text}
                    </span>
                  </div>
                </div>
                <div className="stat-card">
                  <div className="stat-card-label">Sessions</div>
                  <div className="stat-card-value">{selectedAgent.session_count}</div>
                </div>
                <div className="stat-card">
                  <div className="stat-card-label">First Seen</div>
                  <div className="stat-card-value" style={{ fontSize: 13 }}>{formatTime(selectedAgent.first_seen)}</div>
                </div>
                <div className="stat-card">
                  <div className="stat-card-label">Last Seen</div>
                  <div className="stat-card-value" style={{ fontSize: 13 }}>{formatTime(selectedAgent.last_seen)}</div>
                </div>
              </div>

              <div className="export-grid">
                <div className="panel" style={{ marginBottom: 0 }}>
                  <div className="panel-header">Top Directories</div>
                  <div className="panel-body">
                    {topDirs.length === 0 ? (
                      <div className="empty-state">No file activity yet.</div>
                    ) : (
                      <table>
                        <thead>
                          <tr><th>Directory</th><th>Accesses</th></tr>
                        </thead>
                        <tbody>
                          {topDirs.map(([path, count]) => (
                            <tr key={path}>
                              <td className="mono-truncate" title={path}>{path}</td>
                              <td>{count}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </div>
                </div>

                <div className="panel" style={{ marginBottom: 0 }}>
                  <div className="panel-header">Network Connections</div>
                  <div className="panel-body">
                    {netConnections.length === 0 ? (
                      <div className="empty-state">No network activity yet.</div>
                    ) : (
                      <table>
                        <thead>
                          <tr><th>Time</th><th>Destination</th></tr>
                        </thead>
                        <tbody>
                          {netConnections.map((e) => (
                            <tr key={e.id}>
                              <td>{formatTime(e.created_at)}</td>
                              <td className="mono-truncate" title={e.path}>{e.path}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </div>
                </div>
              </div>

              <div className="panel">
                <div className="panel-header">Session History</div>
                <div className="panel-body">
                  {sessions.length === 0 ? (
                    <div className="empty-state">No completed sessions yet.</div>
                  ) : (
                    <table>
                      <thead>
                        <tr>
                          <th>Started</th>
                          <th>Ended</th>
                          <th>Reads</th>
                          <th>Writes</th>
                          <th>Net (MB)</th>
                          <th>Procs</th>
                          <th>Cred</th>
                          <th>Alerts</th>
                          <th>Anomaly</th>
                        </tr>
                      </thead>
                      <tbody>
                        {sessions.map((s) => (
                          <tr key={s.id}>
                            <td>{formatTime(s.started_at)}</td>
                            <td>{s.ended_at ? formatTime(s.ended_at) : 'active'}</td>
                            <td>{s.file_reads}</td>
                            <td>{s.file_writes}</td>
                            <td>{(s.net_egress_bytes / (1024 * 1024)).toFixed(2)}</td>
                            <td>{s.proc_spawns}</td>
                            <td>{s.cred_accesses}</td>
                            <td>{s.alert_count}</td>
                            <td>{s.anomaly_score.toFixed(2)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              </div>
            </>
          )}
        </>
      )}
    </div>
  )
}
