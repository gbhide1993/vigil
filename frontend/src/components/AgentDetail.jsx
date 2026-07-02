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
