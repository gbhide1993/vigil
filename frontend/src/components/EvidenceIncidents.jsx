import { useEffect, useState } from 'react'
import { api } from '../api'

const POLL_MS = 10000

function formatTime(iso) {
  if (!iso) return '—'
  try {
    return new Date(iso).toLocaleTimeString(undefined, {
      hour12: false,
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    })
  } catch {
    return '—'
  }
}

function EvidenceIncidentCard({ incident }) {
  const [expanded, setExpanded] = useState(false)
  const firstEvidence = incident.evidence[0]
  const attribution = firstEvidence?.attribution
  const raw = firstEvidence?.raw
  const policy = firstEvidence?.policy

  return (
    <div className="evidence-incident-card">
      <div className="evidence-incident-top">
        <span className={`feed-severity-badge ${incident.severity}`}>{incident.severity.toUpperCase()}</span>
        <span className="evidence-incident-rule">{policy ? policy.rule_id : ''}</span>
      </div>

      <div className="evidence-incident-what">{incident.what}</div>

      <div className="evidence-incident-fields">
        <div><span className="evidence-incident-label">WHAT</span> {incident.what}</div>
        <div><span className="evidence-incident-label">WHY</span> {incident.why}</div>
        <div><span className="evidence-incident-label">WHEN</span> <span className="mono">{formatTime(incident.when)}</span></div>
        <div>
          <span className="evidence-incident-label">AGENT</span>{' '}
          {incident.attributed_agent || 'unknown'} · {incident.attribution_confidence} confidence
        </div>
      </div>

      <button className="btn ghost evidence-incident-toggle" onClick={() => setExpanded((v) => !v)}>
        {expanded ? '▲ HIDE EVIDENCE' : '▼ VIEW EVIDENCE'}
      </button>

      {expanded && (
        <div className="evidence-incident-expanded">
          {attribution && (
            <>
              <div className="evidence-incident-chain">
                {attribution.chain.map((step, i) => (
                  <div key={i} className="evidence-incident-chain-step mono">
                    {i > 0 && '→ '}{step}
                  </div>
                ))}
              </div>
              <div className="evidence-incident-detail">Basis: {attribution.basis}</div>
            </>
          )}
          {raw && (
            <div className="evidence-incident-detail mono">
              PID: {raw.pid ?? '—'}   Parent: {raw.parent_pid ?? '—'}
            </div>
          )}
          {raw && <div className="evidence-incident-detail">Target: {raw.target}</div>}
          {policy && (
            <div className="evidence-incident-detail">Policy: {policy.rule_id} — {policy.rule_name}</div>
          )}
        </div>
      )}
    </div>
  )
}

export default function EvidenceIncidents() {
  const [incidents, setIncidents] = useState([])

  async function load() {
    try {
      const data = await api.getEvidenceIncidents()
      setIncidents(data)
    } catch {
      // ignore poll failures
    }
  }

  useEffect(() => {
    load()
    const id = setInterval(load, POLL_MS)
    return () => clearInterval(id)
  }, [])

  if (incidents.length === 0) return null

  return (
    <div className="evidence-incidents-section">
      <div className="evidence-incidents-heading">Incidents</div>
      {incidents.map((incident) => (
        <EvidenceIncidentCard key={incident.id} incident={incident} />
      ))}
    </div>
  )
}
