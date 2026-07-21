import { useEffect, useState } from 'react'
import { api } from '../api'

const WEBHOOK_STORAGE_KEY = 'vlaw_webhook_url'

function approvalLabel(agent) {
  if (agent.approved === 2) return { label: 'blocked', dot: 'red' }
  if (agent.approved === 0) return { label: 'pending', dot: 'amber' }
  return { label: 'approved', dot: 'green' }
}

function AgentsSection() {
  const [agents, setAgents] = useState([])

  useEffect(() => {
    let cancelled = false
    async function load() {
      try {
        const data = await api.getAgents()
        if (!cancelled) setAgents(data.agents)
      } catch {
        // non-fatal; section just stays empty
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
    <div className="settings-section">
      <h3>Monitored Agents</h3>
      <p className="settings-desc">Agents detected on this machine and their current approval status.</p>
      {agents.length === 0 && <div className="empty-state">No agents detected yet.</div>}
      {agents.map((agent) => {
        const { label, dot } = approvalLabel(agent)
        return (
          <div className="settings-agent-row" key={agent.id}>
            <span className="agent-name mono">{agent.name}</span>
            <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <span className={`status-dot ${dot}`} />
              {label}
            </span>
          </div>
        )
      })}
    </div>
  )
}

function WebhookSection() {
  const [webhookUrl, setWebhookUrl] = useState(() => localStorage.getItem(WEBHOOK_STORAGE_KEY) || '')
  const [saved, setSaved] = useState(false)
  const [saveError, setSaveError] = useState(null)
  const [testStatus, setTestStatus] = useState(null)

  useEffect(() => {
    let cancelled = false
    async function load() {
      try {
        const data = await api.getWebhookUrl()
        if (!cancelled && data.url) {
          setWebhookUrl(data.url)
          localStorage.setItem(WEBHOOK_STORAGE_KEY, data.url)
        }
      } catch {
        // backend unreachable — keep showing the cached localStorage value
      }
    }
    load()
    return () => {
      cancelled = true
    }
  }, [])

  async function handleSaveWebhook() {
    setSaveError(null)
    localStorage.setItem(WEBHOOK_STORAGE_KEY, webhookUrl)
    try {
      await api.setWebhookUrl(webhookUrl)
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    } catch (err) {
      setSaveError(err.message)
    }
  }

  async function handleTestWebhook() {
    setTestStatus('sending')
    try {
      const data = await api.sendTestWebhook()
      setTestStatus(data.sent ? 'success' : 'failed')
    } catch {
      setTestStatus('failed')
    }
    setTimeout(() => setTestStatus(null), 3000)
  }

  const testLabel = { sending: 'Sending...', success: '✓ Sent', failed: '✗ Failed' }[testStatus] || 'Send test'

  return (
    <div className="settings-section">
      <h3>Morning Digest Webhook</h3>
      <p className="settings-desc">
        Receive your daily AI activity summary in Slack, Teams, or any webhook-compatible tool. Sends at 9AM daily.
      </p>
      <div className="settings-input-row">
        <input
          type="url"
          className="settings-input mono"
          placeholder="https://hooks.slack.com/services/..."
          value={webhookUrl}
          onChange={(e) => setWebhookUrl(e.target.value)}
        />
        <button className="btn-settings-save" onClick={handleSaveWebhook}>
          {saved ? '✓ Saved' : 'Save'}
        </button>
        <button className="btn-settings-test" onClick={handleTestWebhook} disabled={!webhookUrl || testStatus === 'sending'}>
          {testLabel}
        </button>
      </div>
      {saveError && <p className="settings-note" style={{ color: 'var(--critical)', fontStyle: 'normal' }}>Save failed: {saveError}</p>}
      <p className="settings-note">
        Webhook delivery sends at 9AM daily via the desktop tray app.
      </p>
    </div>
  )
}

function ConfigAuditSection() {
  const [configAudit, setConfigAudit] = useState(null)

  useEffect(() => {
    let cancelled = false
    async function load() {
      try {
        const data = await api.getConfigAudit()
        if (!cancelled) setConfigAudit(data)
      } catch {
        // non-fatal; section just stays empty
      }
    }
    load()
    return () => {
      cancelled = true
    }
  }, [])

  return (
    <div className="settings-section">
      <h3>Claude Code Config Audit</h3>
      <p className="settings-desc">
        Your native Claude Code permission configuration compared against recommended protections.
      </p>
      {configAudit?.missing?.length > 0 ? (
        <>
          <div className="settings-audit-score">
            {configAudit.configured?.length || 0}/{(configAudit.configured?.length || 0) + configAudit.missing.length} protections active
          </div>
          {configAudit.missing.map((item) => (
            <div className="settings-missing-row" key={item.pattern}>
              <code className="mono">{item.pattern}</code>
              <span>{item.reason}</span>
              <span className={`badge ${item.severity}`}>{item.severity}</span>
            </div>
          ))}
        </>
      ) : configAudit ? (
        <div className="settings-audit-clean">✓ All recommended protections are configured</div>
      ) : (
        <div className="empty-state">Loading config audit…</div>
      )}
    </div>
  )
}

export default function Settings() {
  return (
    <div className="settings-page">
      <div className="page-header">
        <div>
          <div className="page-title">Settings</div>
          <div className="page-subtitle">Agents, digest delivery, and config audit</div>
        </div>
      </div>

      <AgentsSection />
      <WebhookSection />
      <ConfigAuditSection />
    </div>
  )
}
