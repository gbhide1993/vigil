import { useEffect, useState } from 'react'
import { api } from '../api'

export default function Export() {
  const [date, setDate] = useState('today')
  const [preview, setPreview] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false
    async function load() {
      try {
        const res = await fetch(api.exportJsonUrl(date))
        if (!res.ok) throw new Error(`HTTP ${res.status}`)
        const data = await res.json()
        if (!cancelled) {
          setPreview(data)
          setError(null)
        }
      } catch (err) {
        if (!cancelled) setError(err.message)
      }
    }
    load()
    return () => {
      cancelled = true
    }
  }, [date])

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">Export</div>
          <div className="page-subtitle">Generate audit reports for compliance and SIEM ingestion</div>
        </div>
      </div>

      <div className="field" style={{ maxWidth: 240, marginBottom: 20 }}>
        <label>Date</label>
        <input
          type="text"
          value={date}
          onChange={(e) => setDate(e.target.value)}
          placeholder="today or YYYY-MM-DD"
        />
      </div>

      <div className="export-grid">
        <div className="export-card">
          <h3>Audit PDF</h3>
          <p>Formatted report of sessions and alerts for the selected date — suitable for compliance review.</p>
          <a className="btn primary" href={api.exportPdfUrl(date)} download>
            Download PDF
          </a>
        </div>
        <div className="export-card">
          <h3>SIEM JSON</h3>
          <p>Structured session and alert data for ingestion into your SIEM or log pipeline.</p>
          <a className="btn primary" href={api.exportJsonUrl(date)} download={`vlaw-export-${date}.json`}>
            Download JSON
          </a>
        </div>
      </div>

      <div className="panel" style={{ marginTop: 20 }}>
        <div className="panel-header">Preview</div>
        <div className="panel-body" style={{ padding: 16 }}>
          {error && <div className="empty-state">Could not load preview: {error}</div>}
          {!error && !preview && <div className="empty-state">Loading preview…</div>}
          {preview && (
            <pre className="code-preview">{JSON.stringify(preview, null, 2)}</pre>
          )}
        </div>
      </div>
    </div>
  )
}
