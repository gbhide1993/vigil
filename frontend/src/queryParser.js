const DAY_NAMES = ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday']

function eventTime(e) {
  return new Date(e.created_at.replace(' ', 'T') + 'Z')
}

function detailText(e) {
  // detail is a JSON string (or null) — search it as raw text rather than
  // parsing, since query intent is "does this mention X" not structured access.
  return (e.detail || '').toLowerCase()
}

export function parseQuery(q, events, now = new Date()) {
  if (!q.trim()) return events
  const lower = q.toLowerCase().trim()

  // ── TIME FILTERS ──────────────────────────────────────────────

  const afterMatch = lower.match(/after\s+(\d{1,2})(?::(\d{2}))?\s*(am|pm)?/)
  if (afterMatch) {
    let hour = parseInt(afterMatch[1], 10)
    const min = parseInt(afterMatch[2] || '0', 10)
    const ampm = afterMatch[3]
    if (ampm === 'pm' && hour < 12) hour += 12
    if (ampm === 'am' && hour === 12) hour = 0
    const cutoff = new Date(now)
    cutoff.setHours(hour, min, 0, 0)
    return events.filter((e) => eventTime(e) >= cutoff)
  }

  const beforeMatch = lower.match(/before\s+(\d{1,2})(?::(\d{2}))?\s*(am|pm)?/)
  if (beforeMatch) {
    let hour = parseInt(beforeMatch[1], 10)
    const min = parseInt(beforeMatch[2] || '0', 10)
    const ampm = beforeMatch[3]
    if (ampm === 'pm' && hour < 12) hour += 12
    if (ampm === 'am' && hour === 12) hour = 0
    const cutoff = new Date(now)
    cutoff.setHours(hour, min, 0, 0)
    return events.filter((e) => eventTime(e) < cutoff)
  }

  if (lower.includes('yesterday')) {
    const start = new Date(now)
    start.setDate(start.getDate() - 1)
    start.setHours(0, 0, 0, 0)
    const end = new Date(start)
    end.setHours(23, 59, 59, 999)
    return events.filter((e) => {
      const t = eventTime(e)
      return t >= start && t <= end
    })
  }

  if (lower.includes('today')) {
    const start = new Date(now)
    start.setHours(0, 0, 0, 0)
    return events.filter((e) => eventTime(e) >= start)
  }

  const dayMatch = DAY_NAMES.findIndex((d) => lower.includes(d))
  if (dayMatch !== -1) {
    const target = new Date(now)
    const diff = (target.getDay() - dayMatch + 7) % 7 || 7
    target.setDate(target.getDate() - diff)
    target.setHours(0, 0, 0, 0)
    const end = new Date(target)
    end.setHours(23, 59, 59, 999)
    return events.filter((e) => {
      const t = eventTime(e)
      return t >= target && t <= end
    })
  }

  // ── AGENT FILTERS ─────────────────────────────────────────────

  if (lower.includes('claude')) {
    return events.filter((e) => e.agent_name?.toLowerCase().includes('claude'))
  }
  if (lower.includes('cursor')) {
    return events.filter((e) => e.agent_name?.toLowerCase().includes('cursor'))
  }
  if (lower.includes('copilot')) {
    return events.filter((e) => e.agent_name?.toLowerCase().includes('copilot'))
  }

  // ── EVENT TYPE FILTERS ────────────────────────────────────────

  // Credential / secret access
  if (lower.match(/secret|credential|cred|\.env|api.?key|password|token/)) {
    return events.filter(
      (e) =>
        e.event_type === 'cred_access' ||
        e.path?.toLowerCase().match(/\.env|secret|credential|id_rsa|\.pem|\.key/) ||
        detailText(e).match(/password|api_key|secret|token/)
    )
  }

  // File modification — path carries the file path for file_write/file_read/cred_access
  const modMatch = lower.match(/(?:modified?|wrote?|edit(?:ed)?|changed?)\s*(.*)/)
  if (modMatch) {
    const target = modMatch[1].trim()
    return events.filter(
      (e) => e.event_type === 'file_write' && (!target || e.path?.toLowerCase().includes(target))
    )
  }

  // Process spawns — the command line lives in `path`, not a separate field
  if (lower.match(/spawn|^ran\b|executed?/)) {
    const target = lower.replace(/spawn(ed)?|^ran\b|executed?/, '').trim()
    return events.filter(
      (e) =>
        e.event_type === 'proc_spawn' &&
        (!target || e.path?.toLowerCase().includes(target) || detailText(e).includes(target))
    )
  }

  // Network / domain — destination lives in `path` for net_connect events
  if (lower.match(/connect|domain|network|http|api\.|\.com|\.io|\.dev|\.net|\.org/)) {
    const target = lower.replace(/connected?\s+to\s*/i, '').trim()
    return events.filter((e) => e.event_type === 'net_connect' && (!target || e.path?.toLowerCase().includes(target)))
  }

  // MCP
  if (lower.includes('mcp')) {
    return events.filter((e) => e.event_type === 'mcp_connect')
  }

  // ── FALLBACK — substring match across all text fields ─────────
  return events.filter((e) => {
    const haystack = [e.agent_name, e.event_type, e.path, e.detail].filter(Boolean).join(' ').toLowerCase()
    return haystack.includes(lower)
  })
}
