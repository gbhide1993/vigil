// A calendar day picked with the browser's native date input (no extra dependency),
// plus quick choices. A day always means the calendar day on THIS machine, the same
// local day the reports and the dashboard use; the zone is shown next to the picker.

const pad = (n) => String(n).padStart(2, '0')

export function localIsoDate(d = new Date()) {
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
}

export function shiftDays(iso, days) {
  const [y, m, d] = iso.split('-').map(Number)
  return localIsoDate(new Date(y, m - 1, d + days))
}

export function isIsoDate(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value || '')) return false
  const [y, m, d] = value.split('-').map(Number)
  const parsed = new Date(y, m - 1, d)
  return parsed.getFullYear() === y && parsed.getMonth() === m - 1 && parsed.getDate() === d
}

// "Asia/Calcutta, UTC+05:30" for the given day (the offset can differ across DST changes).
export function timezoneLabel(iso) {
  let name = 'local time'
  try {
    name = Intl.DateTimeFormat().resolvedOptions().timeZone || name
  } catch {
    // keep the generic name
  }
  const [y, m, d] = (isIsoDate(iso) ? iso : localIsoDate()).split('-').map(Number)
  const minutes = -new Date(y, m - 1, d).getTimezoneOffset()
  const sign = minutes >= 0 ? '+' : '-'
  const abs = Math.abs(minutes)
  return `${name}, UTC${sign}${pad(Math.floor(abs / 60))}:${pad(abs % 60)}`
}

// Returns an error message for a day that cannot be reported, or null.
export function dayProblem(value) {
  if (!isIsoDate(value)) return 'Pick a date from the calendar.'
  if (value > localIsoDate()) return 'That day is in the future. Pick today or an earlier day.'
  return null
}

const QUICK = [
  { label: 'Today', offset: 0 },
  { label: 'Yesterday', offset: -1 },
]

export default function DateField({ value, onChange, label = 'Date' }) {
  const today = localIsoDate()
  const problem = dayProblem(value)
  const heading = !problem
    ? new Date(...value.split('-').map((n, i) => (i === 1 ? Number(n) - 1 : Number(n)))).toLocaleDateString(undefined, {
        weekday: 'long', year: 'numeric', month: 'long', day: 'numeric',
      })
    : null

  return (
    <div className="date-field">
      <div className="field date-field-input">
        <label htmlFor="date-field-input">{label}</label>
        <input id="date-field-input" type="date" value={value} max={today} onChange={(e) => onChange(e.target.value)} />
      </div>
      <div className="date-field-quick" role="group" aria-label="Quick choices">
        {QUICK.map((q) => (
          <button
            key={q.label}
            type="button"
            className={`quick-chip ${value === shiftDays(today, q.offset) ? 'active' : ''}`}
            onClick={() => onChange(shiftDays(today, q.offset))}
          >
            {q.label}
          </button>
        ))}
      </div>
      <div className={`date-field-note ${problem ? 'error' : ''}`} role={problem ? 'alert' : undefined}>
        {problem || `${heading} (local day, ${timezoneLabel(value)})`}
      </div>
    </div>
  )
}
