import { useState } from 'react'

// Copies the full (untruncated) value of a path, command or id. Used wherever a
// long value is shown wrapped or cut off with a tooltip.
export default function CopyButton({ text, label = 'Copy' }) {
  const [done, setDone] = useState(false)

  async function copy(e) {
    e.stopPropagation()
    try {
      await navigator.clipboard.writeText(text)
    } catch {
      const area = document.createElement('textarea')
      area.value = text
      area.style.position = 'fixed'
      area.style.opacity = '0'
      document.body.appendChild(area)
      area.select()
      try {
        document.execCommand('copy')
      } finally {
        document.body.removeChild(area)
      }
    }
    setDone(true)
    setTimeout(() => setDone(false), 1200)
  }

  if (!text) return null
  return (
    <button type="button" className="copy-btn" onClick={copy} title="Copy the full value" aria-label="Copy the full value">
      {done ? 'Copied' : label}
    </button>
  )
}
