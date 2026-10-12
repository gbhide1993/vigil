// Tray tooltip text from /api/agents and /api/stats. Kept free of Electron so it can be tested.
//
// Per agent the backend says (api/agents.py, core/agent_activity.py):
//   activity "active"      real activity in the last 5 minutes (file change, new tool process, ...)
//   activity "open_idle"   an agent process exists (an app or background helper) but nothing is happening
//   activity "not_running" no process of that agent exists
// An open session alone never counts: a background helper can keep one open for days.

function names(agents) {
  return agents.map((a) => a.name || 'agent').join(', ')
}

function trayStatusText({ agents = [], needsReview = 0 } = {}) {
  if (needsReview > 0) {
    return `Vigil — ${needsReview} alert${needsReview !== 1 ? 's' : ''} need${needsReview !== 1 ? '' : 's'} review.`
  }
  const active = agents.filter((a) => a.activity === 'active')
  if (active.length > 0) return `Vigil: ${names(active)} active`
  const idle = agents.filter((a) => a.activity === 'open_idle')
  if (idle.length > 0) return `Vigil: ${names(idle)} open (idle)`
  return 'Vigil: watching'
}

module.exports = { trayStatusText }
