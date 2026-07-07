const dot = document.getElementById('dot')
const alertBody = document.getElementById('alert-body')
const alertTitle = document.getElementById('alert-title')
const fieldAgent = document.getElementById('field-agent')
const fieldAction = document.getElementById('field-action')
const fieldTarget = document.getElementById('field-target')
const btnAllow = document.getElementById('btn-allow')
const btnInvestigate = document.getElementById('btn-investigate')
const btnBlock = document.getElementById('btn-block')
const moreBadge = document.getElementById('more-badge')

let activeAlert = null

function parseDetail(alert) {
  if (!alert || !alert.detail) return {}
  try {
    return JSON.parse(alert.detail)
  } catch (e) {
    return {}
  }
}

function render(state, alert, total) {
  activeAlert = alert

  if (state === 'alert' && alert) {
    dot.classList.remove('idle')
    dot.classList.add('alert')
    alertBody.classList.remove('hidden')

    const detail = parseDetail(alert)
    alertTitle.textContent = alert.title || 'Alert'
    fieldAgent.textContent = alert.agent_name || detail.agent || '—'
    fieldAction.textContent = alert.action_display || '—'
    fieldTarget.textContent = alert.path || detail.target || '—'

    const isRedLine = typeof alert.rule_type === 'string' && alert.rule_type.includes('red_line')
    btnAllow.disabled = isRedLine

    if (total > 1) {
      moreBadge.textContent = `+ ${total - 1} more`
      moreBadge.classList.remove('hidden')
    } else {
      moreBadge.classList.add('hidden')
    }
  } else {
    dot.classList.remove('alert')
    dot.classList.add('idle')
    alertBody.classList.add('hidden')
    moreBadge.classList.add('hidden')
  }
}

window.vlaw.onAlertState(({ state, alert, total }) => {
  render(state, alert, total || 0)
})

btnAllow.addEventListener('click', async () => {
  if (!activeAlert || btnAllow.disabled) return
  render('idle', null)
  window.vlaw.hideFlyout()
  await window.vlaw.sendAction('resolve', activeAlert.id)
})

btnInvestigate.addEventListener('click', async () => {
  window.vlaw.hideFlyout()
  await window.vlaw.sendAction('investigate')
})

moreBadge.addEventListener('click', async () => {
  window.vlaw.hideFlyout()
  await window.vlaw.sendAction('investigate', null)
})

btnBlock.addEventListener('click', async () => {
  if (!activeAlert) return
  const alertId = activeAlert.id
  const agentId = activeAlert.agent_id
  render('idle', null)
  window.vlaw.hideFlyout()
  await window.vlaw.sendAction('block', alertId, agentId)
})
