const dot = document.getElementById('dot')
const alertBody = document.getElementById('alert-body')
const alertTitle = document.getElementById('alert-title')
const fieldAgent = document.getElementById('field-agent')
const fieldAction = document.getElementById('field-action')
const fieldTarget = document.getElementById('field-target')
const btnAllow = document.getElementById('btn-allow')
const btnInvestigate = document.getElementById('btn-investigate')
const btnBlock = document.getElementById('btn-block')
const queueNav = document.getElementById('queue-nav')
const queueBadge = document.getElementById('queue-badge')
const btnPrev = document.getElementById('btn-prev')
const btnNext = document.getElementById('btn-next')

let activeAlert = null

function parseDetail(alert) {
  if (!alert || !alert.detail) return {}
  try {
    return JSON.parse(alert.detail)
  } catch (e) {
    return {}
  }
}

function render(state, alert, index, total) {
  activeAlert = alert

  if (state === 'alert' && alert) {
    dot.classList.remove('idle')
    dot.classList.add('alert')
    alertBody.classList.remove('hidden')

    const detail = parseDetail(alert)
    alertTitle.textContent = alert.title || 'Alert'
    fieldAgent.textContent = alert.agent_name || detail.agent || '—'
    fieldAction.textContent = alert.event_type || detail.action || alert.description || '—'
    fieldTarget.textContent = alert.path || detail.target || '—'

    const isRedLine = typeof alert.rule_type === 'string' && alert.rule_type.includes('red_line')
    btnAllow.disabled = isRedLine

    if (total > 1) {
      queueNav.classList.remove('hidden')
      queueBadge.textContent = `${index + 1} of ${total} alerts`
    } else {
      queueNav.classList.add('hidden')
    }
  } else {
    dot.classList.remove('alert')
    dot.classList.add('idle')
    alertBody.classList.add('hidden')
    queueNav.classList.add('hidden')
  }
}

window.vlaw.onAlertState(({ state, alert, index, total }) => {
  render(state, alert, index || 0, total || 0)
})

btnPrev.addEventListener('click', async () => {
  const result = await window.vlaw.stepAlert(-1)
  if (result.alert) render('alert', result.alert, result.index, result.total)
})

btnNext.addEventListener('click', async () => {
  const result = await window.vlaw.stepAlert(1)
  if (result.alert) render('alert', result.alert, result.index, result.total)
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

btnBlock.addEventListener('click', async () => {
  if (!activeAlert) return
  const alertId = activeAlert.id
  const agentId = activeAlert.agent_id
  render('idle', null)
  window.vlaw.hideFlyout()
  await window.vlaw.sendAction('block', alertId, agentId)
})
