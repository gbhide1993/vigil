const { app, Tray, Menu, BrowserWindow, ipcMain, screen, shell, Notification } = require('electron')
const path = require('path')
const http = require('http')
const cron = require('node-cron')

const BACKEND_URL = 'http://localhost:7422'
const WEB_UI_URL = 'http://localhost:7423'
const POLL_INTERVAL_MS = 4000

let tray = null
let flyout = null
let pollTimer = null
let currentAlert = null
let qualifyingCount = 0
let consecutiveFailures = 0
let lastNotifiedAlertId = undefined // undefined = not yet primed by first poll

const FAILURE_THRESHOLD = 3

function httpRequest(method, urlPath, body) {
  return new Promise((resolve, reject) => {
    const url = new URL(BACKEND_URL + urlPath)
    const data = body ? JSON.stringify(body) : null
    const req = http.request(
      {
        hostname: url.hostname,
        port: url.port,
        path: url.pathname + url.search,
        method,
        headers: data
          ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) }
          : {},
        timeout: 3000,
      },
      (res) => {
        let raw = ''
        res.on('data', (chunk) => (raw += chunk))
        res.on('end', () => {
          let parsed = null
          try {
            parsed = raw ? JSON.parse(raw) : null
          } catch (e) {
            // non-JSON body, ignore
          }
          resolve({ status: res.statusCode, body: parsed })
        })
      }
    )
    req.on('error', reject)
    req.on('timeout', () => {
      req.destroy(new Error('request timed out'))
    })
    if (data) req.write(data)
    req.end()
  })
}

function isQualifyingAlert(alert) {
  const severity = alert.severity === 'critical'
  const redLine = typeof alert.rule_type === 'string' && alert.rule_type.includes('red_line')
  return severity || redLine
}

function truncateAction(str) {
  if (!str) return str
  // Command paths (esp. Windows) often contain spaces themselves (e.g.
  // "C:\Program Files\...\bash.exe -c ..."), so a naive split(' ')[0] would
  // cut mid-path. Find the executable by matching the first path-like
  // token that ends in a known executable/script extension instead.
  const exeMatch = str.match(/[^\s"']*\.(exe|cmd|bat|sh|ps1|py|js)\b/i)
  const firstSegment = exeMatch ? exeMatch[0] : str.split(' ')[0]
  const filename = firstSegment.split(/[\\/]/).pop()
  return filename || firstSegment
}

function parseDetail(alert) {
  if (!alert || !alert.detail) return {}
  try {
    return JSON.parse(alert.detail)
  } catch (e) {
    return {}
  }
}

function withTruncatedAction(alert) {
  if (!alert) return alert
  const detail = parseDetail(alert)
  const rawAction = alert.event_type || detail.action || alert.description || ''
  return { ...alert, action_display: truncateAction(rawAction) }
}

async function pollAlerts() {
  try {
    const { status, body } = await httpRequest('GET', '/alerts?status=open')
    if (status !== 200 || !body) {
      throw new Error(`unexpected response status ${status}`)
    }
    consecutiveFailures = 0
    const alerts = (body.alerts || []).filter(isQualifyingAlert)
    if (alerts.length === 0) {
      currentAlert = null
      qualifyingCount = 0
      if (lastNotifiedAlertId === undefined) lastNotifiedAlertId = null
      setTrayState('idle')
      applyFlyoutState('idle', null)
      return
    }
    // API returns rows ordered by created_at DESC, so the first element is
    // the most recent qualifying alert
    qualifyingCount = alerts.length
    currentAlert = alerts[0]
    setTrayState('alert')
    applyFlyoutState('alert', currentAlert)
    maybeNotifyNewAlert(currentAlert)
  } catch (err) {
    console.error('poll failed:', err.message)
    consecutiveFailures += 1
    if (consecutiveFailures >= FAILURE_THRESHOLD) {
      setTrayState('warning')
    }
  }
}

function maybeNotifyNewAlert(alert) {
  if (!alert) return
  if (lastNotifiedAlertId === undefined) {
    // first poll since launch — prime silently, don't toast for alerts
    // that were already open before the app started
    lastNotifiedAlertId = alert.id
    return
  }
  if (alert.id === lastNotifiedAlertId) return
  lastNotifiedAlertId = alert.id

  const isRedLine = typeof alert.rule_type === 'string' && alert.rule_type.includes('red_line')
  const title = isRedLine ? 'V-LAW — RED LINE' : 'V-LAW — CRITICAL'
  const body = (alert.title || '').slice(0, 80)

  const notification = new Notification({
    title,
    body,
    icon: path.join(__dirname, 'assets', 'icon_red.png'),
  })
  notification.on('click', () => {
    toggleFlyout()
  })
  notification.show()
}

async function triggerDigestNow() {
  try {
    const { status, body } = await httpRequest('GET', '/digest/daily')
    if (status !== 200 || !body) {
      console.error('digest fetch failed:', status)
      return
    }
    const notification = new Notification({
      title: 'V-LAW Morning Digest',
      body: body.summary,
      icon: path.join(__dirname, 'assets', body.clean ? 'icon_green.png' : 'icon_red.png'),
    })
    notification.on('click', () => {
      shell.openExternal(WEB_UI_URL)
    })
    notification.show()
  } catch (err) {
    console.error('digest trigger failed:', err.message)
  }
}

function setTrayIcon(iconName, tooltip) {
  if (!tray) return
  tray.setImage(path.join(__dirname, 'assets', iconName))
  tray.setToolTip(tooltip)
}

function setTrayIdle() {
  setTrayIcon('icon_green.png', 'V-LAW: idle')
}

function setTrayAlert() {
  setTrayIcon('icon_red.png', 'V-LAW: open critical alert')
}

function setTrayWarning() {
  setTrayIcon('icon_amber.png', 'V-LAW — backend unreachable')
}

function setTrayState(state) {
  if (state === 'alert') return setTrayAlert()
  if (state === 'warning') return setTrayWarning()
  return setTrayIdle()
}

const FLYOUT_WIDTH = 320
const FLYOUT_HEIGHT_IDLE = 48
const FLYOUT_HEIGHT_ALERT = 200

function createFlyout() {
  flyout = new BrowserWindow({
    width: FLYOUT_WIDTH,
    height: FLYOUT_HEIGHT_IDLE,
    show: false,
    frame: false,
    resizable: false,
    movable: false,
    fullscreenable: false,
    skipTaskbar: true,
    transparent: true,
    alwaysOnTop: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  })
  flyout.loadFile(path.join(__dirname, 'flyout.html'))

  flyout.on('blur', () => {
    if (flyout && !flyout.isDestroyed()) flyout.hide()
  })

  return flyout
}

function positionFlyout(height) {
  const trayBounds = tray.getBounds()

  // Some Windows configs briefly report (0,0) before the tray icon is fully
  // rendered — skip repositioning rather than snapping the flyout to the
  // top-left corner of the screen.
  if (trayBounds.x === 0 && trayBounds.y === 0) return

  const display = screen.getDisplayNearestPoint({ x: trayBounds.x, y: trayBounds.y })
  const winWidth = FLYOUT_WIDTH
  const winHeight = height != null ? height : flyout.getBounds().height

  let x = Math.round(trayBounds.x + trayBounds.width / 2 - winWidth / 2)
  let y

  // Bottom taskbar (the common Windows layout): tray icon sits in the
  // bottom quarter of the display -> flyout goes above it. Otherwise
  // (top taskbar) the flyout goes below. Left/right taskbars aren't
  // handled separately for now.
  if (trayBounds.y + trayBounds.height > display.workArea.height * 0.75) {
    y = Math.round(trayBounds.y - winHeight - 8)
  } else {
    y = Math.round(trayBounds.y + trayBounds.height + 8)
  }

  x = Math.max(display.workArea.x + 8, Math.min(x, display.workArea.x + display.workArea.width - winWidth - 8))

  flyout.setBounds({ x, y, width: winWidth, height: winHeight })
}

function applyFlyoutState(state, alert) {
  if (!flyout || flyout.isDestroyed()) return
  flyout.webContents.send('alert-state', {
    state,
    alert: withTruncatedAction(alert),
    total: qualifyingCount,
  })
  if (flyout.isVisible()) {
    positionFlyout(state === 'alert' ? FLYOUT_HEIGHT_ALERT : FLYOUT_HEIGHT_IDLE)
  }
}

function toggleFlyout() {
  if (!flyout || flyout.isDestroyed()) {
    flyout = createFlyout()
  }
  if (flyout.isVisible()) {
    flyout.hide()
    return
  }
  const state = currentAlert ? 'alert' : 'idle'
  positionFlyout(state === 'alert' ? FLYOUT_HEIGHT_ALERT : FLYOUT_HEIGHT_IDLE)
  flyout.show()
  flyout.focus()
  flyout.webContents.send('alert-state', {
    state,
    alert: withTruncatedAction(currentAlert),
    total: qualifyingCount,
  })
}

function createTray() {
  tray = new Tray(path.join(__dirname, 'assets', 'icon_green.png'))
  tray.setToolTip('V-LAW: idle')

  tray.on('click', () => {
    toggleFlyout()
  })

  tray.on('right-click', () => {
    const template = [
      { label: 'Open V-LAW', click: () => shell.openExternal(WEB_UI_URL) },
      { type: 'separator' },
    ]
    if (!app.isPackaged) {
      template.push({ label: 'Test digest toast', click: () => triggerDigestNow() })
      template.push({ type: 'separator' })
    }
    template.push({ label: 'Quit V-LAW', click: () => app.quit() })
    const menu = Menu.buildFromTemplate(template)
    tray.popUpContextMenu(menu)
  })
}

ipcMain.handle('send-action', async (_event, { type, alertId, agentId }) => {
  try {
    if (type === 'resolve') {
      const { status, body } = await httpRequest('POST', `/alerts/${alertId}/resolve`, {
        action: 'dismiss',
      })
      const ok = status >= 200 && status < 300
      if (ok) {
        currentAlert = null
        setTrayState('idle')
      }
      return { ok, status, body }
    }
    if (type === 'block') {
      const { status, body } = await httpRequest('POST', `/agents/${agentId}/block`)
      const ok = status >= 200 && status < 300
      if (ok) {
        currentAlert = null
        setTrayState('idle')
      }
      return { ok, status, body }
    }
    if (type === 'investigate') {
      await shell.openExternal(WEB_UI_URL)
      return { ok: true }
    }
    return { ok: false, error: 'unknown action type' }
  } catch (err) {
    return { ok: false, error: err.message }
  }
})

ipcMain.on('hide-flyout', () => {
  if (flyout && !flyout.isDestroyed()) flyout.hide()
})

app.whenReady().then(() => {
  app.setLoginItemSettings({ openAtLogin: true, openAsHidden: true })
  createTray()
  createFlyout()
  pollAlerts()
  pollTimer = setInterval(pollAlerts, POLL_INTERVAL_MS)
  cron.schedule('0 9 * * *', () => {
    triggerDigestNow()
  })
})

app.on('window-all-closed', (e) => {
  // tray app has no dock-visible windows to close into quitting
  e.preventDefault()
})

app.on('before-quit', () => {
  if (pollTimer) clearInterval(pollTimer)
})
