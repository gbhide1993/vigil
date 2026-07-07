const { app, Tray, Menu, BrowserWindow, ipcMain, screen, shell } = require('electron')
const path = require('path')
const http = require('http')

const BACKEND_URL = 'http://localhost:7422'
const WEB_UI_URL = 'http://localhost:7423'
const POLL_INTERVAL_MS = 4000

let tray = null
let flyout = null
let pollTimer = null
let currentAlert = null
let activeAlerts = []
let activeIndex = 0

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

async function pollAlerts() {
  try {
    const { status, body } = await httpRequest('GET', '/alerts?status=open')
    if (status !== 200 || !body) {
      setTrayState('idle')
      return
    }
    const alerts = (body.alerts || []).filter(isQualifyingAlert)
    if (alerts.length === 0) {
      currentAlert = null
      activeAlerts = []
      activeIndex = 0
      setTrayState('idle')
      applyFlyoutState('idle', null)
      return
    }
    // oldest-first ordering — API returns rows by created_at DESC, so reverse
    const oldestFirst = [...alerts].reverse()
    // keep pointing at the same alert (by id) across polls if still present,
    // otherwise reset to the oldest
    const prevId = activeAlerts[activeIndex] ? activeAlerts[activeIndex].id : null
    activeAlerts = oldestFirst
    const keepIndex = prevId != null ? oldestFirst.findIndex((a) => a.id === prevId) : -1
    activeIndex = keepIndex >= 0 ? keepIndex : 0
    currentAlert = activeAlerts[activeIndex]
    setTrayState('alert')
    applyFlyoutState('alert', currentAlert)
  } catch (err) {
    console.error('poll failed:', err.message)
    setTrayState('idle')
  }
}

function setTrayState(state) {
  if (!tray) return
  const iconName = state === 'alert' ? 'icon_red.png' : 'icon_green.png'
  tray.setImage(path.join(__dirname, 'assets', iconName))
  tray.setToolTip(state === 'alert' ? 'V-LAW: open critical alert' : 'V-LAW: idle')
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
  const display = screen.getDisplayNearestPoint({ x: trayBounds.x, y: trayBounds.y })
  const winWidth = FLYOUT_WIDTH
  const winHeight = height != null ? height : flyout.getBounds().height

  let x = Math.round(trayBounds.x + trayBounds.width / 2 - winWidth / 2)
  let y

  // Windows taskbar tray is typically bottom-right -> flyout above the icon.
  // Fall back to below the icon if the tray sits at the top of the screen.
  if (trayBounds.y > display.workArea.y + display.workArea.height / 2) {
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
    alert,
    index: activeIndex,
    total: activeAlerts.length,
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
    alert: currentAlert,
    index: activeIndex,
    total: activeAlerts.length,
  })
}

function createTray() {
  tray = new Tray(path.join(__dirname, 'assets', 'icon_green.png'))
  tray.setToolTip('V-LAW: idle')

  tray.on('click', () => {
    toggleFlyout()
  })

  tray.on('right-click', () => {
    app.quit()
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

ipcMain.handle('step-alert', (_event, direction) => {
  if (activeAlerts.length === 0) return { alert: null, index: 0, total: 0 }
  activeIndex = (activeIndex + direction + activeAlerts.length) % activeAlerts.length
  currentAlert = activeAlerts[activeIndex]
  return { alert: currentAlert, index: activeIndex, total: activeAlerts.length }
})

app.whenReady().then(() => {
  app.setLoginItemSettings({ openAtLogin: true, openAsHidden: true })
  createTray()
  createFlyout()
  pollAlerts()
  pollTimer = setInterval(pollAlerts, POLL_INTERVAL_MS)
})

app.on('window-all-closed', (e) => {
  // tray app has no dock-visible windows to close into quitting
  e.preventDefault()
})

app.on('before-quit', () => {
  if (pollTimer) clearInterval(pollTimer)
})
