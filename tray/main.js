const { app, Tray, Menu, BrowserWindow, ipcMain, screen, shell, Notification } = require('electron')
const path = require('path')
const fs = require('fs')
const http = require('http')
const cron = require('node-cron')
const { spawn, execFile } = require('child_process')

// Only one tray instance may run at a time — otherwise a second launch
// (e.g. auto-launch at boot plus a manual double-click of the shortcut)
// spawns a second backend that fails to bind the already-taken port,
// showing a false "Backend crashed" state next to the real, working one.
const gotSingleInstanceLock = app.requestSingleInstanceLock()
if (!gotSingleInstanceLock) {
  app.quit()
}

const BACKEND_URL = 'http://localhost:7422'
const WEB_UI_URL = 'http://localhost:7422'
const POLL_INTERVAL_MS = 4000

let tray = null
let flyout = null
let pollTimer = null
let currentAlert = null
let qualifyingCount = 0
let consecutiveFailures = 0
let lastNotifiedAlertId = undefined // undefined = not yet primed by first poll
let activeSessionCount = 0

const FAILURE_THRESHOLD = 3

let backendProcess = null
let backendReady = false
let backendFailCount = 0
let backendStableTimer = null
const MAX_BACKEND_FAILURES = 3
const BACKEND_STABLE_MS = 10000

function getBackendPath() {
  if (app.isPackaged) {
    // Installer layout: app\tray\V-LAW.exe and app\backend\vlaw-backend.exe
    // are siblings under the install root, one level up from the tray exe.
    const appDir = path.dirname(path.dirname(process.execPath))
    return path.join(appDir, 'backend', 'vlaw-backend.exe')
  }
  // Dev mode — backend started manually
  return null
}

function spawnBackend() {
  const backendPath = getBackendPath()

  if (!backendPath) {
    console.log('Dev mode: backend not spawned by tray')
    backendReady = true
    return
  }

  if (!fs.existsSync(backendPath)) {
    console.error(`Backend exe not found at: ${backendPath}`)
    setTrayWarning()
    tray.setToolTip('V-LAW — Backend not found. Reinstall V-LAW.')
    return
  }

  console.log(`Spawning backend: ${backendPath}`)

  backendProcess = spawn(backendPath, [], {
    detached: false,
    stdio: 'ignore',
    windowsHide: true,
  })

  backendProcess.on('error', (err) => {
    console.error('Backend spawn error:', err)
    handleBackendCrash()
  })

  backendProcess.on('exit', (code) => {
    console.log(`Backend exited with code ${code}`)
    backendProcess = null
    if (code !== 0 && code !== null) {
      handleBackendCrash()
    }
  })
}

function killBackendProcess() {
  if (!backendProcess) return
  const pid = backendProcess.pid
  // Plain ChildProcess.kill() is unreliable against the packaged
  // console-mode PyInstaller exe on Windows — it can leave the process
  // running. taskkill /F /T forcibly kills it and its child tree.
  if (process.platform === 'win32' && pid) {
    execFile('taskkill', ['/pid', String(pid), '/T', '/F'], () => {})
  } else {
    backendProcess.kill()
  }
  backendProcess = null
}

function handleBackendCrash() {
  backendReady = false
  if (backendStableTimer) {
    clearTimeout(backendStableTimer)
    backendStableTimer = null
  }
  backendFailCount++

  if (backendFailCount >= MAX_BACKEND_FAILURES) {
    setTrayWarning()
    tray.setToolTip('V-LAW — Backend crashed. Right-click → Restart Backend.')
    return
  }

  setTimeout(() => {
    console.log('Retrying backend spawn...')
    spawnBackend()
    waitForBackend()
  }, 3000)
}

async function waitForBackend(maxAttempts = 30, intervalMs = 1000) {
  console.log('Waiting for backend to be ready...')

  for (let i = 0; i < maxAttempts; i++) {
    try {
      const res = await fetch(`${BACKEND_URL}/health`, { signal: AbortSignal.timeout(1000) })
      if (res.ok) {
        console.log(`Backend ready after ${i + 1}s`)
        backendReady = true
        setTrayIdle()
        pollAlerts()
        pollTimer = setInterval(pollAlerts, POLL_INTERVAL_MS)
        // Only clear the failure count once the backend has stayed up for a
        // while — a backend that passes the health check and then crashes a
        // second later is still crash-looping, not recovered.
        if (backendStableTimer) clearTimeout(backendStableTimer)
        backendStableTimer = setTimeout(() => {
          backendFailCount = 0
          backendStableTimer = null
        }, BACKEND_STABLE_MS)
        return
      }
    } catch {
      // Not ready yet — keep waiting
    }
    await new Promise((r) => setTimeout(r, intervalMs))
  }

  console.error('Backend failed to start within 30 seconds')
  setTrayWarning()
  tray.setToolTip('V-LAW — Backend failed to start. Right-click → Restart Backend.')
}

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

async function pollActiveSessionCount() {
  try {
    const { status, body } = await httpRequest('GET', '/sessions?status=open')
    if (status === 200 && body) {
      activeSessionCount = (body.sessions || []).length
    }
  } catch (err) {
    // non-fatal — tooltip just keeps the last known count until this succeeds again
  }
}

async function pollAlerts() {
  if (!backendReady) return
  try {
    const { status, body } = await httpRequest('GET', '/alerts?status=open')
    if (status !== 200 || !body) {
      throw new Error(`unexpected response status ${status}`)
    }
    consecutiveFailures = 0
    await pollActiveSessionCount()
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

// Builds the toast body text for the 9AM digest. Two formats:
//   - Clean day (body.clean === true): proof-of-value leads, since the
//     alert summary alone ("All clear.") doesn't remind the customer why
//     they're paying on the majority of days nothing went wrong.
//   - Day with alerts: the existing alert summary keeps priority (it's
//     the actionable part), with a shorter proof-of-value line appended
//     after a separator — still present, but secondary to what needs
//     attention today.
// proof_of_value fields are always real query results from
// backend/api/digest_api.py — a genuine 0 is shown as 0, never omitted.
function formatDigestBody(body) {
  const pov = body.proof_of_value
  if (!pov) return body.summary // defensive: older backend without proof_of_value

  if (body.clean) {
    return (
      `${pov.days_clean} day${pov.days_clean !== 1 ? 's' : ''} clean. ` +
      `${pov.agents_watched} agent${pov.agents_watched !== 1 ? 's' : ''} watched. ` +
      `${pov.files_monitored_7d} files monitored.\n` +
      `${pov.network_destinations_verified_7d} destination${pov.network_destinations_verified_7d !== 1 ? 's' : ''} verified. ` +
      `Config: ${pov.config_audit_summary}.`
    )
  }

  return (
    `${body.summary}\n` +
    `—\n` +
    `${pov.days_clean} day${pov.days_clean !== 1 ? 's' : ''} clean before today. ` +
    `${pov.agents_watched} agent${pov.agents_watched !== 1 ? 's' : ''} watched this week.`
  )
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
      body: formatDigestBody(body),
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

const APP_VERSION = '0.1.1-beta'

function setTrayIdle() {
  const tooltip = activeSessionCount > 0
    ? `V-LAW v${APP_VERSION} — Watching ${activeSessionCount} agent${activeSessionCount !== 1 ? 's' : ''}. All clear.`
    : `V-LAW v${APP_VERSION} — All clear`
  setTrayIcon('icon_green.png', tooltip)
}

function setTrayAlert() {
  setTrayIcon('icon_red.png', 'V-LAW: open critical alert')
}

function setTrayWarning() {
  setTrayIcon('icon_amber.png', 'V-LAW — Backend offline. Restart V-LAW.')
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
      { label: `V-LAW v${APP_VERSION}`, enabled: false },
      { type: 'separator' },
      { label: 'Open V-LAW', click: () => shell.openExternal(WEB_UI_URL) },
      { type: 'separator' },
      {
        label: 'Restart Backend',
        click: () => {
          killBackendProcess()
          if (pollTimer) clearInterval(pollTimer)
          if (backendStableTimer) {
            clearTimeout(backendStableTimer)
            backendStableTimer = null
          }
          backendReady = false
          backendFailCount = 0
          setTrayWarning()
          tray.setToolTip('V-LAW — Restarting backend...')
          setTimeout(() => {
            spawnBackend()
            waitForBackend()
          }, 1000)
        },
      },
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
  if (app.dock) app.dock.hide()

  createTray()
  createFlyout()

  // Set amber immediately — backend not ready yet
  setTrayWarning()
  tray.setToolTip('V-LAW — Starting...')

  // Spawn backend, then wait for health, then start polling
  spawnBackend()
  waitForBackend() // starts pollAlerts() internally once healthy

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
  if (backendProcess) {
    console.log('Killing backend process before quit...')
    killBackendProcess()
  }
})
