import { useEffect, useState } from 'react'
import Sidebar from './components/Sidebar'
import Status from './components/Status'
import Incidents from './components/Incidents'
import History from './components/History'
import AgentDetail from './components/AgentDetail'
import Alerts from './components/Alerts'
import Export from './components/Export'
import Settings from './components/Settings'
import WelcomeScreen from './components/WelcomeScreen'
import { api } from './api'

export default function App() {
  const [view, setView] = useState('status')
  const [needsReviewCount, setNeedsReviewCount] = useState(0)
  const [hasSessions, setHasSessions] = useState(null)
  const [backendDown, setBackendDown] = useState(false)
  // null until the backend has actually answered at least once -- Sidebar
  // shows nothing rather than a hardcoded or stale value while this is null.
  const [version, setVersion] = useState(null)

  useEffect(() => {
    let cancelled = false
    let inFlight = false
    // Counts consecutive failures of this specific poll, not a global
    // tally -- a single dropped request (page load race, one-off network
    // blip) must not flip the whole dashboard into "backend down" on its
    // own. Two in a row (6s at this interval) is the threshold before
    // showing anything, and it's reset to 0 on any success so a flaky-then-
    // recovered backend doesn't need a third failure to matter again.
    let consecutiveFailures = 0
    async function load() {
      if (inFlight) return
      inFlight = true
      try {
        const data = await api.getStats()
        // needs_review = open alerts at severity high or critical. The
        // Incidents badge used to show alerts_open (every open alert,
        // any severity, including low-severity noise), which is why it
        // read ~3100 instead of the much smaller number that actually
        // needs a human to look at it.
        if (!cancelled) {
          setNeedsReviewCount(data.needs_review)
          setVersion(data.version)
          consecutiveFailures = 0
          setBackendDown(false)
        }
      } catch {
        consecutiveFailures += 1
        if (!cancelled && consecutiveFailures >= 2) setBackendDown(true)
      } finally {
        inFlight = false
      }
    }
    load()
    const id = setInterval(load, 3000)
    return () => {
      cancelled = true
      clearInterval(id)
    }
  }, [])

  useEffect(() => {
    // Once a first session shows up, the welcome screen never needs to come
    // back for this app lifetime — stop polling to save the request.
    if (hasSessions) return
    let cancelled = false
    let inFlight = false
    async function load() {
      if (inFlight) return
      inFlight = true
      try {
        const data = await api.getSessions()
        if (!cancelled) setHasSessions(data.sessions.length > 0)
      } catch {
        // ignore poll failures — keep showing whatever state we last knew
      } finally {
        inFlight = false
      }
    }
    load()
    const id = setInterval(load, 3000)
    return () => {
      cancelled = true
      clearInterval(id)
    }
  }, [hasSessions])

  useEffect(() => {
    api.trackEvent('dashboard_open', { view })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  function handleNavigate(newView) {
    api.trackEvent('view_changed', { view: newView })
    setView(newView)
  }

  if (hasSessions === false) {
    return (
      <div className="app-shell">
        <main className="main-content">
          {backendDown && <div className="backend-down-banner">Backend not responding</div>}
          <WelcomeScreen />
        </main>
      </div>
    )
  }

  return (
    <div className="app-shell">
      <Sidebar view={view} onNavigate={handleNavigate} needsReviewCount={needsReviewCount} version={version} />
      <main className="main-content">
        {backendDown && <div className="backend-down-banner">Backend not responding</div>}
        {view === 'status' && <Status onNavigate={setView} />}
        {view === 'incidents' && <Incidents onNavigate={setView} />}
        {view === 'history' && <History />}
        {view === 'agents' && <AgentDetail />}
        {view === 'alerts' && <Alerts onNavigate={setView} />}
        {view === 'export' && <Export />}
        {view === 'settings' && <Settings />}
      </main>
    </div>
  )
}
