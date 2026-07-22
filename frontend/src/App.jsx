import { useEffect, useState } from 'react'
import Sidebar from './components/Sidebar'
import Status from './components/Status'
import Incidents from './components/Incidents'
import History from './components/History'
import AgentDetail from './components/AgentDetail'
import Settings from './components/Settings'
import WelcomeScreen from './components/WelcomeScreen'
import { api } from './api'

export default function App() {
  const [view, setView] = useState('status')
  const [openAlertCount, setOpenAlertCount] = useState(0)
  const [hasSessions, setHasSessions] = useState(null)

  useEffect(() => {
    let cancelled = false
    async function load() {
      try {
        const data = await api.getStats()
        if (!cancelled) setOpenAlertCount(data.alerts_open)
      } catch {
        // ignore poll failures
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
    async function load() {
      try {
        const data = await api.getSessions()
        if (!cancelled) setHasSessions(data.sessions.length > 0)
      } catch {
        // ignore poll failures — keep showing whatever state we last knew
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
          <WelcomeScreen />
        </main>
      </div>
    )
  }

  return (
    <div className="app-shell">
      <Sidebar view={view} onNavigate={handleNavigate} openAlertCount={openAlertCount} />
      <main className="main-content">
        {view === 'status' && <Status onNavigate={setView} />}
        {view === 'incidents' && <Incidents onNavigate={setView} />}
        {view === 'history' && <History />}
        {view === 'agents' && <AgentDetail />}
        {view === 'settings' && <Settings />}
      </main>
    </div>
  )
}
