import { useEffect, useState } from 'react'
import Sidebar from './components/Sidebar'
import Status from './components/Status'
import Incidents from './components/Incidents'
import History from './components/History'
import AgentDetail from './components/AgentDetail'
import Settings from './components/Settings'
import { api } from './api'

export default function App() {
  const [view, setView] = useState('status')
  const [openAlertCount, setOpenAlertCount] = useState(0)

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
    api.trackEvent('dashboard_open', { view })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  function handleNavigate(newView) {
    api.trackEvent('view_changed', { view: newView })
    setView(newView)
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
