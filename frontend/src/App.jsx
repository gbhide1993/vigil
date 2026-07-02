import { useEffect, useState } from 'react'
import Sidebar from './components/Sidebar'
import LiveFeed from './components/LiveFeed'
import AgentDetail from './components/AgentDetail'
import Alerts from './components/Alerts'
import Export from './components/Export'
import { api } from './api'

export default function App() {
  const [view, setView] = useState('live')
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

  return (
    <div className="app-shell">
      <Sidebar view={view} onNavigate={setView} openAlertCount={openAlertCount} />
      <main className="main-content">
        {view === 'live' && <LiveFeed />}
        {view === 'agents' && <AgentDetail />}
        {view === 'alerts' && <Alerts />}
        {view === 'export' && <Export />}
      </main>
    </div>
  )
}
