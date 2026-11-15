import { Routes, Route, useLocation } from 'react-router-dom'
import { Sidebar } from './components/layout/Sidebar'
import { Header } from './components/layout/Header'
import { Overview } from './pages/Overview'
import { LiveMonitoring } from './pages/LiveMonitoring'
import { ThreatDetection } from './pages/ThreatDetection'
import { AttackPath } from './pages/AttackPath'
import { AgentActivity } from './pages/AgentActivity'
import { EventDetail } from './pages/EventDetail'
import { Reports } from './pages/Reports'
import { Settings } from './pages/Settings'
import { useWebSocket } from './hooks/useWebSocket'
import { useStore } from './store/useStore'
import type { WSMessage } from './types'

const PAGE_TITLES: Record<string, string> = {
  '/': 'Security Overview',
  '/monitoring': 'Live Network Monitoring',
  '/threats': 'Threat Detection',
  '/attack-path': 'Attack Path Analysis',
  '/agents': 'AI Agent Activity',
  '/events': 'Security Events',
  '/reports': 'Reports',
  '/settings': 'Settings & System Health',
}

function App() {
  const location = useLocation()
  const addLiveEvent = useStore((s) => s.addLiveEvent)
  const setLatestInvestigation = useStore((s) => s.setLatestInvestigation)
  const setLatestRecommendation = useStore((s) => s.setLatestRecommendation)
  const setWsConnected = useStore((s) => s.setWsConnected)

  const handleWsMessage = (msg: WSMessage) => {
    switch (msg.type) {
      case 'connection_ack':
        setWsConnected(true)
        break
      case 'new_event':
        addLiveEvent(msg.payload)
        break
      case 'investigation_complete':
        setLatestInvestigation(msg.payload)
        break
      case 'defence_recommendation':
        setLatestRecommendation(msg.payload)
        break
    }
  }

  useWebSocket(handleWsMessage)

  const title = PAGE_TITLES[location.pathname] ??
    (location.pathname.startsWith('/events/') ? 'Event Detail' : 'AgentShield')

  return (
    <div className="flex h-screen overflow-hidden bg-bg-primary">
      <Sidebar />
      <div className="flex flex-col flex-1 overflow-hidden">
        <Header title={title} />
        <main className="flex-1 overflow-y-auto">
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/monitoring" element={<LiveMonitoring />} />
            <Route path="/threats" element={<ThreatDetection />} />
            <Route path="/attack-path" element={<AttackPath />} />
            <Route path="/agents" element={<AgentActivity />} />
            <Route path="/events/:eventId" element={<EventDetail />} />
            <Route path="/events" element={<ThreatDetection />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/settings" element={<Settings />} />
          </Routes>
        </main>
      </div>
    </div>
  )
}

export default App
