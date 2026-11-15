import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard, Activity, ShieldAlert, GitBranch,
  Bot, FileSearch, BarChart3, Settings, Shield
} from 'lucide-react'

const NAV_ITEMS = [
  { to: '/', icon: LayoutDashboard, label: 'Overview' },
  { to: '/monitoring', icon: Activity, label: 'Live Monitoring' },
  { to: '/threats', icon: ShieldAlert, label: 'Threats' },
  { to: '/attack-path', icon: GitBranch, label: 'Attack Path' },
  { to: '/agents', icon: Bot, label: 'AI Agents' },
  { to: '/events', icon: FileSearch, label: 'Event Details' },
  { to: '/reports', icon: BarChart3, label: 'Reports' },
  { to: '/settings', icon: Settings, label: 'Settings' },
]

export function Sidebar() {
  return (
    <aside className="w-56 bg-bg-secondary border-r border-border flex flex-col shrink-0">
      {/* Logo */}
      <div className="flex items-center gap-3 px-4 py-5 border-b border-border">
        <Shield size={24} className="text-accent-cyan" />
        <div>
          <p className="text-text-primary font-bold text-sm tracking-wide">AGENT</p>
          <p className="text-accent-cyan font-bold text-sm tracking-wide -mt-1">SHIELD</p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-2 py-4 space-y-1">
        {NAV_ITEMS.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors ${
                isActive
                  ? 'bg-accent-cyan/10 text-accent-cyan border border-accent-cyan/20'
                  : 'text-text-muted hover:text-text-secondary hover:bg-bg-tertiary'
              }`
            }
          >
            <Icon size={16} />
            {label}
          </NavLink>
        ))}
      </nav>

      <div className="px-4 py-3 border-t border-border">
        <p className="text-xs text-text-muted">AgentShield v1.0.0</p>
      </div>
    </aside>
  )
}
