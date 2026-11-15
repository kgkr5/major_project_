import { useQuery } from '@tanstack/react-query'
import {
  Activity, ShieldAlert, AlertTriangle, ShieldCheck,
  Bot, Cpu, ArrowUpRight, Radio, Network,
  Clock3, ChevronRight
} from 'lucide-react'
import { Link } from 'react-router-dom'
import {
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip
} from 'recharts'

import { api } from '../api/client'
import { ThreatTimeline } from '../components/charts/ThreatTimeline'
import { SeverityBadge } from '../components/common/SeverityBadge'
import { formatRelativeTime, SEVERITY_COLORS } from '../utils/severity'
import type { DashboardStats, SecurityEvent } from '../types'
import { useStore } from '../store/useStore'

const COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#22c55e',
}

export function Overview() {
  const { data: stats } = useQuery<DashboardStats>({
    queryKey: ['stats'],
    queryFn: () => api.dashboard.stats() as Promise<DashboardStats>,
    refetchInterval: 10000,
  })

  const { data: timeline } = useQuery({
    queryKey: ['timeline'],
    queryFn: () => api.dashboard.threatTimeline(168),
    refetchInterval: 30000,
  })

  const { data: severity } = useQuery({
    queryKey: ['severity-dist'],
    queryFn: () => api.dashboard.severityDistribution(),
    refetchInterval: 30000,
  })

  const { data: recentEvents } = useQuery({
    queryKey: ['recent-events'],
    queryFn: () => api.events.list({ limit: 10 }) as Promise<{ items: SecurityEvent[] }>,
    refetchInterval: 10000,
  })

  const liveEvents = useStore((s) => s.liveEvents)
  const wsConnected = useStore((s) => s.wsConnected)

  const displayEvents = liveEvents.length > 0
    ? liveEvents.slice(0, 10)
    : recentEvents?.items ?? []

  const pieData = severity
    ? Object.entries(severity as Record<string, number>)
        .filter(([, value]) => value > 0)
        .map(([name, value]) => ({
          name: name.toUpperCase(),
          value,
        }))
    : []

  const cards = [
    {
      title: 'Total Network Flows',
      value: stats?.total_flows ?? 0,
      icon: Network,
      color: '#38bdf8',
      note: 'Traffic flows analyzed',
    },
    {
      title: 'Security Events',
      value: stats?.total_events ?? 0,
      icon: ShieldAlert,
      color: '#a78bfa',
      note: 'Recorded security events',
    },
    {
      title: 'Attacks Detected',
      value: stats?.attacks_detected ?? 0,
      icon: AlertTriangle,
      color: '#fb7185',
      note: 'ML-detected attacks',
    },
    {
      title: 'Critical Threats',
      value: stats?.critical_threats ?? 0,
      icon: ShieldCheck,
      color: '#f87171',
      note: 'Requires immediate attention',
    },
  ]

  const agentsRunning = stats?.agents_running ?? 0

  return (
    <div className="overview-page">

      {/* Page heading */}
      <section className="overview-heading">
        <div>
          <div className="overview-eyebrow">
            <span className="eyebrow-dot" />
            SECURITY OPERATIONS CENTER
          </div>
          <h2>Security Overview</h2>
          <p>Monitor network activity, threats and AI-driven defence operations.</p>
        </div>

        <div className="overview-live">
          <span className={`live-dot ${wsConnected ? '' : 'offline'}`} />
          {wsConnected ? 'LIVE MONITORING' : 'LIVE DISCONNECTED'}
        </div>
      </section>

      {/* KPI cards */}
      <section className="overview-stats">
        {cards.map((card, index) => {
          const Icon = card.icon

          return (
            <article
              className="overview-stat-card"
              key={card.title}
              style={{ animationDelay: `${index * 80}ms` }}
            >
              <div className="stat-card-top">
                <div className="stat-icon" style={{
                  color: card.color,
                  background: `${card.color}15`,
                  borderColor: `${card.color}30`,
                }}>
                  <Icon size={21} />
                </div>
                <span className="stat-card-arrow">
                  <ArrowUpRight size={17} />
                </span>
              </div>

              <p className="stat-card-label">{card.title}</p>
              <h3>{card.value.toLocaleString()}</h3>
              <p className="stat-card-note">{card.note}</p>
            </article>
          )
        })}
      </section>

      {/* Charts */}
      <section className="overview-charts">

        <article className="overview-panel threat-panel">
          <div className="panel-heading">
            <div>
              <div className="panel-title">
                <Activity size={18} />
                <h3>Threat Activity</h3>
              </div>
              <p>Network threat analysis over the last 7 days</p>
            </div>
            <span className="panel-period">LAST 7 DAYS</span>
          </div>

          <div className="threat-chart">
            <ThreatTimeline data={(timeline as any) ?? []} />
          </div>
        </article>

        <article className="overview-panel severity-panel">
          <div className="panel-heading">
            <div>
              <div className="panel-title">
                <ShieldAlert size={18} />
                <h3>Threat Severity</h3>
              </div>
              <p>Distribution of detected threats</p>
            </div>
          </div>

          {pieData.length > 0 ? (
            <>
              <div className="severity-chart">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={pieData}
                      dataKey="value"
                      nameKey="name"
                      cx="50%"
                      cy="50%"
                      innerRadius={59}
                      outerRadius={83}
                      paddingAngle={4}
                      stroke="none"
                      animationDuration={900}
                    >
                      {pieData.map((entry) => (
                        <Cell
                          key={entry.name}
                          fill={COLORS[entry.name] ?? SEVERITY_COLORS[entry.name] ?? '#64748b'}
                        />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        background: '#111c2e',
                        border: '1px solid #26364d',
                        borderRadius: 10,
                        color: '#e2e8f0',
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
                <div className="severity-center">
                  <strong>{stats?.attacks_detected ?? 0}</strong>
                  <span>ATTACKS</span>
                </div>
              </div>

              <div className="severity-legend">
                {pieData.map((item) => (
                  <div className="severity-legend-item" key={item.name}>
                    <span style={{ background: COLORS[item.name] ?? '#64748b' }} />
                    <span>{item.name}</span>
                    <strong>{item.value}</strong>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="severity-empty">
              <ShieldCheck size={32} />
              <p>No severity data available</p>
            </div>
          )}
        </article>
      </section>

      {/* Events and agents */}
      <section className="overview-bottom">

        <article className="overview-panel events-panel">
          <div className="panel-heading">
            <div>
              <div className="panel-title">
                <Radio size={18} />
                <h3>Recent Security Events</h3>
              </div>
              <p>Latest detected security incidents</p>
            </div>

            <Link to="/events" className="panel-link">
              View all <ChevronRight size={15} />
            </Link>
          </div>

          <div className="events-table-wrap">
            <table className="events-table">
              <thead>
                <tr>
                  <th>TIME</th>
                  <th>SOURCE IP</th>
                  <th>DESTINATION</th>
                  <th>ATTACK TYPE</th>
                  <th>SEVERITY</th>
                  <th>RISK</th>
                </tr>
              </thead>
              <tbody>
                {displayEvents.map((event) => (
                  <tr key={event.event_id}>
                    <td className="event-time">
                      <Clock3 size={12} />
                      {formatRelativeTime(event.created_at)}
                    </td>
                    <td className="event-source">{event.source_ip}</td>
                    <td>{event.destination_ip}</td>
                    <td>{event.attack_category ?? 'Unknown'}</td>
                    <td><SeverityBadge severity={event.severity} size="sm" /></td>
                    <td>
                      <span className="event-risk">
                        {event.risk_score ?? '—'}
                      </span>
                    </td>
                  </tr>
                ))}

                {displayEvents.length === 0 && (
                  <tr>
                    <td colSpan={6} className="events-empty">
                      <ShieldCheck size={25} />
                      <span>No security events detected yet</span>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </article>

        <article className="overview-panel agents-panel">
          <div className="panel-heading">
            <div>
              <div className="panel-title">
                <Bot size={18} />
                <h3>AI Agent Status</h3>
              </div>
              <p>Multi-agent defence framework</p>
            </div>
            <span className="agent-count">{agentsRunning}/3</span>
          </div>

          <div className="agent-list">
            {[
              { name: 'Detection Agent', description: 'Network threat detection', icon: Activity },
              { name: 'Analysis Agent', description: 'Attack investigation', icon: Cpu },
              { name: 'Defence Agent', description: 'Defence recommendations', icon: ShieldCheck },
            ].map((agent, index) => {
              const Icon = agent.icon
              const running = index < agentsRunning

              return (
                <div className="agent-row" key={agent.name}>
                  <div className="agent-icon">
                    <Icon size={18} />
                  </div>
                  <div className="agent-info">
                    <strong>{agent.name}</strong>
                    <span>{agent.description}</span>
                  </div>
                  <span className={`agent-status ${running ? 'running' : 'inactive'}`}>
                    <i />
                    {running ? 'RUNNING' : 'INACTIVE'}
                  </span>
                </div>
              )
            })}
          </div>

          <Link to="/agents" className="agent-details-link">
            Explore agent activity <ChevronRight size={15} />
          </Link>
        </article>
      </section>

      <footer className="overview-footer">
        <span>AGENTSHIELD SECURITY PLATFORM</span>
        <span>Data refreshes automatically</span>
      </footer>
    </div>
  )
}
