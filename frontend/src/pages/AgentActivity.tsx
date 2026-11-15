import { useQuery } from '@tanstack/react-query'
import {
  Bot, Activity, ShieldAlert, ShieldCheck, Search,
  BrainCircuit, Clock3, ArrowRight, AlertTriangle,
  RefreshCw, Zap, Network
} from 'lucide-react'
import { api } from '../api/client'
import { formatRelativeTime } from '../utils/severity'
import type { AllAgentStatus } from '../types'

const agentDefinitions = [
  {
    key: 'detection',
    name: 'Detection Agent',
    description: 'Correlates Suricata alerts with ML predictions',
    color: 'red',
    icon: ShieldAlert,
    stage: '01',
  },
  {
    key: 'analysis',
    name: 'Attack Analysis Agent',
    description: 'Investigates threats and constructs attack paths',
    color: 'orange',
    icon: BrainCircuit,
    stage: '02',
  },
  {
    key: 'defence',
    name: 'Defence Agent',
    description: 'Generates defensive recommendations (read-only)',
    color: 'purple',
    icon: ShieldCheck,
    stage: '03',
  },
]

export function AgentActivity() {
  const { data: agentStatus, isFetching: statusFetching, refetch } =
    useQuery<AllAgentStatus>({
      queryKey: ['agent-status'],
      queryFn: () => api.agents.status() as Promise<AllAgentStatus>,
      refetchInterval: 5000,
    })

  const { data: detEvents } = useQuery({
    queryKey: ['det-events'],
    queryFn: () => api.agents.detectionEvents(10),
    refetchInterval: 10000,
  })

  const { data: investigations } = useQuery({
    queryKey: ['investigations-brief'],
    queryFn: () => api.agents.investigations(10),
    refetchInterval: 10000,
  })

  const { data: recommendations } = useQuery({
    queryKey: ['recommendations-brief'],
    queryFn: () => api.agents.recommendations(10),
    refetchInterval: 10000,
  })

  const detections = (detEvents as any[]) ?? []
  const investigationList = (investigations as any[]) ?? []
  const recommendationList = (recommendations as any[]) ?? []

  const agents = agentDefinitions.map(agent => ({
    ...agent,
    status: agentStatus?.[agent.key as keyof AllAgentStatus],
  }))

  const runningAgents = agents.filter(
    agent => agent.status?.status?.toUpperCase() === 'RUNNING'
  ).length

  const totalProcessed = agents.reduce(
    (total, agent) => total + (agent.status?.events_processed ?? 0), 0
  )

  return (
    <div className="agent-page">

      {/* Page heading */}
      <section className="agent-page-heading">
        <div>
          <div className="agent-eyebrow">
            <span />
            MULTI-AGENT SECURITY OPERATIONS
          </div>
          <h2>AI Agent Activity</h2>
          <p>Monitor intelligent agents, investigations and defensive recommendations.</p>
        </div>

        <button
          className="agent-refresh"
          onClick={() => refetch()}
          disabled={statusFetching}
        >
          <RefreshCw size={15} className={statusFetching ? 'agent-spin' : ''} />
          Refresh
        </button>
      </section>

      {/* Summary cards */}
      <section className="agent-summary-grid">
        <article className="agent-summary-card">
          <div className="agent-summary-icon cyan"><Bot size={20} /></div>
          <span>AI Agents</span>
          <strong>{agents.length}</strong>
          <small>Registered security agents</small>
        </article>

        <article className="agent-summary-card">
          <div className="agent-summary-icon green"><Activity size={20} /></div>
          <span>Agents Running</span>
          <strong>{runningAgents}<small> / {agents.length}</small></strong>
          <small>Current reported status</small>
        </article>

        <article className="agent-summary-card">
          <div className="agent-summary-icon purple"><Zap size={20} /></div>
          <span>Events Processed</span>
          <strong>{totalProcessed.toLocaleString()}</strong>
          <small>Reported across all agents</small>
        </article>

        <article className="agent-summary-card">
          <div className="agent-summary-icon orange"><Search size={20} /></div>
          <span>Investigations</span>
          <strong>{investigationList.length}</strong>
          <small>Recently returned investigations</small>
        </article>
      </section>

      {/* Agent execution pipeline */}
      <section className="agent-section">
        <div className="agent-section-heading">
          <div>
            <h3><Network size={18} /> Agent Execution Pipeline</h3>
            <p>Three stages of the AgentShield security analysis workflow.</p>
          </div>
          <span className="agent-section-badge">3 STAGES</span>
        </div>

        <div className="agent-pipeline">
          {agents.map((agent, index) => {
            const Icon = agent.icon
            const status = agent.status?.status ?? 'UNKNOWN'

            return (
              <div className="agent-pipeline-item" key={agent.key}>
                <article className={`agent-card agent-${agent.color}`}>
                  <div className="agent-card-top">
                    <span className="agent-stage">STAGE {agent.stage}</span>
                    <Icon size={22} />
                  </div>

                  <h4>{agent.name}</h4>
                  <p>{agent.description}</p>

                  <div className="agent-status-line">
                    <span className={`agent-status-dot ${status.toLowerCase()}`} />
                    <strong>{status}</strong>
                  </div>

                  <div className="agent-card-divider" />

                  <div className="agent-card-metrics">
                    <span>Events processed</span>
                    <strong>{agent.status?.events_processed ?? 0}</strong>
                  </div>

                  {agent.status?.last_activity && (
                    <div className="agent-last-activity">
                      <Clock3 size={12} />
                      Last activity: {formatRelativeTime(agent.status.last_activity)}
                    </div>
                  )}

                  {agent.status?.error_message && (
                    <div className="agent-error">
                      <AlertTriangle size={13} />
                      {agent.status.error_message}
                    </div>
                  )}
                </article>

                {index < agents.length - 1 && (
                  <div className="agent-pipeline-arrow">
                    <ArrowRight size={20} />
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </section>

      {/* Activity panels */}
      <section className="agent-activity-grid">

        {/* Detection events */}
        <article className="agent-activity-panel">
          <div className="agent-panel-heading">
            <div className="agent-panel-icon red"><ShieldAlert size={17} /></div>
            <div>
              <h3>Recent Detections</h3>
              <p>Security events identified by detection</p>
            </div>
            <span className="agent-count">{detections.length}</span>
          </div>

          <div className="agent-panel-content">
            {detections.map((ev: any, index: number) => (
              <div className="agent-activity-item" key={ev.event_id ?? index}>
                <div className="agent-activity-main">
                  <strong className="agent-ip">{ev.source_ip ?? 'Unknown source'}</strong>
                  <span className={`agent-severity ${String(ev.severity ?? 'LOW').toLowerCase()}`}>
                    {ev.severity ?? 'UNKNOWN'}
                  </span>
                </div>
                <p>{ev.attack_category ?? 'Unclassified activity'}</p>
                {ev.created_at && (
                  <small>{formatRelativeTime(ev.created_at)}</small>
                )}
              </div>
            ))}

            {detections.length === 0 && (
              <div className="agent-empty">
                <ShieldCheck size={24} />
                <span>No detections available</span>
              </div>
            )}
          </div>
        </article>

        {/* Investigations */}
        <article className="agent-activity-panel">
          <div className="agent-panel-heading">
            <div className="agent-panel-icon orange"><BrainCircuit size={17} /></div>
            <div>
              <h3>Investigation Intelligence</h3>
              <p>Attack analysis and investigation results</p>
            </div>
            <span className="agent-count">{investigationList.length}</span>
          </div>

          <div className="agent-panel-content">
            {investigationList.map((inv: any, index: number) => (
              <div className="agent-activity-item" key={inv.investigation_id ?? index}>
                <strong className="agent-investigation-type">
                  {inv.attack_type ?? 'Unknown attack'}
                </strong>
                <p className="agent-route">
                  {inv.entry_point ?? 'Unknown'} <ArrowRight size={12} />
                  {inv.target ?? 'Unknown'}
                </p>
                <div className="agent-investigation-meta">
                  <span>{inv.potential_impact ?? inv.impact ?? 'Impact unavailable'} impact</span>
                  <span className={inv.llm_used ? 'llm-active' : 'llm-fallback'}>
                    {inv.llm_used ? 'LLM analysis' : 'Rule-based analysis'}
                  </span>
                </div>
              </div>
            ))}

            {investigationList.length === 0 && (
              <div className="agent-empty">
                <BrainCircuit size={24} />
                <span>No investigations available</span>
              </div>
            )}
          </div>
        </article>

        {/* Defence recommendations */}
        <article className="agent-activity-panel">
          <div className="agent-panel-heading">
            <div className="agent-panel-icon purple"><ShieldCheck size={17} /></div>
            <div>
              <h3>Defence Recommendations</h3>
              <p>Suggested defensive actions</p>
            </div>
            <span className="agent-count">{recommendationList.length}</span>
          </div>

          <div className="agent-panel-content">
            {recommendationList.map((rec: any, index: number) => (
              <div className="agent-activity-item" key={rec.defence_id ?? index}>
                <div className="agent-activity-main">
                  <strong className="agent-priority">{rec.priority ?? 'UNSPECIFIED'}</strong>
                  <span className="agent-execution-status">
                    {rec.execution_status ?? 'UNKNOWN'}
                  </span>
                </div>

                <p>{rec.risk_level ?? 'Unknown'} risk level</p>

                {rec.actions?.length > 0 && (
                  <div className="agent-action-list">
                    {rec.actions.slice(0, 3).map((action: any, actionIndex: number) => (
                      <span key={actionIndex}>
                        {typeof action === 'string' ? action : action.action ?? action.name ?? 'Recommended action'}
                      </span>
                    ))}
                  </div>
                )}

                {rec.requires_admin_approval && (
                  <div className="agent-approval-warning">
                    <AlertTriangle size={13} />
                    Requires admin approval
                  </div>
                )}

                {!rec.requires_admin_approval && (
                  <div className="agent-readonly-note">
                    Recommendation only — no action executed here.
                  </div>
                )}
              </div>
            ))}

            {recommendationList.length === 0 && (
              <div className="agent-empty">
                <ShieldCheck size={24} />
                <span>No recommendations available</span>
              </div>
            )}
          </div>
        </article>
      </section>

      <div className="agent-footer-note">
        <ShieldCheck size={15} />
        Defence recommendations are advisory. Network changes require authorised administrator approval.
      </div>
    </div>
  )
}
