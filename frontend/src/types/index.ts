// TypeScript types matching backend Pydantic schemas

export interface SecurityEvent {
  id: number
  event_id: string
  source_ip: string
  destination_ip: string
  source_port?: number
  destination_port?: number
  protocol?: string
  attack_category?: string
  ml_prediction?: string
  ml_confidence?: number
  suricata_alert: boolean
  suricata_signature?: string
  risk_score?: number
  severity?: string
  evidence?: string[]
  status: string
  created_at: string
  updated_at: string
}

export interface SecurityEventList {
  items: SecurityEvent[]
  total: number
  page: number
  limit: number
  pages: number
}

export interface DashboardStats {
  total_flows: number
  total_events: number
  attacks_detected: number
  critical_threats: number
  high_risk_events: number
  benign_traffic: number
  active_sensors: number
  model_status: string
  ollama_status: string
  agents_running: number
  last_updated: string
}

export interface ThreatTimelinePoint {
  timestamp: string
  attacks: number
  benign: number
  critical: number
  high: number
}

export interface SeverityDistribution {
  critical: number
  high: number
  medium: number
  low: number
  normal: number
}

export interface ComponentHealth {
  component: string
  status: 'OK' | 'DEGRADED' | 'DOWN' | 'UNKNOWN'
  message?: string
  details?: Record<string, unknown>
  checked_at: string
}

export interface SystemHealth {
  overall: string
  components: Record<string, ComponentHealth>
  checked_at: string
}

export interface AgentStatusOut {
  name: string
  status: string
  events_processed: number
  last_activity?: string
  current_task?: string
  error_message?: string
}

export interface AllAgentStatus {
  detection: AgentStatusOut
  analysis: AgentStatusOut
  defence: AgentStatusOut
}

export interface AttackPathNode {
  id: string
  ip: string
  node_type: 'attacker' | 'victim' | 'intermediate' | 'unknown'
  risk_level?: string
  label?: string
}

export interface AttackPathEdge {
  source: string
  target: string
  label?: string
  observed: boolean
}

export interface InvestigationResult {
  investigation_id: string
  event_id: string
  attack_type?: string
  entry_point?: string
  target?: string
  nodes: AttackPathNode[]
  edges: AttackPathEdge[]
  affected_assets: string[]
  observed_evidence: string[]
  hypotheses: string[]
  potential_impact?: string
  confidence?: number
  explanation?: string
  llm_used: boolean
  created_at: string
}

export interface RecommendedAction {
  action_id: string
  action_type: string
  description: string
  target?: string
  priority: number
  rationale: string
}

export interface DefenceRecommendation {
  defence_id: string
  investigation_id: string
  risk_level: string
  recommended_actions: RecommendedAction[]
  priority: string
  requires_admin_approval: boolean
  execution_status: string
  created_at: string
}

export interface NetworkFlow {
  id: number
  flow_id: string
  source_ip: string
  destination_ip: string
  source_port?: number
  destination_port?: number
  protocol?: string
  duration_us?: number
  pcap_source?: string
  created_at: string
}

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NORMAL'

// WebSocket message types
export type WSMessage =
  | { type: 'new_event'; payload: SecurityEvent }
  | { type: 'investigation_complete'; payload: InvestigationResult }
  | { type: 'defence_recommendation'; payload: DefenceRecommendation }
  | { type: 'connection_ack'; payload: { message: string; model_status: string; connections: number } }
  | { type: 'keepalive' }
  | { type: 'pong' }
