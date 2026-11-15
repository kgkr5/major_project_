import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation } from '@tanstack/react-query'
import { ArrowLeft, CheckCircle, XCircle } from 'lucide-react'
import { api } from '../api/client'
import { SeverityBadge } from '../components/common/SeverityBadge'
import { formatTimestamp, formatConfidence } from '../utils/severity'

export function EventDetail() {
  const { eventId } = useParams<{ eventId: string }>()
  const navigate = useNavigate()

  const { data: event, isLoading } = useQuery({
    queryKey: ['event', eventId],
    queryFn: () => api.events.get(eventId!),
    enabled: !!eventId,
  })

  const { data: investigation } = useQuery({
    queryKey: ['investigation', eventId],
    queryFn: () => api.events.investigation(eventId!),
    enabled: !!eventId,
    retry: false,
  })

  const { data: defence } = useQuery({
    queryKey: ['defence', eventId],
    queryFn: () => api.events.defence(eventId!),
    enabled: !!eventId,
    retry: false,
  })

  const approve = useMutation({
    mutationFn: (id: string) => api.agents.approveRecommendation(id),
  })

  const reject = useMutation({
    mutationFn: (id: string) => api.agents.rejectRecommendation(id),
  })

  const ev = event as any
  const inv = investigation as any
  const def = defence as any

  if (isLoading) return <div className="p-6 text-text-muted">Loading event…</div>
  if (!ev) return <div className="p-6 text-text-muted">Event not found</div>

  return (
    <div className="p-6 space-y-4 max-w-5xl">
      <button onClick={() => navigate(-1)} className="flex items-center gap-2 text-sm text-text-muted hover:text-text-secondary">
        <ArrowLeft size={14} /> Back
      </button>

      <div className="flex items-start justify-between">
        <div>
          <h2 className="text-text-primary font-semibold text-lg font-mono">{ev.event_id}</h2>
          <p className="text-text-muted text-xs mt-1">{formatTimestamp(ev.created_at)}</p>
        </div>
        <SeverityBadge severity={ev.severity} />
      </div>

      {/* Network metadata */}
      <div className="bg-bg-secondary border border-border rounded-lg p-4">
        <h3 className="text-text-secondary text-sm font-medium mb-3">Network Details</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {[
            ['Source IP', ev.source_ip],
            ['Destination IP', ev.destination_ip],
            ['Src Port', ev.source_port],
            ['Dst Port', ev.destination_port],
            ['Protocol', ev.protocol],
            ['Attack Category', ev.attack_category ?? '—'],
            ['Status', ev.status],
            ['Risk Score', ev.risk_score ?? '—'],
          ].map(([label, value]) => (
            <div key={label}>
              <p className="text-text-muted text-xs">{label}</p>
              <p className="text-text-secondary font-mono text-sm mt-0.5">{value}</p>
            </div>
          ))}
        </div>
      </div>

      {/* ML prediction */}
      {ev.ml_prediction && (
        <div className="bg-bg-secondary border border-border rounded-lg p-4">
          <h3 className="text-text-secondary text-sm font-medium mb-3">ML Classification</h3>
          <div className="flex items-center gap-6">
            <div>
              <p className="text-text-muted text-xs">Prediction</p>
              <p className={`font-mono text-lg font-bold mt-0.5 ${ev.ml_prediction === 'ATTACK' ? 'text-red-400' : 'text-green-400'}`}>
                {ev.ml_prediction}
              </p>
            </div>
            <div>
              <p className="text-text-muted text-xs">Confidence</p>
              <p className="font-mono text-lg text-text-primary mt-0.5">{formatConfidence(ev.ml_confidence)}</p>
            </div>
            <div className="flex-1">
              <p className="text-text-muted text-xs mb-1">Confidence bar</p>
              <div className="h-2 bg-border rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full ${ev.ml_prediction === 'ATTACK' ? 'bg-red-400' : 'bg-green-400'}`}
                  style={{ width: `${(ev.ml_confidence ?? 0) * 100}%` }}
                />
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Suricata evidence */}
      {ev.suricata_alert && (
        <div className="bg-bg-secondary border border-border rounded-lg p-4">
          <h3 className="text-text-secondary text-sm font-medium mb-2">Suricata Alert</h3>
          <p className="text-orange-400 text-sm font-mono">{ev.suricata_signature ?? 'Unknown signature'}</p>
        </div>
      )}

      {/* Evidence list */}
      {ev.evidence && ev.evidence.length > 0 && (
        <div className="bg-bg-secondary border border-border rounded-lg p-4">
          <h3 className="text-text-secondary text-sm font-medium mb-2">Evidence</h3>
          <ul className="space-y-1">
            {ev.evidence.map((e: string, i: number) => (
              <li key={i} className="text-xs text-text-secondary">• {e}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Investigation */}
      {inv && (
        <div className="bg-bg-secondary border border-border rounded-lg p-4">
          <h3 className="text-text-secondary text-sm font-medium mb-3">Agent Investigation</h3>
          {inv.explanation && (
            <pre className="text-xs text-text-secondary whitespace-pre-wrap font-sans leading-relaxed border border-border rounded p-3 bg-bg-primary">
              {inv.explanation}
            </pre>
          )}
        </div>
      )}

      {/* Defence recommendations */}
      {def && (
        <div className="bg-bg-secondary border border-border rounded-lg p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-text-secondary text-sm font-medium">Defence Recommendations</h3>
            <div className="flex gap-2">
              {def.execution_status === 'RECOMMENDED' && (
                <>
                  <button
                    onClick={() => approve.mutate(def.defence_id)}
                    className="flex items-center gap-1 px-3 py-1 text-xs bg-green-500/20 border border-green-500/30 text-green-400 rounded hover:bg-green-500/30"
                  >
                    <CheckCircle size={12} /> Approve
                  </button>
                  <button
                    onClick={() => reject.mutate(def.defence_id)}
                    className="flex items-center gap-1 px-3 py-1 text-xs bg-red-500/20 border border-red-500/30 text-red-400 rounded hover:bg-red-500/30"
                  >
                    <XCircle size={12} /> Reject
                  </button>
                </>
              )}
              {def.execution_status !== 'RECOMMENDED' && (
                <span className={`text-xs px-2 py-1 rounded border ${def.execution_status === 'APPROVED' ? 'bg-green-500/20 border-green-500/30 text-green-400' : 'bg-red-500/20 border-red-500/30 text-red-400'}`}>
                  {def.execution_status}
                </span>
              )}
            </div>
          </div>
          <div className="text-xs text-yellow-400 mb-3">⚠ All actions require administrator manual execution</div>
          <div className="space-y-2">
            {(def.recommended_actions ?? []).map((a: any, i: number) => (
              <div key={i} className="flex items-start gap-3 p-3 border border-border rounded">
                <span className="text-xs font-mono text-accent-cyan min-w-fit">P{a.priority}</span>
                <div>
                  <p className="text-sm text-text-secondary">{a.description}</p>
                  <p className="text-xs text-text-muted mt-0.5">{a.rationale}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
