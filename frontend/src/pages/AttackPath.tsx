import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Network, Search, ShieldAlert, Activity, Target,
  BrainCircuit, Clock3, ArrowRight, RefreshCw,
  ShieldCheck, Crosshair, FileSearch, Layers3
} from 'lucide-react'
import { api } from '../api/client'
import { AttackPathGraph } from '../components/flow/AttackPathGraph'
import { formatRelativeTime } from '../utils/severity'
import type { InvestigationResult } from '../types'

export function AttackPath() {
  const [selected, setSelected] = useState<string | null>(null)
  const [search, setSearch] = useState('')

  const { data: investigations, isFetching, refetch } =
    useQuery<InvestigationResult[]>({
      queryKey: ['investigations'],
      queryFn: () => api.agents.investigations(20) as Promise<InvestigationResult[]>,
      refetchInterval: 15000,
    })

  const items = investigations ?? []

  const selectedInv = items.find(i => i.investigation_id === selected) ?? items[0] ?? null

  const filtered = useMemo(() => {
    const q = search.toLowerCase().trim()
    if (!q) return items

    return items.filter(inv =>
      (inv.investigation_id ?? '').toLowerCase().includes(q) ||
      (inv.attack_type ?? '').toLowerCase().includes(q) ||
      (inv.entry_point ?? '').toLowerCase().includes(q) ||
      (inv.target ?? '').toLowerCase().includes(q)
    )
  }, [items, search])

  const highImpact = items.filter(
    i => i.potential_impact?.toUpperCase() === 'HIGH'
  ).length

  const averageConfidence = items.length
    ? items.reduce((sum, i) => sum + (i.confidence ?? 0), 0) / items.length
    : 0

  const totalAssets = new Set(items.flatMap(i => i.affected_assets ?? [])).size

  return (
    <div className="attack-page">

      {/* Heading */}
      <section className="attack-heading">
        <div>
          <div className="attack-eyebrow">
            <span />
            SECURITY INVESTIGATION CENTER
          </div>
          <h2>Attack Path Analysis</h2>
          <p>Explore investigation results, attack relationships and supporting evidence.</p>
        </div>

        <button className="attack-refresh" onClick={() => refetch()} disabled={isFetching}>
          <RefreshCw size={15} className={isFetching ? 'attack-spin' : ''} />
          Refresh
        </button>
      </section>

      {/* Summary */}
      <section className="attack-summary-grid">
        <article className="attack-summary-card">
          <div className="attack-summary-icon cyan"><FileSearch size={20} /></div>
          <span>Total Investigations</span>
          <strong>{items.length}</strong>
          <small>Recently returned records</small>
        </article>

        <article className="attack-summary-card">
          <div className="attack-summary-icon red"><ShieldAlert size={20} /></div>
          <span>High Impact</span>
          <strong>{highImpact}</strong>
          <small>Investigations marked HIGH</small>
        </article>

        <article className="attack-summary-card">
          <div className="attack-summary-icon purple"><BrainCircuit size={20} /></div>
          <span>Average Confidence</span>
          <strong>{(averageConfidence * 100).toFixed(0)}%</strong>
          <small>Across returned investigations</small>
        </article>

        <article className="attack-summary-card">
          <div className="attack-summary-icon orange"><Target size={20} /></div>
          <span>Affected Assets</span>
          <strong>{totalAssets}</strong>
          <small>Unique reported assets</small>
        </article>
      </section>

      {/* Main workspace */}
      <section className="attack-workspace">

        {/* Investigation explorer */}
        <aside className="attack-explorer">
          <div className="attack-explorer-heading">
            <div>
              <h3><Layers3 size={17} /> Investigation Explorer</h3>
              <p>Select an investigation to inspect</p>
            </div>
            <span>{filtered.length}</span>
          </div>

          <div className="attack-search">
            <Search size={15} />
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search investigations..."
            />
          </div>

          <div className="attack-investigation-list">
            {filtered.map(inv => (
              <button
                key={inv.investigation_id}
                onClick={() => setSelected(inv.investigation_id)}
                className={`attack-investigation-item ${
                  selectedInv?.investigation_id === inv.investigation_id ? 'active' : ''
                }`}
              >
                <div className="attack-investigation-top">
                  <span>{inv.attack_type ?? 'Unknown attack'}</span>
                  <span className={`attack-impact ${(inv.potential_impact ?? 'unknown').toLowerCase()}`}>
                    {inv.potential_impact ?? 'UNKNOWN'}
                  </span>
                </div>
                <small className="attack-id">{inv.investigation_id}</small>
                <div className="attack-route-small">
                  <span>{inv.entry_point ?? 'Unknown source'}</span>
                  <ArrowRight size={12} />
                  <span>{inv.target ?? 'Unknown target'}</span>
                </div>
                <div className="attack-investigation-footer">
                  <span>{formatRelativeTime(inv.created_at)}</span>
                  {inv.llm_used && <span className="attack-llm-tag">LLM</span>}
                </div>
              </button>
            ))}

            {filtered.length === 0 && (
              <div className="attack-empty">
                <Search size={22} />
                <span>No matching investigations</span>
              </div>
            )}

            {items.length === 0 && (
              <div className="attack-empty">
                <FileSearch size={22} />
                <span>No investigations available</span>
              </div>
            )}
          </div>
        </aside>

        {/* Graph and details */}
        <div className="attack-main">

          <article className="attack-graph-panel">
            <div className="attack-panel-heading">
              <div>
                <h3><Network size={18} /> Attack Path Graph</h3>
                <p>
                  {selectedInv
                    ? `Investigation: ${selectedInv.investigation_id}`
                    : 'Select an investigation to explore its graph'}
                </p>
              </div>

              {selectedInv && (
                <span className="attack-confidence">
                  CONFIDENCE <strong>{((selectedInv.confidence ?? 0) * 100).toFixed(0)}%</strong>
                </span>
              )}
            </div>

            <div className="attack-graph-content">
              <AttackPathGraph
                nodes={selectedInv?.nodes ?? []}
                edges={selectedInv?.edges ?? []}
              />
            </div>

            <div className="attack-graph-legend">
              <span><i className="attacker-dot" /> Attacker</span>
              <span><i className="intermediate-dot" /> Intermediate</span>
              <span><i className="victim-dot" /> Victim</span>
              <span><i className="observed-line" /> Observed connection</span>
            </div>
          </article>

          {selectedInv ? (
            <>
              {/* Investigation details */}
              <article className="attack-details-panel">
                <div className="attack-panel-heading">
                  <div>
                    <h3><Crosshair size={18} /> Investigation Intelligence</h3>
                    <p>Details reported by the Attack Analysis Agent</p>
                  </div>
                  <span className={`attack-impact ${(selectedInv.potential_impact ?? 'unknown').toLowerCase()}`}>
                    {selectedInv.potential_impact ?? 'UNKNOWN'} IMPACT
                  </span>
                </div>

                <div className="attack-detail-grid">
                  <div>
                    <span>ATTACK TYPE</span>
                    <strong>{selectedInv.attack_type ?? 'Unknown'}</strong>
                  </div>
                  <div>
                    <span>ENTRY POINT</span>
                    <strong className="attack-mono">{selectedInv.entry_point ?? 'Unknown'}</strong>
                  </div>
                  <div>
                    <span>TARGET</span>
                    <strong className="attack-mono">{selectedInv.target ?? 'Unknown'}</strong>
                  </div>
                  <div>
                    <span>CONFIDENCE</span>
                    <strong>{((selectedInv.confidence ?? 0) * 100).toFixed(0)}%</strong>
                  </div>
                </div>

                <div className="attack-analysis-status">
                  <span className={selectedInv.llm_used ? 'llm-active' : 'llm-fallback'}>
                    <BrainCircuit size={14} />
                    {selectedInv.llm_used ? 'LLM-assisted analysis' : 'Rule-based analysis'}
                  </span>
                  <span><Clock3 size={13} /> {formatRelativeTime(selectedInv.created_at)}</span>
                </div>
              </article>

              {/* Evidence and hypotheses */}
              <div className="attack-evidence-grid">
                <article className="attack-info-panel">
                  <div className="attack-info-heading">
                    <ShieldCheck size={17} />
                    <h3>Observed Evidence</h3>
                    <span>{selectedInv.observed_evidence?.length ?? 0}</span>
                  </div>

                  {(selectedInv.observed_evidence ?? []).length > 0 ? (
                    <ul>
                      {selectedInv.observed_evidence.map((e, i) => (
                        <li key={i}>{e}</li>
                      ))}
                    </ul>
                  ) : (
                    <p className="attack-no-data">No observed evidence provided.</p>
                  )}
                </article>

                <article className="attack-info-panel">
                  <div className="attack-info-heading hypothesis">
                    <Activity size={17} />
                    <h3>Attack Hypotheses</h3>
                    <span>{selectedInv.hypotheses?.length ?? 0}</span>
                  </div>

                  {(selectedInv.hypotheses ?? []).length > 0 ? (
                    <ul className="hypothesis-list">
                      {selectedInv.hypotheses.map((h, i) => (
                        <li key={i}>{h}</li>
                      ))}
                    </ul>
                  ) : (
                    <p className="attack-no-data">No hypotheses provided.</p>
                  )}
                </article>
              </div>

              {/* Explanation */}
              <article className="attack-explanation-panel">
                <div className="attack-info-heading">
                  <BrainCircuit size={17} />
                  <h3>Investigation Summary</h3>
                  {selectedInv.llm_used && <span className="attack-llm-tag">LLM</span>}
                </div>
                <p>
                  {selectedInv.explanation || 'No investigation explanation is available for this record.'}
                </p>
              </article>

              {/* Affected assets */}
              <article className="attack-assets-panel">
                <div className="attack-info-heading">
                  <Target size={17} />
                  <h3>Affected Assets</h3>
                  <span>{selectedInv.affected_assets?.length ?? 0}</span>
                </div>
                <div className="attack-assets-list">
                  {(selectedInv.affected_assets ?? []).length > 0
                    ? selectedInv.affected_assets.map((asset, i) => (
                      <span key={i}>{asset}</span>
                    ))
                    : <p className="attack-no-data">No affected assets reported.</p>
                  }
                </div>
              </article>
            </>
          ) : (
            <div className="attack-select-empty">
              <Network size={34} />
              <h3>No Investigation Selected</h3>
              <p>Choose an investigation from the explorer to view its attack path and analysis.</p>
            </div>
          )}
        </div>
      </section>

      <div className="attack-footer-note">
        <ShieldCheck size={15} />
        Attack paths represent investigation findings and hypotheses. They should not be interpreted as confirmed execution of every inferred step.
      </div>
    </div>
  )
}
