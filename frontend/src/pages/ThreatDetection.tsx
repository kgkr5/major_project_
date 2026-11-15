import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import {
  AlertTriangle, ShieldAlert, ShieldCheck, Activity,
  Search, RefreshCw, ChevronLeft, ChevronRight,
  Crosshair, Clock3, Radio, ArrowUpRight
} from 'lucide-react'
import { api } from '../api/client'
import { SeverityBadge } from '../components/common/SeverityBadge'
import { formatRelativeTime, formatConfidence } from '../utils/severity'
import type { SecurityEventList } from '../types'

const SEVERITIES = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NORMAL']

export function ThreatDetection() {
  const navigate = useNavigate()
  const [page, setPage] = useState(1)
  const [severity, setSeverity] = useState('ALL')
  const [search, setSearch] = useState('')

  const { data, isLoading, isFetching, refetch } = useQuery<SecurityEventList>({
    queryKey: ['events', page, severity],
    queryFn: () => api.events.list({
      page,
      limit: 20,
      severity: severity === 'ALL' ? undefined : severity,
    }) as Promise<SecurityEventList>,
    refetchInterval: 15000,
  })

  const events = data?.items ?? []

  const filtered = useMemo(() => {
    const q = search.toLowerCase().trim()
    if (!q) return events

    return events.filter((ev) =>
      ev.source_ip.toLowerCase().includes(q) ||
      ev.destination_ip.toLowerCase().includes(q) ||
      (ev.attack_category ?? '').toLowerCase().includes(q) ||
      (ev.suricata_signature ?? '').toLowerCase().includes(q) ||
      (ev.ml_prediction ?? '').toLowerCase().includes(q)
    )
  }, [events, search])

  const stats = useMemo(() => ({
    critical: events.filter(e => e.severity?.toUpperCase() === 'CRITICAL').length,
    high: events.filter(e => e.severity?.toUpperCase() === 'HIGH').length,
    medium: events.filter(e => e.severity?.toUpperCase() === 'MEDIUM').length,
    low: events.filter(e => e.severity?.toUpperCase() === 'LOW').length,
    normal: events.filter(e => e.severity?.toUpperCase() === 'NORMAL').length,
    attacks: events.filter(e => e.ml_prediction === 'ATTACK').length,
    suricata: events.filter(e => e.suricata_alert).length,
  }), [events])

  const severityTotal = stats.critical + stats.high + stats.medium + stats.low + stats.normal

  const severityItems = [
    { name: 'Critical', value: stats.critical, color: '#f43f5e' },
    { name: 'High', value: stats.high, color: '#f97316' },
    { name: 'Medium', value: stats.medium, color: '#eab308' },
    { name: 'Low', value: stats.low, color: '#06b6d4' },
    { name: 'Normal', value: stats.normal, color: '#22c55e' },
  ]

  return (
    <div className="threat-page">

      <section className="threat-heading">
        <div>
          <div className="threat-eyebrow">
            <span className="threat-eyebrow-dot" />
            SECURITY OPERATIONS CENTER
          </div>
          <h2>Threat Detection</h2>
          <p>Identify, monitor and investigate suspicious network activity.</p>
        </div>

        <button className="threat-refresh" onClick={() => refetch()} disabled={isFetching}>
          <RefreshCw size={15} className={isFetching ? 'threat-spin' : ''} />
          Refresh
        </button>
      </section>

      <section className="threat-stat-grid">
        <article className="threat-stat-card">
          <div className="threat-stat-top">
            <span>Total Events</span>
            <div className="threat-stat-icon cyan"><Activity size={19} /></div>
          </div>
          <strong>{(data?.total ?? 0).toLocaleString()}</strong>
          <small>All recorded security events</small>
        </article>

        <article className="threat-stat-card">
          <div className="threat-stat-top">
            <span>Critical Threats</span>
            <div className="threat-stat-icon red"><ShieldAlert size={19} /></div>
          </div>
          <strong>{stats.critical}</strong>
          <small>On the current page</small>
        </article>

        <article className="threat-stat-card">
          <div className="threat-stat-top">
            <span>High Risk</span>
            <div className="threat-stat-icon orange"><AlertTriangle size={19} /></div>
          </div>
          <strong>{stats.high}</strong>
          <small>On the current page</small>
        </article>

        <article className="threat-stat-card">
          <div className="threat-stat-top">
            <span>ML Attack Predictions</span>
            <div className="threat-stat-icon purple"><Crosshair size={19} /></div>
          </div>
          <strong>{stats.attacks}</strong>
          <small>On the current page</small>
        </article>
      </section>

      <section className="threat-insights-grid">
        <article className="threat-panel severity-panel">
          <div className="threat-panel-heading">
            <div>
              <h3>Threat Severity Distribution</h3>
              <p>Breakdown of events on the current page</p>
            </div>
            <ShieldCheck size={19} />
          </div>

          <div className="threat-severity-content">
            <div className="threat-severity-total">
              <strong>{severityTotal}</strong>
              <span>EVENTS</span>
            </div>

            <div className="threat-severity-list">
              {severityItems.map(item => (
                <div className="threat-severity-row" key={item.name}>
                  <span className="threat-severity-dot" style={{ background: item.color }} />
                  <span className="threat-severity-name">{item.name}</span>
                  <div className="threat-severity-track">
                    <span style={{
                      width: `${severityTotal ? item.value / severityTotal * 100 : 0}%`,
                      background: item.color,
                    }} />
                  </div>
                  <strong>{item.value}</strong>
                </div>
              ))}
            </div>
          </div>
        </article>

        <article className="threat-panel detection-panel">
          <div className="threat-panel-heading">
            <div>
              <h3>Detection Intelligence</h3>
              <p>Detection signals from available sources</p>
            </div>
            <Crosshair size={19} />
          </div>

          <div className="threat-intel-row">
            <div className="threat-intel-icon purple"><Activity size={18} /></div>
            <div>
              <strong>ML Attack Predictions</strong>
              <span>Machine learning classification</span>
            </div>
            <b>{stats.attacks}</b>
          </div>

          <div className="threat-intel-row">
            <div className="threat-intel-icon orange"><Radio size={18} /></div>
            <div>
              <strong>Suricata Alerts</strong>
              <span>Events with Suricata alerts</span>
            </div>
            <b>{stats.suricata}</b>
          </div>

          <div className="threat-intel-note">
            Counts reflect the events loaded on the current page.
          </div>
        </article>
      </section>

      <section className="threat-events-panel">
        <div className="threat-events-heading">
          <div>
            <div className="threat-events-title">
              <AlertTriangle size={19} />
              <h3>Security Event Intelligence</h3>
            </div>
            <p>Review detected threats and investigate individual events.</p>
          </div>
          <span className="threat-live-indicator">
            <span /> AUTO REFRESH · 15 SEC
          </span>
        </div>

        <div className="threat-filter-bar">
          <div className="threat-search">
            <Search size={16} />
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search IP, attack category or signature..."
            />
          </div>

          <div className="threat-filter-buttons">
            {SEVERITIES.map(s => (
              <button
                key={s}
                onClick={() => { setSeverity(s); setPage(1) }}
                className={severity === s ? 'active' : ''}
              >
                {s}
              </button>
            ))}
          </div>
        </div>

        <div className="threat-results-meta">
          <span>
            Showing <strong>{filtered.length}</strong> of{' '}
            <strong>{events.length}</strong> loaded events
          </span>
          <span>{data?.total ?? 0} total database events</span>
        </div>

        <div className="threat-table-wrap">
          <table className="threat-table">
            <thead>
              <tr>
                <th>DETECTED</th>
                <th>SOURCE IP</th>
                <th>DESTINATION</th>
                <th>ATTACK CATEGORY</th>
                <th>SEVERITY</th>
                <th>RISK SCORE</th>
                <th>ML PREDICTION</th>
                <th>SURICATA</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {isLoading && (
                <tr><td colSpan={9} className="threat-empty">Loading security events...</td></tr>
              )}

              {!isLoading && filtered.length === 0 && (
                <tr>
                  <td colSpan={9} className="threat-empty">
                    <ShieldCheck size={28} />
                    <strong>No security events found</strong>
                    <span>Try another search or severity filter.</span>
                  </td>
                </tr>
              )}

              {filtered.map(ev => (
                <tr key={ev.event_id} onClick={() => navigate(`/events/${ev.event_id}`)}>
                  <td className="threat-time">
                    <Clock3 size={12} />
                    {formatRelativeTime(ev.created_at)}
                  </td>
                  <td className="threat-source">{ev.source_ip}</td>
                  <td className="threat-destination">
                    {ev.destination_ip}
                    <small>{ev.destination_port ? `:${ev.destination_port}` : ''}</small>
                  </td>
                  <td className="threat-category">{ev.attack_category ?? 'Unclassified'}</td>
                  <td><SeverityBadge severity={ev.severity ?? 'NORMAL'} size="sm" /></td>
                  <td>
                    <span className="threat-risk-score">{ev.risk_score ?? '—'}</span>
                  </td>
                  <td>
                    {ev.ml_prediction ? (
                      <div className={`threat-ml ${ev.ml_prediction === 'ATTACK' ? 'attack' : 'benign'}`}>
                        <span>{ev.ml_prediction}</span>
                        <small>{formatConfidence(ev.ml_confidence)}</small>
                      </div>
                    ) : <span className="threat-muted">—</span>}
                  </td>
                  <td>
                    {ev.suricata_alert
                      ? <span className="threat-suricata alert">● ALERT</span>
                      : <span className="threat-suricata">—</span>}
                  </td>
                  <td><ArrowUpRight size={16} className="threat-row-arrow" /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="threat-table-footer">
          <span>AGENTSHIELD · THREAT INTELLIGENCE</span>

          {data && data.pages > 1 && (
            <div className="threat-pagination">
              <button disabled={page === 1} onClick={() => setPage(p => p - 1)}>
                <ChevronLeft size={15} /> Previous
              </button>
              <span>Page <strong>{page}</strong> of <strong>{data.pages}</strong></span>
              <button disabled={page === data.pages} onClick={() => setPage(p => p + 1)}>
                Next <ChevronRight size={15} />
              </button>
            </div>
          )}
        </div>
      </section>
    </div>
  )
}
