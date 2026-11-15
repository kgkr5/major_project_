import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Download,
  FileBarChart,
  ShieldAlert,
  Activity,
  BrainCircuit,
  Search,
  Clock,
  RefreshCw,
  Server,
  AlertTriangle,
  CheckCircle2,
  BarChart3,
  FileText,
} from 'lucide-react'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from 'recharts'
import { api } from '../api/client'

const severityColors: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#06b6d4',
}


const cardStyle =
  'bg-bg-secondary border border-border rounded-xl p-5'

const formatNumber = (value: number) =>
  new Intl.NumberFormat('en-US').format(value || 0)

export function Reports() {
  const [days, setDays] = useState(7)

  const fromDt = new Date(Date.now() - days * 86400_000).toISOString()

  const {
    data: summary,
    isLoading,
    isError,
    refetch,
    isFetching,
  } = useQuery({
    queryKey: ['report-summary', days],
    queryFn: () => api.reports.summary({ from: fromDt }),
  })

  const s = summary as any

  const severityData = Object.entries(s?.severity_distribution ?? {}).map(
    ([name, value]) => ({
      name: name.toUpperCase(),
      value: Number(value),
      color: severityColors[name.toUpperCase()] ?? '#64748b',
    }),
  )

  const attackCategories = s?.attack_categories ?? []
  const topSources = s?.top_source_ips ?? []
  const mlStatistics = s?.ml_statistics ?? {}

  const totalEvents = severityData.reduce(
    (total, item) => total + item.value,
    0,
  )

  const totalCategorizedAttacks = attackCategories.reduce(
    (total: number, item: any) => total + Number(item.count || 0),
    0,
  )

  const totalMlPredictions = Object.values(mlStatistics).reduce(
    (total: number, value: any) => total + Number(value || 0),
    0,
  )

  const handleExport = () => {
    const url = api.reports.exportCsv({ from: fromDt })
    window.open(url, '_blank')
  }

  const periodLabel =
    days === 1 ? 'Last 24 hours' : `Last ${days} days`

  return (
    <div className="min-h-full p-5 md:p-7 space-y-6">

      {/* PAGE HEADER */}
      <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-5">
        <div>
          <div className="flex items-center gap-2 text-accent-cyan text-xs font-semibold uppercase tracking-widest mb-2">
            <FileBarChart size={15} />
            Security Intelligence
          </div>

          <h1 className="text-2xl md:text-3xl font-bold text-text-primary">
            Security Reports
          </h1>

          <p className="text-sm text-text-muted mt-2">
            Security activity, threat intelligence and detection analytics.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <select
            value={days}
            onChange={(e) => setDays(Number(e.target.value))}
            className="bg-bg-secondary border border-border rounded-lg px-4 py-2.5 text-sm text-text-primary outline-none focus:border-accent-cyan"
          >
            <option value={1}>Last 24 hours</option>
            <option value={7}>Last 7 days</option>
            <option value={30}>Last 30 days</option>
          </select>

          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg border border-border text-text-secondary hover:text-text-primary hover:border-accent-cyan/50 transition-colors text-sm"
          >
            <RefreshCw
              size={15}
              className={isFetching ? 'animate-spin' : ''}
            />
            Refresh
          </button>

          <button
            onClick={handleExport}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-accent-cyan text-slate-950 font-semibold hover:opacity-90 transition-opacity text-sm"
          >
            <Download size={16} />
            Export CSV
          </button>
        </div>
      </div>

      {/* REPORT PERIOD */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-accent-cyan/20 bg-accent-cyan/5 px-4 py-3">
        <div className="flex items-center gap-2 text-sm text-text-secondary">
          <Clock size={15} className="text-accent-cyan" />
          <span>Selected reporting period:</span>
          <span className="font-semibold text-accent-cyan">{periodLabel}</span>
        </div>

        <span className="text-xs text-text-muted">
          {s?.period?.from
            ? new Date(s.period.from).toLocaleString()
            : 'Waiting for report data'}
        </span>
      </div>

      {/* LOADING */}
      {isLoading && (
        <div className={`${cardStyle} flex items-center justify-center py-16`}>
          <RefreshCw size={20} className="animate-spin text-accent-cyan mr-3" />
          <span className="text-sm text-text-secondary">
            Generating security report...
          </span>
        </div>
      )}

      {/* ERROR */}
      {isError && (
        <div className={`${cardStyle} text-center py-12`}>
          <AlertTriangle size={30} className="text-red-400 mx-auto mb-3" />
          <h3 className="text-text-primary font-semibold">
            Unable to load reports
          </h3>
          <p className="text-text-muted text-sm mt-2">
            The report API could not be reached. Check the backend connection.
          </p>
          <button
            onClick={() => refetch()}
            className="mt-4 px-4 py-2 rounded-lg bg-accent-cyan/10 text-accent-cyan text-sm"
          >
            Try again
          </button>
        </div>
      )}

      {/* REPORT CONTENT */}
      {!isLoading && !isError && s && (
        <>
          {/* KPI CARDS */}
          <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">

            <div className={cardStyle}>
              <div className="flex items-center justify-between">
                <div className="p-2.5 rounded-lg bg-accent-cyan/10">
                  <Activity size={20} className="text-accent-cyan" />
                </div>
                <span className="text-xs text-text-muted uppercase tracking-wider">
                  Events
                </span>
              </div>
              <p className="text-3xl font-bold font-mono text-text-primary mt-5">
                {formatNumber(totalEvents)}
              </p>
              <p className="text-sm text-text-muted mt-1">
                Security events in selected period
              </p>
            </div>

            <div className={cardStyle}>
              <div className="flex items-center justify-between">
                <div className="p-2.5 rounded-lg bg-red-500/10">
                  <ShieldAlert size={20} className="text-red-400" />
                </div>
                <span className="text-xs text-text-muted uppercase tracking-wider">
                  Categories
                </span>
              </div>
              <p className="text-3xl font-bold font-mono text-text-primary mt-5">
                {formatNumber(totalCategorizedAttacks)}
              </p>
              <p className="text-sm text-text-muted mt-1">
                Events with attack categories
              </p>
            </div>

            <div className={cardStyle}>
              <div className="flex items-center justify-between">
                <div className="p-2.5 rounded-lg bg-purple-500/10">
                  <BrainCircuit size={20} className="text-purple-400" />
                </div>
                <span className="text-xs text-text-muted uppercase tracking-wider">
                  ML Analysis
                </span>
              </div>
              <p className="text-3xl font-bold font-mono text-text-primary mt-5">
                {formatNumber(totalMlPredictions)}
              </p>
              <p className="text-sm text-text-muted mt-1">
                Recorded ML predictions (all time)
              </p>
            </div>

            <div className={cardStyle}>
              <div className="flex items-center justify-between">
                <div className="p-2.5 rounded-lg bg-green-500/10">
                  <Search size={20} className="text-green-400" />
                </div>
                <span className="text-xs text-text-muted uppercase tracking-wider">
                  Investigations
                </span>
              </div>
              <p className="text-3xl font-bold font-mono text-text-primary mt-5">
                {formatNumber(s.total_investigations ?? 0)}
              </p>
              <p className="text-sm text-text-muted mt-1">
                Total recorded investigations
              </p>
            </div>
          </div>

          {/* CHARTS */}
          <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">

            {/* ATTACK CATEGORIES */}
            <div className={`${cardStyle} xl:col-span-2`}>
              <div className="flex items-center justify-between mb-5">
                <div>
                  <div className="flex items-center gap-2">
                    <BarChart3 size={18} className="text-accent-cyan" />
                    <h2 className="font-semibold text-text-primary">
                      Attack Categories
                    </h2>
                  </div>
                  <p className="text-xs text-text-muted mt-1">
                    Most frequently recorded attack categories
                  </p>
                </div>
                <span className="text-xs text-text-muted">
                  Top 10
                </span>
              </div>

              {attackCategories.length > 0 ? (
                <ResponsiveContainer width="100%" height={280}>
                  <BarChart
                    data={attackCategories}
                    layout="vertical"
                    margin={{ top: 5, right: 20, bottom: 5, left: 15 }}
                  >
                    <CartesianGrid
                      strokeDasharray="3 3"
                      stroke="#263244"
                      horizontal={false}
                    />
                    <XAxis
                      type="number"
                      allowDecimals={false}
                      tick={{ fill: '#94a3b8', fontSize: 11 }}
                      axisLine={false}
                      tickLine={false}
                    />
                    <YAxis
                      type="category"
                      dataKey="category"
                      width={115}
                      tick={{ fill: '#cbd5e1', fontSize: 11 }}
                      axisLine={false}
                      tickLine={false}
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#111827',
                        border: '1px solid #334155',
                        borderRadius: '8px',
                        color: '#fff',
                      }}
                    />
                    <Bar
                      dataKey="count"
                      name="Events"
                      fill="#06b6d4"
                      radius={[0, 5, 5, 0]}
                      barSize={18}
                    />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-[280px] flex flex-col items-center justify-center text-text-muted">
                  <BarChart3 size={30} className="mb-3 opacity-40" />
                  <p className="text-sm">No attack categories recorded.</p>
                </div>
              )}
            </div>

            {/* SEVERITY DISTRIBUTION */}
            <div className={cardStyle}>
              <div className="flex items-center gap-2 mb-1">
                <ShieldAlert size={18} className="text-red-400" />
                <h2 className="font-semibold text-text-primary">
                  Severity Distribution
                </h2>
              </div>
              <p className="text-xs text-text-muted">
                Event severity breakdown
              </p>

              {severityData.length > 0 ? (
                <>
                  <div className="relative h-[210px] mt-3">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={severityData}
                          dataKey="value"
                          nameKey="name"
                          cx="50%"
                          cy="50%"
                          innerRadius={58}
                          outerRadius={85}
                          paddingAngle={3}
                          stroke="none"
                        >
                          {severityData.map((entry: any) => (
                            <Cell
                              key={entry.name}
                              fill={entry.color}
                            />
                          ))}
                        </Pie>
                        <Tooltip
                          contentStyle={{
                            backgroundColor: '#111827',
                            border: '1px solid #334155',
                            borderRadius: '8px',
                          }}
                        />
                      </PieChart>
                    </ResponsiveContainer>

                    <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                      <span className="text-2xl font-bold font-mono text-text-primary">
                        {formatNumber(totalEvents)}
                      </span>
                      <span className="text-[10px] text-text-muted uppercase">
                        Total Events
                      </span>
                    </div>
                  </div>

                  <div className="space-y-3 mt-2">
                    {severityData.map((item: any) => (
                      <div
                        key={item.name}
                        className="flex items-center justify-between"
                      >
                        <div className="flex items-center gap-2">
                          <span
                            className="w-2.5 h-2.5 rounded-full"
                            style={{ backgroundColor: item.color }}
                          />
                          <span className="text-xs text-text-secondary">
                            {item.name}
                          </span>
                        </div>
                        <span className="text-xs font-mono font-semibold text-text-primary">
                          {formatNumber(item.value)}
                        </span>
                      </div>
                    ))}
                  </div>
                </>
              ) : (
                <div className="h-[250px] flex items-center justify-center text-sm text-text-muted">
                  No severity data available.
                </div>
              )}
            </div>
          </div>

          {/* SOURCE IP AND ML STATISTICS */}
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">

            {/* TOP SOURCE IPS */}
            <div className={cardStyle}>
              <div className="flex items-center justify-between mb-5">
                <div>
                  <div className="flex items-center gap-2">
                    <Server size={18} className="text-accent-cyan" />
                    <h2 className="font-semibold text-text-primary">
                      Top Source IP Addresses
                    </h2>
                  </div>
                  <p className="text-xs text-text-muted mt-1">
                    Sources associated with recorded security events
                  </p>
                </div>
                <span className="text-xs text-text-muted">Top 10</span>
              </div>

              {topSources.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-border text-text-muted">
                        <th className="text-left py-3 font-medium">#</th>
                        <th className="text-left py-3 font-medium">IP Address</th>
                        <th className="text-right py-3 font-medium">Events</th>
                      </tr>
                    </thead>
                    <tbody>
                      {topSources.map((row: any, index: number) => (
                        <tr
                          key={`${row.ip}-${index}`}
                          className="border-b border-border/50 last:border-0 hover:bg-white/[0.02]"
                        >
                          <td className="py-3 text-text-muted text-xs">
                            {String(index + 1).padStart(2, '0')}
                          </td>
                          <td className="py-3 font-mono text-xs text-accent-cyan">
                            {row.ip ?? 'Unknown'}
                          </td>
                          <td className="py-3 text-right">
                            <span className="font-mono font-semibold text-text-primary">
                              {formatNumber(row.count)}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="py-12 text-center text-sm text-text-muted">
                  No source IP records available.
                </div>
              )}
            </div>

            {/* ML STATISTICS */}
            <div className={cardStyle}>
              <div className="flex items-center gap-2 mb-1">
                <BrainCircuit size={18} className="text-purple-400" />
                <h2 className="font-semibold text-text-primary">
                  ML Detection Statistics
                </h2>
              </div>
              <p className="text-xs text-text-muted mb-5">
                Recorded model predictions across all available records
              </p>

              {Object.keys(mlStatistics).length > 0 ? (
                <div className="space-y-4">
                  {Object.entries(mlStatistics).map(([label, count]: [string, any]) => {
                    const value = Number(count || 0)
                    const percentage =
                      totalMlPredictions > 0
                        ? (value / totalMlPredictions) * 100
                        : 0

                    const isAttack = label.toUpperCase() === 'ATTACK'

                    return (
                      <div key={label}>
                        <div className="flex justify-between items-center mb-2">
                          <div className="flex items-center gap-2">
                            {isAttack ? (
                              <AlertTriangle size={15} className="text-red-400" />
                            ) : (
                              <CheckCircle2 size={15} className="text-green-400" />
                            )}
                            <span className="text-sm text-text-secondary">
                              {label}
                            </span>
                          </div>
                          <span className="font-mono text-sm font-semibold text-text-primary">
                            {formatNumber(value)}
                          </span>
                        </div>

                        <div className="h-2 rounded-full bg-bg-primary overflow-hidden">
                          <div
                            className={`h-full rounded-full ${
                              isAttack ? 'bg-red-400' : 'bg-green-400'
                            }`}
                            style={{ width: `${percentage}%` }}
                          />
                        </div>

                        <p className="text-right text-[10px] text-text-muted mt-1">
                          {percentage.toFixed(1)}%
                        </p>
                      </div>
                    )
                  })}
                </div>
              ) : (
                <div className="py-12 text-center text-sm text-text-muted">
                  No ML prediction records available.
                </div>
              )}
            </div>
          </div>

          {/* REPORT INFORMATION */}
          <div className={`${cardStyle} flex flex-col md:flex-row md:items-center justify-between gap-4`}>
            <div className="flex items-start gap-3">
              <div className="p-2.5 rounded-lg bg-accent-cyan/10">
                <FileText size={20} className="text-accent-cyan" />
              </div>
              <div>
                <h3 className="text-sm font-semibold text-text-primary">
                  Report Information
                </h3>
                <p className="text-xs text-text-muted mt-1">
                  Generated security analytics summary
                </p>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
              <div>
                <p className="text-text-muted mb-1">Reporting period</p>
                <p className="text-text-secondary">
                  {s.period?.from
                    ? new Date(s.period.from).toLocaleDateString()
                    : 'N/A'}
                  {' – '}
                  {s.period?.to
                    ? new Date(s.period.to).toLocaleDateString()
                    : 'N/A'}
                </p>
              </div>

              <div>
                <p className="text-text-muted mb-1">Generated at</p>
                <p className="text-text-secondary">
                  {s.generated_at
                    ? new Date(s.generated_at).toLocaleString()
                    : 'N/A'}
                </p>
              </div>
            </div>
          </div>
        </>
      )}

      {!isLoading && !isError && !s && (
        <div className={`${cardStyle} text-center py-16`}>
          <FileBarChart size={32} className="mx-auto text-text-muted mb-3" />
          <p className="text-text-primary font-semibold">
            No report data available
          </p>
          <p className="text-text-muted text-sm mt-2">
            Security report data will appear here when available.
          </p>
        </div>
      )}
    </div>
  )
}
