import { useQuery } from '@tanstack/react-query'
import {
  Activity,
  Database,
  BrainCircuit,
  Radio,
  Server,
  ShieldCheck,
  ShieldAlert,
  Settings as SettingsIcon,
  Clock,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Cpu,
  FileText,
  Gauge,
  Info,
} from 'lucide-react'
import { api } from '../api/client'
import { StatusIndicator } from '../components/common/StatusIndicator'
import type { SystemHealth } from '../types'

const componentIcons: Record<string, any> = {
  database: Database,
  ml_model: BrainCircuit,
  ollama: Cpu,
  suricata: ShieldCheck,
  capture: Radio,
}

const componentDescriptions: Record<string, string> = {
  database: 'Checks database connectivity and availability.',
  ml_model: 'Checks whether the machine-learning detection model is available.',
  ollama: 'Checks the local LLM service used for investigation explanations.',
  suricata: 'Checks the intrusion detection integration.',
  capture: 'Checks the network packet capture sensor.',
}

const componentNames: Record<string, string> = {
  database: 'Database',
  ml_model: 'ML Detection Model',
  ollama: 'Ollama LLM',
  suricata: 'Suricata IDS',
  capture: 'Network Capture',
}

const getStatusColor = (status?: string) => {
  switch (status?.toUpperCase()) {
    case 'OK':
      return 'text-green-400 bg-green-500/10 border-green-500/20'
    case 'DOWN':
    case 'ERROR':
      return 'text-red-400 bg-red-500/10 border-red-500/20'
    case 'DEGRADED':
    case 'WARNING':
      return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20'
    default:
      return 'text-slate-400 bg-slate-500/10 border-slate-500/20'
  }
}

const formatValue = (value: unknown): string => {
  if (value === null || value === undefined || value === '') {
    return 'Not configured'
  }

  if (typeof value === 'object') {
    return JSON.stringify(value, null, 2)
  }

  return String(value)
}

const cardStyle =
  'bg-bg-secondary border border-border rounded-xl p-5'

export function Settings() {
  const {
    data: health,
    isLoading,
    isError,
    refetch,
    isFetching,
  } = useQuery<SystemHealth>({
    queryKey: ['health'],
    queryFn: () => api.health.overall() as Promise<SystemHealth>,
    refetchInterval: 10_000,
  })

  const {
    data: settings,
    isLoading: settingsLoading,
    isError: settingsError,
  } = useQuery<Record<string, unknown>>({
    queryKey: ['settings'],
    queryFn: async () =>
      (await api.settings.get()) as Record<string, unknown>,
  })

  const components = health?.components ?? {}

  const componentEntries = Object.entries(components)

  const healthyCount = componentEntries.filter(
    ([, component]) => component.status?.toUpperCase() === 'OK',
  ).length

  const downCount = componentEntries.filter(
    ([, component]) => component.status?.toUpperCase() === 'DOWN',
  ).length

  const overallStatus = health?.overall ?? 'UNKNOWN'

  const riskThresholds =
    settings?.risk_thresholds as Record<string, unknown> | undefined

  const thresholdColors: Record<string, string> = {
    critical: 'bg-red-500',
    high: 'bg-orange-500',
    medium: 'bg-yellow-500',
    low: 'bg-cyan-500',
  }

  const lastChecked = health?.checked_at
    ? new Date(health.checked_at).toLocaleString()
    : 'Waiting for health check'

  return (
    <div className="min-h-full p-5 md:p-7 space-y-6">

      {/* HEADER */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-accent-cyan text-xs font-semibold uppercase tracking-widest mb-2">
            <SettingsIcon size={15} />
            System Administration
          </div>

          <h1 className="text-2xl md:text-3xl font-bold text-text-primary">
            Settings & System Health
          </h1>

          <p className="text-sm text-text-muted mt-2">
            Monitor AgentShield services, system configuration and security status.
          </p>
        </div>

        <button
          onClick={() => refetch()}
          disabled={isFetching}
          className="flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg border border-border text-text-secondary hover:text-text-primary hover:border-accent-cyan/50 transition-colors text-sm"
        >
          <RefreshCw
            size={15}
            className={isFetching ? 'animate-spin' : ''}
          />
          Refresh Health
        </button>
      </div>

      {/* OVERALL SYSTEM STATUS */}
      <div className={`${cardStyle} relative overflow-hidden`}>
        <div className="absolute top-0 right-0 w-48 h-48 bg-accent-cyan/[0.04] rounded-full blur-3xl pointer-events-none" />

        <div className="relative flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="flex items-center gap-4">
            <div className={`p-4 rounded-xl border ${
              overallStatus === 'OK'
                ? 'bg-green-500/10 border-green-500/20'
                : 'bg-yellow-500/10 border-yellow-500/20'
            }`}>
              {overallStatus === 'OK' ? (
                <ShieldCheck size={30} className="text-green-400" />
              ) : (
                <ShieldAlert size={30} className="text-yellow-400" />
              )}
            </div>

            <div>
              <p className="text-xs text-text-muted uppercase tracking-widest">
                Overall System Health
              </p>

              <h2 className={`text-2xl font-bold mt-1 ${
                overallStatus === 'OK'
                  ? 'text-green-400'
                  : 'text-yellow-400'
              }`}>
                {isLoading ? 'Checking...' : overallStatus}
              </h2>

              <p className="text-xs text-text-muted mt-1">
                {overallStatus === 'OK'
                  ? 'All monitored components are operational.'
                  : 'One or more components need attention.'}
              </p>
            </div>
          </div>

          <div className="grid grid-cols-3 gap-3">
            <div className="rounded-lg bg-bg-primary border border-border px-5 py-3 text-center">
              <p className="text-2xl font-bold font-mono text-text-primary">
                {componentEntries.length}
              </p>
              <p className="text-[10px] text-text-muted uppercase mt-1">
                Components
              </p>
            </div>

            <div className="rounded-lg bg-bg-primary border border-border px-5 py-3 text-center">
              <p className="text-2xl font-bold font-mono text-green-400">
                {healthyCount}
              </p>
              <p className="text-[10px] text-text-muted uppercase mt-1">
                Healthy
              </p>
            </div>

            <div className="rounded-lg bg-bg-primary border border-border px-5 py-3 text-center">
              <p className="text-2xl font-bold font-mono text-red-400">
                {downCount}
              </p>
              <p className="text-[10px] text-text-muted uppercase mt-1">
                Down
              </p>
            </div>
          </div>
        </div>

        <div className="relative flex flex-wrap items-center justify-between gap-3 border-t border-border mt-5 pt-4">
          <div className="flex items-center gap-2 text-xs text-text-muted">
            <Clock size={14} className="text-accent-cyan" />
            Last health check: {lastChecked}
          </div>

          <span className="text-xs text-text-muted">
            Automatic refresh every 10 seconds
          </span>
        </div>
      </div>

      {/* HEALTH ERROR */}
      {isError && (
        <div className="rounded-xl border border-red-500/30 bg-red-500/5 p-4 flex items-start gap-3">
          <XCircle size={20} className="text-red-400 mt-0.5" />
          <div>
            <p className="text-sm font-semibold text-red-400">
              Health check failed
            </p>
            <p className="text-xs text-text-muted mt-1">
              Unable to retrieve component health information from the backend.
              Check the API connection and try refreshing.
            </p>
          </div>
        </div>
      )}

      {/* COMPONENT HEALTH */}
      <section>
        <div className="flex items-center justify-between mb-4">
          <div>
            <div className="flex items-center gap-2">
              <Activity size={18} className="text-accent-cyan" />
              <h2 className="font-semibold text-text-primary">
                Component Health
              </h2>
            </div>
            <p className="text-xs text-text-muted mt-1">
              Live status of monitored AgentShield services
            </p>
          </div>

          <span className="text-xs text-text-muted">
            {componentEntries.length} monitored services
          </span>
        </div>

        {isLoading ? (
          <div className={`${cardStyle} flex items-center justify-center py-12`}>
            <RefreshCw size={19} className="animate-spin text-accent-cyan mr-3" />
            <span className="text-sm text-text-secondary">
              Checking system components...
            </span>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {componentEntries.map(([key, component]) => {
              const Icon = componentIcons[key] ?? Server

              return (
                <div
                  key={key}
                  className={`${cardStyle} hover:border-accent-cyan/30 transition-colors`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-center gap-3">
                      <div className="p-2.5 rounded-lg bg-accent-cyan/10">
                        <Icon size={20} className="text-accent-cyan" />
                      </div>

                      <div>
                        <h3 className="text-sm font-semibold text-text-primary">
                          {componentNames[key] ?? key.replace(/_/g, ' ')}
                        </h3>
                        <p className="text-[11px] text-text-muted mt-1">
                          {componentDescriptions[key] ?? 'System component health check.'}
                        </p>
                      </div>
                    </div>

                    <span className={`text-[10px] font-semibold uppercase tracking-wider px-2 py-1 rounded-md border ${getStatusColor(component.status)}`}>
                      {component.status}
                    </span>
                  </div>

                  <div className="mt-5 pt-4 border-t border-border">
                    <StatusIndicator
                      status={component.status}
                      label={component.message || component.status}
                    />

                    <p className="text-[10px] text-text-muted mt-3">
                      Checked: {component.checked_at
                        ? new Date(component.checked_at).toLocaleTimeString()
                        : 'Not available'}
                    </p>

                    {component.details && (
                      <details className="mt-3">
                        <summary className="text-xs text-accent-cyan cursor-pointer hover:text-text-primary">
                          View technical details
                        </summary>

                        <pre className="text-[10px] text-text-muted mt-2 p-3 rounded-lg bg-bg-primary border border-border overflow-auto max-h-36 whitespace-pre-wrap break-words">
                          {JSON.stringify(component.details, null, 2)}
                        </pre>
                      </details>
                    )}
                  </div>
                </div>
              )
            })}

            {!componentEntries.length && !isError && (
              <div className={`${cardStyle} md:col-span-2 xl:col-span-3 text-center py-10`}>
                <Info size={25} className="mx-auto text-text-muted mb-2" />
                <p className="text-sm text-text-muted">
                  No component health information available.
                </p>
              </div>
            )}
          </div>
        )}
      </section>

      {/* CONFIGURATION */}
      <section>
        <div className="flex items-center gap-2 mb-4">
          <SettingsIcon size={18} className="text-accent-cyan" />
          <div>
            <h2 className="font-semibold text-text-primary">
              System Configuration
            </h2>
            <p className="text-xs text-text-muted mt-1">
              Current non-sensitive application configuration
            </p>
          </div>
        </div>

        {settingsLoading ? (
          <div className={cardStyle}>
            <p className="text-sm text-text-muted">
              Loading configuration...
            </p>
          </div>
        ) : settingsError ? (
          <div className={`${cardStyle} text-sm text-red-400`}>
            Unable to retrieve system configuration.
          </div>
        ) : settings ? (
          <div className={`${cardStyle} space-y-5`}>
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
              {Object.entries(settings)
                .filter(([key]) => key !== 'risk_thresholds')
                .map(([key, value]) => (
                  <div
                    key={key}
                    className="rounded-lg bg-bg-primary border border-border p-4 min-w-0"
                  >
                    <p className="text-[10px] text-text-muted uppercase tracking-widest mb-2">
                      {key.replace(/_/g, ' ')}
                    </p>

                    <p className="text-sm text-text-primary font-mono break-all">
                      {formatValue(value)}
                    </p>
                  </div>
                ))}
            </div>

            {/* RISK THRESHOLDS */}
            {riskThresholds && (
              <div className="border-t border-border pt-5">
                <div className="flex items-center gap-2 mb-4">
                  <Gauge size={18} className="text-accent-cyan" />
                  <h3 className="text-sm font-semibold text-text-primary">
                    Risk Threshold Configuration
                  </h3>
                </div>

                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  {Object.entries(riskThresholds).map(([key, value]) => (
                    <div
                      key={key}
                      className="rounded-lg bg-bg-primary border border-border p-4"
                    >
                      <div className="flex items-center gap-2 mb-3">
                        <span className={`w-2.5 h-2.5 rounded-full ${thresholdColors[key] ?? 'bg-slate-400'}`} />
                        <span className="text-xs text-text-muted uppercase">
                          {key}
                        </span>
                      </div>

                      <p className="text-2xl font-bold font-mono text-text-primary">
                        {formatValue(value)}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : (
          <div className={cardStyle}>
            <p className="text-sm text-text-muted">
              No configuration information available.
            </p>
          </div>
        )}
      </section>

      {/* SECURITY INFORMATION */}
      <section className="rounded-xl border border-yellow-500/30 bg-yellow-500/[0.04] p-5">
        <div className="flex items-center gap-2 mb-4">
          <AlertTriangle size={19} className="text-yellow-400" />
          <h2 className="font-semibold text-yellow-400">
            Security Information & Known Limitations
          </h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="flex items-start gap-3">
            <Info size={16} className="text-yellow-400 mt-0.5 shrink-0" />
            <p className="text-xs text-text-secondary leading-relaxed">
              WSL2 packet capture monitors supported WSL2 network interfaces.
              It does not automatically capture all Windows host traffic.
            </p>
          </div>

          <div className="flex items-start gap-3">
            <Info size={16} className="text-yellow-400 mt-0.5 shrink-0" />
            <p className="text-xs text-text-secondary leading-relaxed">
              The ML classifier uses binary BENIGN and ATTACK predictions.
              Attack sub-types are identified using additional rule-based logic.
            </p>
          </div>

          <div className="flex items-start gap-3">
            <Info size={16} className="text-yellow-400 mt-0.5 shrink-0" />
            <p className="text-xs text-text-secondary leading-relaxed">
              Ollama-generated explanations are advisory information and must
              not be treated as independently verified security evidence.
            </p>
          </div>

          <div className="flex items-start gap-3">
            <ShieldCheck size={16} className="text-yellow-400 mt-0.5 shrink-0" />
            <p className="text-xs text-text-secondary leading-relaxed">
              Defensive recommendations require administrator approval.
              The system does not automatically execute firewall or network changes.
            </p>
          </div>

          <div className="flex items-start gap-3">
            <CheckCircle2 size={16} className="text-green-400 mt-0.5 shrink-0" />
            <p className="text-xs text-text-secondary leading-relaxed">
              AgentShield is designed for defensive security monitoring,
              investigation and response recommendations.
            </p>
          </div>

          <div className="flex items-start gap-3">
            <FileText size={16} className="text-yellow-400 mt-0.5 shrink-0" />
            <p className="text-xs text-text-secondary leading-relaxed">
              Component availability depends on the local environment,
              installed services and configured permissions.
            </p>
          </div>
        </div>
      </section>

      {/* FOOTER */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-2 border-t border-border pt-4">
        <div className="flex items-center gap-2 text-xs text-text-muted">
          <ShieldCheck size={14} className="text-accent-cyan" />
          AgentShield Security Framework
        </div>

        <span className="text-xs text-text-muted">
          System health automatically monitored every 10 seconds
        </span>
      </div>
    </div>
  )
}
