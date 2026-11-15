
interface Props {
  status: 'OK' | 'DEGRADED' | 'DOWN' | 'UNKNOWN' | string
  label: string
  detail?: string
}

const STATUS_DOT: Record<string, string> = {
  OK: 'bg-green-400',
  RUNNING: 'bg-green-400',
  DEGRADED: 'bg-yellow-400',
  IDLE: 'bg-yellow-400',
  DOWN: 'bg-red-400',
  ERROR: 'bg-red-400',
  UNKNOWN: 'bg-gray-400',
  UNAVAILABLE: 'bg-red-400',
}

export function StatusIndicator({ status, label, detail }: Props) {
  const dotClass = STATUS_DOT[status?.toUpperCase()] ?? 'bg-gray-400'
  return (
    <div className="flex items-center gap-2">
      <span className={`w-2 h-2 rounded-full ${dotClass} animate-pulse`} />
      <span className="text-sm text-text-secondary">{label}</span>
      {detail && <span className="text-xs text-text-muted">({detail})</span>}
    </div>
  )
}
