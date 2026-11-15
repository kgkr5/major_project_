import { getSeverityBg } from '../../utils/severity'

interface Props {
  severity?: string
  size?: 'sm' | 'md'
}

export function SeverityBadge({ severity = 'NORMAL', size = 'md' }: Props) {
  const cls = getSeverityBg(severity)
  const sizeClass = size === 'sm' ? 'text-xs px-1.5 py-0.5' : 'text-xs px-2 py-1'
  return (
    <span className={`inline-flex items-center rounded border font-mono font-medium ${sizeClass} ${cls}`}>
      {severity}
    </span>
  )
}
