import type { LucideIcon } from 'lucide-react'

interface Props {
  title: string
  value: number | string
  icon: LucideIcon
  color?: string
  subtitle?: string
}

export function StatCard({ title, value, icon: Icon, color = '#06b6d4', subtitle }: Props) {
  return (
    <div className="bg-bg-secondary border border-border rounded-lg p-4 flex items-start gap-4">
      <div className="p-2 rounded-lg" style={{ backgroundColor: `${color}20` }}>
        <Icon size={20} style={{ color }} />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-text-muted text-xs uppercase tracking-wide">{title}</p>
        <p className="text-2xl font-mono font-bold text-text-primary mt-0.5">{value}</p>
        {subtitle && <p className="text-xs text-text-muted mt-0.5">{subtitle}</p>}
      </div>
    </div>
  )
}
