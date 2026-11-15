import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, Legend
} from 'recharts'
import type { ThreatTimelinePoint } from '../../types'

interface Props {
  data: ThreatTimelinePoint[]
}

export function ThreatTimeline({ data }: Props) {
  if (!data || data.length === 0) {
    return (
      <div className="h-48 flex items-center justify-center text-text-muted text-sm">
        No timeline data available
      </div>
    )
  }

  const formatted = data.map((d) => ({
    ...d,
    time: d.timestamp.includes('T') ? d.timestamp.split('T')[1]?.slice(0, 5) : d.timestamp,
  }))

  return (
    <ResponsiveContainer width="100%" height={200}>
      <AreaChart data={formatted} margin={{ top: 10, right: 10, left: -10, bottom: 0 }}>
        <defs>
          <linearGradient id="attackGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
            <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
          </linearGradient>
          <linearGradient id="benignGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#22c55e" stopOpacity={0.2} />
            <stop offset="95%" stopColor="#22c55e" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
        <XAxis dataKey="time" tick={{ fill: '#6b7280', fontSize: 11 }} />
        <YAxis tick={{ fill: '#6b7280', fontSize: 11 }} />
        <Tooltip
          contentStyle={{ backgroundColor: '#111827', border: '1px solid #1f2937', borderRadius: 6 }}
          labelStyle={{ color: '#d1d5db' }}
        />
        <Legend wrapperStyle={{ fontSize: 12, color: '#9ca3af' }} />
        <Area type="monotone" dataKey="attacks" stroke="#ef4444" fill="url(#attackGrad)" name="Attacks" />
        <Area type="monotone" dataKey="benign" stroke="#22c55e" fill="url(#benignGrad)" name="Benign" />
      </AreaChart>
    </ResponsiveContainer>
  )
}
