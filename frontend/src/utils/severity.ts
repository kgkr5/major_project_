// Utility functions for severity colors and risk display

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NORMAL' | string

export const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#22c55e',
  NORMAL: '#3b82f6',
}

export const SEVERITY_BG: Record<string, string> = {
  CRITICAL: 'bg-red-500/20 text-red-400 border-red-500/30',
  HIGH: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  MEDIUM: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  LOW: 'bg-green-500/20 text-green-400 border-green-500/30',
  NORMAL: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
}

export function getSeverityColor(severity: string): string {
  return SEVERITY_COLORS[severity?.toUpperCase()] ?? '#6b7280'
}

export function getSeverityBg(severity: string): string {
  return SEVERITY_BG[severity?.toUpperCase()] ?? 'bg-gray-500/20 text-gray-400 border-gray-500/30'
}

export function getStatusColor(status: string): string {
  const s = status?.toUpperCase()
  if (s === 'OK' || s === 'RUNNING') return 'text-green-400'
  if (s === 'DEGRADED' || s === 'IDLE') return 'text-yellow-400'
  if (s === 'DOWN' || s === 'ERROR') return 'text-red-400'
  return 'text-gray-400'
}

export function formatConfidence(confidence?: number): string {
  if (confidence === undefined || confidence === null) return 'N/A'
  return `${(confidence * 100).toFixed(1)}%`
}

export function formatTimestamp(ts: string): string {
  try {
    return new Date(ts).toLocaleString()
  } catch {
    return ts
  }
}

export function formatRelativeTime(ts: string): string {
  try {
    const diff = Date.now() - new Date(ts).getTime()
    const seconds = Math.floor(diff / 1000)
    if (seconds < 60) return `${seconds}s ago`
    const minutes = Math.floor(seconds / 60)
    if (minutes < 60) return `${minutes}m ago`
    const hours = Math.floor(minutes / 60)
    if (hours < 24) return `${hours}h ago`
    return `${Math.floor(hours / 24)}d ago`
  } catch {
    return ts
  }
}
