import { useStore } from '../../store/useStore'
import { Wifi, WifiOff } from 'lucide-react'

interface Props {
  title: string
}

export function Header({ title }: Props) {
  const wsConnected = useStore((s) => s.wsConnected)
  const now = new Date().toLocaleString()

  return (
    <header className="h-14 bg-bg-secondary border-b border-border flex items-center justify-between px-6 shrink-0">
      <h1 className="text-text-primary font-semibold text-base">{title}</h1>
      <div className="flex items-center gap-4">
        <span className="text-text-muted text-xs font-mono">{now}</span>
        <div className="flex items-center gap-1.5">
          {wsConnected ? (
            <>
              <Wifi size={14} className="text-green-400" />
              <span className="text-xs text-green-400">Live</span>
            </>
          ) : (
            <>
              <WifiOff size={14} className="text-red-400" />
              <span className="text-xs text-red-400">Disconnected</span>
            </>
          )}
        </div>
      </div>
    </header>
  )
}
