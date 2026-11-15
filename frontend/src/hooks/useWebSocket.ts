// WebSocket hook for real-time AgentShield events

import { useEffect, useRef, useCallback } from 'react'
import type { WSMessage } from '../types'

const WS_URL = `ws://${window.location.hostname}:8000/ws/events`

type MessageHandler = (msg: WSMessage) => void

export function useWebSocket(onMessage: MessageHandler) {
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimeout = useRef<ReturnType<typeof setTimeout> | null>(null)
  const handlerRef = useRef(onMessage)
  handlerRef.current = onMessage

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return

    const ws = new WebSocket(WS_URL)
    wsRef.current = ws

    ws.onopen = () => {
      console.log('[AgentShield] WebSocket connected')
    }

    ws.onmessage = (event) => {
      try {
        const msg: WSMessage = JSON.parse(event.data)
        handlerRef.current(msg)
      } catch {
        // ignore parse errors
      }
    }

    ws.onclose = () => {
      console.log('[AgentShield] WebSocket disconnected. Reconnecting in 3s...')
      reconnectTimeout.current = setTimeout(connect, 3000)
    }

    ws.onerror = (err) => {
      console.warn('[AgentShield] WebSocket error:', err)
      ws.close()
    }
  }, [])

  useEffect(() => {
    connect()
    return () => {
      if (reconnectTimeout.current) clearTimeout(reconnectTimeout.current)
      wsRef.current?.close()
    }
  }, [connect])

  const sendPing = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send('ping')
    }
  }, [])

  return { sendPing }
}
