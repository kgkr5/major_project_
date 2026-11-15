// Global Zustand store for AgentShield live data

import { create } from 'zustand'
import type { SecurityEvent, DashboardStats, InvestigationResult, DefenceRecommendation } from '../types'

interface AgentShieldStore {
  // Live events feed
  liveEvents: SecurityEvent[]
  addLiveEvent: (event: SecurityEvent) => void

  // Stats
  stats: DashboardStats | null
  setStats: (stats: DashboardStats) => void

  // Investigations
  latestInvestigation: InvestigationResult | null
  setLatestInvestigation: (inv: InvestigationResult) => void

  // Recommendations
  latestRecommendation: DefenceRecommendation | null
  setLatestRecommendation: (rec: DefenceRecommendation) => void

  // WebSocket connection status
  wsConnected: boolean
  setWsConnected: (connected: boolean) => void
}

export const useStore = create<AgentShieldStore>((set) => ({
  liveEvents: [],
  addLiveEvent: (event) =>
    set((state) => ({
      liveEvents: [event, ...state.liveEvents].slice(0, 100), // keep last 100
    })),

  stats: null,
  setStats: (stats) => set({ stats }),

  latestInvestigation: null,
  setLatestInvestigation: (inv) => set({ latestInvestigation: inv }),

  latestRecommendation: null,
  setLatestRecommendation: (rec) => set({ latestRecommendation: rec }),

  wsConnected: false,
  setWsConnected: (connected) => set({ wsConnected: connected }),
}))
