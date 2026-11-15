// Typed API client for AgentShield backend

const BASE_URL = '/api/v1'

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${BASE_URL}${path}`, {
    headers: { 'Content-Type': 'application/json', ...options?.headers },
    ...options,
  })
  if (!response.ok) {
    const error = await response.text()
    throw new Error(`API ${response.status}: ${error}`)
  }
  return response.json()
}

// ── Dashboard ─────────────────────────────────────────────────────────────

export const api = {
  dashboard: {
    stats: () => request('/dashboard/stats'),
    threatTimeline: (hours = 24) => request(`/dashboard/threat-timeline?hours=${hours}`),
    severityDistribution: () => request('/dashboard/severity-distribution'),
    topSources: (limit = 10) => request(`/dashboard/top-sources?limit=${limit}`),
  },

  events: {
    list: (params?: { page?: number; limit?: number; severity?: string; from?: string; to?: string }) => {
      const q = new URLSearchParams()
      if (params?.page) q.set('page', String(params.page))
      if (params?.limit) q.set('limit', String(params.limit))
      if (params?.severity) q.set('severity', params.severity)
      if (params?.from) q.set('from', params.from)
      if (params?.to) q.set('to', params.to)
      return request(`/events?${q}`)
    },
    get: (eventId: string) => request(`/events/${eventId}`),
    investigation: (eventId: string) => request(`/events/${eventId}/investigation`),
    defence: (eventId: string) => request(`/events/${eventId}/defence`),
  },

  agents: {
    status: () => request('/agents/status'),
    detectionEvents: (limit = 20) => request(`/agents/detection/events?limit=${limit}`),
    investigations: (limit = 20) => request(`/agents/analysis/investigations?limit=${limit}`),
    recommendations: (limit = 20) => request(`/agents/defence/recommendations?limit=${limit}`),
    approveRecommendation: (id: string) =>
      request(`/agents/defence/recommendations/${id}/approve`, { method: 'POST' }),
    rejectRecommendation: (id: string) =>
      request(`/agents/defence/recommendations/${id}/reject`, { method: 'POST' }),
  },

  flows: {
    list: (page = 1, limit = 20) => request(`/flows?page=${page}&limit=${limit}`),
    get: (flowId: string) => request(`/flows/${flowId}`),
    uploadStatus: (taskId: string) => request(`/flows/upload/${taskId}/status`),
  },

  health: {
    overall: () => request('/health'),
    suricata: () => request('/health/suricata'),
    model: () => request('/health/model'),
    ollama: () => request('/health/ollama'),
    capture: () => request('/health/capture'),
    database: () => request('/health/database'),
  },

  reports: {
    summary: (params?: { from?: string; to?: string }) => {
      const q = new URLSearchParams()
      if (params?.from) q.set('from', params.from)
      if (params?.to) q.set('to', params.to)
      return request(`/reports/summary?${q}`)
    },
    exportCsv: (params?: { from?: string; to?: string }) => {
      const q = new URLSearchParams({ format: 'csv' })
      if (params?.from) q.set('from', params.from)
      if (params?.to) q.set('to', params.to)
      return `${BASE_URL}/reports/export?${q}`
    },
  },

  settings: {
    get: () => request('/settings'),
  },
}

// Upload PCAP (multipart form)
export async function uploadPcap(file: File): Promise<{ task_id: string; status: string; message: string }> {
  const form = new FormData()
  form.append('file', file)
  const response = await fetch(`${BASE_URL}/flows/upload-pcap`, {
    method: 'POST',
    body: form,
  })
  if (!response.ok) {
    const error = await response.text()
    throw new Error(`Upload failed ${response.status}: ${error}`)
  }
  return response.json()
}
