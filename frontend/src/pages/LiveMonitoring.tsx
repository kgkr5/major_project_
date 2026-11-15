import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Activity, Upload, Network, Radio, Search,
  RefreshCw, FileUp, ShieldCheck, Clock3,
  ArrowDownToLine, Wifi
} from 'lucide-react'
import { api, uploadPcap } from '../api/client'
import type { NetworkFlow } from '../types'
import { useStore } from '../store/useStore'

export function LiveMonitoring() {
  const [uploadStatus, setUploadStatus] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [protocolFilter, setProtocolFilter] = useState('ALL')
  const [isUploading, setIsUploading] = useState(false)

  const liveEvents = useStore((s) => s.liveEvents)
  const wsConnected = useStore((s) => s.wsConnected)

  const { data, isFetching, refetch } = useQuery<{
    items: NetworkFlow[]
    total: number
  }>({
    queryKey: ['flows'],
    queryFn: () => api.flows.list(1, 30) as Promise<{
      items: NetworkFlow[]
      total: number
    }>,
    refetchInterval: 10000,
  })

  const flows = data?.items ?? []

  const protocols = useMemo(
    () => [...new Set(flows.map((f) => f.protocol).filter(Boolean))],
    [flows]
  )

  const filteredFlows = useMemo(() => {
    return flows.filter((flow) => {
      const matchesSearch = [
        flow.source_ip,
        flow.destination_ip,
        flow.protocol,
        String(flow.source_port),
        String(flow.destination_port),
      ].some((value) =>
        String(value ?? '').toLowerCase().includes(search.toLowerCase())
      )

      const matchesProtocol =
        protocolFilter === 'ALL' || flow.protocol === protocolFilter

      return matchesSearch && matchesProtocol
    })
  }, [flows, search, protocolFilter])

  const uniqueSources = new Set(flows.map((f) => f.source_ip)).size

  const handleUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return

    setIsUploading(true)
    setUploadStatus(`Uploading ${file.name}...`)

    try {
      const result = await uploadPcap(file)
      setUploadStatus(
        `Upload successful. Task ID: ${result.task_id}. ${result.message}`
      )
    } catch (err: unknown) {
      setUploadStatus(
        `Upload failed: ${err instanceof Error ? err.message : 'Unknown error'}`
      )
    } finally {
      setIsUploading(false)
      e.target.value = ''
    }
  }

  return (
    <div className="monitoring-page">

      {/* Page heading */}
      <section className="monitoring-heading">
        <div>
          <div className="monitoring-eyebrow">
            <span className="eyebrow-dot" />
            NETWORK SECURITY OPERATIONS
          </div>
          <h2>Live Network Monitoring</h2>
          <p>
            Monitor network flows, inspect traffic metadata and analyze
            uploaded packet captures.
          </p>
        </div>

        <div className={`monitoring-connection ${wsConnected ? 'connected' : 'disconnected'}`}>
          <span />
          {wsConnected ? 'WEBSOCKET CONNECTED' : 'WEBSOCKET DISCONNECTED'}
        </div>
      </section>

      {/* Statistics */}
      <section className="monitoring-stats">
        <article className="monitoring-stat-card">
          <div className="monitoring-stat-icon cyan">
            <Network size={20} />
          </div>
          <div>
            <span>Total Network Flows</span>
            <strong>{(data?.total ?? 0).toLocaleString()}</strong>
            <small>Recorded by AgentShield</small>
          </div>
        </article>

        <article className="monitoring-stat-card">
          <div className="monitoring-stat-icon purple">
            <Radio size={20} />
          </div>
          <div>
            <span>Live Security Events</span>
            <strong>{liveEvents.length}</strong>
            <small>Events received in this session</small>
          </div>
        </article>

        <article className="monitoring-stat-card">
          <div className="monitoring-stat-icon blue">
            <Wifi size={20} />
          </div>
          <div>
            <span>Unique Source IPs</span>
            <strong>{uniqueSources}</strong>
            <small>In the displayed flow records</small>
          </div>
        </article>

        <article className="monitoring-stat-card">
          <div className="monitoring-stat-icon green">
            <ShieldCheck size={20} />
          </div>
          <div>
            <span>Protocols Observed</span>
            <strong>{protocols.length}</strong>
            <small>In the displayed flow records</small>
          </div>
        </article>
      </section>

      {/* PCAP upload */}
      <section className="monitoring-upload-panel">
        <div className="monitoring-upload-info">
          <div className="monitoring-upload-icon">
            <FileUp size={23} />
          </div>
          <div>
            <h3>Analyze Network Traffic</h3>
            <p>
              Upload a PCAP or PCAPNG file to extract network flows
              and run security analysis.
            </p>
          </div>
        </div>

        <label className={`monitoring-upload-button ${isUploading ? 'uploading' : ''}`}>
          {isUploading ? (
            <RefreshCw size={16} className="monitoring-spin" />
          ) : (
            <Upload size={16} />
          )}
          {isUploading ? 'Uploading...' : 'Upload PCAP'}
          <input
            type="file"
            accept=".pcap,.pcapng"
            className="hidden"
            disabled={isUploading}
            onChange={handleUpload}
          />
        </label>
      </section>

      {uploadStatus && (
        <div className={`monitoring-upload-status ${
          uploadStatus.startsWith('Upload failed') ? 'error' : 'success'
        }`}>
          <FileUp size={17} />
          <span>{uploadStatus}</span>
          <button onClick={() => setUploadStatus(null)} aria-label="Dismiss">
            ×
          </button>
        </div>
      )}

      {/* Flow table */}
      <section className="monitoring-table-panel">
        <div className="monitoring-table-heading">
          <div>
            <div className="monitoring-table-title">
              <Activity size={18} />
              <h3>Network Flow Records</h3>
            </div>
            <p>Inspect extracted network traffic information</p>
          </div>

          <button
            className="monitoring-refresh-button"
            onClick={() => refetch()}
            disabled={isFetching}
          >
            <RefreshCw size={14} className={isFetching ? 'monitoring-spin' : ''} />
            Refresh
          </button>
        </div>

        <div className="monitoring-filters">
          <div className="monitoring-search">
            <Search size={16} />
            <input
              type="text"
              placeholder="Search IP address, port or protocol..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>

          <select
            value={protocolFilter}
            onChange={(e) => setProtocolFilter(e.target.value)}
            aria-label="Filter by protocol"
          >
            <option value="ALL">All Protocols</option>
            {protocols.map((protocol) => (
              <option key={protocol} value={protocol}>{protocol}</option>
            ))}
          </select>
        </div>

        <div className="monitoring-table-meta">
          <span>
            Showing <strong>{filteredFlows.length}</strong> of{' '}
            <strong>{flows.length}</strong> loaded records
          </span>
          <span className="monitoring-auto-refresh">
            <span />
            Auto-refresh: 10 seconds
          </span>
        </div>

        <div className="monitoring-table-wrap">
          <table className="monitoring-table">
            <thead>
              <tr>
                <th>SOURCE IP</th>
                <th>DESTINATION IP</th>
                <th>SRC PORT</th>
                <th>DST PORT</th>
                <th>PROTOCOL</th>
                <th>DURATION (µs)</th>
                <th>PCAP SOURCE</th>
                <th>TIME</th>
              </tr>
            </thead>

            <tbody>
              {filteredFlows.map((flow) => (
                <tr key={flow.flow_id}>
                  <td className="monitoring-source-ip">{flow.source_ip}</td>
                  <td className="monitoring-destination-ip">{flow.destination_ip}</td>
                  <td className="monitoring-mono">{flow.source_port}</td>
                  <td className="monitoring-mono">{flow.destination_port}</td>
                  <td>
                    <span className="monitoring-protocol">
                      {flow.protocol}
                    </span>
                  </td>
                  <td className="monitoring-mono">
                    {flow.duration_us?.toLocaleString() ?? '—'}
                  </td>
                  <td className="monitoring-file-name">
                    {flow.pcap_source?.split('/').pop() ?? '—'}
                  </td>
                  <td className="monitoring-time">
                    <Clock3 size={12} />
                    {new Date(flow.created_at).toLocaleTimeString()}
                  </td>
                </tr>
              ))}

              {filteredFlows.length === 0 && (
                <tr>
                  <td colSpan={8} className="monitoring-empty">
                    <div>
                      <ArrowDownToLine size={28} />
                      <strong>
                        {flows.length === 0
                          ? 'No network flows recorded yet'
                          : 'No matching network flows'}
                      </strong>
                      <span>
                        {flows.length === 0
                          ? 'Upload a PCAP file to begin traffic analysis.'
                          : 'Try changing your search or protocol filter.'}
                      </span>
                    </div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="monitoring-table-footer">
          <span>AGENTSHIELD NETWORK ANALYSIS</span>
          <span>Latest data is refreshed automatically</span>
        </div>
      </section>
    </div>
  )
}
