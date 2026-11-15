import React, { useMemo } from 'react'
import ReactFlow, {
  Node, Edge, Background, Controls, MiniMap,
  MarkerType, BackgroundVariant
} from 'reactflow'
import 'reactflow/dist/style.css'
import type { AttackPathNode, AttackPathEdge } from '../../types'

const NODE_COLORS: Record<string, { bg: string; border: string; text: string }> = {
  attacker: { bg: '#7f1d1d', border: '#ef4444', text: '#fca5a5' },
  victim: { bg: '#7c2d12', border: '#f97316', text: '#fdba74' },
  intermediate: { bg: '#713f12', border: '#eab308', text: '#fde047' },
  unknown: { bg: '#1f2937', border: '#374151', text: '#9ca3af' },
}

interface Props {
  nodes: AttackPathNode[]
  edges: AttackPathEdge[]
}

export function AttackPathGraph({ nodes, edges }: Props) {
  const rfNodes: Node[] = useMemo(
    () =>
      nodes.map((n, idx) => {
        const colors = NODE_COLORS[n.node_type] ?? NODE_COLORS.unknown
        return {
          id: n.id,
          position: { x: idx * 220, y: n.node_type === 'intermediate' ? 150 : 50 },
          data: {
            label: (
              <div className="text-center" style={{ color: colors.text }}>
                <div className="text-xs font-bold">{n.node_type.toUpperCase()}</div>
                <div className="text-sm font-mono mt-1">{n.ip}</div>
                {n.risk_level && (
                  <div className="text-xs mt-0.5 opacity-70">{n.risk_level}</div>
                )}
              </div>
            ),
          },
          style: {
            background: colors.bg,
            border: `1px solid ${colors.border}`,
            borderRadius: 8,
            padding: 8,
            minWidth: 160,
          },
        }
      }),
    [nodes]
  )

  const rfEdges: Edge[] = useMemo(
    () =>
      edges.map((e, idx) => ({
        id: `edge-${idx}`,
        source: e.source,
        target: e.target,
        label: e.label,
        animated: e.observed,
        style: {
          stroke: e.observed ? '#06b6d4' : '#4b5563',
          strokeDasharray: e.observed ? undefined : '5 5',
        },
        labelStyle: { fill: '#9ca3af', fontSize: 10 },
        markerEnd: { type: MarkerType.ArrowClosed, color: e.observed ? '#06b6d4' : '#4b5563' },
      })),
    [edges]
  )

  if (nodes.length === 0) {
    return (
      <div className="h-64 flex items-center justify-center text-text-muted text-sm border border-border rounded-lg">
        Select an investigation to view its attack path
      </div>
    )
  }

  return (
    <div style={{ height: 400 }} className="border border-border rounded-lg overflow-hidden">
      <ReactFlow nodes={rfNodes} edges={rfEdges} fitView>
        <Background variant={BackgroundVariant.Dots} color="#1f2937" gap={20} />
        <Controls style={{ filter: 'invert(0.8)' }} />
        <MiniMap
          style={{ background: '#111827', border: '1px solid #1f2937' }}
          nodeColor={(n) => {
            const type = (n.data as { label: React.ReactNode })?.label ? 'unknown' : 'unknown'
            return NODE_COLORS[type]?.border ?? '#374151'
          }}
        />
      </ReactFlow>
    </div>
  )
}
