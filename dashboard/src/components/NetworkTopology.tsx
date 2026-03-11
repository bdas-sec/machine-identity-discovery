import { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';
import { Network } from 'lucide-react';
import type { Alert } from '@/types';

interface NetworkTopologyProps {
  alerts: Alert[];
  activeScenario?: string | null;
  compact?: boolean;
}

interface TopoNode {
  id: string;
  label: string;
  zone: 'cloud' | 'cicd' | 'k8s' | 'mgmt';
  type: 'service' | 'agent' | 'attacker';
  fx?: number;
  fy?: number;
  x?: number;
  y?: number;
  alerting?: boolean;
}

interface TopoLink {
  source: string | TopoNode;
  target: string | TopoNode;
  active: boolean;
  label?: string;
}

const NODES: TopoNode[] = [
  // Cloud zone
  { id: 'vulnerable-app', label: 'Vuln App', zone: 'cloud', type: 'service' },
  { id: 'cloud-workload', label: 'Cloud Workload', zone: 'cloud', type: 'agent' },
  { id: 'mock-imds', label: 'IMDS', zone: 'cloud', type: 'service' },
  { id: 'vault', label: 'Vault', zone: 'cloud', type: 'service' },
  // CI/CD zone
  { id: 'cicd-runner', label: 'CI/CD Runner', zone: 'cicd', type: 'agent' },
  { id: 'mock-cicd', label: 'CI/CD Server', zone: 'cicd', type: 'service' },
  // K8s zone
  { id: 'k8s-node-1', label: 'K8s Node 1', zone: 'k8s', type: 'agent' },
  { id: 'k8s-node-2', label: 'K8s Node 2', zone: 'k8s', type: 'agent' },
  // Management zone
  { id: 'wazuh-manager', label: 'Wazuh', zone: 'mgmt', type: 'service' },
  { id: 'dashboard', label: 'Dashboard', zone: 'mgmt', type: 'service' },
  // Attacker
  { id: 'attacker', label: 'Attacker', zone: 'cloud', type: 'attacker' },
];

const BASE_LINKS: Omit<TopoLink, 'active'>[] = [
  { source: 'cloud-workload', target: 'mock-imds', label: 'IMDS' },
  { source: 'cloud-workload', target: 'vault', label: 'Secrets' },
  { source: 'cloud-workload', target: 'vulnerable-app' },
  { source: 'cicd-runner', target: 'mock-cicd', label: 'Pipeline' },
  { source: 'cicd-runner', target: 'cloud-workload' },
  { source: 'k8s-node-1', target: 'k8s-node-2' },
  { source: 'k8s-node-1', target: 'cloud-workload' },
  { source: 'wazuh-manager', target: 'cloud-workload' },
  { source: 'wazuh-manager', target: 'cicd-runner' },
  { source: 'wazuh-manager', target: 'k8s-node-1' },
  { source: 'wazuh-manager', target: 'dashboard' },
  { source: 'attacker', target: 'vulnerable-app' },
  { source: 'attacker', target: 'cloud-workload' },
];

const ZONE_COLORS: Record<string, string> = {
  cloud: '#3b82f6',
  cicd: '#22c55e',
  k8s: '#a78bfa',
  mgmt: '#6b7280',
};

const ZONE_LABELS: Record<string, string> = {
  cloud: 'Cloud Network',
  cicd: 'CI/CD Network',
  k8s: 'Kubernetes',
  mgmt: 'Management',
};

// Zone center positions (relative to width/height)
const ZONE_POSITIONS: Record<string, { cx: number; cy: number }> = {
  cloud: { cx: 0.3, cy: 0.35 },
  cicd: { cx: 0.75, cy: 0.3 },
  k8s: { cx: 0.7, cy: 0.72 },
  mgmt: { cx: 0.25, cy: 0.75 },
};

export default function NetworkTopology({ alerts, activeScenario, compact = false }: NetworkTopologyProps) {
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ width: 800, height: 500 });
  const simulationRef = useRef<d3.Simulation<TopoNode, TopoLink> | null>(null);

  // Track which nodes are alerting based on recent alerts
  const alertingNodes = new Set(
    alerts.slice(0, 5).map((a) => a.agent.toLowerCase().replace(/[^a-z0-9-]/g, ''))
  );

  // Resize observer
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    const observer = new ResizeObserver((entries) => {
      for (const entry of entries) {
        const { width, height } = entry.contentRect;
        if (width > 0 && height > 0) {
          setDimensions({ width, height });
        }
      }
    });
    observer.observe(container);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    const { width, height } = dimensions;

    // Position nodes based on zone
    const nodes: TopoNode[] = NODES.map((n) => {
      const zone = ZONE_POSITIONS[n.zone];
      const jitter = () => (Math.random() - 0.5) * 80;
      return {
        ...n,
        fx: zone.cx * width + jitter(),
        fy: zone.cy * height + jitter(),
        alerting: alertingNodes.has(n.id),
      };
    });

    const links: TopoLink[] = BASE_LINKS.map((l) => ({
      ...l,
      active: activeScenario != null && (
        alertingNodes.has(l.source as string) || alertingNodes.has(l.target as string)
      ),
    }));

    // Draw zone backgrounds
    const zones = svg.append('g').attr('class', 'zones');
    Object.entries(ZONE_POSITIONS).forEach(([zone, pos]) => {
      const cx = pos.cx * width;
      const cy = pos.cy * height;
      const r = Math.min(width, height) * 0.22;

      zones
        .append('ellipse')
        .attr('cx', cx)
        .attr('cy', cy)
        .attr('rx', r)
        .attr('ry', r * 0.7)
        .attr('fill', ZONE_COLORS[zone])
        .attr('fill-opacity', 0.04)
        .attr('stroke', ZONE_COLORS[zone])
        .attr('stroke-opacity', 0.15)
        .attr('stroke-width', 1)
        .attr('stroke-dasharray', '4,4');

      zones
        .append('text')
        .attr('x', cx)
        .attr('y', cy - r * 0.7 + 16)
        .attr('text-anchor', 'middle')
        .attr('fill', ZONE_COLORS[zone])
        .attr('fill-opacity', 0.5)
        .attr('font-size', compact ? '10px' : '11px')
        .attr('font-weight', '500')
        .attr('letter-spacing', '0.05em')
        .text(ZONE_LABELS[zone].toUpperCase());
    });

    // Draw links
    const linkGroup = svg.append('g').attr('class', 'links');
    const linkElements = linkGroup
      .selectAll('line')
      .data(links)
      .join('line')
      .attr('x1', (d) => {
        const s = nodes.find((n) => n.id === (typeof d.source === 'string' ? d.source : d.source.id));
        return s?.fx || 0;
      })
      .attr('y1', (d) => {
        const s = nodes.find((n) => n.id === (typeof d.source === 'string' ? d.source : d.source.id));
        return s?.fy || 0;
      })
      .attr('x2', (d) => {
        const t = nodes.find((n) => n.id === (typeof d.target === 'string' ? d.target : d.target.id));
        return t?.fx || 0;
      })
      .attr('y2', (d) => {
        const t = nodes.find((n) => n.id === (typeof d.target === 'string' ? d.target : d.target.id));
        return t?.fy || 0;
      })
      .attr('stroke', (d) => (d.active ? '#ef4444' : 'rgba(255,255,255,0.08)'))
      .attr('stroke-width', (d) => (d.active ? 2 : 1))
      .attr('stroke-dasharray', (d) => (d.active ? '6,4' : 'none'));

    // Animate active links
    linkElements
      .filter((d) => d.active)
      .attr('class', 'animate-dash');

    // Link labels
    linkGroup
      .selectAll('text')
      .data(links.filter((l) => l.label && l.active))
      .join('text')
      .attr('x', (d) => {
        const s = nodes.find((n) => n.id === (typeof d.source === 'string' ? d.source : d.source.id));
        const t = nodes.find((n) => n.id === (typeof d.target === 'string' ? d.target : d.target.id));
        return ((s?.fx || 0) + (t?.fx || 0)) / 2;
      })
      .attr('y', (d) => {
        const s = nodes.find((n) => n.id === (typeof d.source === 'string' ? d.source : d.source.id));
        const t = nodes.find((n) => n.id === (typeof d.target === 'string' ? d.target : d.target.id));
        return ((s?.fy || 0) + (t?.fy || 0)) / 2 - 6;
      })
      .attr('text-anchor', 'middle')
      .attr('fill', '#ef4444')
      .attr('font-size', '9px')
      .attr('font-weight', '600')
      .text((d) => d.label || '');

    // Draw nodes
    const nodeGroup = svg.append('g').attr('class', 'nodes');

    // Node glow for alerting
    nodeGroup
      .selectAll('circle.glow')
      .data(nodes.filter((n) => n.alerting))
      .join('circle')
      .attr('cx', (d) => d.fx || 0)
      .attr('cy', (d) => d.fy || 0)
      .attr('r', compact ? 18 : 22)
      .attr('fill', 'none')
      .attr('stroke', '#ef4444')
      .attr('stroke-opacity', 0.4)
      .attr('stroke-width', 2)
      .attr('class', 'animate-pulse-alert');

    // Node circles
    nodeGroup
      .selectAll('circle.node')
      .data(nodes)
      .join('circle')
      .attr('class', 'node')
      .attr('cx', (d) => d.fx || 0)
      .attr('cy', (d) => d.fy || 0)
      .attr('r', (d) => {
        if (d.type === 'attacker') return compact ? 10 : 14;
        return compact ? 8 : 10;
      })
      .attr('fill', (d) => {
        if (d.type === 'attacker') return '#ef4444';
        if (d.alerting) return '#f97316';
        return ZONE_COLORS[d.zone];
      })
      .attr('stroke', (d) => {
        if (d.type === 'attacker') return '#fca5a5';
        return 'rgba(255,255,255,0.2)';
      })
      .attr('stroke-width', (d) => (d.type === 'attacker' ? 2 : 1));

    // Node labels
    nodeGroup
      .selectAll('text')
      .data(nodes)
      .join('text')
      .attr('x', (d) => d.fx || 0)
      .attr('y', (d) => (d.fy || 0) + (compact ? 18 : 22))
      .attr('text-anchor', 'middle')
      .attr('fill', (d) => (d.alerting ? '#f97316' : 'rgba(255,255,255,0.6)'))
      .attr('font-size', compact ? '9px' : '10px')
      .attr('font-weight', (d) => (d.alerting ? '600' : '400'))
      .text((d) => d.label);

    // Attacker icon (skull-like X)
    const attackerNode = nodes.find((n) => n.type === 'attacker');
    if (attackerNode) {
      const ax = attackerNode.fx || 0;
      const ay = attackerNode.fy || 0;
      const s = compact ? 4 : 5;
      nodeGroup
        .append('line')
        .attr('x1', ax - s).attr('y1', ay - s)
        .attr('x2', ax + s).attr('y2', ay + s)
        .attr('stroke', '#fff').attr('stroke-width', 2);
      nodeGroup
        .append('line')
        .attr('x1', ax + s).attr('y1', ay - s)
        .attr('x2', ax - s).attr('y2', ay + s)
        .attr('stroke', '#fff').attr('stroke-width', 2);
    }

    return () => {
      simulationRef.current?.stop();
    };
  }, [dimensions, alerts, activeScenario, compact, alertingNodes]);

  return (
    <div className="card h-full flex flex-col">
      <div className="card-header">
        <div className="flex items-center gap-2">
          <Network className="w-4 h-4 text-nhi-400" />
          <h3 className="text-sm font-medium text-gray-300">Network Topology</h3>
        </div>
        {activeScenario && (
          <span className="text-xs text-red-400 animate-pulse">Attack Active</span>
        )}
      </div>
      <div ref={containerRef} className="flex-1 min-h-0">
        <svg
          ref={svgRef}
          width={dimensions.width}
          height={dimensions.height}
          className="w-full h-full"
        />
      </div>
    </div>
  );
}
