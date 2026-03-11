export interface Alert {
  id: string;
  ruleId: string;
  level: number;
  description: string;
  agent: string;
  timestamp: string;
  mitreTactics?: string[];
  mitreTechniques?: string[];
}

export interface Scenario {
  id: string;
  name: string;
  category: string;
  difficulty: string;
  description: string;
  phases: Phase[];
  expectedAlerts: ExpectedAlert[];
  mitreAttack?: {
    tactics: string[];
    techniques: { id: string; name: string }[];
  };
}

export interface Phase {
  name: string;
  description: string;
  critical: boolean;
  status: 'pending' | 'running' | 'completed' | 'failed';
}

export interface ExpectedAlert {
  ruleId: string;
  level: number;
  description: string;
}

export interface DashboardState {
  scenariosRun: number;
  alertsGenerated: number;
  detectionRate: number;
  activeScenario: string | null;
  currentPhase: number;
  totalPhases: number;
}

export interface MitreHeatmapEntry {
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  count: number;
  scenarios: string[];
}

export interface TopologyNode {
  id: string;
  label: string;
  zone: 'cloud' | 'cicd' | 'k8s' | 'mgmt';
  x: number;
  y: number;
  type: 'service' | 'agent' | 'attacker';
}

export interface TopologyLink {
  source: string;
  target: string;
  active: boolean;
  label?: string;
}

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

export function getSeverity(level: number): SeverityLevel {
  if (level >= 14) return 'critical';
  if (level >= 12) return 'high';
  if (level >= 8) return 'medium';
  if (level >= 4) return 'low';
  return 'info';
}

export function getSeverityColor(level: number): string {
  const s = getSeverity(level);
  const colors: Record<SeverityLevel, string> = {
    critical: 'text-red-500',
    high: 'text-orange-500',
    medium: 'text-yellow-500',
    low: 'text-blue-500',
    info: 'text-gray-500',
  };
  return colors[s];
}

export function getSeverityBg(level: number): string {
  const s = getSeverity(level);
  const colors: Record<SeverityLevel, string> = {
    critical: 'bg-red-500/20 border-red-500/50 text-red-400',
    high: 'bg-orange-500/20 border-orange-500/50 text-orange-400',
    medium: 'bg-yellow-500/20 border-yellow-500/50 text-yellow-400',
    low: 'bg-blue-500/20 border-blue-500/50 text-blue-400',
    info: 'bg-gray-500/20 border-gray-500/50 text-gray-400',
  };
  return colors[s];
}
