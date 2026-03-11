import { useState, useEffect, useCallback } from 'react';
import {
  Play,
  BarChart3,
  Clock,
  CheckCircle2,
  XCircle,
} from 'lucide-react';
import NetworkTopology from '@/components/NetworkTopology';
import AttackTimeline from '@/components/AttackTimeline';
import AlertFeed from '@/components/AlertFeed';
import ScenarioCard from '@/components/ScenarioCard';
import { useWebSocket } from '@/hooks/useWebSocket';
import { useApi } from '@/hooks/useApi';
import type { DashboardState, Scenario, Phase, Alert } from '@/types';

// Hardcoded scenario catalog for when the API is down
const FALLBACK_SCENARIOS: Scenario[] = [
  {
    id: 'S1-01', name: 'Hardcoded Credentials in Source Code', category: 'API Keys & Secrets',
    difficulty: 'Easy', description: 'Discover and exfiltrate hardcoded credentials from application source code',
    phases: [
      { name: 'Source Code Access', description: 'Access application source files', critical: false, status: 'pending' },
      { name: 'Credential Pattern Search', description: 'Search for hardcoded secrets', critical: false, status: 'pending' },
      { name: 'Config File Analysis', description: 'Extract credentials from config', critical: false, status: 'pending' },
      { name: 'Credential Exfiltration', description: 'Extract and use credentials', critical: true, status: 'pending' },
    ],
    expectedAlerts: [
      { ruleId: '100600', level: 7, description: 'NHI: Sensitive configuration file access detected' },
      { ruleId: '100601', level: 10, description: 'NHI: Credential discovery attempt via file search' },
      { ruleId: '100900', level: 12, description: 'NHI: AWS Access Key pattern detected in logs' },
    ],
  },
  {
    id: 'S2-01', name: 'IMDS Credential Theft (AWS)', category: 'Cloud Metadata',
    difficulty: 'Medium', description: 'Extract IAM credentials from AWS Instance Metadata Service',
    phases: [
      { name: 'IMDS Discovery', description: 'Discover metadata endpoint', critical: false, status: 'pending' },
      { name: 'Role Enumeration', description: 'List available IAM roles', critical: false, status: 'pending' },
      { name: 'Credential Extraction', description: 'Extract temporary credentials', critical: true, status: 'pending' },
    ],
    expectedAlerts: [
      { ruleId: '100650', level: 8, description: 'NHI: IMDS metadata access detected' },
      { ruleId: '100651', level: 12, description: 'NHI: IMDS IAM credential request' },
      { ruleId: '100658', level: 14, description: 'NHI: IMDS credential exfiltration' },
    ],
  },
  {
    id: 'S2-03', name: 'Kubernetes ServiceAccount Token Theft', category: 'Kubernetes',
    difficulty: 'Medium', description: 'Extract Kubernetes service account token from pod filesystem',
    phases: [
      { name: 'Token Discovery', description: 'Find SA token mount', critical: false, status: 'pending' },
      { name: 'Token Extraction', description: 'Read and exfiltrate token', critical: true, status: 'pending' },
    ],
    expectedAlerts: [
      { ruleId: '100750', level: 10, description: 'NHI: K8s ServiceAccount token access' },
      { ruleId: '100751', level: 12, description: 'NHI: K8s ServiceAccount token theft' },
    ],
  },
  {
    id: 'S3-01', name: 'IMDS Role Assumption', category: 'Cloud Metadata',
    difficulty: 'Hard', description: 'Use stolen IMDS credentials to assume IAM role',
    phases: [
      { name: 'Credential Retrieval', description: 'Get IMDS credentials', critical: false, status: 'pending' },
      { name: 'Role Assumption', description: 'Assume IAM role', critical: true, status: 'pending' },
    ],
    expectedAlerts: [
      { ruleId: '100651', level: 12, description: 'NHI: IMDS IAM credential request' },
      { ruleId: '100657', level: 14, description: 'NHI: Cloud credential abuse' },
    ],
  },
  {
    id: 'S5-01', name: 'Pipeline Poisoning', category: 'CI/CD Pipeline',
    difficulty: 'Hard', description: 'Identify and modify CI/CD pipeline configurations',
    phases: [
      { name: 'Pipeline Discovery', description: 'Find pipeline config files', critical: false, status: 'pending' },
      { name: 'Config Modification', description: 'Inject malicious steps', critical: true, status: 'pending' },
    ],
    expectedAlerts: [
      { ruleId: '100803', level: 12, description: 'NHI: CI/CD pipeline config modification' },
    ],
  },
];

// Categories for the dropdown
const CATEGORIES = [
  'All Categories',
  'API Keys & Secrets',
  'Cloud Metadata',
  'CI/CD Pipeline',
  'Kubernetes',
  'AI Agent',
  'Infrastructure',
];

interface DetectionResult {
  ruleId: string;
  expected: boolean;
  fired: boolean;
  timeToDetect?: number;
}

export default function InteractivePage() {
  const { alerts, connected } = useWebSocket();
  const { fetchScenarios, executeScenario, loading } = useApi();
  const [scenarios, setScenarios] = useState<Scenario[]>(FALLBACK_SCENARIOS);
  const [selectedCategory, setSelectedCategory] = useState('All Categories');
  const [selectedScenario, setSelectedScenario] = useState<Scenario | null>(null);
  const [runningId, setRunningId] = useState<string | null>(null);
  const [completedIds, setCompletedIds] = useState<Set<string>>(new Set());
  const [phases, setPhases] = useState<Phase[]>([]);
  const [currentPhase, setCurrentPhase] = useState(0);
  const [detectionResults, setDetectionResults] = useState<DetectionResult[]>([]);
  const [scenarioAlerts, setScenarioAlerts] = useState<Alert[]>([]);
  const [startTime, setStartTime] = useState<number | null>(null);

  useEffect(() => {
    fetchScenarios().then((data) => {
      if (data.length > 0) setScenarios(data);
    });
  }, [fetchScenarios]);

  const filteredScenarios = selectedCategory === 'All Categories'
    ? scenarios
    : scenarios.filter((s) => s.category === selectedCategory);

  const handleSelectScenario = (scenario: Scenario) => {
    setSelectedScenario(scenario);
    setDetectionResults([]);
    setScenarioAlerts([]);
  };

  const handleRun = useCallback(async (id: string) => {
    const scenario = scenarios.find((s) => s.id === id || s.id.toLowerCase() === id.toLowerCase());
    if (!scenario) return;

    setRunningId(id);
    setStartTime(Date.now());
    setScenarioAlerts([]);

    // Animate phases
    const ph = scenario.phases.map((p) => ({ ...p, status: 'pending' as const }));
    setPhases(ph);
    setCurrentPhase(0);

    // Simulate phase progression
    for (let i = 0; i < ph.length; i++) {
      setCurrentPhase(i);
      setPhases((prev) =>
        prev.map((p, idx) => ({
          ...p,
          status: idx < i ? 'completed' : idx === i ? 'running' : 'pending',
        }))
      );
      await new Promise((r) => setTimeout(r, 1200));
    }

    // Execute via API
    await executeScenario(id.toLowerCase().replace('s', 's'));

    // Mark all phases completed
    setPhases((prev) => prev.map((p) => ({ ...p, status: 'completed' as const })));
    setCurrentPhase(ph.length - 1);
    setCompletedIds((prev) => new Set([...prev, id]));
    setRunningId(null);

    // Build detection results from alerts that arrived
    const now = Date.now();
    const results: DetectionResult[] = scenario.expectedAlerts.map((ea) => {
      const matchingAlert = alerts.find((a) => a.ruleId === ea.ruleId);
      return {
        ruleId: ea.ruleId,
        expected: true,
        fired: !!matchingAlert,
        timeToDetect: matchingAlert && startTime ? now - startTime : undefined,
      };
    });
    setDetectionResults(results);
  }, [scenarios, executeScenario, alerts, startTime]);

  // Track alerts that arrive during scenario execution
  useEffect(() => {
    if (runningId && alerts.length > 0) {
      setScenarioAlerts(alerts.slice(0, 20));
    }
  }, [alerts, runningId]);

  const detectionRate = detectionResults.length > 0
    ? (detectionResults.filter((r) => r.fired).length / detectionResults.length) * 100
    : 0;

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="px-6 py-4 border-b border-gray-800">
        <h1 className="text-lg font-bold text-white">Interactive Mode</h1>
        <p className="text-xs text-gray-500 mt-0.5">
          Select and run attack scenarios, observe detections in real-time
        </p>
      </div>

      <div className="flex-1 flex gap-4 p-4 min-h-0 overflow-hidden">
        {/* Left panel: Scenario selector */}
        <div className="w-[300px] shrink-0 flex flex-col gap-3 overflow-y-auto">
          <select
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
            className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-300 focus:outline-none focus:border-nhi-500"
          >
            {CATEGORIES.map((c) => (
              <option key={c} value={c}>{c}</option>
            ))}
          </select>

          <div className="space-y-2">
            {filteredScenarios.map((scenario) => (
              <button
                key={scenario.id}
                onClick={() => handleSelectScenario(scenario)}
                className={`w-full text-left card px-3 py-2.5 transition-all duration-150 ${
                  selectedScenario?.id === scenario.id
                    ? 'border-nhi-500/50 bg-nhi-500/5'
                    : 'hover:border-gray-600/50'
                }`}
              >
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-mono text-gray-600">{scenario.id}</span>
                  {completedIds.has(scenario.id) && (
                    <CheckCircle2 className="w-3 h-3 text-green-400" />
                  )}
                </div>
                <p className="text-xs text-gray-300 mt-0.5 leading-snug">{scenario.name}</p>
              </button>
            ))}
          </div>
        </div>

        {/* Center: Topology + Timeline */}
        <div className="flex-1 flex flex-col gap-3 min-w-0 min-h-0">
          <div className="flex-1 min-h-0">
            <NetworkTopology
              alerts={scenarioAlerts.length > 0 ? scenarioAlerts : alerts}
              activeScenario={runningId}
            />
          </div>
          <div className="h-[140px] shrink-0">
            <AttackTimeline
              phases={phases}
              currentPhase={currentPhase}
              scenarioName={selectedScenario?.name}
              compact
            />
          </div>
        </div>

        {/* Right: Alerts + Results */}
        <div className="w-[320px] shrink-0 flex flex-col gap-3 min-h-0">
          {/* Selected scenario card */}
          {selectedScenario && (
            <div className="shrink-0">
              <ScenarioCard
                scenario={selectedScenario}
                onRun={handleRun}
                running={runningId === selectedScenario.id}
                completed={completedIds.has(selectedScenario.id)}
              />
            </div>
          )}

          {/* Alert feed */}
          <div className="flex-1 min-h-0">
            <AlertFeed
              alerts={scenarioAlerts.length > 0 ? scenarioAlerts : alerts}
              compact
            />
          </div>

          {/* Detection results */}
          {detectionResults.length > 0 && (
            <div className="card shrink-0 p-3 animate-fade-in">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <BarChart3 className="w-4 h-4 text-nhi-400" />
                  <h4 className="text-xs font-medium text-gray-300">Detection Results</h4>
                </div>
                <span className={`text-sm font-bold ${detectionRate >= 90 ? 'text-green-400' : detectionRate >= 50 ? 'text-yellow-400' : 'text-red-400'}`}>
                  {detectionRate.toFixed(0)}%
                </span>
              </div>
              <div className="space-y-1">
                {detectionResults.map((r) => (
                  <div key={r.ruleId} className="flex items-center gap-2 text-xs">
                    {r.fired ? (
                      <CheckCircle2 className="w-3 h-3 text-green-400 shrink-0" />
                    ) : (
                      <XCircle className="w-3 h-3 text-red-400 shrink-0" />
                    )}
                    <span className="font-mono text-gray-500">{r.ruleId}</span>
                    {r.timeToDetect && (
                      <span className="flex items-center gap-0.5 text-gray-600">
                        <Clock className="w-2.5 h-2.5" />
                        {(r.timeToDetect / 1000).toFixed(1)}s
                      </span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
