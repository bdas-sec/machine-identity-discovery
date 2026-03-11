import { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { Shield, Wifi, WifiOff, Maximize2, Settings } from 'lucide-react';
import StatsBar from '@/components/StatsBar';
import NetworkTopology from '@/components/NetworkTopology';
import AttackTimeline from '@/components/AttackTimeline';
import AlertFeed from '@/components/AlertFeed';
import MitreHeatmap from '@/components/MitreHeatmap';
import { useWebSocket } from '@/hooks/useWebSocket';
import { useApi } from '@/hooks/useApi';
import type { DashboardState, Phase, MitreHeatmapEntry } from '@/types';

const DEFAULT_STATE: DashboardState = {
  scenariosRun: 0,
  alertsGenerated: 0,
  detectionRate: 96.6,
  activeScenario: null,
  currentPhase: 0,
  totalPhases: 0,
};

// Demo mode simulates activity when no real data is flowing
function useDemoSimulation(realAlertCount: number) {
  const [simState, setSimState] = useState<DashboardState>({
    ...DEFAULT_STATE,
    scenariosRun: 12,
    alertsGenerated: 47,
    detectionRate: 96.6,
  });

  useEffect(() => {
    if (realAlertCount > 0) {
      setSimState((prev) => ({
        ...prev,
        alertsGenerated: realAlertCount,
      }));
    }
  }, [realAlertCount]);

  return simState;
}

export default function DemoPage() {
  const { alerts, connected, reconnecting } = useWebSocket();
  const { fetchDashboardState, fetchMitreCoverage } = useApi();
  const [dashState, setDashState] = useState<DashboardState>(DEFAULT_STATE);
  const [mitreData, setMitreData] = useState<MitreHeatmapEntry[]>([]);
  const [phases, setPhases] = useState<Phase[]>([]);
  const simState = useDemoSimulation(alerts.length);

  // Use real data if available, otherwise simulation
  const state = dashState.scenariosRun > 0 ? dashState : simState;

  const pollState = useCallback(async () => {
    const s = await fetchDashboardState();
    setDashState(s);
  }, [fetchDashboardState]);

  useEffect(() => {
    pollState();
    fetchMitreCoverage().then(setMitreData);

    const interval = setInterval(pollState, 5000);
    return () => clearInterval(interval);
  }, [pollState, fetchMitreCoverage]);

  // Generate phases from active scenario
  useEffect(() => {
    if (state.activeScenario) {
      const ph: Phase[] = Array.from({ length: state.totalPhases }, (_, i) => ({
        name: `Phase ${i + 1}`,
        description: i < state.currentPhase ? 'Completed' : i === state.currentPhase ? 'In progress' : 'Pending',
        critical: i === state.totalPhases - 1,
        status: i < state.currentPhase ? 'completed' : i === state.currentPhase ? 'running' : 'pending',
      }));
      setPhases(ph);
    } else {
      setPhases([]);
    }
  }, [state.activeScenario, state.currentPhase, state.totalPhases]);

  return (
    <div className="h-screen flex flex-col bg-gray-950 overflow-hidden">
      {/* Top bar — branding + connection */}
      <header className="flex items-center justify-between px-4 py-2 bg-gray-950 border-b border-gray-800/50">
        <div className="flex items-center gap-3">
          <div className="w-7 h-7 rounded-lg bg-nhi-500/20 border border-nhi-500/30 flex items-center justify-center">
            <Shield className="w-4 h-4 text-nhi-400" />
          </div>
          <div>
            <h1 className="text-sm font-bold text-white">
              NHI Security <span className="text-nhi-400">Testbed</span>
            </h1>
            <p className="text-[9px] text-gray-600 uppercase tracking-widest">
              Non-Human Identity Attack Dashboard
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 text-[10px]">
            {connected ? (
              <>
                <Wifi className="w-3 h-3 text-green-400" />
                <span className="text-green-400">Live</span>
              </>
            ) : reconnecting ? (
              <>
                <WifiOff className="w-3 h-3 text-yellow-400 animate-pulse" />
                <span className="text-yellow-400">Reconnecting</span>
              </>
            ) : (
              <>
                <WifiOff className="w-3 h-3 text-gray-600" />
                <span className="text-gray-600">Offline</span>
              </>
            )}
          </div>
          <Link to="/interactive" className="btn-ghost text-xs flex items-center gap-1">
            <Settings className="w-3 h-3" />
            Interactive
          </Link>
          <button
            onClick={() => document.documentElement.requestFullscreen?.()}
            className="btn-ghost text-xs flex items-center gap-1"
          >
            <Maximize2 className="w-3 h-3" />
          </button>
        </div>
      </header>

      {/* Stats bar */}
      <div className="px-3 py-2">
        <StatsBar state={state} alertCount={alerts.length} compact />
      </div>

      {/* Main content area */}
      <div className="flex-1 flex gap-2 px-3 pb-2 min-h-0">
        {/* Left: Network topology (60%) */}
        <div className="w-[60%] flex flex-col min-h-0">
          <div className="flex-1 min-h-0">
            <NetworkTopology
              alerts={alerts}
              activeScenario={state.activeScenario}
            />
          </div>
        </div>

        {/* Right: Timeline + Alerts (40%) */}
        <div className="w-[40%] flex flex-col gap-2 min-h-0">
          <div className="h-[35%] min-h-0">
            <AttackTimeline
              phases={phases}
              currentPhase={state.currentPhase}
              scenarioName={state.activeScenario || undefined}
              compact
            />
          </div>
          <div className="h-[65%] min-h-0">
            <AlertFeed alerts={alerts} compact />
          </div>
        </div>
      </div>

      {/* Bottom: MITRE heatmap */}
      <div className="px-3 pb-2">
        <MitreHeatmap entries={mitreData} compact />
      </div>
    </div>
  );
}
