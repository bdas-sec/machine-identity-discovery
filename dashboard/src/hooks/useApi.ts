import { useState, useCallback } from 'react';
import type { DashboardState, Scenario, MitreHeatmapEntry } from '@/types';

const BASE_URL = import.meta.env.VITE_API_URL || '';

async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (!res.ok) {
    throw new Error(`API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

export function useApi() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchDashboardState = useCallback(async (): Promise<DashboardState> => {
    try {
      return await apiFetch<DashboardState>('/api/dashboard/state');
    } catch {
      // Return sensible defaults when API is unavailable
      return {
        scenariosRun: 0,
        alertsGenerated: 0,
        detectionRate: 0,
        activeScenario: null,
        currentPhase: 0,
        totalPhases: 0,
      };
    }
  }, []);

  const fetchScenarios = useCallback(async (): Promise<Scenario[]> => {
    try {
      return await apiFetch<Scenario[]>('/api/scenarios');
    } catch {
      return [];
    }
  }, []);

  const executeScenario = useCallback(async (scenarioId: string) => {
    setLoading(true);
    setError(null);
    try {
      const result = await apiFetch(`/api/scenarios/${scenarioId}/run`, {
        method: 'POST',
        body: JSON.stringify({ verbose: true }),
      });
      return result;
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Unknown error';
      setError(msg);
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchMitreCoverage = useCallback(async (): Promise<MitreHeatmapEntry[]> => {
    try {
      return await apiFetch<MitreHeatmapEntry[]>('/api/dashboard/mitre-coverage');
    } catch {
      return [];
    }
  }, []);

  return {
    loading,
    error,
    fetchDashboardState,
    fetchScenarios,
    executeScenario,
    fetchMitreCoverage,
  };
}
