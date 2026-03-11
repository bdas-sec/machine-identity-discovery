import { useState } from 'react';
import {
  Play,
  CheckCircle2,
  Loader2,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import type { Scenario } from '@/types';

interface ScenarioCardProps {
  scenario: Scenario;
  onRun?: (id: string) => void;
  running?: boolean;
  completed?: boolean;
}

const DIFFICULTY_COLORS: Record<string, string> = {
  easy: 'bg-green-500/20 border-green-500/40 text-green-400',
  medium: 'bg-yellow-500/20 border-yellow-500/40 text-yellow-400',
  hard: 'bg-orange-500/20 border-orange-500/40 text-orange-400',
  expert: 'bg-red-500/20 border-red-500/40 text-red-400',
};

const CATEGORY_COLORS: Record<string, string> = {
  'api keys & secrets': 'bg-nhi-500/20 border-nhi-500/40 text-nhi-400',
  'cloud metadata': 'bg-blue-500/20 border-blue-500/40 text-blue-400',
  'ci/cd pipeline': 'bg-green-500/20 border-green-500/40 text-green-400',
  kubernetes: 'bg-purple-500/20 border-purple-500/40 text-purple-400',
  'ai agent': 'bg-pink-500/20 border-pink-500/40 text-pink-400',
  infrastructure: 'bg-gray-500/20 border-gray-500/40 text-gray-400',
};

function getCategoryColor(category: string): string {
  const key = category.toLowerCase();
  for (const [k, v] of Object.entries(CATEGORY_COLORS)) {
    if (key.includes(k)) return v;
  }
  return 'bg-gray-500/20 border-gray-500/40 text-gray-400';
}

export default function ScenarioCard({ scenario, onRun, running = false, completed = false }: ScenarioCardProps) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="card hover:border-gray-600/50 transition-colors duration-200">
      <div className="p-4">
        {/* Header */}
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 mb-1.5">
              <span className="text-xs font-mono text-gray-500">{scenario.id}</span>
              <span className={`badge border ${getCategoryColor(scenario.category)}`}>
                {scenario.category}
              </span>
              <span
                className={`badge border ${
                  DIFFICULTY_COLORS[scenario.difficulty.toLowerCase()] ||
                  DIFFICULTY_COLORS.medium
                }`}
              >
                {scenario.difficulty}
              </span>
            </div>
            <h3 className="text-sm font-semibold text-gray-200 leading-snug">
              {scenario.name}
            </h3>
            <p className="text-xs text-gray-500 mt-1 leading-relaxed">
              {scenario.description}
            </p>
          </div>

          {/* Run button */}
          <button
            onClick={() => onRun?.(scenario.id)}
            disabled={running}
            className={`shrink-0 flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all duration-200 ${
              completed
                ? 'bg-green-500/15 text-green-400 border border-green-500/30'
                : running
                ? 'bg-yellow-500/15 text-yellow-400 border border-yellow-500/30'
                : 'bg-nhi-500/15 text-nhi-400 border border-nhi-500/30 hover:bg-nhi-500/25'
            }`}
          >
            {completed ? (
              <CheckCircle2 className="w-3.5 h-3.5" />
            ) : running ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Play className="w-3.5 h-3.5" />
            )}
            {completed ? 'Done' : running ? 'Running' : 'Run'}
          </button>
        </div>

        {/* MITRE techniques */}
        {scenario.mitreAttack && scenario.mitreAttack.techniques.length > 0 && (
          <div className="flex gap-1 mt-2 flex-wrap">
            {scenario.mitreAttack.techniques.map((t) => (
              <span
                key={t.id}
                className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-gray-800 text-gray-400 border border-gray-700/50"
                title={t.name}
              >
                {t.id}
              </span>
            ))}
          </div>
        )}

        {/* Expandable details */}
        <button
          onClick={() => setExpanded(!expanded)}
          className="flex items-center gap-1 mt-3 text-[10px] text-gray-500 hover:text-gray-400 transition-colors"
        >
          {expanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
          {expanded ? 'Hide details' : 'Show phases & expected alerts'}
        </button>

        {expanded && (
          <div className="mt-3 space-y-3 animate-fade-in">
            {/* Phases */}
            {scenario.phases.length > 0 && (
              <div>
                <h4 className="text-[10px] uppercase tracking-wider text-gray-500 mb-1.5">
                  Phases
                </h4>
                <div className="space-y-1">
                  {scenario.phases.map((phase, idx) => (
                    <div
                      key={idx}
                      className="flex items-center gap-2 text-xs text-gray-400"
                    >
                      <span className="text-gray-600 font-mono w-4">{idx + 1}.</span>
                      <span>{phase.name}</span>
                      {phase.critical && (
                        <AlertTriangle className="w-3 h-3 text-red-400" />
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Expected alerts */}
            {scenario.expectedAlerts.length > 0 && (
              <div>
                <h4 className="text-[10px] uppercase tracking-wider text-gray-500 mb-1.5">
                  Expected Alerts
                </h4>
                <div className="space-y-1">
                  {scenario.expectedAlerts.map((alert) => (
                    <div
                      key={alert.ruleId}
                      className="flex items-center gap-2 text-xs"
                    >
                      <span className="font-mono text-nhi-400">{alert.ruleId}</span>
                      <span className="text-gray-600">L{alert.level}</span>
                      <span className="text-gray-400 truncate">{alert.description}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
