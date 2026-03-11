import { CheckCircle2, Circle, Loader2, XCircle, ChevronRight } from 'lucide-react';
import type { Phase } from '@/types';

interface AttackTimelineProps {
  phases: Phase[];
  currentPhase: number;
  scenarioName?: string;
  compact?: boolean;
}

function PhaseIcon({ status }: { status: Phase['status'] }) {
  switch (status) {
    case 'completed':
      return <CheckCircle2 className="w-5 h-5 text-green-400" />;
    case 'running':
      return <Loader2 className="w-5 h-5 text-yellow-400 animate-spin" />;
    case 'failed':
      return <XCircle className="w-5 h-5 text-red-400" />;
    default:
      return <Circle className="w-5 h-5 text-gray-600" />;
  }
}

function statusColor(status: Phase['status']): string {
  switch (status) {
    case 'completed':
      return 'border-green-500/50 bg-green-500/10';
    case 'running':
      return 'border-yellow-500/50 bg-yellow-500/10 animate-glow';
    case 'failed':
      return 'border-red-500/50 bg-red-500/10';
    default:
      return 'border-gray-700 bg-gray-800/50';
  }
}

function connectorColor(leftStatus: Phase['status']): string {
  if (leftStatus === 'completed') return 'bg-green-500/40';
  if (leftStatus === 'running') return 'bg-yellow-500/40';
  return 'bg-gray-700/40';
}

export default function AttackTimeline({
  phases,
  currentPhase,
  scenarioName,
  compact = false,
}: AttackTimelineProps) {
  if (phases.length === 0) {
    return (
      <div className="card h-full flex flex-col">
        <div className="card-header">
          <h3 className="text-sm font-medium text-gray-300">Attack Timeline</h3>
        </div>
        <div className="flex-1 flex items-center justify-center text-gray-600 text-sm">
          <div className="text-center">
            <ChevronRight className="w-8 h-8 mx-auto mb-2 opacity-30" />
            <p>No active scenario</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="card h-full flex flex-col">
      <div className="card-header">
        <div>
          <h3 className="text-sm font-medium text-gray-300">Attack Timeline</h3>
          {scenarioName && (
            <p className="text-xs text-nhi-400 mt-0.5">{scenarioName}</p>
          )}
        </div>
        <span className="text-xs text-gray-500">
          Phase {currentPhase + 1}/{phases.length}
        </span>
      </div>

      <div className={`flex-1 overflow-x-auto ${compact ? 'p-3' : 'p-4'}`}>
        <div className="flex items-start gap-0 min-w-max">
          {phases.map((phase, idx) => (
            <div key={idx} className="flex items-start">
              {/* Phase pill */}
              <div
                className={`relative border rounded-lg ${statusColor(phase.status)} ${
                  compact ? 'px-3 py-2 min-w-[120px]' : 'px-4 py-3 min-w-[160px]'
                } transition-all duration-300`}
              >
                <div className="flex items-center gap-2 mb-1">
                  <PhaseIcon status={phase.status} />
                  <span
                    className={`font-medium ${
                      compact ? 'text-xs' : 'text-sm'
                    } text-gray-200`}
                  >
                    {phase.name}
                  </span>
                </div>
                {!compact && (
                  <p className="text-xs text-gray-500 ml-7 leading-relaxed">
                    {phase.description}
                  </p>
                )}
                {phase.critical && (
                  <span className="absolute -top-2 -right-2 px-1.5 py-0.5 bg-red-500 text-white text-[9px] font-bold rounded uppercase">
                    Critical
                  </span>
                )}
              </div>

              {/* Connector */}
              {idx < phases.length - 1 && (
                <div className="flex items-center self-center px-1">
                  <div
                    className={`h-0.5 w-6 ${connectorColor(phase.status)} transition-colors duration-300`}
                  />
                  <ChevronRight
                    className={`w-3 h-3 ${
                      phase.status === 'completed'
                        ? 'text-green-500/60'
                        : 'text-gray-700'
                    }`}
                  />
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
