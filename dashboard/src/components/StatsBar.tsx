import { useEffect, useState, useRef } from 'react';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Play,
  Layers,
} from 'lucide-react';
import type { DashboardState } from '@/types';

interface StatsBarProps {
  state: DashboardState;
  alertCount: number;
  compact?: boolean;
}

function AnimatedCounter({ value, duration = 600 }: { value: number; duration?: number }) {
  const [display, setDisplay] = useState(0);
  const prevRef = useRef(0);

  useEffect(() => {
    const start = prevRef.current;
    const diff = value - start;
    if (diff === 0) return;

    const startTime = performance.now();
    const animate = (now: number) => {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      // Ease out cubic
      const eased = 1 - Math.pow(1 - progress, 3);
      setDisplay(Math.round(start + diff * eased));
      if (progress < 1) requestAnimationFrame(animate);
    };
    requestAnimationFrame(animate);
    prevRef.current = value;
  }, [value, duration]);

  return <>{display}</>;
}

function ProgressRing({ percent, size = 40 }: { percent: number; size?: number }) {
  const strokeWidth = 3;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (percent / 100) * circumference;
  const color = percent >= 90 ? '#22c55e' : percent >= 70 ? '#eab308' : '#ef4444';

  return (
    <svg width={size} height={size} className="transform -rotate-90">
      <circle
        cx={size / 2}
        cy={size / 2}
        r={radius}
        fill="none"
        stroke="rgba(255,255,255,0.1)"
        strokeWidth={strokeWidth}
      />
      <circle
        cx={size / 2}
        cy={size / 2}
        r={radius}
        fill="none"
        stroke={color}
        strokeWidth={strokeWidth}
        strokeDasharray={circumference}
        strokeDashoffset={offset}
        strokeLinecap="round"
        className="transition-all duration-700 ease-out"
      />
    </svg>
  );
}

export default function StatsBar({ state, alertCount, compact = false }: StatsBarProps) {
  const stats = [
    {
      icon: Play,
      label: 'Scenarios Run',
      value: <AnimatedCounter value={state.scenariosRun} />,
      color: 'text-nhi-400',
      bgColor: 'bg-nhi-500/10',
    },
    {
      icon: AlertTriangle,
      label: 'Alerts Generated',
      value: <AnimatedCounter value={alertCount} />,
      color: 'text-orange-400',
      bgColor: 'bg-orange-500/10',
    },
    {
      icon: CheckCircle2,
      label: 'Detection Rate',
      value: (
        <div className="flex items-center gap-2">
          <ProgressRing percent={state.detectionRate} size={compact ? 32 : 40} />
          <span>{state.detectionRate.toFixed(1)}%</span>
        </div>
      ),
      color: state.detectionRate >= 90 ? 'text-green-400' : 'text-yellow-400',
      bgColor: state.detectionRate >= 90 ? 'bg-green-500/10' : 'bg-yellow-500/10',
    },
    {
      icon: Activity,
      label: 'Active Scenario',
      value: state.activeScenario || 'Idle',
      color: state.activeScenario ? 'text-green-400' : 'text-gray-500',
      bgColor: state.activeScenario ? 'bg-green-500/10' : 'bg-gray-500/10',
    },
    {
      icon: Layers,
      label: 'Current Phase',
      value: state.activeScenario
        ? `${state.currentPhase}/${state.totalPhases}`
        : '--',
      color: 'text-blue-400',
      bgColor: 'bg-blue-500/10',
    },
  ];

  return (
    <div
      className={`grid gap-3 ${
        compact ? 'grid-cols-5' : 'grid-cols-2 md:grid-cols-3 lg:grid-cols-5'
      }`}
    >
      {stats.map((stat) => (
        <div
          key={stat.label}
          className={`card flex items-center gap-3 ${compact ? 'px-3 py-2' : 'px-4 py-3'}`}
        >
          <div
            className={`${stat.bgColor} rounded-lg ${
              compact ? 'p-1.5' : 'p-2'
            } shrink-0`}
          >
            <stat.icon className={`${stat.color} ${compact ? 'w-4 h-4' : 'w-5 h-5'}`} />
          </div>
          <div className="min-w-0">
            <p className="text-[10px] uppercase tracking-wider text-gray-500 truncate">
              {stat.label}
            </p>
            <p
              className={`${stat.color} font-semibold ${
                compact ? 'text-sm' : 'text-lg'
              } truncate`}
            >
              {stat.value}
            </p>
          </div>
        </div>
      ))}
    </div>
  );
}
