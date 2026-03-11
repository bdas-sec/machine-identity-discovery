import { useEffect, useRef } from 'react';
import { AlertTriangle, Bell } from 'lucide-react';
import type { Alert } from '@/types';
import { getSeverityBg, getSeverity } from '@/types';

interface AlertFeedProps {
  alerts: Alert[];
  maxItems?: number;
  compact?: boolean;
}

function formatTime(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString('en-US', {
      hour12: false,
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  } catch {
    return ts;
  }
}

function SeverityBadge({ level }: { level: number }) {
  const severity = getSeverity(level);
  const bg = getSeverityBg(level);
  return (
    <span className={`badge border ${bg} uppercase text-[10px]`}>
      {severity === 'critical' || severity === 'high' ? (
        <AlertTriangle className="w-2.5 h-2.5 mr-1" />
      ) : null}
      L{level}
    </span>
  );
}

export default function AlertFeed({ alerts, maxItems = 50, compact = false }: AlertFeedProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const autoScrollRef = useRef(true);
  const visibleAlerts = alerts.slice(0, maxItems);

  // Auto-scroll when new alerts arrive, if user hasn't scrolled up
  useEffect(() => {
    if (autoScrollRef.current && containerRef.current) {
      containerRef.current.scrollTop = 0;
    }
  }, [alerts.length]);

  const handleScroll = () => {
    if (!containerRef.current) return;
    // If scrolled near top (alerts are newest-first), auto-scroll is on
    autoScrollRef.current = containerRef.current.scrollTop < 50;
  };

  if (visibleAlerts.length === 0) {
    return (
      <div className="card h-full flex flex-col">
        <div className="card-header">
          <div className="flex items-center gap-2">
            <Bell className="w-4 h-4 text-gray-500" />
            <h3 className="text-sm font-medium text-gray-300">Alert Feed</h3>
          </div>
          <span className="text-xs text-gray-600">0 alerts</span>
        </div>
        <div className="flex-1 flex items-center justify-center text-gray-600 text-sm">
          <div className="text-center">
            <Bell className="w-8 h-8 mx-auto mb-2 opacity-30" />
            <p>Waiting for alerts...</p>
            <p className="text-xs mt-1">Run a scenario to generate detections</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="card h-full flex flex-col">
      <div className="card-header">
        <div className="flex items-center gap-2">
          <Bell className="w-4 h-4 text-nhi-400" />
          <h3 className="text-sm font-medium text-gray-300">Alert Feed</h3>
        </div>
        <span className="text-xs text-gray-500">{alerts.length} alerts</span>
      </div>
      <div
        ref={containerRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto"
      >
        {visibleAlerts.map((alert, idx) => (
          <div
            key={alert.id}
            className={`px-3 py-2.5 border-b border-gray-700/30 hover:bg-gray-750/50 transition-colors ${
              idx === 0 ? 'animate-slide-in' : ''
            }`}
          >
            <div className="flex items-start justify-between gap-2">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 mb-1">
                  <SeverityBadge level={alert.level} />
                  <span className="text-[10px] font-mono text-gray-500">
                    {alert.ruleId}
                  </span>
                  <span className="text-[10px] text-gray-600">
                    {formatTime(alert.timestamp)}
                  </span>
                </div>
                <p
                  className={`text-gray-300 leading-snug truncate ${
                    compact ? 'text-xs' : 'text-sm'
                  }`}
                  title={alert.description}
                >
                  {alert.description}
                </p>
                <div className="flex items-center gap-2 mt-1">
                  <span className="text-[10px] text-gray-600">
                    Agent: <span className="text-gray-400">{alert.agent}</span>
                  </span>
                  {alert.mitreTechniques && alert.mitreTechniques.length > 0 && (
                    <span className="text-[10px] text-nhi-500">
                      {alert.mitreTechniques.join(', ')}
                    </span>
                  )}
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
