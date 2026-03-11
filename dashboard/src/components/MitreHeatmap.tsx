import { useState } from 'react';
import { Grid3x3, X } from 'lucide-react';
import type { MitreHeatmapEntry } from '@/types';

interface MitreHeatmapProps {
  entries: MitreHeatmapEntry[];
  compact?: boolean;
  onTechniqueClick?: (entry: MitreHeatmapEntry) => void;
}

const TACTICS_ORDER = [
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Impact',
];

// Default coverage data when API is unavailable
const DEFAULT_ENTRIES: MitreHeatmapEntry[] = [
  { techniqueId: 'T1552.001', techniqueName: 'Credentials In Files', tactic: 'Credential Access', count: 5, scenarios: ['S1-01', 'S1-02', 'S1-04', 'S1-05', 'S3-05'] },
  { techniqueId: 'T1552.004', techniqueName: 'Private Keys', tactic: 'Credential Access', count: 2, scenarios: ['S1-03', 'S4-02'] },
  { techniqueId: 'T1552.005', techniqueName: 'Cloud Instance Metadata', tactic: 'Credential Access', count: 3, scenarios: ['S2-01', 'S3-01'] },
  { techniqueId: 'T1552.007', techniqueName: 'Container API', tactic: 'Credential Access', count: 1, scenarios: ['S2-02'] },
  { techniqueId: 'T1528', techniqueName: 'Steal App Access Token', tactic: 'Credential Access', count: 3, scenarios: ['S2-03', 'S2-04', 'S5-03'] },
  { techniqueId: 'T1555', techniqueName: 'Credentials from Stores', tactic: 'Credential Access', count: 2, scenarios: ['S2-05', 'S3-04'] },
  { techniqueId: 'T1078.004', techniqueName: 'Cloud Accounts', tactic: 'Privilege Escalation', count: 1, scenarios: ['S3-01'] },
  { techniqueId: 'T1069.003', techniqueName: 'Cloud Groups', tactic: 'Discovery', count: 1, scenarios: ['S3-02'] },
  { techniqueId: 'T1087.004', techniqueName: 'Cloud Account Discovery', tactic: 'Discovery', count: 1, scenarios: ['S3-03'] },
  { techniqueId: 'T1083', techniqueName: 'File and Directory Discovery', tactic: 'Discovery', count: 2, scenarios: ['S1-01', 'S5-01'] },
  { techniqueId: 'T1021', techniqueName: 'Remote Services', tactic: 'Lateral Movement', count: 1, scenarios: ['S4-01'] },
  { techniqueId: 'T1195.002', techniqueName: 'Supply Chain: Software', tactic: 'Initial Access', count: 1, scenarios: ['S5-01'] },
  { techniqueId: 'T1098', techniqueName: 'Account Manipulation', tactic: 'Persistence', count: 1, scenarios: ['S5-02'] },
  { techniqueId: 'T1059', techniqueName: 'Command & Scripting', tactic: 'Execution', count: 1, scenarios: ['S5-04'] },
  { techniqueId: 'T1078', techniqueName: 'Valid Accounts', tactic: 'Defense Evasion', count: 2, scenarios: ['S3-01', 'S4-05'] },
  { techniqueId: 'T1530', techniqueName: 'Data from Cloud Storage', tactic: 'Collection', count: 1, scenarios: ['S2-01'] },
  { techniqueId: 'T1496', techniqueName: 'Resource Hijacking', tactic: 'Impact', count: 1, scenarios: ['S5-01'] },
];

function intensityColor(count: number, maxCount: number): string {
  if (count === 0) return 'bg-gray-800/40';
  const ratio = count / Math.max(maxCount, 1);
  if (ratio >= 0.8) return 'bg-red-500/60 hover:bg-red-500/70';
  if (ratio >= 0.5) return 'bg-orange-500/50 hover:bg-orange-500/60';
  if (ratio >= 0.25) return 'bg-yellow-500/40 hover:bg-yellow-500/50';
  return 'bg-nhi-500/30 hover:bg-nhi-500/40';
}

export default function MitreHeatmap({ entries, compact = false, onTechniqueClick }: MitreHeatmapProps) {
  const [selectedEntry, setSelectedEntry] = useState<MitreHeatmapEntry | null>(null);

  const data = entries.length > 0 ? entries : DEFAULT_ENTRIES;
  const maxCount = Math.max(...data.map((e) => e.count), 1);
  const coveredTechniques = new Set(data.filter((e) => e.count > 0).map((e) => e.techniqueId));
  const totalTechniques = data.length;

  // Group by tactic
  const tacticMap = new Map<string, MitreHeatmapEntry[]>();
  TACTICS_ORDER.forEach((t) => tacticMap.set(t, []));
  data.forEach((entry) => {
    const existing = tacticMap.get(entry.tactic);
    if (existing) {
      existing.push(entry);
    }
  });

  const handleClick = (entry: MitreHeatmapEntry) => {
    setSelectedEntry(entry);
    onTechniqueClick?.(entry);
  };

  return (
    <div className={`card ${compact ? '' : 'h-full'} flex flex-col`}>
      <div className="card-header">
        <div className="flex items-center gap-2">
          <Grid3x3 className="w-4 h-4 text-nhi-400" />
          <h3 className="text-sm font-medium text-gray-300">MITRE ATT&CK Coverage</h3>
        </div>
        <span className="text-xs">
          <span className="text-nhi-400 font-medium">{coveredTechniques.size}</span>
          <span className="text-gray-600">/{totalTechniques} techniques</span>
        </span>
      </div>

      <div className={`flex-1 overflow-x-auto ${compact ? 'p-2' : 'p-4'}`}>
        <div className="flex gap-1 min-w-max">
          {TACTICS_ORDER.map((tactic) => {
            const techniques = tacticMap.get(tactic) || [];
            if (compact && techniques.length === 0) return null;

            return (
              <div key={tactic} className="flex flex-col gap-1" style={{ minWidth: compact ? 80 : 110 }}>
                {/* Tactic header */}
                <div
                  className={`text-center border-b border-gray-700/50 ${
                    compact ? 'pb-1 mb-0.5' : 'pb-2 mb-1'
                  }`}
                >
                  <span
                    className={`${
                      compact ? 'text-[8px]' : 'text-[10px]'
                    } font-medium uppercase tracking-wider text-gray-500`}
                  >
                    {compact ? tactic.split(' ').map(w => w[0]).join('') : tactic}
                  </span>
                </div>

                {/* Technique cells */}
                {techniques.map((entry) => (
                  <button
                    key={entry.techniqueId}
                    onClick={() => handleClick(entry)}
                    className={`${intensityColor(entry.count, maxCount)} rounded ${
                      compact ? 'px-1 py-0.5' : 'px-2 py-1.5'
                    } text-left transition-colors duration-150 border border-transparent hover:border-gray-600/50`}
                    title={`${entry.techniqueId}: ${entry.techniqueName} (${entry.count} scenarios)`}
                  >
                    <span className={`block ${compact ? 'text-[7px]' : 'text-[9px]'} font-mono text-gray-400`}>
                      {entry.techniqueId}
                    </span>
                    {!compact && (
                      <span className="block text-[9px] text-gray-300 leading-tight mt-0.5 truncate">
                        {entry.techniqueName}
                      </span>
                    )}
                  </button>
                ))}

                {techniques.length === 0 && !compact && (
                  <div className="bg-gray-800/20 rounded px-2 py-3 text-center">
                    <span className="text-[9px] text-gray-600">No coverage</span>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Detail panel */}
      {selectedEntry && !compact && (
        <div className="border-t border-gray-700/50 p-3 animate-slide-in">
          <div className="flex items-start justify-between">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-nhi-400">
                  {selectedEntry.techniqueId}
                </span>
                <span className="text-sm font-medium text-gray-200">
                  {selectedEntry.techniqueName}
                </span>
              </div>
              <p className="text-xs text-gray-500 mt-1">
                Tactic: {selectedEntry.tactic} | Covered by {selectedEntry.count} scenario(s)
              </p>
              <div className="flex gap-1 mt-2 flex-wrap">
                {selectedEntry.scenarios.map((s) => (
                  <span key={s} className="badge border border-nhi-500/30 bg-nhi-500/10 text-nhi-400">
                    {s}
                  </span>
                ))}
              </div>
            </div>
            <button
              onClick={() => setSelectedEntry(null)}
              className="text-gray-500 hover:text-gray-300 p-1"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
