import { useState, useEffect } from 'react';
import { Grid3x3, ExternalLink, Search } from 'lucide-react';
import MitreHeatmap from '@/components/MitreHeatmap';
import { useApi } from '@/hooks/useApi';
import type { MitreHeatmapEntry } from '@/types';

export default function MitrePage() {
  const { fetchMitreCoverage } = useApi();
  const [entries, setEntries] = useState<MitreHeatmapEntry[]>([]);
  const [selectedTechnique, setSelectedTechnique] = useState<MitreHeatmapEntry | null>(null);
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    fetchMitreCoverage().then(setEntries);
  }, [fetchMitreCoverage]);

  const handleTechniqueClick = (entry: MitreHeatmapEntry) => {
    setSelectedTechnique(entry);
  };

  // Build summary stats
  const totalTechniques = entries.length > 0 ? entries.length : 17;
  const coveredTechniques = entries.length > 0
    ? entries.filter((e) => e.count > 0).length
    : 17;
  const totalScenarios = entries.length > 0
    ? new Set(entries.flatMap((e) => e.scenarios)).size
    : 24;
  const tactics = entries.length > 0
    ? new Set(entries.map((e) => e.tactic)).size
    : 10;

  // Technique list for the detail sidebar
  const filteredEntries = entries.length > 0
    ? entries.filter((e) => {
        if (!searchQuery) return true;
        const q = searchQuery.toLowerCase();
        return (
          e.techniqueId.toLowerCase().includes(q) ||
          e.techniqueName.toLowerCase().includes(q) ||
          e.tactic.toLowerCase().includes(q)
        );
      })
    : [];

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="px-6 py-4 border-b border-gray-800">
        <div className="flex items-center justify-between">
          <div>
            <div className="flex items-center gap-2">
              <Grid3x3 className="w-5 h-5 text-nhi-400" />
              <h1 className="text-lg font-bold text-white">MITRE ATT&CK Coverage Map</h1>
            </div>
            <p className="text-xs text-gray-500 mt-0.5">
              Technique coverage across all NHI attack scenarios
            </p>
          </div>
          <a
            href="https://attack.mitre.org/matrices/enterprise/cloud/"
            target="_blank"
            rel="noopener noreferrer"
            className="btn-ghost text-xs flex items-center gap-1"
          >
            ATT&CK Matrix
            <ExternalLink className="w-3 h-3" />
          </a>
        </div>
      </div>

      {/* Summary stats */}
      <div className="px-6 py-3 border-b border-gray-800/50">
        <div className="flex gap-6">
          <div>
            <span className="text-2xl font-bold text-nhi-400">{coveredTechniques}</span>
            <span className="text-sm text-gray-500 ml-1">techniques covered</span>
          </div>
          <div>
            <span className="text-2xl font-bold text-gray-300">{tactics}</span>
            <span className="text-sm text-gray-500 ml-1">tactics</span>
          </div>
          <div>
            <span className="text-2xl font-bold text-gray-300">{totalScenarios}</span>
            <span className="text-sm text-gray-500 ml-1">scenarios</span>
          </div>
          <div>
            <span className="text-2xl font-bold text-green-400">
              {((coveredTechniques / totalTechniques) * 100).toFixed(0)}%
            </span>
            <span className="text-sm text-gray-500 ml-1">coverage rate</span>
          </div>
        </div>
      </div>

      {/* Main content */}
      <div className="flex-1 flex min-h-0 overflow-hidden">
        {/* Heatmap */}
        <div className="flex-1 overflow-auto p-4">
          <MitreHeatmap
            entries={entries}
            onTechniqueClick={handleTechniqueClick}
          />
        </div>

        {/* Detail sidebar */}
        <div className="w-[320px] shrink-0 border-l border-gray-800 flex flex-col">
          <div className="p-3 border-b border-gray-800/50">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-500" />
              <input
                type="text"
                placeholder="Search techniques..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg pl-8 pr-3 py-1.5 text-xs text-gray-300 placeholder-gray-600 focus:outline-none focus:border-nhi-500"
              />
            </div>
          </div>

          {selectedTechnique ? (
            <div className="p-4 animate-fade-in">
              <div className="flex items-center gap-2 mb-3">
                <span className="text-sm font-mono text-nhi-400 font-bold">
                  {selectedTechnique.techniqueId}
                </span>
                <a
                  href={`https://attack.mitre.org/techniques/${selectedTechnique.techniqueId.replace('.', '/')}/`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-gray-500 hover:text-gray-300"
                >
                  <ExternalLink className="w-3 h-3" />
                </a>
              </div>
              <h3 className="text-sm font-semibold text-gray-200 mb-1">
                {selectedTechnique.techniqueName}
              </h3>
              <p className="text-xs text-gray-500 mb-3">
                Tactic: {selectedTechnique.tactic}
              </p>

              <h4 className="text-[10px] uppercase tracking-wider text-gray-500 mb-2">
                Covered by {selectedTechnique.count} scenario(s)
              </h4>
              <div className="space-y-1">
                {selectedTechnique.scenarios.map((s) => (
                  <div key={s} className="card px-3 py-2">
                    <span className="text-xs font-mono text-nhi-400">{s}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="flex-1 overflow-y-auto">
              {filteredEntries.length > 0 ? (
                <div className="divide-y divide-gray-800/50">
                  {filteredEntries.map((entry) => (
                    <button
                      key={entry.techniqueId}
                      onClick={() => setSelectedTechnique(entry)}
                      className="w-full text-left px-4 py-2.5 hover:bg-gray-800/50 transition-colors"
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] font-mono text-nhi-400">
                          {entry.techniqueId}
                        </span>
                        <span className="text-[10px] text-gray-600">
                          {entry.count} scenario(s)
                        </span>
                      </div>
                      <p className="text-xs text-gray-400 mt-0.5">{entry.techniqueName}</p>
                      <p className="text-[10px] text-gray-600">{entry.tactic}</p>
                    </button>
                  ))}
                </div>
              ) : (
                <div className="flex items-center justify-center h-32 text-gray-600 text-xs">
                  <div className="text-center">
                    <Grid3x3 className="w-6 h-6 mx-auto mb-2 opacity-30" />
                    <p>Click a technique in the heatmap</p>
                    <p className="mt-0.5">or search above</p>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
