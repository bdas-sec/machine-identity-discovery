import { useState, useEffect, useMemo, useCallback } from 'react';
import { Search, Filter, Play, LayoutGrid, List } from 'lucide-react';
import ScenarioCard from '@/components/ScenarioCard';
import { useApi } from '@/hooks/useApi';
import type { Scenario } from '@/types';

const CATEGORIES = [
  'All',
  'API Keys & Secrets',
  'Cloud Metadata',
  'CI/CD Pipeline',
  'Kubernetes',
  'AI Agent',
  'Infrastructure',
];

const DIFFICULTIES = ['All', 'Easy', 'Medium', 'Hard', 'Expert'];

// Hardcoded scenario catalog for offline use
const OFFLINE_SCENARIOS: Scenario[] = [
  {
    id: 'S1-01', name: 'Hardcoded Credentials in Source Code', category: 'API Keys & Secrets',
    difficulty: 'Easy', description: 'Discover and exfiltrate hardcoded credentials from application source code',
    phases: [
      { name: 'Source Code Access', description: 'Access source files', critical: false, status: 'pending' },
      { name: 'Pattern Search', description: 'Search for credential patterns', critical: false, status: 'pending' },
      { name: 'Config Analysis', description: 'Extract from config', critical: false, status: 'pending' },
      { name: 'Exfiltration', description: 'Extract credentials', critical: true, status: 'pending' },
    ],
    expectedAlerts: [
      { ruleId: '100600', level: 7, description: 'Sensitive config file access' },
      { ruleId: '100601', level: 10, description: 'Credential discovery attempt' },
      { ruleId: '100900', level: 12, description: 'AWS Access Key pattern detected' },
    ],
  },
  {
    id: 'S1-02', name: 'AWS Credentials Discovery', category: 'API Keys & Secrets',
    difficulty: 'Easy', description: 'Search for AWS credential files on filesystem',
    phases: [{ name: 'AWS Dir Search', description: 'Search ~/.aws/', critical: false, status: 'pending' }],
    expectedAlerts: [{ ruleId: '100601', level: 10, description: 'AWS credential file access' }],
  },
  {
    id: 'S1-03', name: 'SSH Key Discovery', category: 'API Keys & Secrets',
    difficulty: 'Easy', description: 'Enumerate SSH private keys for lateral movement',
    phases: [{ name: 'SSH Dir Enum', description: 'Search ~/.ssh/', critical: false, status: 'pending' }],
    expectedAlerts: [{ ruleId: '100602', level: 10, description: 'SSH key file access' }],
  },
  {
    id: 'S2-01', name: 'IMDS Credential Theft (AWS)', category: 'Cloud Metadata',
    difficulty: 'Medium', description: 'Extract IAM credentials from AWS Instance Metadata Service',
    phases: [
      { name: 'IMDS Discovery', description: 'Discover metadata endpoint', critical: false, status: 'pending' },
      { name: 'Role Enumeration', description: 'List IAM roles', critical: false, status: 'pending' },
      { name: 'Credential Extraction', description: 'Extract temp credentials', critical: true, status: 'pending' },
    ],
    expectedAlerts: [
      { ruleId: '100650', level: 8, description: 'IMDS metadata access' },
      { ruleId: '100651', level: 12, description: 'IMDS IAM credential request' },
    ],
  },
  {
    id: 'S2-02', name: 'Process Environment Harvesting', category: 'Cloud Metadata',
    difficulty: 'Medium', description: 'Extract secrets from process environment variables',
    phases: [{ name: 'Env Extraction', description: 'Read /proc/1/environ', critical: true, status: 'pending' }],
    expectedAlerts: [{ ruleId: '100607', level: 10, description: 'Process environ access' }],
  },
  {
    id: 'S2-03', name: 'K8s ServiceAccount Token Theft', category: 'Kubernetes',
    difficulty: 'Medium', description: 'Extract Kubernetes service account token from pod',
    phases: [{ name: 'Token Extraction', description: 'Read SA token', critical: true, status: 'pending' }],
    expectedAlerts: [{ ruleId: '100750', level: 10, description: 'SA token access' }],
  },
  {
    id: 'S2-04', name: 'CI/CD Token Extraction', category: 'CI/CD Pipeline',
    difficulty: 'Medium', description: 'Extract GitHub/GitLab tokens from CI/CD runner',
    phases: [{ name: 'Token Discovery', description: 'Find CI tokens in env', critical: true, status: 'pending' }],
    expectedAlerts: [{ ruleId: '100800', level: 10, description: 'CI/CD token access' }],
  },
  {
    id: 'S3-01', name: 'IMDS Role Assumption', category: 'Cloud Metadata',
    difficulty: 'Hard', description: 'Use stolen IMDS credentials to assume IAM role',
    phases: [
      { name: 'Credential Retrieval', description: 'Get IMDS creds', critical: false, status: 'pending' },
      { name: 'Role Assumption', description: 'Assume IAM role', critical: true, status: 'pending' },
    ],
    expectedAlerts: [{ ruleId: '100657', level: 14, description: 'Cloud credential abuse' }],
  },
  {
    id: 'S3-02', name: 'Kubernetes RBAC Probing', category: 'Kubernetes',
    difficulty: 'Hard', description: 'Enumerate Kubernetes permissions via RBAC',
    phases: [{ name: 'RBAC Enum', description: 'List K8s permissions', critical: false, status: 'pending' }],
    expectedAlerts: [{ ruleId: '100752', level: 10, description: 'K8s RBAC probing' }],
  },
  {
    id: 'S5-01', name: 'Pipeline Poisoning', category: 'CI/CD Pipeline',
    difficulty: 'Hard', description: 'Identify and modify CI/CD pipeline configurations for persistence',
    phases: [
      { name: 'Pipeline Discovery', description: 'Find pipeline configs', critical: false, status: 'pending' },
      { name: 'Config Injection', description: 'Inject malicious steps', critical: true, status: 'pending' },
    ],
    expectedAlerts: [{ ruleId: '100803', level: 12, description: 'Pipeline config modification' }],
  },
];

export default function ScenariosPage() {
  const { fetchScenarios, executeScenario, loading } = useApi();
  const [scenarios, setScenarios] = useState<Scenario[]>(OFFLINE_SCENARIOS);
  const [search, setSearch] = useState('');
  const [category, setCategory] = useState('All');
  const [difficulty, setDifficulty] = useState('All');
  const [runningId, setRunningId] = useState<string | null>(null);
  const [completedIds, setCompletedIds] = useState<Set<string>>(new Set());
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('grid');

  useEffect(() => {
    fetchScenarios().then((data) => {
      if (data.length > 0) setScenarios(data);
    });
  }, [fetchScenarios]);

  const filtered = useMemo(() => {
    return scenarios.filter((s) => {
      if (category !== 'All' && s.category !== category) return false;
      if (difficulty !== 'All' && s.difficulty !== difficulty) return false;
      if (search) {
        const q = search.toLowerCase();
        return (
          s.name.toLowerCase().includes(q) ||
          s.id.toLowerCase().includes(q) ||
          s.description.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [scenarios, search, category, difficulty]);

  const handleRun = useCallback(async (id: string) => {
    setRunningId(id);
    await executeScenario(id.toLowerCase().replace('s', 's'));
    setCompletedIds((prev) => new Set([...prev, id]));
    setRunningId(null);
  }, [executeScenario]);

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="px-6 py-4 border-b border-gray-800">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-lg font-bold text-white">Scenario Catalog</h1>
            <p className="text-xs text-gray-500 mt-0.5">
              {filtered.length} of {scenarios.length} scenarios
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setViewMode('grid')}
              className={`p-1.5 rounded ${viewMode === 'grid' ? 'bg-gray-700 text-white' : 'text-gray-500 hover:text-gray-300'}`}
            >
              <LayoutGrid className="w-4 h-4" />
            </button>
            <button
              onClick={() => setViewMode('list')}
              className={`p-1.5 rounded ${viewMode === 'list' ? 'bg-gray-700 text-white' : 'text-gray-500 hover:text-gray-300'}`}
            >
              <List className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="px-6 py-3 border-b border-gray-800/50 flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 max-w-xs">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
          <input
            type="text"
            placeholder="Search scenarios..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-gray-800 border border-gray-700 rounded-lg pl-9 pr-3 py-2 text-sm text-gray-300 placeholder-gray-600 focus:outline-none focus:border-nhi-500"
          />
        </div>

        <div className="flex items-center gap-1.5">
          <Filter className="w-3.5 h-3.5 text-gray-500" />
          <select
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-300 focus:outline-none focus:border-nhi-500"
          >
            {CATEGORIES.map((c) => (
              <option key={c} value={c}>{c}</option>
            ))}
          </select>
        </div>

        <select
          value={difficulty}
          onChange={(e) => setDifficulty(e.target.value)}
          className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-300 focus:outline-none focus:border-nhi-500"
        >
          {DIFFICULTIES.map((d) => (
            <option key={d} value={d}>{d}</option>
          ))}
        </select>

        {(search || category !== 'All' || difficulty !== 'All') && (
          <button
            onClick={() => { setSearch(''); setCategory('All'); setDifficulty('All'); }}
            className="text-xs text-gray-500 hover:text-gray-300 underline"
          >
            Clear filters
          </button>
        )}
      </div>

      {/* Scenario grid */}
      <div className="flex-1 overflow-y-auto p-6">
        {filtered.length === 0 ? (
          <div className="flex items-center justify-center h-40 text-gray-600 text-sm">
            No scenarios match your filters.
          </div>
        ) : (
          <div
            className={
              viewMode === 'grid'
                ? 'grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3'
                : 'space-y-3 max-w-3xl'
            }
          >
            {filtered.map((scenario) => (
              <ScenarioCard
                key={scenario.id}
                scenario={scenario}
                onRun={handleRun}
                running={runningId === scenario.id}
                completed={completedIds.has(scenario.id)}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
