import { useState, useEffect, useCallback } from 'react';
import {
  Trophy,
  Flag,
  Send,
  X,
  CheckCircle2,
  Clock,
  Users,
  Star,
  Zap,
  Shield,
  Lock,
  ChevronUp,
} from 'lucide-react';

const BASE_URL = import.meta.env.VITE_API_URL || '';

interface Challenge {
  id: string;
  title: string;
  description: string;
  category: string;
  points: number;
  difficulty: string;
  hint: string;
  completed: boolean;
}

interface ScoreboardEntry {
  session_id: string;
  name: string;
  team: string;
  score: number;
  completed: number;
  total: number;
  started: string;
}

interface SessionData {
  session_id: string;
  name: string;
  team: string;
  score: number;
  completed: string[];
  started: string;
}

const DIFFICULTY_COLORS: Record<string, string> = {
  easy: 'bg-green-500/20 text-green-400 border-green-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  hard: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  expert: 'bg-red-500/20 text-red-400 border-red-500/30',
};

const CATEGORY_COLORS: Record<string, string> = {
  'credential-discovery': 'bg-blue-500/20 text-blue-400',
  'cloud-metadata': 'bg-cyan-500/20 text-cyan-400',
  cicd: 'bg-purple-500/20 text-purple-400',
  kubernetes: 'bg-indigo-500/20 text-indigo-400',
  'spiffe-spire': 'bg-teal-500/20 text-teal-400',
  'ai-agent': 'bg-pink-500/20 text-pink-400',
  'kill-chain': 'bg-red-500/20 text-red-400',
  evasion: 'bg-gray-500/20 text-gray-400',
};

export default function CtfPage() {
  const [sessionId, setSessionId] = useState<string | null>(() =>
    localStorage.getItem('ctf_session_id')
  );
  const [sessionData, setSessionData] = useState<SessionData | null>(null);
  const [challenges, setChallenges] = useState<Challenge[]>([]);
  const [totalPoints, setTotalPoints] = useState(0);
  const [scoreboard, setScoreboard] = useState<ScoreboardEntry[]>([]);
  const [registerName, setRegisterName] = useState('');
  const [registerTeam, setRegisterTeam] = useState('');
  const [selectedChallenge, setSelectedChallenge] = useState<Challenge | null>(null);
  const [flagInput, setFlagInput] = useState('');
  const [submitResult, setSubmitResult] = useState<{
    correct: boolean;
    message: string;
    points_awarded: number;
  } | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [activeTab, setActiveTab] = useState<'challenges' | 'scoreboard'>('challenges');

  // Fetch challenges
  const fetchChallenges = useCallback(async () => {
    try {
      const params = sessionId ? `?session_id=${sessionId}` : '';
      const res = await fetch(`${BASE_URL}/api/ctf/challenges${params}`);
      if (!res.ok) return;
      const data = await res.json();
      setChallenges(data.challenges || []);
      setTotalPoints(data.total_points || 0);
    } catch {
      // API unavailable
    }
  }, [sessionId]);

  // Fetch scoreboard
  const fetchScoreboard = useCallback(async () => {
    try {
      const res = await fetch(`${BASE_URL}/api/ctf/scoreboard`);
      if (!res.ok) return;
      const data = await res.json();
      setScoreboard(data.scoreboard || []);
    } catch {
      // API unavailable
    }
  }, []);

  // Fetch session data
  const fetchSession = useCallback(async () => {
    if (!sessionId) return;
    try {
      const res = await fetch(`${BASE_URL}/api/ctf/session/${sessionId}`);
      if (!res.ok) {
        // Session expired/invalid
        setSessionId(null);
        localStorage.removeItem('ctf_session_id');
        return;
      }
      const data = await res.json();
      setSessionData(data);
    } catch {
      // API unavailable
    }
  }, [sessionId]);

  // Poll for updates
  useEffect(() => {
    fetchChallenges();
    fetchScoreboard();
    fetchSession();
    const interval = setInterval(() => {
      fetchScoreboard();
      fetchChallenges();
      fetchSession();
    }, 5000);
    return () => clearInterval(interval);
  }, [fetchChallenges, fetchScoreboard, fetchSession]);

  // Register
  const handleRegister = async () => {
    if (!registerName.trim()) return;
    try {
      const res = await fetch(`${BASE_URL}/api/ctf/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: registerName.trim(), team: registerTeam.trim() }),
      });
      if (!res.ok) return;
      const data = await res.json();
      setSessionId(data.session_id);
      localStorage.setItem('ctf_session_id', data.session_id);
    } catch {
      // API unavailable
    }
  };

  // Submit flag
  const handleSubmitFlag = async () => {
    if (!selectedChallenge || !flagInput.trim() || !sessionId) return;
    setSubmitting(true);
    setSubmitResult(null);
    try {
      const res = await fetch(
        `${BASE_URL}/api/ctf/submit/${selectedChallenge.id}?session_id=${sessionId}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ flag: flagInput.trim() }),
        }
      );
      if (!res.ok) return;
      const data = await res.json();
      setSubmitResult(data);
      if (data.correct) {
        fetchChallenges();
        fetchScoreboard();
        fetchSession();
      }
    } catch {
      // API unavailable
    } finally {
      setSubmitting(false);
    }
  };

  const completedCount = challenges.filter((c) => c.completed).length;
  const currentScore = sessionData?.score ?? 0;

  // Registration screen
  if (!sessionId) {
    return (
      <div className="h-full flex items-center justify-center">
        <div className="w-full max-w-md p-8">
          <div className="text-center mb-8">
            <div className="w-16 h-16 rounded-2xl bg-nhi-500/20 border border-nhi-500/30 flex items-center justify-center mx-auto mb-4">
              <Flag className="w-8 h-8 text-nhi-400" />
            </div>
            <h1 className="text-2xl font-bold text-white">NHI Security CTF</h1>
            <p className="text-sm text-gray-400 mt-2">
              DEFCON Demo Labs — Capture The Flag
            </p>
            <p className="text-xs text-gray-600 mt-1">
              10 challenges across NHI attack categories
            </p>
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-gray-400 mb-1.5">
                Your Name / Handle
              </label>
              <input
                type="text"
                value={registerName}
                onChange={(e) => setRegisterName(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleRegister()}
                placeholder="h4ck3r"
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-sm text-gray-300 placeholder-gray-600 focus:outline-none focus:border-nhi-500"
                autoFocus
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-400 mb-1.5">
                Team (optional)
              </label>
              <input
                type="text"
                value={registerTeam}
                onChange={(e) => setRegisterTeam(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleRegister()}
                placeholder="Team name"
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-sm text-gray-300 placeholder-gray-600 focus:outline-none focus:border-nhi-500"
              />
            </div>
            <button
              onClick={handleRegister}
              disabled={!registerName.trim()}
              className="w-full bg-nhi-500 hover:bg-nhi-600 disabled:bg-gray-700 disabled:text-gray-500 text-white font-medium rounded-lg px-4 py-2.5 text-sm transition-colors"
            >
              Start CTF
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="px-6 py-4 border-b border-gray-800">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-lg font-bold text-white flex items-center gap-2">
              <Flag className="w-5 h-5 text-nhi-400" />
              NHI Security CTF
            </h1>
            <p className="text-xs text-gray-500 mt-0.5">
              Playing as <span className="text-nhi-400">{sessionData?.name ?? '...'}</span>
              {sessionData?.team ? (
                <span className="text-gray-600"> / {sessionData.team}</span>
              ) : null}
              <span className="text-gray-700 ml-2">ID: {sessionId}</span>
            </p>
          </div>
          <div className="flex items-center gap-4">
            <div className="text-right">
              <div className="text-xl font-bold text-nhi-400">{currentScore}</div>
              <div className="text-[10px] text-gray-500 uppercase tracking-wider">Points</div>
            </div>
            <div className="text-right">
              <div className="text-xl font-bold text-white">
                {completedCount}
                <span className="text-gray-500 text-sm">/{challenges.length}</span>
              </div>
              <div className="text-[10px] text-gray-500 uppercase tracking-wider">Solved</div>
            </div>
          </div>
        </div>

        {/* Progress bar */}
        <div className="mt-3 h-1.5 bg-gray-800 rounded-full overflow-hidden">
          <div
            className="h-full bg-gradient-to-r from-nhi-600 to-nhi-400 rounded-full transition-all duration-500"
            style={{
              width: totalPoints > 0 ? `${(currentScore / totalPoints) * 100}%` : '0%',
            }}
          />
        </div>

        {/* Tab toggle */}
        <div className="flex gap-1 mt-3">
          <button
            onClick={() => setActiveTab('challenges')}
            className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
              activeTab === 'challenges'
                ? 'bg-gray-700 text-white'
                : 'text-gray-500 hover:text-gray-300'
            }`}
          >
            <Zap className="w-3 h-3 inline mr-1" />
            Challenges
          </button>
          <button
            onClick={() => setActiveTab('scoreboard')}
            className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
              activeTab === 'scoreboard'
                ? 'bg-gray-700 text-white'
                : 'text-gray-500 hover:text-gray-300'
            }`}
          >
            <Trophy className="w-3 h-3 inline mr-1" />
            Scoreboard
          </button>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-6">
        {activeTab === 'challenges' ? (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
            {challenges.map((c) => (
              <button
                key={c.id}
                onClick={() => {
                  setSelectedChallenge(c);
                  setFlagInput('');
                  setSubmitResult(null);
                }}
                className={`text-left p-4 rounded-lg border transition-all duration-150 ${
                  c.completed
                    ? 'bg-green-500/5 border-green-500/20'
                    : 'bg-gray-800/50 border-gray-700/50 hover:border-gray-600'
                }`}
              >
                <div className="flex items-start justify-between mb-2">
                  <div className="flex items-center gap-2">
                    {c.completed ? (
                      <CheckCircle2 className="w-4 h-4 text-green-400 shrink-0" />
                    ) : (
                      <Lock className="w-4 h-4 text-gray-600 shrink-0" />
                    )}
                    <span className="text-xs font-mono text-gray-500">{c.id}</span>
                  </div>
                  <span className="text-sm font-bold text-nhi-400">+{c.points}</span>
                </div>
                <h3
                  className={`text-sm font-semibold mb-1 ${
                    c.completed ? 'text-green-400' : 'text-white'
                  }`}
                >
                  {c.title}
                </h3>
                <p className="text-xs text-gray-500 mb-3 line-clamp-2">{c.description}</p>
                <div className="flex items-center gap-2">
                  <span
                    className={`text-[10px] px-1.5 py-0.5 rounded border ${
                      DIFFICULTY_COLORS[c.difficulty] || 'bg-gray-500/20 text-gray-400'
                    }`}
                  >
                    {c.difficulty}
                  </span>
                  <span
                    className={`text-[10px] px-1.5 py-0.5 rounded ${
                      CATEGORY_COLORS[c.category] || 'bg-gray-500/20 text-gray-400'
                    }`}
                  >
                    {c.category}
                  </span>
                </div>
              </button>
            ))}
          </div>
        ) : (
          <div className="max-w-2xl mx-auto">
            <div className="flex items-center gap-2 mb-4">
              <Trophy className="w-5 h-5 text-yellow-400" />
              <h2 className="text-lg font-bold text-white">Live Scoreboard</h2>
              <span className="text-xs text-gray-600 ml-auto">
                <Users className="w-3 h-3 inline mr-1" />
                {scoreboard.length} players
              </span>
            </div>
            {scoreboard.length === 0 ? (
              <div className="text-center text-gray-600 text-sm py-12">
                No players registered yet. Be the first!
              </div>
            ) : (
              <div className="space-y-2">
                {scoreboard.map((entry, idx) => (
                  <div
                    key={entry.session_id}
                    className={`flex items-center gap-3 p-3 rounded-lg border ${
                      entry.session_id === sessionId
                        ? 'bg-nhi-500/10 border-nhi-500/30'
                        : 'bg-gray-800/50 border-gray-700/50'
                    }`}
                  >
                    <div className="w-8 text-center">
                      {idx === 0 ? (
                        <Star className="w-5 h-5 text-yellow-400 mx-auto" />
                      ) : idx === 1 ? (
                        <Star className="w-5 h-5 text-gray-400 mx-auto" />
                      ) : idx === 2 ? (
                        <Star className="w-5 h-5 text-orange-400 mx-auto" />
                      ) : (
                        <span className="text-sm font-mono text-gray-500">#{idx + 1}</span>
                      )}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="text-sm font-medium text-white truncate">
                        {entry.name}
                        {entry.session_id === sessionId && (
                          <span className="text-[10px] text-nhi-400 ml-2">(you)</span>
                        )}
                      </div>
                      {entry.team && (
                        <div className="text-[10px] text-gray-500 truncate">{entry.team}</div>
                      )}
                    </div>
                    <div className="text-right">
                      <div className="text-sm font-bold text-nhi-400">{entry.score}</div>
                      <div className="text-[10px] text-gray-500">
                        {entry.completed}/{entry.total} solved
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Challenge modal */}
      {selectedChallenge && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-gray-900 border border-gray-700 rounded-xl w-full max-w-lg shadow-2xl">
            {/* Modal header */}
            <div className="flex items-center justify-between p-5 border-b border-gray-800">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-xs font-mono text-gray-500">
                    {selectedChallenge.id}
                  </span>
                  <span
                    className={`text-[10px] px-1.5 py-0.5 rounded border ${
                      DIFFICULTY_COLORS[selectedChallenge.difficulty] ||
                      'bg-gray-500/20 text-gray-400'
                    }`}
                  >
                    {selectedChallenge.difficulty}
                  </span>
                  <span className="text-sm font-bold text-nhi-400">
                    +{selectedChallenge.points}
                  </span>
                </div>
                <h2 className="text-base font-bold text-white">{selectedChallenge.title}</h2>
              </div>
              <button
                onClick={() => setSelectedChallenge(null)}
                className="text-gray-500 hover:text-gray-300 p-1"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal body */}
            <div className="p-5 space-y-4">
              <p className="text-sm text-gray-300">{selectedChallenge.description}</p>

              <div className="bg-gray-800/50 border border-gray-700/50 rounded-lg p-3">
                <div className="flex items-center gap-1.5 mb-1">
                  <Shield className="w-3.5 h-3.5 text-yellow-400" />
                  <span className="text-xs font-medium text-yellow-400">Hint</span>
                </div>
                <p className="text-xs text-gray-400">{selectedChallenge.hint}</p>
              </div>

              {selectedChallenge.completed ? (
                <div className="flex items-center gap-2 bg-green-500/10 border border-green-500/20 rounded-lg p-3">
                  <CheckCircle2 className="w-4 h-4 text-green-400" />
                  <span className="text-sm text-green-400 font-medium">
                    Challenge completed!
                  </span>
                </div>
              ) : (
                <>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={flagInput}
                      onChange={(e) => setFlagInput(e.target.value)}
                      onKeyDown={(e) => e.key === 'Enter' && handleSubmitFlag()}
                      placeholder="NHI{your_flag_here}"
                      className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-sm font-mono text-gray-300 placeholder-gray-600 focus:outline-none focus:border-nhi-500"
                      autoFocus
                    />
                    <button
                      onClick={handleSubmitFlag}
                      disabled={!flagInput.trim() || submitting}
                      className="bg-nhi-500 hover:bg-nhi-600 disabled:bg-gray-700 disabled:text-gray-500 text-white rounded-lg px-4 py-2.5 text-sm font-medium transition-colors flex items-center gap-1.5"
                    >
                      {submitting ? (
                        <Clock className="w-4 h-4 animate-spin" />
                      ) : (
                        <Send className="w-4 h-4" />
                      )}
                      Submit
                    </button>
                  </div>

                  {submitResult && (
                    <div
                      className={`flex items-center gap-2 rounded-lg p-3 border ${
                        submitResult.correct
                          ? 'bg-green-500/10 border-green-500/20'
                          : 'bg-red-500/10 border-red-500/20'
                      }`}
                    >
                      {submitResult.correct ? (
                        <CheckCircle2 className="w-4 h-4 text-green-400 shrink-0" />
                      ) : (
                        <X className="w-4 h-4 text-red-400 shrink-0" />
                      )}
                      <span
                        className={`text-sm ${
                          submitResult.correct ? 'text-green-400' : 'text-red-400'
                        }`}
                      >
                        {submitResult.message}
                      </span>
                      {submitResult.points_awarded > 0 && (
                        <span className="text-sm text-nhi-400 ml-auto font-bold flex items-center gap-1">
                          <ChevronUp className="w-3 h-3" />+{submitResult.points_awarded}
                        </span>
                      )}
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
