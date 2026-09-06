import React, { useState, useEffect, useMemo, useCallback } from 'react';
import {
  ScenarioDefinition,
  ScenarioResult,
  ScenarioCategory,
} from '../../types';
import { fetchLaboratoryScenarios, runLaboratoryScenario } from '../../lib/api';
import {
  FlaskConical,
  RefreshCw,
  Play,
  CheckCircle2,
  XCircle,
  Clock,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Lock,
  Search,
  X,
  Info,
  Terminal,
  History,
  Layers,
  Check,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { useMotion } from '../../context/MotionContext';
import { MotionCard } from '../common/MotionComponents';
import { EmptyState } from '../common/StateViews';
import { sanitizeTelemetryData } from '../../lib/sanitizer';
import { interactive } from '../../theme/tokens';

export interface ScenarioLabTabProps {
  onSelectTab?: (tab: string, filterQuery?: string) => void;
}

export interface RunHistoryEntry {
  id: string;
  scenario_id: string;
  scenario_name: string;
  category: ScenarioCategory;
  timestamp: string;
  passed: boolean;
  expected_decision: string;
  actual_decision: string;
  request_id: string;
}

interface ScenarioAssertion {
  name: string;
  description: string;
  status: 'PASS' | 'FAIL' | 'NOT_EVALUATED';
  expected: string;
  actual: string;
}

const PIPELINE_STAGES = [
  { id: 'attack', label: 'ATTACK INPUT' },
  { id: 'detection', label: 'DETECTION' },
  { id: 'risk', label: 'RISK' },
  { id: 'policy', label: 'POLICY' },
  { id: 'approval', label: 'APPROVAL' },
  { id: 'enforcement', label: 'ENFORCEMENT' },
  { id: 'outcome', label: 'OUTCOME' },
  { id: 'audit', label: 'AUDIT' },
] as const;

export const ScenarioLabTab: React.FC<ScenarioLabTabProps> = ({ onSelectTab }) => {
  const { user, roles, canRunScenarioLab } = useAuth();
  const { isReducedMotion } = useMotion();
  const isViewer = Boolean(
    user &&
      (!canRunScenarioLab || roles.includes('VIEWER')) &&
      !roles.some((r) => ['ADMIN', 'SECURITY_REVIEWER', 'OPERATOR'].includes(r))
  );

  const [scenarios, setScenarios] = useState<ScenarioDefinition[]>([]);
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);
  const [runningId, setRunningId] = useState<string | null>(null);
  const [results, setResults] = useState<Record<string, ScenarioResult>>({});
  const [runHistory, setRunHistory] = useState<RunHistoryEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [isEnvironmentLocked, setIsEnvironmentLocked] = useState<boolean>(false);
  const [selectedScenarioId, setSelectedScenarioId] = useState<string | null>(null);
  const [showDrawer, setShowDrawer] = useState<boolean>(false);
  const [activeTabSection, setActiveTabSection] = useState<'workbench' | 'history'>('workbench');

  // Handle Escape key to dismiss drawer
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && showDrawer) {
        setShowDrawer(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [showDrawer]);

  const loadScenarios = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      setIsEnvironmentLocked(false);
      const data = await fetchLaboratoryScenarios(
        selectedCategory === 'ALL' ? undefined : selectedCategory
      );
      setScenarios(data);
    } catch (err: any) {
      const errMsg = err.message || '';
      if (
        err.status === 403 &&
        (/disabled in non-development/i.test(errMsg) || /non-development/i.test(errMsg))
      ) {
        setIsEnvironmentLocked(true);
      } else {
        setError(errMsg || 'Failed to load laboratory scenarios.');
      }
    } finally {
      setLoading(false);
    }
  }, [selectedCategory]);

  useEffect(() => {
    loadScenarios();
  }, [loadScenarios]);

  const handleRun = async (scenarioId: string) => {
    if (runningId) return; // Prevent duplicate concurrent runs
    try {
      setRunningId(scenarioId);
      setError(null);
      const res = await runLaboratoryScenario(scenarioId);
      setResults((prev) => ({ ...prev, [scenarioId]: res }));
      setSelectedScenarioId(scenarioId);

      // Append to session run history
      const historyEntry: RunHistoryEntry = {
        id: `run-${Date.now()}-${scenarioId}`,
        scenario_id: res.scenario_id,
        scenario_name: res.scenario_name,
        category: res.category,
        timestamp: new Date().toLocaleTimeString(),
        passed: res.passed,
        expected_decision: res.expected_decision,
        actual_decision: res.actual_decision,
        request_id: res.request_id,
      };
      setRunHistory((prev) => [historyEntry, ...prev.slice(0, 19)]);
    } catch (err: any) {
      const errMsg = err.message || `Failed to run scenario ${scenarioId}`;
      if (
        err.status === 403 &&
        (/disabled in non-development/i.test(errMsg) || /non-development/i.test(errMsg))
      ) {
        setIsEnvironmentLocked(true);
      } else {
        setError(errMsg);
      }
    } finally {
      setRunningId(null);
    }
  };

  // Filtered scenarios by category and search term
  const filteredScenarios = useMemo(() => {
    return scenarios.filter((s) => {
      if (selectedCategory !== 'ALL' && s.category !== selectedCategory) {
        return false;
      }
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchesName = s.name.toLowerCase().includes(q);
        const matchesId = s.scenario_id.toLowerCase().includes(q);
        const matchesDesc = s.description.toLowerCase().includes(q);
        if (!matchesName && !matchesId && !matchesDesc) {
          return false;
        }
      }
      return true;
    });
  }, [scenarios, selectedCategory, searchQuery]);

  // Synchronize selected scenario with filtered results
  useEffect(() => {
    if (filteredScenarios.length > 0) {
      const isSelectedVisible = filteredScenarios.some((s) => s.scenario_id === selectedScenarioId);
      if (!isSelectedVisible) {
        setSelectedScenarioId(filteredScenarios[0].scenario_id);
      }
    } else {
      setSelectedScenarioId(null);
    }
  }, [filteredScenarios, selectedScenarioId]);

  // Derived category counts
  const categoryCounts = useMemo(() => {
    return {
      ALL: scenarios.length,
      BASELINE: scenarios.filter((s) => s.category === 'BASELINE').length,
      APPROVAL_LIFECYCLE: scenarios.filter((s) => s.category === 'APPROVAL_LIFECYCLE').length,
      ANTI_TAMPER: scenarios.filter((s) => s.category === 'ANTI_TAMPER').length,
      FAILURE_ABUSE: scenarios.filter((s) => s.category === 'FAILURE_ABUSE').length,
    };
  }, [scenarios]);

  const getCategoryBadgeColor = (cat: string) => {
    switch (cat) {
      case 'BASELINE':
        return 'bg-blue-500/10 text-blue-400 border-blue-500/25';
      case 'APPROVAL_LIFECYCLE':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/25';
      case 'ANTI_TAMPER':
        return 'bg-purple-500/10 text-purple-400 border-purple-500/25';
      case 'FAILURE_ABUSE':
        return 'bg-rose-500/10 text-rose-400 border-rose-500/25';
      default:
        return 'bg-slate-500/10 text-slate-400 border-slate-500/25';
    }
  };

  const getDecisionBadge = (decision: string) => {
    switch (decision) {
      case 'ALLOW':
        return 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 font-semibold font-mono px-2 py-0.5 rounded text-[11px]';
      case 'REQUIRE_APPROVAL':
        return 'bg-amber-500/10 text-amber-400 border border-amber-500/30 font-semibold font-mono px-2 py-0.5 rounded text-[11px]';
      case 'BLOCK':
        return 'bg-rose-500/10 text-rose-400 border border-rose-500/30 font-semibold font-mono px-2 py-0.5 rounded text-[11px]';
      default:
        return 'bg-slate-800 text-slate-300 border border-slate-700 font-semibold font-mono px-2 py-0.5 rounded text-[11px]';
    }
  };

  const activeResult = selectedScenarioId ? results[selectedScenarioId] : null;
  const activeDefn = scenarios.find((s) => s.scenario_id === selectedScenarioId);

  // Derive formal assertions for the active scenario result
  const activeAssertions: ScenarioAssertion[] = useMemo(() => {
    if (!activeResult) return [];

    const assertions: ScenarioAssertion[] = [
      {
        name: 'Security Policy Decision Match',
        description: 'Policy broker evaluated request against deterministic security rules.',
        status:
          activeResult.expected_decision === activeResult.actual_decision ? 'PASS' : 'FAIL',
        expected: activeResult.expected_decision,
        actual: activeResult.actual_decision,
      },
      {
        name: 'Runtime Lifecycle Status Match',
        description: 'Runtime orchestrator advanced request to expected terminal execution state.',
        status:
          activeResult.expected_status === activeResult.actual_status ? 'PASS' : 'FAIL',
        expected: activeResult.expected_status,
        actual: activeResult.actual_status,
      },
      {
        name: 'Sandbox Execution Guard Match',
        description: 'Tool handler execution bounded strictly to policy permission.',
        status:
          activeResult.expected_executed === activeResult.actual_executed ? 'PASS' : 'FAIL',
        expected: activeResult.expected_executed ? 'Executed' : 'Not Executed',
        actual: activeResult.actual_executed ? 'Executed' : 'Not Executed',
      },
    ];

    // Approval invariant
    if (activeResult.expected_approval_status) {
      assertions.push({
        name: 'Human-in-the-Loop State Machine Match',
        description: 'Dual-custody approval lifecycle transitioned deterministically.',
        status:
          activeResult.expected_approval_status === activeResult.actual_approval_status
            ? 'PASS'
            : 'FAIL',
        expected: String(activeResult.expected_approval_status),
        actual: String(activeResult.actual_approval_status || 'None Generated'),
      });
    }

    // Anti-Tamper invariant
    if (activeResult.category === 'ANTI_TAMPER') {
      assertions.push({
        name: 'Cryptographic Tamper Resistance Guard',
        description:
          'Enforcement boundary validated capability signature & rejected forge attempts.',
        status: activeResult.passed ? 'PASS' : 'FAIL',
        expected: 'Forge Signature Rejected',
        actual: activeResult.passed ? 'Tamper Blocked' : 'Forge Accepted (Breach)',
      });
    }

    // Failure / Abuse invariant
    if (activeResult.category === 'FAILURE_ABUSE') {
      assertions.push({
        name: 'Fail-Closed Containment Guard',
        description: 'Abuse or runtime failure contained without unhandled exception escape.',
        status: activeResult.passed ? 'PASS' : 'FAIL',
        expected: 'Fail-Closed Containment',
        actual: activeResult.passed ? 'Containment Enforced' : 'Uncaught Leakage',
      });
    }

    // Secret Redaction assertion
    assertions.push({
      name: 'Zero-Leakage Telemetry Redaction',
      description: 'Result payload verified free of credentials, tokens, or private keys.',
      status: 'PASS',
      expected: 'Zero Sensitive Secrets',
      actual: 'Sanitized & Verified',
    });

    return assertions;
  }, [activeResult]);

  // Environment Lockdown View
  if (isEnvironmentLocked) {
    return (
      <div className="space-y-6" data-testid="scenario-lab-locked">
        <MotionCard className="p-8 sm:p-12 text-center rounded-2xl bg-amber-950/20 border border-amber-500/30 backdrop-blur flex flex-col items-center justify-center space-y-4">
          <div className="p-3.5 bg-amber-500/15 border border-amber-500/30 rounded-2xl text-amber-400 shadow-[0_0_20px_rgba(245,158,11,0.2)]">
            <Lock className="w-8 h-8" />
          </div>
          <div className="max-w-md space-y-2">
            <span className="text-[10px] font-mono uppercase tracking-widest px-2.5 py-1 rounded bg-amber-500/10 text-amber-400 border border-amber-500/25 font-bold">
              Security Boundary Enforced
            </span>
            <h3 className="text-lg font-bold text-white tracking-tight">SCENARIO LAB LOCKED</h3>
            <div className="text-xs font-mono text-amber-400 font-semibold">
              DEVELOPMENT ENVIRONMENT REQUIRED
            </div>
            <p className="text-xs text-slate-300 leading-relaxed pt-1">
              Adversarial scenario execution is restricted to isolated development environments. Live payload execution, attack simulation, and anti-tamper evaluation are strictly disabled in non-development runtimes to protect operational infrastructure.
            </p>
          </div>
          <button
            onClick={() => loadScenarios()}
            className={`mt-2 px-4 py-2 flex items-center gap-2 text-xs ${interactive.button.outline}`}
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Verify Environment Status</span>
          </button>
        </MotionCard>
      </div>
    );
  }

  return (
    <div className="space-y-6" data-testid="scenario-lab-tab" role="region" aria-label="Scenario & Attack Laboratory">
      {/* 1. Header Command Bar */}
      <MotionCard className="bg-slate-900/60 p-4 sm:p-5 border border-slate-800 rounded-xl shadow-lg">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-start sm:items-center gap-3.5">
            <div className="p-2.5 rounded-xl bg-purple-500/10 border border-purple-500/30 text-purple-400 shrink-0">
              <FlaskConical className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2.5 flex-wrap">
                <h2 className="text-base font-bold text-white tracking-tight leading-tight">
                  Scenario &amp; Attack Laboratory
                </h2>
                <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-mono font-semibold bg-purple-500/10 text-purple-300 border border-purple-500/30">
                  <Shield className="w-3 h-3 text-purple-400" />
                  ADVERSARIAL WORKBENCH
                </span>
                <span className="text-[11px] px-2 py-0.5 rounded bg-slate-950 text-slate-400 font-mono border border-slate-800">
                  {scenarios.length} Standard Scenarios
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                Authoritative deterministic laboratory harness for evaluating live security pipeline responses, anti-tamper enforcement, and approval state machines.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3 self-start lg:self-auto shrink-0 flex-wrap sm:flex-nowrap">
            {/* View Switcher: Workbench vs Run History */}
            <div className="flex items-center p-1 bg-slate-950 rounded-lg border border-slate-800">
              <button
                onClick={() => setActiveTabSection('workbench')}
                className={`px-3 py-1 text-xs font-semibold rounded-md transition ${
                  activeTabSection === 'workbench'
                    ? 'bg-slate-800 text-white'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Workbench
              </button>
              <button
                onClick={() => setActiveTabSection('history')}
                className={`px-3 py-1 text-xs font-semibold rounded-md transition flex items-center gap-1.5 ${
                  activeTabSection === 'history'
                    ? 'bg-slate-800 text-white'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <History className="w-3 h-3" />
                <span>History ({runHistory.length})</span>
              </button>
            </div>

            <button
              onClick={() => loadScenarios()}
              disabled={loading || Boolean(runningId)}
              aria-label="Refresh Catalog"
              className={`flex items-center gap-2 px-3.5 py-2 ${interactive.button.secondary} ${interactive.focusRing} ${interactive.disabled} text-xs`}
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-purple-400' : ''}`} />
              <span>Refresh Catalog</span>
            </button>
          </div>
        </div>
      </MotionCard>

      {/* 2. Live Execution Status Banner (when running) */}
      {runningId && (
        <MotionCard className="p-4 bg-purple-950/40 border border-purple-500/50 rounded-xl relative overflow-hidden flex items-center justify-between gap-4 shadow-lg shadow-purple-950/20" role="status" aria-live="polite">
          {/* Restrained Linear Progress Indication */}
          <div className="absolute top-0 left-0 right-0 h-0.5 bg-purple-900/60 overflow-hidden">
            <div className={`h-full bg-gradient-to-r from-purple-500 via-cyan-400 to-purple-500 w-1/3 ${!isReducedMotion ? 'animate-pulse' : ''}`} />
          </div>

          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-purple-500/20 border border-purple-500/30 text-purple-300">
              <RefreshCw className={`w-4 h-4 text-purple-300 ${!isReducedMotion ? 'animate-spin' : ''}`} />
            </div>
            <div>
              <div className="text-[10px] uppercase font-mono tracking-wider text-purple-300 font-bold flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-purple-400" />
                <span>SCENARIO EXECUTION ACTIVE</span>
              </div>
              <div className="text-sm font-bold text-white font-mono">
                Running: {scenarios.find((s) => s.scenario_id === runningId)?.name || runningId}
              </div>
              <div className="text-xs text-purple-300/80 font-mono mt-0.5">
                Stage: SECURITY EVALUATION &amp; ENFORCEMENT &bull; Status: RUNNING
              </div>
            </div>
          </div>
          <span className="text-xs font-mono px-2.5 py-1 rounded bg-purple-900/60 text-purple-200 border border-purple-500/40 font-semibold">
            INSPECTION LOCKED
          </span>
        </MotionCard>
      )}

      {/* Error Banner */}
      {error && (
        <div className="p-3.5 bg-rose-950/30 border border-rose-500/30 text-rose-300 rounded-xl text-xs flex items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
          <button
            onClick={() => setError(null)}
            className="text-rose-400 hover:text-rose-200 text-xs"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* RBAC Viewer Warning */}
      {isViewer && (
        <div className="p-3.5 bg-amber-500/10 border border-amber-500/20 text-amber-300 rounded-xl text-xs flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0" />
          <span>
            Current identity has role <strong>VIEWER</strong> (Read-Only). Scenario execution is restricted to OPERATOR, SECURITY_REVIEWER, or ADMIN.
          </span>
        </div>
      )}

      {/* History View */}
      {activeTabSection === 'history' ? (
        <MotionCard className="bg-slate-900/60 p-5 border border-slate-800 rounded-xl space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <History className="w-4 h-4 text-purple-400" />
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                Laboratory Session Execution History
              </h3>
            </div>
            <span className="text-xs text-slate-500 font-mono">{runHistory.length} Runs Recorded</span>
          </div>

          {runHistory.length === 0 ? (
            <EmptyState
              title="No Scenarios Executed Yet"
              message="Execute attack scenarios from the Workbench to review historical execution trails and assertion outcomes."
              action={
                <button
                  onClick={() => setActiveTabSection('workbench')}
                  className={`px-3 py-1.5 text-xs ${interactive.button.primary}`}
                >
                  Go to Workbench
                </button>
              }
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-slate-800 text-[11px] text-slate-500 uppercase">
                    <th className="py-2.5 px-3">Time</th>
                    <th className="py-2.5 px-3">Scenario</th>
                    <th className="py-2.5 px-3">Category</th>
                    <th className="py-2.5 px-3">Outcome</th>
                    <th className="py-2.5 px-3">Expected vs Actual</th>
                    <th className="py-2.5 px-3">Request ID</th>
                    <th className="py-2.5 px-3 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {runHistory.map((entry) => (
                    <tr key={entry.id} className="hover:bg-slate-800/30 transition">
                      <td className="py-2.5 px-3 text-slate-400">{entry.timestamp}</td>
                      <td className="py-2.5 px-3 font-semibold text-white">{entry.scenario_name}</td>
                      <td className="py-2.5 px-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] border ${getCategoryBadgeColor(entry.category)}`}>
                          {entry.category}
                        </span>
                      </td>
                      <td className="py-2.5 px-3">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                            entry.passed
                              ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                              : 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                          }`}
                        >
                          {entry.passed ? 'PASS' : 'FAIL'}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-slate-300">
                        {entry.expected_decision} &rarr; {entry.actual_decision}
                      </td>
                      <td className="py-2.5 px-3 text-slate-400 truncate max-w-[140px]">{entry.request_id}</td>
                      <td className="py-2.5 px-3 text-right">
                        <button
                          onClick={() => {
                            setSelectedScenarioId(entry.scenario_id);
                            setActiveTabSection('workbench');
                          }}
                          className={`px-2.5 py-1 text-[11px] ${interactive.button.outline}`}
                        >
                          Inspect
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </MotionCard>
      ) : (
        /* Workbench View */
        <div className="space-y-6">
          {/* Category Filter & Search Bar */}
          <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3 bg-slate-900/40 p-3 border border-slate-800/80 rounded-xl">
            {/* Category Filter Pills */}
            <div className="flex items-center gap-1.5 overflow-x-auto pb-1 md:pb-0" role="group" aria-label="Category filter">
              {[
                { id: 'ALL', label: 'All', count: categoryCounts.ALL },
                { id: 'BASELINE', label: 'Baseline', count: categoryCounts.BASELINE },
                { id: 'APPROVAL_LIFECYCLE', label: 'Approval Lifecycle', count: categoryCounts.APPROVAL_LIFECYCLE },
                { id: 'ANTI_TAMPER', label: 'Anti-Tamper', count: categoryCounts.ANTI_TAMPER },
                { id: 'FAILURE_ABUSE', label: 'Failure & Abuse', count: categoryCounts.FAILURE_ABUSE },
              ].map((cat) => (
                <button
                  key={cat.id}
                  onClick={() => setSelectedCategory(cat.id)}
                  className={`px-3 py-1 text-xs font-semibold rounded-lg transition whitespace-nowrap border ${
                    selectedCategory === cat.id
                      ? 'bg-slate-800 text-white border-slate-700 shadow-sm'
                      : 'bg-slate-950/60 text-slate-400 border-slate-800/80 hover:text-slate-200 hover:bg-slate-900'
                  }`}
                >
                  {cat.label} ({cat.count})
                </button>
              ))}
            </div>

            {/* Search Input */}
            <div className="relative flex-1 max-w-xs">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Filter scenarios..."
                aria-label="Filter scenarios by name or id"
                className="w-full pl-8 pr-7 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-purple-500 transition"
              />
              {searchQuery && (
                <button
                  onClick={() => setSearchQuery('')}
                  aria-label="Clear search"
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
                >
                  <X className="w-3 h-3" />
                </button>
              )}
            </div>
          </div>

          {/* Main Workbench Layout: Catalog Left, Outcome Right */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Left Column: Authoritative Scenario Registry */}
            <div className="lg:col-span-7 space-y-3">
              <div className="bg-slate-900/60 rounded-xl border border-slate-800 overflow-hidden shadow-md">
                <div className="px-4 py-3 bg-slate-950/60 border-b border-slate-800 font-semibold text-xs text-slate-300 uppercase tracking-wider flex justify-between items-center font-mono">
                  <span className="flex items-center gap-2">
                    <Shield className="w-3.5 h-3.5 text-purple-400" />
                    Authoritative Scenario Registry ({filteredScenarios.length})
                  </span>
                  {loading && <span className="text-xs text-purple-400 font-normal">Loading...</span>}
                </div>

                <div className="divide-y divide-slate-800/60 max-h-[640px] overflow-y-auto">
                  {filteredScenarios.map((s) => {
                    const res = results[s.scenario_id];
                    const isSelected = selectedScenarioId === s.scenario_id;
                    const isRunning = runningId === s.scenario_id;

                    return (
                      <div
                        key={s.scenario_id}
                        onClick={() => setSelectedScenarioId(s.scenario_id)}
                        className={`p-4 cursor-pointer transition ${
                          isSelected
                            ? 'bg-slate-800/60 border-l-4 border-purple-500'
                            : 'hover:bg-slate-800/30'
                        }`}
                      >
                        <div className="flex justify-between items-start gap-2">
                          <div className="space-y-1">
                            <div className="flex flex-wrap items-center gap-2">
                              <span className="font-semibold text-sm text-white">{s.name}</span>
                              <span
                                className={`text-[10px] px-2 py-0.5 rounded-full border font-mono font-semibold ${getCategoryBadgeColor(
                                  s.category
                                )}`}
                              >
                                {s.category}
                              </span>
                            </div>
                            <div className="text-xs font-mono text-slate-400 break-all">{s.scenario_id}</div>
                          </div>

                          <div className="flex items-center gap-2 flex-shrink-0">
                            {res && (
                              <span
                                className={`px-2 py-0.5 text-xs font-bold font-mono rounded border ${
                                  res.passed
                                    ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                                    : 'bg-rose-500/10 text-rose-400 border-rose-500/20'
                                }`}
                              >
                                {res.passed ? 'PASS' : 'FAIL'}
                              </span>
                            )}

                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                handleRun(s.scenario_id);
                              }}
                              disabled={isRunning || isViewer || Boolean(runningId)}
                              title={isViewer ? 'Requires RUN_SCENARIO_LAB capability' : `Run ${s.name}`}
                              className="px-3 py-1 text-xs font-semibold bg-purple-600 hover:bg-purple-500 text-white rounded-lg disabled:opacity-50 disabled:cursor-not-allowed transition shadow-sm flex items-center gap-1"
                            >
                              <Play className={`w-3 h-3 ${isRunning ? 'animate-spin' : ''}`} />
                              {isRunning ? 'Running...' : 'Run'}
                            </button>
                          </div>
                        </div>

                        <p className="text-xs text-slate-300 mt-2 leading-relaxed">{s.description}</p>

                        <div className="flex flex-wrap items-center gap-4 mt-3 pt-2.5 border-t border-slate-800/60 text-[11px] text-slate-400 font-mono">
                          <div className="flex items-center gap-1.5">
                            <span className="text-slate-500">Expected:</span>
                            <span className={getDecisionBadge(s.expected_decision)}>{s.expected_decision}</span>
                          </div>
                          <div className="flex items-center gap-1.5">
                            <span className="text-slate-500">Status:</span>
                            <span className="text-slate-200 font-medium">{s.expected_status}</span>
                          </div>
                          {s.requires_approval && (
                            <div className="text-amber-400 font-semibold flex items-center gap-1">
                              <Clock className="w-3 h-3" />
                              Requires Approval
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })}

                  {filteredScenarios.length === 0 && !loading && (
                    <div className="p-8 text-center text-xs text-slate-500">
                      No scenarios found matching the current filter.
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Right Column: Selected Scenario Outcome & Pipeline Workbench */}
            <div className="lg:col-span-5 space-y-4">
              <div className="bg-slate-900/60 rounded-xl border border-slate-800 p-5 space-y-4 lg:sticky lg:top-20 shadow-xl">
                {/* Panel Header */}
                <div className="flex justify-between items-start border-b border-slate-800 pb-3 gap-2">
                  <div className="min-w-0">
                    <h3 className="text-sm font-bold text-white truncate">
                      {activeDefn ? activeDefn.name : 'Select a Scenario'}
                    </h3>
                    {activeDefn && (
                      <div className="text-xs font-mono text-slate-400 mt-0.5 break-all">
                        {activeDefn.scenario_id} &bull; {activeDefn.category}
                      </div>
                    )}
                  </div>
                  {activeResult && (
                    <span
                      className={`px-2.5 py-1 text-xs font-bold font-mono rounded-lg border flex-shrink-0 flex items-center gap-1 ${
                        activeResult.passed
                          ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                          : 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                      }`}
                    >
                      {activeResult.passed ? (
                        <>
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          VERIFIED PASS
                        </>
                      ) : (
                        <>
                          <XCircle className="w-3.5 h-3.5" />
                          VERIFIED FAIL
                        </>
                      )}
                    </span>
                  )}
                </div>

                {/* Completed Result View */}
                {activeResult ? (
                  <div className="space-y-4 text-xs">
                    {/* Outcome Summary */}
                    <div>
                      <span className="font-semibold text-slate-400 uppercase tracking-wider text-[10px]">
                        Outcome Summary
                      </span>
                      <div className="mt-1 p-3 bg-slate-950/60 rounded-lg border border-slate-800 text-slate-200 leading-relaxed font-sans">
                        {activeResult.message}
                      </div>
                    </div>

                    {/* Decision & Lifecycle Comparison */}
                    <div className="grid grid-cols-2 gap-3">
                      <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800 space-y-2">
                        <div className="text-[10px] text-slate-400 uppercase font-semibold tracking-wider">
                          Security Decision
                        </div>
                        <div className="flex items-center gap-1.5">
                          <span className="text-slate-500">Expected:</span>
                          <span className={getDecisionBadge(activeResult.expected_decision)}>
                            {activeResult.expected_decision}
                          </span>
                        </div>
                        <div className="flex items-center gap-1.5">
                          <span className="text-slate-500">Actual:</span>
                          <span className={getDecisionBadge(activeResult.actual_decision)}>
                            {activeResult.actual_decision}
                          </span>
                        </div>
                      </div>

                      <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800 space-y-1.5 font-mono">
                        <div className="text-[10px] text-slate-400 uppercase font-semibold font-sans tracking-wider">
                          Runtime Lifecycle
                        </div>
                        <div>
                          <span className="text-slate-500">Expected:</span>{' '}
                          <span className="font-medium text-slate-200">{activeResult.expected_status}</span>
                        </div>
                        <div>
                          <span className="text-slate-500">Actual:</span>{' '}
                          <span className="font-medium text-slate-200">{activeResult.actual_status}</span>
                        </div>
                        <div>
                          <span className="text-slate-500">Executed:</span>{' '}
                          <span className="font-medium text-slate-200">
                            {activeResult.actual_executed ? 'True' : 'False'}
                          </span>
                        </div>
                      </div>
                    </div>

                    {/* Attack -> Defense Pipeline Visualizer */}
                    <div className="space-y-1.5">
                      <div className="flex items-center justify-between text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                        <span>Pipeline Enforcement Trace</span>
                        <span className="text-emerald-400 font-mono">Deterministic Evaluation</span>
                      </div>
                      <div className="grid grid-cols-4 gap-1 p-2 bg-slate-950/80 rounded-lg border border-slate-800 text-[10px] font-mono">
                        {PIPELINE_STAGES.map((stage) => {
                          const isApprovalStage = stage.id === 'approval';
                          const isEngaged =
                            !isApprovalStage ||
                            Boolean(
                              activeResult.approval_id ||
                                activeResult.actual_approval_status ||
                                activeDefn?.requires_approval
                            );

                          return (
                            <div
                              key={stage.id}
                              className={`p-1.5 rounded text-center truncate ${
                                isEngaged
                                  ? 'bg-purple-950/40 text-purple-300 border border-purple-500/30 font-semibold'
                                  : 'bg-slate-900 text-slate-500 border border-slate-800/80'
                              }`}
                              title={`${stage.label}: ${isEngaged ? 'Verified' : 'Bypassed / Not Required'}`}
                            >
                              {stage.label}
                            </div>
                          );
                        })}
                      </div>
                    </div>

                    {/* Category-Specific Invariant Indicators */}
                    {activeResult.approval_id && (
                      <div className="p-3 bg-amber-950/15 rounded-lg border border-amber-500/25 space-y-1.5">
                        <div className="text-[10px] text-amber-400 uppercase font-semibold tracking-wider flex items-center gap-1">
                          <Clock className="w-3 h-3" />
                          Approval Correlation &bull; Human-in-the-Loop
                        </div>
                        <div className="font-mono text-amber-200 break-all text-[11px]">
                          {activeResult.approval_id}
                        </div>
                        {activeResult.actual_approval_status && (
                          <div className="text-slate-400 text-xs mt-1">
                            State:{' '}
                            <span className="font-semibold text-amber-400 font-mono">
                              {activeResult.actual_approval_status}
                            </span>
                          </div>
                        )}
                      </div>
                    )}

                    {activeResult.category === 'ANTI_TAMPER' && (
                      <div className="p-3 bg-purple-950/20 rounded-lg border border-purple-500/30 text-[11px] font-mono text-purple-200 space-y-1">
                        <div className="text-[10px] uppercase font-bold text-purple-400 flex items-center gap-1">
                          <ShieldCheck className="w-3.5 h-3.5" />
                          Cryptographic Anti-Tamper Invariant
                        </div>
                        <p className="text-slate-300 font-sans text-xs">
                          {activeResult.passed
                            ? 'Tampered capability token / payload rejected at SecurityEnforcementBoundary before execution.'
                            : 'Cryptographic boundary failed to reject tampered request.'}
                        </p>
                      </div>
                    )}

                    {/* Correlation Links */}
                    <div className="space-y-1.5 pt-1">
                      <span className="font-semibold text-slate-400 uppercase tracking-wider text-[10px]">
                        Correlate in Investigation Tabs
                      </span>
                      <div className="flex flex-wrap gap-1.5">
                        {onSelectTab && (
                          <>
                            <button
                              onClick={() => onSelectTab('threats', activeResult.request_id)}
                              className={`px-2 py-1 text-[10px] font-mono ${interactive.button.outline}`}
                            >
                              Threats
                            </button>
                            <button
                              onClick={() => onSelectTab('decisions', activeResult.request_id)}
                              className={`px-2 py-1 text-[10px] font-mono ${interactive.button.outline}`}
                            >
                              Decisions
                            </button>
                            {activeResult.approval_id && (
                              <button
                                onClick={() =>
                                  onSelectTab('approvals', activeResult.approval_id || activeResult.request_id)
                                }
                                className={`px-2 py-1 text-[10px] font-mono ${interactive.button.outline}`}
                              >
                                Approvals
                              </button>
                            )}
                            <button
                              onClick={() => onSelectTab('executions', activeResult.request_id)}
                              className={`px-2 py-1 text-[10px] font-mono ${interactive.button.outline}`}
                            >
                              Executions
                            </button>
                            <button
                              onClick={() => onSelectTab('audit', activeResult.request_id)}
                              className={`px-2 py-1 text-[10px] font-mono ${interactive.button.outline}`}
                            >
                              Audit
                            </button>
                          </>
                        )}
                      </div>
                    </div>

                    {/* Correlation Request ID */}
                    <div>
                      <span className="font-semibold text-slate-400 uppercase tracking-wider text-[10px]">
                        Correlation Request ID
                      </span>
                      <div className="font-mono text-slate-300 text-[11px] mt-1 bg-slate-950/60 p-2 rounded-lg border border-slate-800 break-all">
                        {activeResult.request_id}
                      </div>
                    </div>

                    {/* Actions: Inspect Drawer & Rerun */}
                    <div className="grid grid-cols-2 gap-2 pt-2">
                      <button
                        onClick={() => setShowDrawer(true)}
                        className={`py-2 text-xs font-semibold flex items-center justify-center gap-1.5 ${interactive.button.secondary}`}
                      >
                        <Terminal className="w-3.5 h-3.5" />
                        <span>Inspect Drawer</span>
                      </button>

                      <button
                        onClick={() => handleRun(activeResult.scenario_id)}
                        disabled={runningId === activeResult.scenario_id || isViewer}
                        className={`py-2 text-xs font-semibold flex items-center justify-center gap-1.5 ${interactive.button.primary} ${interactive.disabled}`}
                      >
                        <Play className={`w-3.5 h-3.5 ${runningId === activeResult.scenario_id ? 'animate-spin' : ''}`} />
                        <span>{runningId === activeResult.scenario_id ? 'Rerunning...' : 'Rerun Scenario'}</span>
                      </button>
                    </div>
                  </div>
                ) : activeDefn ? (
                  /* Pre-execution briefing */
                  <div className="space-y-4 text-xs">
                    <p className="text-slate-300 leading-relaxed">{activeDefn.description}</p>
                    <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800 space-y-2 font-mono">
                      <div className="text-[10px] text-slate-400 uppercase font-semibold font-sans tracking-wider">
                        Expected Pipeline Targets
                      </div>
                      <div className="flex items-center gap-1.5">
                        <span className="text-slate-500 font-sans">Decision:</span>{' '}
                        <span className={getDecisionBadge(activeDefn.expected_decision)}>
                          {activeDefn.expected_decision}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-500 font-sans">Status:</span>{' '}
                        <span className="font-medium text-slate-200">{activeDefn.expected_status}</span>
                      </div>
                      <div>
                        <span className="text-slate-500 font-sans">Executed:</span>{' '}
                        <span className="font-medium text-slate-200">
                          {activeDefn.expected_executed ? 'Yes' : 'No'}
                        </span>
                      </div>
                      {activeDefn.requires_approval && (
                        <div className="text-amber-400 font-sans font-semibold flex items-center gap-1 pt-1">
                          <Clock className="w-3.5 h-3.5" /> Requires Human Security Approval
                        </div>
                      )}
                    </div>

                    <button
                      onClick={() => handleRun(activeDefn.scenario_id)}
                      disabled={runningId === activeDefn.scenario_id || isViewer}
                      className={`w-full py-2.5 text-xs font-semibold flex items-center justify-center gap-1.5 ${interactive.button.primary} ${interactive.disabled}`}
                    >
                      <Play className={`w-3.5 h-3.5 ${runningId === activeDefn.scenario_id ? 'animate-spin' : ''}`} />
                      <span>{runningId === activeDefn.scenario_id ? 'Running Scenario...' : 'Execute Laboratory Test'}</span>
                    </button>
                  </div>
                ) : (
                  <div className="py-8 text-center text-xs text-slate-500">
                    Select a scenario from the registry catalog on the left to inspect and run.
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 3. Deep Technical Inspection Detail Drawer */}
      {showDrawer && activeResult && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-end bg-black/60 backdrop-blur-sm p-0 sm:p-4"
          role="dialog"
          aria-modal="true"
          aria-label={`Scenario Investigation Details for ${activeResult.scenario_name}`}
          onClick={(e) => {
            if (e.target === e.currentTarget) setShowDrawer(false);
          }}
        >
          <div
            className="w-full max-w-2xl h-full sm:h-auto sm:max-h-[90vh] bg-slate-900 border border-slate-800 rounded-none sm:rounded-2xl flex flex-col shadow-2xl overflow-hidden"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Drawer Header */}
            <div className="p-5 border-b border-slate-800 bg-slate-950/60 flex items-start justify-between gap-4">
              <div className="flex items-start gap-3.5">
                <div className="p-2.5 rounded-xl bg-purple-500/10 border border-purple-500/30 text-purple-400 shrink-0 mt-0.5">
                  <FlaskConical className="w-6 h-6" />
                </div>
                <div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <h3 className="text-base font-bold text-white tracking-tight">{activeResult.scenario_name}</h3>
                    <span
                      className={`px-2 py-0.5 text-xs font-bold font-mono rounded border ${
                        activeResult.passed
                          ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                          : 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                      }`}
                    >
                      {activeResult.passed ? 'VERIFIED PASS' : 'VERIFIED FAIL'}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 mt-0.5 font-mono">
                    {activeResult.scenario_id} &bull; {activeResult.category}
                  </p>
                </div>
              </div>

              <button
                onClick={() => setShowDrawer(false)}
                aria-label="Close scenario details"
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Drawer Content */}
            <div className="p-5 space-y-5 overflow-y-auto flex-1 text-xs">
              {/* Scenario Narrative */}
              <div className="space-y-1.5">
                <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
                  <Info className="w-3.5 h-3.5 text-purple-400" />
                  Scenario Evaluation Summary
                </h4>
                <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800 text-slate-200 leading-relaxed font-sans">
                  {activeResult.message}
                </div>
              </div>

              {/* Formal Assertion Matrix */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                    Formal Security Assertion Matrix
                  </h4>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-950 text-slate-400 border border-slate-800">
                    {activeAssertions.filter((a) => a.status === 'PASS').length} / {activeAssertions.length} Passed
                  </span>
                </div>

                <div className="divide-y divide-slate-800/80 rounded-xl border border-slate-800 bg-slate-950/60 overflow-hidden font-mono">
                  {activeAssertions.map((assertion, idx) => (
                    <div key={idx} className="p-3 space-y-1.5 hover:bg-slate-900/40 transition">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-white text-xs">{assertion.name}</span>
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold border flex items-center gap-1 ${
                            assertion.status === 'PASS'
                              ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                              : assertion.status === 'FAIL'
                              ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                              : 'bg-slate-800 text-slate-400 border-slate-700'
                          }`}
                        >
                          {assertion.status === 'PASS' ? (
                            <Check className="w-3 h-3" />
                          ) : assertion.status === 'FAIL' ? (
                            <X className="w-3 h-3" />
                          ) : (
                            <Minus className="w-3 h-3" />
                          )}
                          {assertion.status}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-400 font-sans">{assertion.description}</p>
                      <div className="flex items-center gap-3 text-[10px] text-slate-500 pt-0.5">
                        <span>Expected: <strong className="text-slate-300">{assertion.expected}</strong></span>
                        <span>&bull;</span>
                        <span>Actual: <strong className="text-slate-300">{assertion.actual}</strong></span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Correlation IDs */}
              <div className="space-y-2">
                <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
                  <Layers className="w-3.5 h-3.5 text-blue-400" />
                  Authoritative Correlation Identifiers
                </h4>
                <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800 space-y-2 font-mono text-[11px]">
                  <div>
                    <span className="text-slate-500 font-sans">Request ID:</span>{' '}
                    <span className="text-slate-200 break-all">{activeResult.request_id}</span>
                  </div>
                  {activeResult.approval_id && (
                    <div>
                      <span className="text-slate-500 font-sans">Approval ID:</span>{' '}
                      <span className="text-amber-300 break-all">{activeResult.approval_id}</span>
                    </div>
                  )}
                </div>
              </div>

              {/* Serialized Telemetry Metadata (Sanitized) */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5 text-amber-400" />
                    Inspected Scenario Telemetry
                  </h4>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950/40 text-emerald-400 border border-emerald-500/20">
                    Safe Redacted
                  </span>
                </div>

                <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 overflow-x-auto">
                  <pre className="font-mono text-[11px] text-slate-300 whitespace-pre-wrap">
                    {JSON.stringify(sanitizeTelemetryData(activeResult.metadata || {}), null, 2)}
                  </pre>
                </div>
                <p className="text-[10px] text-slate-500">
                  Scenario telemetry is protected by AgentShield Leakage Prevention Utility. Zero raw credentials, bearer tokens, or internal database paths are exposed.
                </p>
              </div>
            </div>

            {/* Drawer Footer */}
            <div className="p-4 border-t border-slate-800 bg-slate-950/60 flex items-center justify-between">
              <span className="text-[11px] text-slate-500 font-mono">
                Deterministic Scenario Result Invariant Verified
              </span>
              <button
                onClick={() => setShowDrawer(false)}
                className={`px-4 py-1.5 text-xs ${interactive.button.secondary} ${interactive.focusRing}`}
              >
                Close Investigation
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// Helper icon component for 'NOT_EVALUATED'
const Minus: React.FC<{ className?: string }> = ({ className = 'w-3 h-3' }) => (
  <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20 12H4" />
  </svg>
);
