import React, { useState, useEffect } from 'react';
import {
  ScenarioDefinition,
  ScenarioResult,
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
} from 'lucide-react';

export const ScenarioLabTab: React.FC = () => {
  const [scenarios, setScenarios] = useState<ScenarioDefinition[]>([]);
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [loading, setLoading] = useState<boolean>(true);
  const [runningId, setRunningId] = useState<string | null>(null);
  const [results, setResults] = useState<Record<string, ScenarioResult>>({});
  const [error, setError] = useState<string | null>(null);
  const [selectedScenarioId, setSelectedScenarioId] = useState<string | null>(null);

  const loadScenarios = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await fetchLaboratoryScenarios(
        selectedCategory === 'ALL' ? undefined : selectedCategory
      );
      setScenarios(data);
      if (data.length > 0 && !selectedScenarioId) {
        setSelectedScenarioId(data[0].scenario_id);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to load laboratory scenarios.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadScenarios();
  }, [selectedCategory]);

  const handleRun = async (scenarioId: string) => {
    try {
      setRunningId(scenarioId);
      setError(null);
      const res = await runLaboratoryScenario(scenarioId);
      setResults((prev) => ({ ...prev, [scenarioId]: res }));
      setSelectedScenarioId(scenarioId);
    } catch (err: any) {
      setError(err.message || `Failed to run scenario ${scenarioId}`);
    } finally {
      setRunningId(null);
    }
  };

  const getCategoryBadgeColor = (cat: string) => {
    switch (cat) {
      case 'BASELINE':
        return 'bg-blue-500/10 text-blue-400 border-blue-500/20';
      case 'APPROVAL_LIFECYCLE':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
      case 'ANTI_TAMPER':
        return 'bg-purple-500/10 text-purple-400 border-purple-500/20';
      case 'FAILURE_ABUSE':
        return 'bg-rose-500/10 text-rose-400 border-rose-500/20';
      default:
        return 'bg-slate-500/10 text-slate-400 border-slate-500/20';
    }
  };

  const getDecisionBadge = (decision: string) => {
    switch (decision) {
      case 'ALLOW':
        return 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-semibold font-mono px-2 py-0.5 rounded text-[11px]';
      case 'REQUIRE_APPROVAL':
        return 'bg-amber-500/10 text-amber-400 border border-amber-500/20 font-semibold font-mono px-2 py-0.5 rounded text-[11px]';
      case 'BLOCK':
        return 'bg-rose-500/10 text-rose-400 border border-rose-500/20 font-semibold font-mono px-2 py-0.5 rounded text-[11px]';
      default:
        return 'bg-slate-800 text-slate-300 border border-slate-700 font-semibold font-mono px-2 py-0.5 rounded text-[11px]';
    }
  };

  const activeResult = selectedScenarioId ? results[selectedScenarioId] : null;
  const activeDefn = scenarios.find((s) => s.scenario_id === selectedScenarioId);

  return (
    <div className="space-y-6" data-testid="scenario-lab-tab">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 bg-slate-900/60 p-5 border border-slate-800 rounded-xl">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-purple-500/10 border border-purple-500/30 rounded-lg text-purple-400">
            <FlaskConical className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-base font-bold text-white leading-tight">
              Scenario &amp; Attack Laboratory
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Authoritative deterministic laboratory harness for evaluating live security pipeline responses, anti-tamper enforcement, and approval state machines.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2 self-start sm:self-auto">
          <button
            onClick={() => loadScenarios()}
            disabled={loading}
            className="px-3 py-1.5 text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg border border-slate-700 transition disabled:opacity-50 flex items-center gap-1.5"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh Catalog
          </button>
        </div>
      </div>

      {error && (
        <div className="p-3.5 bg-rose-950/30 border border-rose-500/30 text-rose-300 rounded-xl text-xs flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-rose-400 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Category Filter Navigation */}
      <div className="flex flex-wrap gap-2">
        {['ALL', 'BASELINE', 'APPROVAL_LIFECYCLE', 'ANTI_TAMPER', 'FAILURE_ABUSE'].map((cat) => (
          <button
            key={cat}
            onClick={() => setSelectedCategory(cat)}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold border transition ${
              selectedCategory === cat
                ? 'bg-slate-800 text-white border-slate-700 shadow-sm'
                : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-slate-200 hover:bg-slate-900/60'
            }`}
          >
            {cat.replace(/_/g, ' ')}
          </button>
        ))}
      </div>

      {/* Main Grid: Catalog on Left, Selected Result Panel on Right */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Scenario Registry List */}
        <div className="lg:col-span-7 space-y-3">
          <div className="bg-slate-900/60 rounded-xl border border-slate-800 overflow-hidden">
            <div className="px-4 py-3 bg-slate-950/60 border-b border-slate-800 font-semibold text-xs text-slate-300 uppercase tracking-wider flex justify-between items-center font-mono">
              <span className="flex items-center gap-2">
                <Shield className="w-3.5 h-3.5 text-blue-400" />
                Authoritative Scenario Registry ({scenarios.length})
              </span>
              {loading && <span className="text-xs text-blue-400 font-normal">Loading...</span>}
            </div>

            <div className="divide-y divide-slate-800/60 max-h-[640px] overflow-y-auto">
              {scenarios.map((s) => {
                const res = results[s.scenario_id];
                const isSelected = selectedScenarioId === s.scenario_id;
                const isRunning = runningId === s.scenario_id;

                return (
                  <div
                    key={s.scenario_id}
                    onClick={() => setSelectedScenarioId(s.scenario_id)}
                    className={`p-4 cursor-pointer transition ${
                      isSelected
                        ? 'bg-slate-800/50 border-l-4 border-blue-500'
                        : 'hover:bg-slate-800/20'
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
                          disabled={isRunning}
                          className="px-3 py-1 text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white rounded-lg disabled:opacity-50 transition shadow-sm flex items-center gap-1"
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

              {scenarios.length === 0 && !loading && (
                <div className="p-8 text-center text-xs text-slate-500">
                  No scenarios found for this category.
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Selected Scenario Outcome Panel */}
        <div className="lg:col-span-5 space-y-4">
          <div className="bg-slate-900/60 rounded-xl border border-slate-800 p-5 space-y-4 sticky top-20">
            <div className="flex justify-between items-start border-b border-slate-800 pb-3 gap-2">
              <div className="min-w-0">
                <h3 className="text-sm font-bold text-white truncate">
                  {activeDefn ? activeDefn.name : 'Select a Scenario'}
                </h3>
                {activeDefn && (
                  <div className="text-xs font-mono text-slate-400 mt-0.5 break-all">{activeDefn.scenario_id}</div>
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

            {activeResult ? (
              <div className="space-y-4 text-xs">
                <div>
                  <span className="font-semibold text-slate-400 uppercase tracking-wider text-[10px]">
                    Outcome Summary
                  </span>
                  <div className="mt-1 p-3 bg-slate-950/60 rounded-lg border border-slate-800 text-slate-200 leading-relaxed">
                    {activeResult.message}
                  </div>
                </div>

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

                {activeResult.approval_id && (
                  <div className="p-3 bg-amber-950/15 rounded-lg border border-amber-500/25 space-y-1.5">
                    <div className="text-[10px] text-amber-400 uppercase font-semibold tracking-wider flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      Approval Correlation
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

                <div>
                  <span className="font-semibold text-slate-400 uppercase tracking-wider text-[10px]">
                    Correlation ID
                  </span>
                  <div className="font-mono text-slate-300 text-[11px] mt-1 bg-slate-950/60 p-2 rounded-lg border border-slate-800 break-all">
                    {activeResult.request_id}
                  </div>
                </div>

                <div className="pt-1">
                  <button
                    onClick={() => handleRun(activeResult.scenario_id)}
                    disabled={runningId === activeResult.scenario_id}
                    className="w-full py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg font-semibold text-xs transition shadow-sm disabled:opacity-50 flex items-center justify-center gap-1.5"
                  >
                    <Play className={`w-3.5 h-3.5 ${runningId === activeResult.scenario_id ? 'animate-spin' : ''}`} />
                    {runningId === activeResult.scenario_id ? 'Rerunning...' : 'Rerun This Scenario'}
                  </button>
                </div>
              </div>
            ) : activeDefn ? (
              <div className="space-y-4 text-xs">
                <p className="text-slate-300 leading-relaxed">{activeDefn.description}</p>
                <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800 space-y-2 font-mono">
                  <div className="text-[10px] text-slate-400 uppercase font-semibold font-sans tracking-wider">
                    Expected Pipeline Targets
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="text-slate-500 font-sans">Decision:</span>{' '}
                    <span className={getDecisionBadge(activeDefn.expected_decision)}>{activeDefn.expected_decision}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 font-sans">Status:</span>{' '}
                    <span className="font-medium text-slate-200">{activeDefn.expected_status}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 font-sans">Executed:</span>{' '}
                    <span className="font-medium text-slate-200">{activeDefn.expected_executed ? 'Yes' : 'No'}</span>
                  </div>
                </div>

                <button
                  onClick={() => handleRun(activeDefn.scenario_id)}
                  disabled={runningId === activeDefn.scenario_id}
                  className="w-full py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg font-semibold text-xs transition shadow-sm disabled:opacity-50 flex items-center justify-center gap-1.5"
                >
                  <Play className={`w-3.5 h-3.5 ${runningId === activeDefn.scenario_id ? 'animate-spin' : ''}`} />
                  {runningId === activeDefn.scenario_id ? 'Running Scenario...' : 'Execute Laboratory Test'}
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
  );
};
