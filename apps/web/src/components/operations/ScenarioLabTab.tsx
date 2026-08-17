import React, { useState, useEffect } from 'react';
import {
  ScenarioDefinition,
  ScenarioResult,
} from '../../types';
import { fetchLaboratoryScenarios, runLaboratoryScenario } from '../../lib/api';


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
        return 'bg-blue-50 text-blue-700 border-blue-200';
      case 'APPROVAL_LIFECYCLE':
        return 'bg-amber-50 text-amber-700 border-amber-200';
      case 'ANTI_TAMPER':
        return 'bg-purple-50 text-purple-700 border-purple-200';
      case 'FAILURE_ABUSE':
        return 'bg-rose-50 text-rose-700 border-rose-200';
      default:
        return 'bg-gray-50 text-gray-700 border-gray-200';
    }
  };

  const getDecisionBadge = (decision: string) => {
    switch (decision) {
      case 'ALLOW':
        return 'bg-emerald-100 text-emerald-800 font-semibold px-2 py-0.5 rounded';
      case 'REQUIRE_APPROVAL':
        return 'bg-amber-100 text-amber-800 font-semibold px-2 py-0.5 rounded';
      case 'BLOCK':
        return 'bg-rose-100 text-rose-800 font-semibold px-2 py-0.5 rounded';
      default:
        return 'bg-gray-100 text-gray-800 font-semibold px-2 py-0.5 rounded';
    }
  };


  const activeResult = selectedScenarioId ? results[selectedScenarioId] : null;
  const activeDefn = scenarios.find((s) => s.scenario_id === selectedScenarioId);

  return (
    <div className="space-y-6" data-testid="scenario-lab-tab">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 bg-white p-6 rounded-lg border border-gray-200 shadow-sm">
        <div>
          <h2 className="text-xl font-bold text-gray-900">Scenario & Attack Laboratory</h2>
          <p className="text-sm text-gray-500 mt-1">
            Authoritative deterministic laboratory harness for evaluating live security pipeline responses, anti-tamper enforcement, and approval state machines.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => loadScenarios()}
            disabled={loading}
            className="px-3 py-1.5 text-xs font-medium bg-gray-100 text-gray-700 rounded border border-gray-300 hover:bg-gray-200 transition"
          >
            Refresh Catalog
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 bg-rose-50 border border-rose-200 text-rose-700 rounded-lg text-sm">
          {error}
        </div>
      )}

      {/* Category Filter Navigation */}
      <div className="flex flex-wrap gap-2">
        {['ALL', 'BASELINE', 'APPROVAL_LIFECYCLE', 'ANTI_TAMPER', 'FAILURE_ABUSE'].map((cat) => (
          <button
            key={cat}
            onClick={() => setSelectedCategory(cat)}
            className={`px-3 py-1.5 rounded-full text-xs font-medium transition ${
              selectedCategory === cat
                ? 'bg-indigo-600 text-white shadow-sm'
                : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
            }`}
          >
            {cat.replace('_', ' ')}
          </button>
        ))}
      </div>

      {/* Main Grid: Catalog on Left, Selected Result Panel on Right */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Scenario List */}
        <div className="lg:col-span-7 space-y-3">
          <div className="bg-white rounded-lg border border-gray-200 shadow-sm overflow-hidden">
            <div className="px-4 py-3 bg-gray-50 border-b border-gray-200 font-semibold text-xs text-gray-700 uppercase tracking-wider flex justify-between items-center">
              <span>Authoritative Scenario Registry ({scenarios.length})</span>
              {loading && <span className="text-xs text-indigo-600 font-normal">Loading...</span>}
            </div>

            <div className="divide-y divide-gray-100 max-h-[620px] overflow-y-auto">
              {scenarios.map((s) => {
                const res = results[s.scenario_id];
                const isSelected = selectedScenarioId === s.scenario_id;
                const isRunning = runningId === s.scenario_id;

                return (
                  <div
                    key={s.scenario_id}
                    onClick={() => setSelectedScenarioId(s.scenario_id)}
                    className={`p-4 cursor-pointer transition hover:bg-gray-50 ${
                      isSelected ? 'bg-indigo-50/60 border-l-4 border-indigo-600' : ''
                    }`}
                  >
                    <div className="flex justify-between items-start gap-2">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-semibold text-sm text-gray-900">{s.name}</span>
                          <span
                            className={`text-[10px] px-2 py-0.5 rounded-full border font-mono ${getCategoryBadgeColor(
                              s.category
                            )}`}
                          >
                            {s.category}
                          </span>
                        </div>
                        <div className="text-xs font-mono text-gray-500 mt-0.5">{s.scenario_id}</div>
                      </div>

                      <div className="flex items-center gap-2">
                        {res && (
                          <span
                            className={`px-2 py-0.5 text-xs font-bold rounded ${
                              res.passed
                                ? 'bg-emerald-100 text-emerald-800'
                                : 'bg-rose-100 text-rose-800'
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
                          className="px-3 py-1 text-xs font-medium bg-indigo-600 text-white rounded hover:bg-indigo-700 disabled:opacity-50 transition shadow-sm"
                        >
                          {isRunning ? 'Running...' : 'Run'}
                        </button>
                      </div>
                    </div>

                    <p className="text-xs text-gray-600 mt-2 leading-relaxed">{s.description}</p>

                    <div className="flex items-center gap-4 mt-3 pt-2 border-t border-gray-100 text-[11px] text-gray-500">
                      <div>
                        Expected: <span className="font-medium text-gray-800">{s.expected_decision}</span>
                      </div>
                      <div>
                        Status: <span className="font-medium text-gray-800">{s.expected_status}</span>
                      </div>
                      {s.requires_approval && (
                        <div className="text-amber-600 font-medium">Requires Approval</div>
                      )}
                    </div>
                  </div>
                );
              })}

              {scenarios.length === 0 && !loading && (
                <div className="p-8 text-center text-sm text-gray-500">
                  No scenarios found for this category.
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Selected Scenario Outcome Panel */}
        <div className="lg:col-span-5 space-y-4">
          <div className="bg-white rounded-lg border border-gray-200 shadow-sm p-5 space-y-4 sticky top-4">
            <div className="flex justify-between items-start border-b border-gray-100 pb-3">
              <div>
                <h3 className="text-base font-bold text-gray-900">
                  {activeDefn ? activeDefn.name : 'Select a Scenario'}
                </h3>
                {activeDefn && (
                  <div className="text-xs font-mono text-gray-500 mt-0.5">{activeDefn.scenario_id}</div>
                )}
              </div>
              {activeResult && (
                <span
                  className={`px-2.5 py-1 text-xs font-bold rounded ${
                    activeResult.passed
                      ? 'bg-emerald-100 text-emerald-800 border border-emerald-300'
                      : 'bg-rose-100 text-rose-800 border border-rose-300'
                  }`}
                >
                  {activeResult.passed ? 'VERIFIED PASS' : 'VERIFIED FAIL'}
                </span>
              )}
            </div>

            {activeResult ? (
              <div className="space-y-4 text-xs">
                <div>
                  <span className="font-semibold text-gray-500 uppercase tracking-wider text-[10px]">
                    Outcome Summary
                  </span>
                  <div className="mt-1 p-3 bg-gray-50 rounded border border-gray-200 text-gray-800 leading-relaxed">
                    {activeResult.message}
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div className="p-3 bg-gray-50 rounded border border-gray-200 space-y-1">
                    <div className="text-[10px] text-gray-500 uppercase font-semibold">
                      Security Decision
                    </div>
                    <div className="flex items-center gap-1.5 mt-1">
                      <span className="text-gray-500">Expected:</span>
                      <span className={getDecisionBadge(activeResult.expected_decision)}>
                        {activeResult.expected_decision}
                      </span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <span className="text-gray-500">Actual:</span>
                      <span className={getDecisionBadge(activeResult.actual_decision)}>
                        {activeResult.actual_decision}
                      </span>
                    </div>
                  </div>

                  <div className="p-3 bg-gray-50 rounded border border-gray-200 space-y-1">
                    <div className="text-[10px] text-gray-500 uppercase font-semibold">
                      Runtime Lifecycle
                    </div>
                    <div>
                      <span className="text-gray-500">Expected:</span>{' '}
                      <span className="font-medium text-gray-900">{activeResult.expected_status}</span>
                    </div>
                    <div>
                      <span className="text-gray-500">Actual:</span>{' '}
                      <span className="font-medium text-gray-900">{activeResult.actual_status}</span>
                    </div>
                    <div>
                      <span className="text-gray-500">Executed:</span>{' '}
                      <span className="font-medium text-gray-900">
                        {activeResult.actual_executed ? 'True' : 'False'}
                      </span>
                    </div>
                  </div>
                </div>

                {activeResult.approval_id && (
                  <div className="p-3 bg-amber-50/50 rounded border border-amber-200 space-y-1">
                    <div className="text-[10px] text-amber-800 uppercase font-semibold">
                      Approval Correlation
                    </div>
                    <div className="font-mono text-gray-800 break-all text-[11px]">
                      {activeResult.approval_id}
                    </div>
                    {activeResult.actual_approval_status && (
                      <div className="text-gray-600 mt-1">
                        State:{' '}
                        <span className="font-semibold text-amber-700">
                          {activeResult.actual_approval_status}
                        </span>
                      </div>
                    )}
                  </div>
                )}

                <div>
                  <span className="font-semibold text-gray-500 uppercase tracking-wider text-[10px]">
                    Correlation ID
                  </span>
                  <div className="font-mono text-gray-600 text-[11px] mt-0.5">
                    {activeResult.request_id}
                  </div>
                </div>

                <div className="pt-2">
                  <button
                    onClick={() => handleRun(activeResult.scenario_id)}
                    disabled={runningId === activeResult.scenario_id}
                    className="w-full py-2 bg-indigo-600 text-white rounded font-medium hover:bg-indigo-700 disabled:opacity-50 transition shadow-sm"
                  >
                    {runningId === activeResult.scenario_id ? 'Rerunning...' : 'Rerun This Scenario'}
                  </button>
                </div>
              </div>
            ) : activeDefn ? (
              <div className="space-y-4 text-xs">
                <p className="text-gray-600 leading-relaxed">{activeDefn.description}</p>
                <div className="p-3 bg-gray-50 rounded border border-gray-200 space-y-2">
                  <div className="text-[10px] text-gray-500 uppercase font-semibold">
                    Expected Pipeline Targets
                  </div>
                  <div>
                    Decision: <span className="font-medium text-gray-900">{activeDefn.expected_decision}</span>
                  </div>
                  <div>
                    Status: <span className="font-medium text-gray-900">{activeDefn.expected_status}</span>
                  </div>
                  <div>
                    Executed: <span className="font-medium text-gray-900">{activeDefn.expected_executed ? 'Yes' : 'No'}</span>
                  </div>
                </div>

                <button
                  onClick={() => handleRun(activeDefn.scenario_id)}
                  disabled={runningId === activeDefn.scenario_id}
                  className="w-full py-2 bg-indigo-600 text-white rounded font-medium hover:bg-indigo-700 disabled:opacity-50 transition shadow-sm"
                >
                  {runningId === activeDefn.scenario_id ? 'Running Scenario...' : 'Execute Laboratory Test'}
                </button>
              </div>
            ) : (
              <div className="py-8 text-center text-sm text-gray-400">
                Select a scenario from the registry catalog on the left to inspect and run.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
