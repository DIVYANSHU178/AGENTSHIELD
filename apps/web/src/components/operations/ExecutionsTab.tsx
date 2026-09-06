import React, { useState, useEffect, useMemo } from 'react';
import { ExecutionActivityItem, TabType } from '../../types';
import { ExecutionStatusBadge } from './OverviewTab';
import {
  Terminal,
  CheckCircle2,
  XCircle,
  Ban,
  Clock,
  Search,
  ArrowRight,
  X,
  Eye,
  RefreshCw,
  RotateCcw,
  SlidersHorizontal,
  Layers,
  Timer,
} from 'lucide-react';
import { MotionCard, MotionList, MotionItem } from '../common/MotionComponents';
import { LoadingState, EmptyState, AuthRequiredState } from '../common/StateViews';
import { sanitizeTelemetryData } from '../../lib/sanitizer';

export interface ExecutionsTabProps {
  executions: ExecutionActivityItem[];
  onRefresh?: () => void;
  loading?: boolean;
  authRequired?: boolean;
  onSignIn?: () => void;
  onSelectTab?: (tab: TabType, filterQuery?: string) => void;
  initialSearch?: string;
}

export const ExecutionsTab: React.FC<ExecutionsTabProps> = ({
  executions = [],
  onRefresh,
  loading = false,
  authRequired = false,
  onSignIn,
  onSelectTab,
  initialSearch = '',
}) => {
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [searchTerm, setSearchTerm] = useState<string>(initialSearch);
  const [selectedExecution, setSelectedExecution] = useState<ExecutionActivityItem | null>(null);

  // Sync initialSearch if provided
  useEffect(() => {
    if (initialSearch) {
      setSearchTerm(initialSearch);
    }
  }, [initialSearch]);

  // Close detail drawer on Escape key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && selectedExecution) {
        setSelectedExecution(null);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [selectedExecution]);

  // Derived list of unique categories from active executions
  const availableCategories = useMemo(() => {
    const cats = new Set<string>();
    executions.forEach((e) => {
      if (e.tool_category) cats.add(e.tool_category);
    });
    return Array.from(cats).sort();
  }, [executions]);

  // Quantified metrics
  const totalExecutions = executions.length;
  const completedCount = useMemo(
    () => executions.filter((e) => e.status === 'COMPLETED').length,
    [executions]
  );
  const deniedCount = useMemo(
    () => executions.filter((e) => e.status === 'DENIED').length,
    [executions]
  );
  const timedOutCount = useMemo(
    () => executions.filter((e) => e.status === 'TIMED_OUT').length,
    [executions]
  );
  const failedCount = useMemo(
    () => executions.filter((e) => e.status === 'FAILED').length,
    [executions]
  );
  const averageLatency = useMemo(() => {
    if (executions.length === 0) return 0;
    const totalMs = executions.reduce((acc, curr) => acc + (curr.duration_ms || 0), 0);
    return totalMs / executions.length;
  }, [executions]);

  // Filtered executions list
  const filteredExecutions = useMemo(() => {
    return executions.filter((e) => {
      if (statusFilter !== 'ALL' && e.status !== statusFilter) return false;
      if (categoryFilter !== 'ALL' && e.tool_category !== categoryFilter) return false;
      if (searchTerm) {
        const term = searchTerm.toLowerCase();
        return (
          e.tool_name.toLowerCase().includes(term) ||
          e.request_id.toLowerCase().includes(term) ||
          e.execution_id.toLowerCase().includes(term) ||
          e.tool_category.toLowerCase().includes(term) ||
          e.action.toLowerCase().includes(term) ||
          (e.error && e.error.toLowerCase().includes(term))
        );
      }
      return true;
    });
  }, [executions, statusFilter, categoryFilter, searchTerm]);

  // Reset all filters
  const handleResetFilters = () => {
    setStatusFilter('ALL');
    setCategoryFilter('ALL');
    setSearchTerm('');
  };

  const hasActiveFilters =
    statusFilter !== 'ALL' || categoryFilter !== 'ALL' || searchTerm.trim().length > 0;

  // Auth Required State
  if (authRequired) {
    return (
      <AuthRequiredState
        title="Execution Activity Requires Authentication"
        message="The AgentShield security backend is healthy and reachable, but runtime execution containment records require an authenticated session."
        onSignIn={onSignIn}
      />
    );
  }

  // Loading State
  if (loading && executions.length === 0) {
    return (
      <LoadingState
        title="Processing Execution Stream"
        message="Connecting to SandboxExecutionBoundary and retrieving runtime execution containment telemetry..."
        stage="Sandbox Telemetry Stream"
      />
    );
  }

  return (
    <div className="space-y-6">
      {/* Header & Lifecycle Indicator */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/60 p-4 border border-slate-800 rounded-xl">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 shrink-0">
            <Terminal className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h3 className="text-sm font-semibold text-white">Sandbox Execution Activity</h3>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950/60 border border-emerald-500/30 text-emerald-300">
                Stage 6 of 7: Controlled Execution &amp; Containment
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Bounded runtime execution containment outcomes &amp; metrics
            </p>
          </div>
        </div>

        {onRefresh && (
          <button
            onClick={onRefresh}
            disabled={loading}
            className="self-start md:self-auto px-3 py-1.5 bg-slate-800 hover:bg-slate-700 active:bg-slate-600 text-slate-200 rounded-lg border border-slate-700 text-xs font-semibold transition flex items-center gap-1.5 disabled:opacity-50"
            title="Refresh executions stream"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Sync Executions</span>
          </button>
        )}
      </div>

      {/* Quantified Metrics KPI Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <MotionCard className="p-3.5 bg-slate-900/50 border border-slate-800 rounded-xl">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium">Dispatched</span>
            <Layers className="w-4 h-4 text-cyan-400 opacity-80" />
          </div>
          <div className="text-2xl font-bold font-mono text-white mt-1">{totalExecutions}</div>
          <div className="text-[10px] font-mono text-slate-500 mt-0.5">Total tool dispatches</div>
        </MotionCard>

        <MotionCard className="p-3.5 bg-slate-900/50 border border-emerald-500/20 rounded-xl">
          <div className="flex items-center justify-between text-emerald-400">
            <span className="text-xs font-medium">Completed</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-300 mt-1">{completedCount}</div>
          <div className="text-[10px] font-mono text-emerald-400/70 mt-0.5">Bounded success</div>
        </MotionCard>

        <MotionCard className="p-3.5 bg-slate-900/50 border border-slate-500/20 rounded-xl">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium">Denied</span>
            <Ban className="w-4 h-4 text-slate-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-300 mt-1">{deniedCount}</div>
          <div className="text-[10px] font-mono text-slate-400/70 mt-0.5">Boundary prevented</div>
        </MotionCard>

        <MotionCard className="p-3.5 bg-slate-900/50 border border-amber-500/20 rounded-xl">
          <div className="flex items-center justify-between text-amber-400">
            <span className="text-xs font-medium">Timed Out</span>
            <Clock className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-300 mt-1">{timedOutCount}</div>
          <div className="text-[10px] font-mono text-amber-400/70 mt-0.5">Budget exhausted</div>
        </MotionCard>

        <MotionCard className="p-3.5 bg-slate-900/50 border border-rose-500/20 rounded-xl">
          <div className="flex items-center justify-between text-rose-400">
            <span className="text-xs font-medium">Failed</span>
            <XCircle className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-rose-300 mt-1">{failedCount}</div>
          <div className="text-[10px] font-mono text-rose-400/70 mt-0.5">Contained fault</div>
        </MotionCard>

        <MotionCard className="p-3.5 bg-slate-900/50 border border-slate-800 rounded-xl col-span-2 sm:col-span-1">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium">Avg Latency</span>
            <Timer className="w-4 h-4 text-cyan-400 opacity-80" />
          </div>
          <div className="text-2xl font-bold font-mono text-white mt-1">
            {averageLatency.toFixed(1)}
            <span className="text-xs font-normal text-slate-500 ml-0.5">ms</span>
          </div>
          <div className="text-[10px] font-mono text-slate-500 mt-0.5">Execution duration</div>
        </MotionCard>
      </div>

      {/* Filter Toolbar */}
      <div className="p-4 bg-slate-900/70 border border-slate-800 rounded-xl space-y-3">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-300">
            <SlidersHorizontal className="w-3.5 h-3.5 text-cyan-400" />
            <span>Execution Stream Filters</span>
          </div>
          {hasActiveFilters && (
            <button
              onClick={handleResetFilters}
              className="text-xs text-slate-400 hover:text-cyan-400 flex items-center gap-1 transition"
            >
              <RotateCcw className="w-3 h-3" />
              <span>Reset Filters</span>
            </button>
          )}
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
          {/* Search Box */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search tool executions..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              aria-label="Search tool executions"
              className="w-full pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>

          {/* Outcome Status Select */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            aria-label="Filter by Outcome Status"
            className="w-full py-1.5 px-2.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Outcomes</option>
            <option value="COMPLETED">COMPLETED</option>
            <option value="DENIED">DENIED</option>
            <option value="TIMED_OUT">TIMED_OUT</option>
            <option value="FAILED">FAILED</option>
          </select>

          {/* Tool Category Select */}
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            aria-label="Filter by Tool Category"
            className="w-full py-1.5 px-2.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Tool Categories ({availableCategories.length})</option>
            {availableCategories.map((cat) => (
              <option key={cat} value={cat}>
                {cat}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Executions Stream */}
      {filteredExecutions.length === 0 ? (
        <EmptyState
          icon={Terminal}
          title={hasActiveFilters ? 'No executions matching filter' : 'No executions recorded'}
          message={
            hasActiveFilters
              ? 'Try modifying or clearing your active investigation filters above.'
              : 'No sandboxed tool executions match the current filter.'
          }
          action={
            hasActiveFilters ? (
              <button
                onClick={handleResetFilters}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs rounded-lg border border-slate-700 font-medium transition"
              >
                Clear Filters
              </button>
            ) : undefined
          }
        />
      ) : (
        <MotionList className="space-y-3">
          {filteredExecutions.map((exec) => (
            <MotionItem key={exec.execution_id}>
              <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl space-y-3 hover:border-slate-700 transition">
                {/* Header */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/60 pb-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono text-sm font-bold text-white tracking-tight">
                      {exec.tool_name}
                    </span>
                    <ExecutionStatusBadge status={exec.status} />
                    <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                      {exec.action} ({exec.tool_category})
                    </span>
                  </div>

                  <div className="flex items-center gap-2 text-xs text-slate-400 font-mono">
                    <span className="flex items-center gap-1">
                      <Timer className="w-3 h-3 text-cyan-400" />
                      <span>Duration:</span>
                      <span className="text-white font-semibold">{exec.duration_ms.toFixed(2)} ms</span>
                    </span>
                    <span>&bull;</span>
                    <span className="flex items-center gap-1 text-slate-400">
                      <Clock className="w-3 h-3 text-slate-500" />
                      {new Date(exec.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                </div>

                {/* Execution Outcome Description / Error Box */}
                {exec.status === 'FAILED' ? (
                  <div className="p-3 bg-rose-950/20 border border-rose-500/20 rounded-lg text-xs text-rose-300 font-mono space-y-1">
                    <div className="text-[10px] uppercase font-bold text-rose-400 flex items-center gap-1.5">
                      <XCircle className="w-3.5 h-3.5" />
                      <span>Contained Fault / Error</span>
                    </div>
                    <div>{exec.error || 'Execution attempted but runtime failure occurred.'}</div>
                  </div>
                ) : exec.status === 'DENIED' ? (
                  <div className="p-2.5 bg-slate-800/50 border border-slate-700/50 rounded-lg text-xs text-slate-300 flex items-center gap-2">
                    <Ban className="w-4 h-4 text-slate-400 flex-shrink-0" />
                    <span>Enforcement Boundary Denied Invocation &bull; Zero Execution In Sandbox</span>
                  </div>
                ) : exec.status === 'TIMED_OUT' ? (
                  <div className="p-2.5 bg-amber-950/20 border border-amber-500/20 rounded-lg text-xs text-amber-300 flex items-center gap-2">
                    <Clock className="w-4 h-4 text-amber-400 flex-shrink-0" />
                    <span>Execution Terminated &bull; Runtime Timeout Budget Exceeded</span>
                  </div>
                ) : (
                  <div className="p-2.5 bg-emerald-950/20 border border-emerald-500/20 rounded-lg text-xs text-emerald-300 flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                    <span>Sandbox Tool Execution Successful within containment limits</span>
                  </div>
                )}

                {/* Sanitized Metadata Preview */}
                {exec.metadata && Object.keys(exec.metadata).length > 0 && (
                  <div className="flex flex-wrap gap-2 text-[11px] text-slate-400 font-mono">
                    {Object.entries(sanitizeTelemetryData(exec.metadata) as Record<string, unknown>).map(
                      ([k, v]) => (
                        <span key={k} className="px-2 py-0.5 bg-slate-950 rounded border border-slate-800">
                          {k}: {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                        </span>
                      )
                    )}
                  </div>
                )}

                {/* Footer Identifiers & Cross-Link Actions */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-[11px] text-slate-500 font-mono pt-1">
                  <div className="flex items-center gap-3">
                    <span>Correlation ID: {exec.request_id}</span>
                    <span>&bull;</span>
                    <span>Exec ID: {exec.execution_id.slice(0, 8)}</span>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => setSelectedExecution(exec)}
                      className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-sans font-medium transition flex items-center gap-1.5 focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none"
                      aria-label={`Inspect execution ${exec.execution_id}`}
                    >
                      <Eye className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Inspect</span>
                    </button>

                    {onSelectTab && (
                      <button
                        onClick={() => onSelectTab('decisions', exec.request_id)}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 text-xs font-sans font-medium transition flex items-center gap-1 focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none"
                        title="View related Security Decision"
                      >
                        <span>View Decision</span>
                        <ArrowRight className="w-3 h-3" />
                      </button>
                    )}

                    {onSelectTab && (
                      <button
                        onClick={() => onSelectTab('audit', exec.request_id)}
                        className="px-2.5 py-1 rounded bg-cyan-950/40 hover:bg-cyan-900/60 border border-cyan-500/30 text-cyan-300 text-xs font-sans font-medium transition flex items-center gap-1 focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none"
                        title="View audit trail for this execution"
                      >
                        <span>Audit Trail</span>
                        <ArrowRight className="w-3 h-3" />
                      </button>
                    )}
                  </div>
                </div>
              </div>
            </MotionItem>
          ))}
        </MotionList>
      )}

      {/* Technical Detail Inspection Drawer */}
      {selectedExecution && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="execution-drawer-title"
          className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 bg-black/80 backdrop-blur-sm"
        >
          <div className="relative w-full max-w-2xl bg-slate-900 border border-slate-700 rounded-2xl p-6 space-y-5 max-h-[90vh] overflow-y-auto shadow-2xl">
            {/* Drawer Header */}
            <div className="flex items-start justify-between gap-3 border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                  <Terminal className="w-5 h-5" />
                </div>
                <div>
                  <h3 id="execution-drawer-title" className="text-base font-bold text-white">
                    Sandbox Execution Containment Details
                  </h3>
                  <p className="text-xs text-slate-400">
                    Bounded runtime execution metrics and isolation telemetry
                  </p>
                </div>
              </div>
              <button
                onClick={() => setSelectedExecution(null)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none"
                aria-label="Close execution details drawer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* IDENTITY SECTION */}
            <div className="space-y-2">
              <div className="text-[10px] font-mono uppercase font-bold text-slate-400 tracking-wider">
                Execution Identity &amp; Target
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
                <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800">
                  <div className="text-slate-500 text-[10px]">Tool Name</div>
                  <div className="text-white font-bold">{selectedExecution.tool_name}</div>
                </div>
                <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800">
                  <div className="text-slate-500 text-[10px]">Category &amp; Action</div>
                  <div className="text-white font-bold">
                    {selectedExecution.action} ({selectedExecution.tool_category})
                  </div>
                </div>
                <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800 sm:col-span-2">
                  <div className="text-slate-500 text-[10px]">Correlation / Request ID</div>
                  <div className="text-cyan-400 font-bold break-all">{selectedExecution.request_id}</div>
                </div>
                <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800 sm:col-span-2">
                  <div className="text-slate-500 text-[10px]">Execution ID</div>
                  <div className="text-slate-300 break-all">{selectedExecution.execution_id}</div>
                </div>
              </div>
            </div>

            {/* CONTAINMENT & OUTCOME */}
            <div className="space-y-2">
              <div className="text-[10px] font-mono uppercase font-bold text-slate-400 tracking-wider">
                Containment Outcome &amp; Latency
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs font-mono">
                <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800">
                  <div className="text-slate-500 text-[10px]">Runtime Status</div>
                  <div className="mt-1">
                    <ExecutionStatusBadge status={selectedExecution.status} />
                  </div>
                </div>
                <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800">
                  <div className="text-slate-500 text-[10px]">Latency Duration</div>
                  <div className="text-white font-bold text-base mt-0.5">
                    {selectedExecution.duration_ms.toFixed(2)} ms
                  </div>
                </div>
                <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800">
                  <div className="text-slate-500 text-[10px]">Success Flag</div>
                  <div
                    className={`font-bold text-sm mt-1 ${
                      selectedExecution.success ? 'text-emerald-400' : 'text-rose-400'
                    }`}
                  >
                    {selectedExecution.success ? 'TRUE' : 'FALSE'}
                  </div>
                </div>
                <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800 sm:col-span-3">
                  <div className="text-slate-500 text-[10px]">Recorded Timestamp</div>
                  <div className="text-slate-300">
                    {new Date(selectedExecution.timestamp).toISOString()} ({new Date(selectedExecution.timestamp).toLocaleString()})
                  </div>
                </div>
              </div>
            </div>

            {/* ERROR DETAILS IF FAILED */}
            {selectedExecution.error && (
              <div className="space-y-1 text-xs">
                <div className="text-[10px] font-mono uppercase font-bold text-rose-400 tracking-wider">
                  Contained Fault Details
                </div>
                <div className="p-3 bg-rose-950/20 border border-rose-500/30 rounded-lg text-rose-300 font-mono break-all">
                  {selectedExecution.error}
                </div>
              </div>
            )}

            {/* SANITIZED METADATA */}
            {selectedExecution.metadata && Object.keys(selectedExecution.metadata).length > 0 && (
              <div className="space-y-1 text-xs">
                <div className="text-[10px] font-mono uppercase font-bold text-slate-400 tracking-wider">
                  Sanitized Execution Metadata
                </div>
                <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-[11px] font-mono max-h-48 overflow-y-auto">
                  <pre className="text-slate-300 whitespace-pre-wrap">
                    {JSON.stringify(sanitizeTelemetryData(selectedExecution.metadata), null, 2)}
                  </pre>
                </div>
              </div>
            )}

            {/* LIFECYCLE CROSS-LINKS */}
            {onSelectTab && (
              <div className="space-y-2 pt-2 border-t border-slate-800">
                <div className="text-[10px] font-mono uppercase font-bold text-slate-400 tracking-wider">
                  Lifecycle Navigation
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <button
                    onClick={() => {
                      const reqId = selectedExecution.request_id;
                      setSelectedExecution(null);
                      onSelectTab('decisions', reqId);
                    }}
                    className="px-3 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold transition flex items-center gap-1.5 focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none"
                  >
                    <span>View Security Decision</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>

                  <button
                    onClick={() => {
                      const reqId = selectedExecution.request_id;
                      setSelectedExecution(null);
                      onSelectTab('audit', reqId);
                    }}
                    className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold transition border border-slate-700 flex items-center gap-1.5 focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none"
                  >
                    <span>View Audit Trail</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
