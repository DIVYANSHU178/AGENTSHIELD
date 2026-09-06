import React, { useState, useEffect, useMemo } from 'react';
import { SecurityDecisionItem, TabType } from '../../types';
import { DecisionBadge, SeverityBadge } from './OverviewTab';
import {
  Shield,
  CheckCircle2,
  Clock,
  Ban,
  Search,
  ArrowRight,
  X,
  Eye,
  RefreshCw,
  RotateCcw,
  SlidersHorizontal,
  Layers,
  Gauge,
} from 'lucide-react';
import { MotionCard, MotionList, MotionItem } from '../common/MotionComponents';
import { LoadingState, EmptyState, AuthRequiredState } from '../common/StateViews';
import { sanitizeTelemetryData } from '../../lib/sanitizer';

export interface DecisionsTabProps {
  decisions: SecurityDecisionItem[];
  onRefresh?: () => void;
  loading?: boolean;
  authRequired?: boolean;
  onSignIn?: () => void;
  onSelectTab?: (tab: TabType, filterQuery?: string) => void;
  initialSearch?: string;
}

export const DecisionsTab: React.FC<DecisionsTabProps> = ({
  decisions = [],
  onRefresh,
  loading = false,
  authRequired = false,
  onSignIn,
  onSelectTab,
  initialSearch = '',
}) => {
  const [decisionFilter, setDecisionFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [riskBandFilter, setRiskBandFilter] = useState<string>('ALL');
  const [searchTerm, setSearchTerm] = useState<string>(initialSearch);
  const [selectedDecision, setSelectedDecision] = useState<SecurityDecisionItem | null>(null);

  // Sync initialSearch if provided
  useEffect(() => {
    if (initialSearch) {
      setSearchTerm(initialSearch);
    }
  }, [initialSearch]);

  // Close detail drawer on Escape key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && selectedDecision) {
        setSelectedDecision(null);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [selectedDecision]);

  // Helper to determine risk band from 0-100 score
  const getRiskBand = (score: number) => {
    if (score >= 80) return 'CRITICAL';
    if (score >= 60) return 'HIGH';
    if (score >= 30) return 'MEDIUM';
    return 'LOW';
  };

  // Quantified metrics
  const totalDecisions = decisions.length;
  const allowedCount = useMemo(
    () => decisions.filter((d) => d.decision === 'ALLOW').length,
    [decisions]
  );
  const requireApprovalCount = useMemo(
    () => decisions.filter((d) => d.decision === 'REQUIRE_APPROVAL').length,
    [decisions]
  );
  const blockedCount = useMemo(
    () => decisions.filter((d) => d.decision === 'BLOCK').length,
    [decisions]
  );
  const maxRiskScore = useMemo(() => {
    if (decisions.length === 0) return 0;
    return Math.max(...decisions.map((d) => d.risk_score || 0));
  }, [decisions]);

  // Filtered decisions list
  const filteredDecisions = useMemo(() => {
    return decisions.filter((d) => {
      if (decisionFilter !== 'ALL' && d.decision !== decisionFilter) return false;
      if (severityFilter !== 'ALL' && d.severity !== severityFilter) return false;
      if (riskBandFilter !== 'ALL' && getRiskBand(d.risk_score) !== riskBandFilter) return false;
      if (searchTerm) {
        const term = searchTerm.toLowerCase();
        return (
          d.reason.toLowerCase().includes(term) ||
          d.policy_id.toLowerCase().includes(term) ||
          d.request_id.toLowerCase().includes(term) ||
          d.decision_id.toLowerCase().includes(term) ||
          d.decision.toLowerCase().includes(term)
        );
      }
      return true;
    });
  }, [decisions, decisionFilter, severityFilter, riskBandFilter, searchTerm]);

  // Reset all filters
  const handleResetFilters = () => {
    setDecisionFilter('ALL');
    setSeverityFilter('ALL');
    setRiskBandFilter('ALL');
    setSearchTerm('');
  };

  const hasActiveFilters =
    decisionFilter !== 'ALL' ||
    severityFilter !== 'ALL' ||
    riskBandFilter !== 'ALL' ||
    searchTerm.trim().length > 0;

  // Auth Required State
  if (authRequired) {
    return (
      <AuthRequiredState
        title="Decisions Ledger Requires Authentication"
        message="The AgentShield security backend is healthy and reachable, but policy evaluation records require an authenticated session."
        onSignIn={onSignIn}
      />
    );
  }

  // Loading State
  if (loading && decisions.length === 0) {
    return (
      <LoadingState
        title="Processing Security Decisions"
        message="Connecting to SecurityDecisionGateway and retrieving authoritative policy evaluation records..."
        stage="Policy Evaluation Ledger"
      />
    );
  }

  return (
    <div className="space-y-6">
      {/* Header & Lifecycle Indicator */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/60 p-4 border border-slate-800 rounded-xl">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-blue-500/10 border border-blue-500/30 flex items-center justify-center text-blue-400 shrink-0">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h3 className="text-sm font-semibold text-white">Security Decisions Ledger</h3>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-950/60 border border-blue-500/30 text-blue-300">
                Stage 3 of 7: Policy &amp; Risk Verdict
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Deterministic Phase 4/5 policy decisions &amp; risk evaluations
            </p>
          </div>
        </div>

        {onRefresh && (
          <button
            onClick={onRefresh}
            disabled={loading}
            className="self-start md:self-auto px-3 py-1.5 bg-slate-800 hover:bg-slate-700 active:bg-slate-600 text-slate-200 rounded-lg border border-slate-700 text-xs font-semibold transition flex items-center gap-1.5 disabled:opacity-50"
            title="Refresh decisions ledger"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Sync Ledger</span>
          </button>
        )}
      </div>

      {/* Quantified Metrics KPI Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        <MotionCard className="p-3.5 bg-slate-900/50 border border-slate-800 rounded-xl">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium">Total Evaluations</span>
            <Layers className="w-4 h-4 text-cyan-400 opacity-80" />
          </div>
          <div className="text-2xl font-bold font-mono text-white mt-1">{totalDecisions}</div>
          <div className="text-[10px] font-mono text-slate-500 mt-0.5">Gateway requests processed</div>
        </MotionCard>

        <MotionCard className="p-3.5 bg-slate-900/50 border border-emerald-500/20 rounded-xl">
          <div className="flex items-center justify-between text-emerald-400">
            <span className="text-xs font-medium">Allowed</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-300 mt-1">{allowedCount}</div>
          <div className="text-[10px] font-mono text-emerald-400/70 mt-0.5">Authorized for sandbox dispatch</div>
        </MotionCard>

        <MotionCard className="p-3.5 bg-slate-900/50 border border-amber-500/20 rounded-xl">
          <div className="flex items-center justify-between text-amber-400">
            <span className="text-xs font-medium">Require Approval</span>
            <Clock className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-300 mt-1">{requireApprovalCount}</div>
          <div className="text-[10px] font-mono text-amber-400/70 mt-0.5">Held for human reviewer</div>
        </MotionCard>

        <MotionCard className="p-3.5 bg-slate-900/50 border border-rose-500/20 rounded-xl">
          <div className="flex items-center justify-between text-rose-400">
            <span className="text-xs font-medium">Blocked</span>
            <Ban className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-rose-300 mt-1">{blockedCount}</div>
          <div className="text-[10px] font-mono text-rose-400/70 mt-0.5">Terminal enforcement</div>
        </MotionCard>

        <MotionCard className="p-3.5 bg-slate-900/50 border border-slate-800 rounded-xl col-span-2 sm:col-span-1">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium">Peak Risk Score</span>
            <Gauge className="w-4 h-4 text-orange-400 opacity-80" />
          </div>
          <div className="text-2xl font-bold font-mono text-white mt-1">
            {maxRiskScore.toFixed(1)}
            <span className="text-xs font-normal text-slate-500">/100</span>
          </div>
          <div className="text-[10px] font-mono text-slate-500 mt-0.5">Highest threat evaluation</div>
        </MotionCard>
      </div>

      {/* Filter Toolbar */}
      <div className="p-4 bg-slate-900/70 border border-slate-800 rounded-xl space-y-3">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-300">
            <SlidersHorizontal className="w-3.5 h-3.5 text-cyan-400" />
            <span>Policy Ledger Filters</span>
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

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
          {/* Search Box */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search decisions..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              aria-label="Search decisions"
              className="w-full pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>

          {/* Decision Verdict Select */}
          <select
            value={decisionFilter}
            onChange={(e) => setDecisionFilter(e.target.value)}
            aria-label="Filter by Decision Verdict"
            className="w-full py-1.5 px-2.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Decisions</option>
            <option value="ALLOW">ALLOW</option>
            <option value="REQUIRE_APPROVAL">REQUIRE_APPROVAL</option>
            <option value="BLOCK">BLOCK</option>
          </select>

          {/* Severity Select */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            aria-label="Filter by Severity"
            className="w-full py-1.5 px-2.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
            <option value="INFO">INFO</option>
          </select>

          {/* Risk Band Select */}
          <select
            value={riskBandFilter}
            onChange={(e) => setRiskBandFilter(e.target.value)}
            aria-label="Filter by Risk Band"
            className="w-full py-1.5 px-2.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Risk Bands</option>
            <option value="CRITICAL">CRITICAL (80-100)</option>
            <option value="HIGH">HIGH (60-79)</option>
            <option value="MEDIUM">MEDIUM (30-59)</option>
            <option value="LOW">LOW (0-29)</option>
          </select>
        </div>
      </div>

      {/* Decisions Ledger */}
      {filteredDecisions.length === 0 ? (
        <EmptyState
          icon={Shield}
          title={hasActiveFilters ? 'No decisions matching filter' : 'No decisions recorded'}
          message={
            hasActiveFilters
              ? 'Try modifying or clearing your active investigation filters above.'
              : 'No policy evaluation decisions match the selected criteria.'
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
        <MotionList className="space-y-4">
          {filteredDecisions.map((dec) => {
            const riskBand = getRiskBand(dec.risk_score);

            return (
              <MotionItem key={dec.decision_id}>
                <div
                  className={`p-5 rounded-xl border space-y-4 transition ${
                    dec.decision === 'ALLOW'
                      ? 'bg-slate-900/70 border-slate-800 hover:border-emerald-500/30'
                      : dec.decision === 'REQUIRE_APPROVAL'
                      ? 'bg-amber-950/15 border-amber-500/25 hover:border-amber-500/40 shadow-sm'
                      : 'bg-rose-950/15 border-rose-500/25 hover:border-rose-500/40 shadow-sm'
                  }`}
                >
                  {/* Decision Header */}
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/60 pb-3">
                    <div className="flex items-center gap-2.5 flex-wrap">
                      <DecisionBadge decision={dec.decision} />
                      <SeverityBadge severity={dec.severity} />
                      <span className="text-xs px-2.5 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                        Policy: {dec.policy_id}
                      </span>
                      {dec.threat_count > 0 && (
                        <span className="text-xs px-2 py-0.5 rounded bg-rose-500/10 border border-rose-500/20 text-rose-300 font-mono">
                          {dec.threat_count} {dec.threat_count === 1 ? 'threat signal' : 'threat signals'}
                        </span>
                      )}
                    </div>

                    <div className="flex items-center gap-2 text-xs text-slate-400 font-mono">
                      <span className="flex items-center gap-1.5">
                        <span className="text-slate-400">Risk Score:</span>
                        <span
                          className={`font-bold px-1.5 py-0.5 rounded ${
                            riskBand === 'CRITICAL'
                              ? 'bg-rose-500/10 text-rose-300 border border-rose-500/30'
                              : riskBand === 'HIGH'
                              ? 'bg-orange-500/10 text-orange-300 border border-orange-500/30'
                              : riskBand === 'MEDIUM'
                              ? 'bg-amber-500/10 text-amber-300 border border-amber-500/30'
                              : 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/30'
                          }`}
                        >
                          {dec.risk_score.toFixed(1)}/100
                        </span>
                      </span>
                      <span>&bull;</span>
                      <span className="flex items-center gap-1 text-slate-400">
                        <Clock className="w-3 h-3 text-slate-500" />
                        {new Date(dec.timestamp).toLocaleTimeString()}
                      </span>
                    </div>
                  </div>

                  {/* Rationale */}
                  <div className="space-y-1 text-xs">
                    <div className="text-slate-400 font-medium">Policy Rationale:</div>
                    <p className="text-slate-200 text-sm leading-relaxed">{dec.reason}</p>
                  </div>

                  {/* REQUIRE_APPROVAL Status Banner (Strict Phase 10 / Phase 11 Invariant) */}
                  {dec.decision === 'REQUIRE_APPROVAL' && (
                    <div className="p-3 bg-amber-950/30 border border-amber-500/30 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs text-amber-300">
                      <div className="flex items-center gap-2">
                        <Clock className="w-4 h-4 text-amber-400 flex-shrink-0" />
                        <div>
                          <span className="font-semibold">Status:</span> Awaiting Human Security Approval &bull;{' '}
                          <span className="text-amber-400 font-mono">Execution: NOT STARTED</span>
                        </div>
                      </div>
                      <div className="flex items-center gap-2 self-start sm:self-auto">
                        <span className="text-[11px] px-2 py-0.5 rounded bg-amber-500/10 border border-amber-500/20 text-amber-400">
                          Dual-Custody Gate &bull; Non-Executing Observer
                        </span>
                        {onSelectTab && (
                          <button
                            onClick={() => onSelectTab('approvals', dec.request_id)}
                            className="px-2.5 py-1 rounded bg-amber-500/20 hover:bg-amber-500/30 text-amber-200 border border-amber-500/40 text-xs font-medium transition flex items-center gap-1"
                          >
                            <span>Open in Approvals</span>
                            <ArrowRight className="w-3 h-3" />
                          </button>
                        )}
                      </div>
                    </div>
                  )}

                  {/* BLOCK Status Banner (Strict Terminal Invariant) */}
                  {dec.decision === 'BLOCK' && (
                    <div className="p-3 bg-rose-950/30 border border-rose-500/30 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs text-rose-300">
                      <div className="flex items-center gap-2">
                        <Ban className="w-4 h-4 text-rose-400 flex-shrink-0" />
                        <div>
                          <span className="font-semibold">Status:</span> TERMINAL - BLOCK &bull;{' '}
                          <span className="text-rose-400 font-mono">Execution: NOT STARTED &bull; Authorization: NOT ISSUED</span>
                        </div>
                      </div>
                      <span className="text-[11px] px-2 py-0.5 rounded bg-rose-500/10 border border-rose-500/20 text-rose-400 self-start sm:self-auto">
                        Zero Override Allowed
                      </span>
                    </div>
                  )}

                  {/* ALLOW Status Banner */}
                  {dec.decision === 'ALLOW' && (
                    <div className="p-2.5 bg-emerald-950/20 border border-emerald-500/20 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs text-emerald-300">
                      <div className="flex items-center gap-2">
                        <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                        <span>Enforcement Authorization Granted &bull; Dispatched to Sandbox Boundary</span>
                      </div>
                      {onSelectTab && (
                        <button
                          onClick={() => onSelectTab('executions', dec.request_id)}
                          className="text-[11px] px-2 py-0.5 rounded bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 flex items-center gap-1 self-start sm:self-auto transition"
                        >
                          <span>Check Execution Outcome</span>
                          <ArrowRight className="w-3 h-3" />
                        </button>
                      )}
                    </div>
                  )}

                  {/* Footer Identifiers & Cross-Link Actions */}
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-[11px] text-slate-500 font-mono pt-1">
                    <div className="flex items-center gap-3">
                      <span>Correlation ID: {dec.request_id}</span>
                      <span>&bull;</span>
                      <span>Decision ID: {dec.decision_id.slice(0, 8)}</span>
                    </div>

                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => setSelectedDecision(dec)}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-sans font-medium transition flex items-center gap-1.5 focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none"
                        aria-label={`Inspect decision ${dec.decision_id}`}
                      >
                        <Eye className="w-3.5 h-3.5 text-cyan-400" />
                        <span>Inspect</span>
                      </button>

                      {onSelectTab && dec.threat_count > 0 && (
                        <button
                          onClick={() => onSelectTab('threats', dec.request_id)}
                          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 text-xs font-sans font-medium transition flex items-center gap-1 focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none"
                          title="View related threat signals"
                        >
                          <span>View Threats</span>
                          <ArrowRight className="w-3 h-3" />
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              </MotionItem>
            );
          })}
        </MotionList>
      )}

      {/* Technical Detail Inspection Drawer */}
      {selectedDecision && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="decision-drawer-title"
          className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 bg-black/80 backdrop-blur-sm"
        >
          <div className="relative w-full max-w-2xl bg-slate-900 border border-slate-700 rounded-2xl p-6 space-y-5 max-h-[90vh] overflow-y-auto shadow-2xl">
            {/* Drawer Header */}
            <div className="flex items-start justify-between gap-3 border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/30 text-blue-400">
                  <Shield className="w-5 h-5" />
                </div>
                <div>
                  <h3 id="decision-drawer-title" className="text-base font-bold text-white">
                    Security Decision Details
                  </h3>
                  <p className="text-xs text-slate-400">
                    Deterministic policy verdict and risk evaluation breakdown
                  </p>
                </div>
              </div>
              <button
                onClick={() => setSelectedDecision(null)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none"
                aria-label="Close decision details drawer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* IDENTITY SECTION */}
            <div className="space-y-2">
              <div className="text-[10px] font-mono uppercase font-bold text-slate-400 tracking-wider">
                Identity &amp; Policy Rule
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
                <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800">
                  <div className="text-slate-500 text-[10px]">Decision Verdict</div>
                  <div className="mt-1">
                    <DecisionBadge decision={selectedDecision.decision} />
                  </div>
                </div>
                <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800">
                  <div className="text-slate-500 text-[10px]">Policy Identifier</div>
                  <div className="text-white font-bold mt-0.5">{selectedDecision.policy_id}</div>
                </div>
                <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800 sm:col-span-2">
                  <div className="text-slate-500 text-[10px]">Correlation / Request ID</div>
                  <div className="text-cyan-400 font-bold break-all">{selectedDecision.request_id}</div>
                </div>
                <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800 sm:col-span-2">
                  <div className="text-slate-500 text-[10px]">Decision ID</div>
                  <div className="text-slate-300 break-all">{selectedDecision.decision_id}</div>
                </div>
              </div>
            </div>

            {/* RISK BREAKDOWN */}
            <div className="space-y-2">
              <div className="text-[10px] font-mono uppercase font-bold text-slate-400 tracking-wider">
                Risk Evaluation Breakdown
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs font-mono">
                <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800">
                  <div className="text-slate-500 text-[10px]">Risk Score</div>
                  <div className="text-white font-bold text-base mt-0.5">
                    {selectedDecision.risk_score.toFixed(1)}/100
                  </div>
                </div>
                <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800">
                  <div className="text-slate-500 text-[10px]">Severity Level</div>
                  <div className="mt-1">
                    <SeverityBadge severity={selectedDecision.severity} />
                  </div>
                </div>
                <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800">
                  <div className="text-slate-500 text-[10px]">Threat Signal Count</div>
                  <div className="text-white font-bold text-base mt-0.5">
                    {selectedDecision.threat_count}
                  </div>
                </div>
                <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800 sm:col-span-3">
                  <div className="text-slate-500 text-[10px]">Evaluated Timestamp</div>
                  <div className="text-slate-300">
                    {new Date(selectedDecision.timestamp).toISOString()} ({new Date(selectedDecision.timestamp).toLocaleString()})
                  </div>
                </div>
              </div>
            </div>

            {/* POLICY RATIONALE */}
            <div className="space-y-1 text-xs">
              <div className="text-[10px] font-mono uppercase font-bold text-slate-400 tracking-wider">
                Authoritative Policy Rationale
              </div>
              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
                <p className="text-slate-200 leading-relaxed font-sans text-sm">
                  {selectedDecision.reason}
                </p>
              </div>
            </div>

            {/* SANITIZED METADATA */}
            {selectedDecision.metadata && Object.keys(selectedDecision.metadata).length > 0 && (
              <div className="space-y-1 text-xs">
                <div className="text-[10px] font-mono uppercase font-bold text-slate-400 tracking-wider">
                  Sanitized Evaluation Metadata
                </div>
                <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-[11px] font-mono max-h-48 overflow-y-auto">
                  <pre className="text-slate-300 whitespace-pre-wrap">
                    {JSON.stringify(sanitizeTelemetryData(selectedDecision.metadata), null, 2)}
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
                      const reqId = selectedDecision.request_id;
                      setSelectedDecision(null);
                      onSelectTab('threats', reqId);
                    }}
                    className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold transition border border-slate-700 flex items-center gap-1.5 focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none"
                  >
                    <span>View Threat Signals</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>

                  {selectedDecision.decision === 'REQUIRE_APPROVAL' && (
                    <button
                      onClick={() => {
                        const reqId = selectedDecision.request_id;
                        setSelectedDecision(null);
                        onSelectTab('approvals', reqId);
                      }}
                      className="px-3 py-2 bg-amber-600 hover:bg-amber-500 text-white rounded-lg text-xs font-semibold transition flex items-center gap-1.5 focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none"
                    >
                      <span>Go to Approvals Queue</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </button>
                  )}

                  <button
                    onClick={() => {
                      const reqId = selectedDecision.request_id;
                      setSelectedDecision(null);
                      onSelectTab('executions', reqId);
                    }}
                    className="px-3 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold transition flex items-center gap-1.5 focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none"
                  >
                    <span>View Executions</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>

                  <button
                    onClick={() => {
                      const reqId = selectedDecision.request_id;
                      setSelectedDecision(null);
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
