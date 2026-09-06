import React, { useState, useEffect, useMemo } from 'react';
import { ThreatActivityItem, TabType } from '../../types';
import { SeverityBadge } from './OverviewTab';
import {
  ShieldAlert,
  Search,
  ShieldCheck,
  AlertTriangle,
  AlertOctagon,
  AlertCircle,
  ArrowRight,
  X,
  Clock,
  Cpu,
  Layers,
  Eye,
  RefreshCw,
  RotateCcw,
  SlidersHorizontal,
} from 'lucide-react';
import { MotionCard, MotionList, MotionItem } from '../common/MotionComponents';
import { LoadingState, EmptyState, AuthRequiredState } from '../common/StateViews';
import { sanitizeTelemetryData } from '../../lib/sanitizer';

export interface ThreatsTabProps {
  threats: ThreatActivityItem[];
  onRefresh?: () => void;
  loading?: boolean;
  authRequired?: boolean;
  onSignIn?: () => void;
  onSelectTab?: (tab: TabType, filterQuery?: string) => void;
  initialSearch?: string;
}

export const ThreatsTab: React.FC<ThreatsTabProps> = ({
  threats = [],
  onRefresh,
  loading = false,
  authRequired = false,
  onSignIn,
  onSelectTab,
  initialSearch = '',
}) => {
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [typeFilter, setTypeFilter] = useState<string>('ALL');
  const [detectorFilter, setDetectorFilter] = useState<string>('ALL');
  const [searchTerm, setSearchTerm] = useState<string>(initialSearch);
  const [selectedThreat, setSelectedThreat] = useState<ThreatActivityItem | null>(null);

  // Sync initialSearch if provided
  useEffect(() => {
    if (initialSearch) {
      setSearchTerm(initialSearch);
    }
  }, [initialSearch]);

  // Close detail drawer on Escape key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && selectedThreat) {
        setSelectedThreat(null);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [selectedThreat]);

  // Derived list of unique detectors from active threats
  const availableDetectors = useMemo(() => {
    const detectors = new Set<string>();
    threats.forEach((t) => {
      if (t.detector) detectors.add(t.detector);
    });
    return Array.from(detectors).sort();
  }, [threats]);

  // Quantified metrics
  const totalThreats = threats.length;
  const criticalThreats = useMemo(
    () => threats.filter((t) => t.severity === 'CRITICAL').length,
    [threats]
  );
  const highThreats = useMemo(
    () => threats.filter((t) => t.severity === 'HIGH').length,
    [threats]
  );
  const mediumLowThreats = useMemo(
    () => threats.filter((t) => t.severity === 'MEDIUM' || t.severity === 'LOW' || t.severity === 'INFO').length,
    [threats]
  );
  const uniqueDetectorsCount = availableDetectors.length;

  // Filtered threats list
  const filteredThreats = useMemo(() => {
    return threats.filter((t) => {
      if (severityFilter !== 'ALL' && t.severity !== severityFilter) return false;
      if (typeFilter !== 'ALL' && t.threat_type !== typeFilter) return false;
      if (detectorFilter !== 'ALL' && t.detector !== detectorFilter) return false;
      if (searchTerm) {
        const term = searchTerm.toLowerCase();
        return (
          t.title.toLowerCase().includes(term) ||
          t.description.toLowerCase().includes(term) ||
          t.request_id.toLowerCase().includes(term) ||
          t.threat_id.toLowerCase().includes(term) ||
          t.detector.toLowerCase().includes(term) ||
          t.threat_type.toLowerCase().includes(term)
        );
      }
      return true;
    });
  }, [threats, severityFilter, typeFilter, detectorFilter, searchTerm]);

  // Reset all filters
  const handleResetFilters = () => {
    setSeverityFilter('ALL');
    setTypeFilter('ALL');
    setDetectorFilter('ALL');
    setSearchTerm('');
  };

  const hasActiveFilters =
    severityFilter !== 'ALL' ||
    typeFilter !== 'ALL' ||
    detectorFilter !== 'ALL' ||
    searchTerm.trim().length > 0;

  // Auth Required State
  if (authRequired) {
    return (
      <AuthRequiredState
        title="Threat Telemetry Requires Authentication"
        message="The AgentShield security backend is healthy and reachable, but threat activity telemetry requires an authenticated session."
        onSignIn={onSignIn}
      />
    );
  }

  // Loading State
  if (loading && threats.length === 0) {
    return (
      <LoadingState
        title="Ingesting Threat Signals"
        message="Connecting to AgentShield runtime telemetry and ingesting deterministic threat detector events..."
        stage="Signal Ingestion & Redaction"
      />
    );
  }

  return (
    <div className="space-y-6">
      {/* Header & Lifecycle Indicator */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/60 p-4 border border-slate-800 rounded-xl">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-400 shrink-0">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h3 className="text-sm font-semibold text-white">Threat Activity Stream</h3>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-950/60 border border-rose-500/30 text-rose-300">
                Stage 1 of 7: Ingestion &amp; Detection
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Deterministic threat signals with full credential &amp; token redaction
            </p>
          </div>
        </div>

        {onRefresh && (
          <button
            onClick={onRefresh}
            disabled={loading}
            className="self-start md:self-auto px-3 py-1.5 bg-slate-800 hover:bg-slate-700 active:bg-slate-600 text-slate-200 rounded-lg border border-slate-700 text-xs font-semibold transition flex items-center gap-1.5 disabled:opacity-50"
            title="Refresh threat signals"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Sync Stream</span>
          </button>
        )}
      </div>

      {/* Quantified Metrics KPI Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        <MotionCard className="p-3.5 bg-slate-900/50 border border-slate-800 rounded-xl">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium">Total Signals</span>
            <Layers className="w-4 h-4 text-cyan-400 opacity-80" />
          </div>
          <div className="text-2xl font-bold font-mono text-white mt-1">{totalThreats}</div>
          <div className="text-[10px] font-mono text-slate-500 mt-0.5">Recorded in session</div>
        </MotionCard>

        <MotionCard className="p-3.5 bg-slate-900/50 border border-rose-500/20 rounded-xl">
          <div className="flex items-center justify-between text-rose-400">
            <span className="text-xs font-medium">Critical Threats</span>
            <AlertOctagon className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-rose-300 mt-1">{criticalThreats}</div>
          <div className="text-[10px] font-mono text-rose-400/70 mt-0.5">Zero tolerance threshold</div>
        </MotionCard>

        <MotionCard className="p-3.5 bg-slate-900/50 border border-orange-500/20 rounded-xl">
          <div className="flex items-center justify-between text-orange-400">
            <span className="text-xs font-medium">High Severity</span>
            <AlertTriangle className="w-4 h-4 text-orange-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-orange-300 mt-1">{highThreats}</div>
          <div className="text-[10px] font-mono text-orange-400/70 mt-0.5">Elevated risk signals</div>
        </MotionCard>

        <MotionCard className="p-3.5 bg-slate-900/50 border border-amber-500/20 rounded-xl">
          <div className="flex items-center justify-between text-amber-400">
            <span className="text-xs font-medium">Medium / Low</span>
            <AlertCircle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-300 mt-1">{mediumLowThreats}</div>
          <div className="text-[10px] font-mono text-amber-400/70 mt-0.5">Controlled or advisory</div>
        </MotionCard>

        <MotionCard className="p-3.5 bg-slate-900/50 border border-slate-800 rounded-xl col-span-2 sm:col-span-1">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium">Active Detectors</span>
            <Cpu className="w-4 h-4 text-emerald-400 opacity-80" />
          </div>
          <div className="text-2xl font-bold font-mono text-white mt-1">{uniqueDetectorsCount}</div>
          <div className="text-[10px] font-mono text-slate-500 mt-0.5">Engines producing signals</div>
        </MotionCard>
      </div>

      {/* Filter Toolbar */}
      <div className="p-4 bg-slate-900/70 border border-slate-800 rounded-xl space-y-3">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-300">
            <SlidersHorizontal className="w-3.5 h-3.5 text-cyan-400" />
            <span>Investigation Filters</span>
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
              placeholder="Search threats..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              aria-label="Search threats"
              className="w-full pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>

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

          {/* Threat Type Select */}
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            aria-label="Filter by Threat Type"
            className="w-full py-1.5 px-2.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Threat Types</option>
            <option value="CREDENTIAL_ACCESS">CREDENTIAL_ACCESS</option>
            <option value="PROMPT_INJECTION">PROMPT_INJECTION</option>
            <option value="SENSITIVE_DATA_ACCESS">SENSITIVE_DATA_ACCESS</option>
            <option value="DATA_EXFILTRATION">DATA_EXFILTRATION</option>
            <option value="DANGEROUS_ACTION">DANGEROUS_ACTION</option>
            <option value="MALICIOUS_DESTINATION">MALICIOUS_DESTINATION</option>
            <option value="PRIVILEGE_ESCALATION">PRIVILEGE_ESCALATION</option>
            <option value="SUSPICIOUS_BEHAVIOR">SUSPICIOUS_BEHAVIOR</option>
            <option value="UNKNOWN">UNKNOWN</option>
          </select>

          {/* Detector Select */}
          <select
            value={detectorFilter}
            onChange={(e) => setDetectorFilter(e.target.value)}
            aria-label="Filter by Detector"
            className="w-full py-1.5 px-2.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Detectors ({availableDetectors.length})</option>
            {availableDetectors.map((det) => (
              <option key={det} value={det}>
                {det}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Threats Ledger */}
      {filteredThreats.length === 0 ? (
        <EmptyState
          icon={ShieldCheck}
          title={hasActiveFilters ? 'No threats matching filter' : 'No threats detected'}
          message={
            hasActiveFilters
              ? 'Try modifying or clearing your active investigation filters above.'
              : 'All monitored agent interactions are currently clean or filtered out.'
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
          {filteredThreats.map((threat) => {
            const isCritical = threat.severity === 'CRITICAL';
            const isHigh = threat.severity === 'HIGH';

            return (
              <MotionItem key={threat.threat_id}>
                <div
                  className={`p-4 rounded-xl border transition space-y-3 ${
                    isCritical
                      ? 'bg-slate-900/80 border-rose-500/30 hover:border-rose-500/50 shadow-sm'
                      : isHigh
                      ? 'bg-slate-900/70 border-orange-500/30 hover:border-orange-500/50'
                      : 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  {/* Top Bar: Threat Type, Severity, Detector, Confidence, Timestamp */}
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/60 pb-2.5">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-mono text-sm font-bold text-white tracking-tight">
                        {threat.threat_type}
                      </span>
                      <SeverityBadge severity={threat.severity} />
                      <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono flex items-center gap-1">
                        <Cpu className="w-3 h-3 text-slate-400" />
                        {threat.detector}
                      </span>
                    </div>

                    <div className="flex items-center gap-2 text-xs text-slate-400 font-mono">
                      <span
                        className={`px-2 py-0.5 rounded text-[11px] font-semibold border ${
                          threat.confidence >= 0.8
                            ? 'bg-rose-500/10 text-rose-300 border-rose-500/20'
                            : threat.confidence >= 0.5
                            ? 'bg-amber-500/10 text-amber-300 border-amber-500/20'
                            : 'bg-slate-800 text-slate-300 border-slate-700'
                        }`}
                        title="Normalized detection confidence"
                      >
                        {(threat.confidence * 100).toFixed(0)}% Confidence
                      </span>
                      <span>&bull;</span>
                      <span className="flex items-center gap-1 text-slate-400">
                        <Clock className="w-3 h-3 text-slate-500" />
                        {new Date(threat.timestamp).toLocaleTimeString()}
                      </span>
                    </div>
                  </div>

                  {/* Title & Description */}
                  <div className="space-y-1 text-xs">
                    <div className="font-semibold text-slate-100">{threat.title}</div>
                    <p className="text-slate-300 leading-relaxed">{threat.description}</p>
                  </div>

                  {/* Sanitized Evidence & Metadata Preview (if available) */}
                  {threat.metadata && Object.keys(threat.metadata).length > 0 && (
                    <div className="p-2.5 bg-slate-950/80 rounded-lg border border-slate-800/80 text-[11px] font-mono text-slate-400 space-y-1">
                      <div className="text-[10px] uppercase font-semibold text-slate-500 flex items-center justify-between">
                        <span>Sanitized Evidence &amp; Telemetry Signals</span>
                        <span className="text-[10px] text-emerald-400/80">Secured &bull; Redacted</span>
                      </div>
                      <pre className="overflow-x-auto text-slate-300 whitespace-pre-wrap max-h-32 text-[11px]">
                        {JSON.stringify(sanitizeTelemetryData(threat.metadata), null, 2)}
                      </pre>
                    </div>
                  )}

                  {/* Footer Identifiers & Cross-Link Actions */}
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-[11px] text-slate-500 font-mono pt-1">
                    <div className="flex items-center gap-3">
                      <span>Correlation ID: {threat.request_id}</span>
                      <span>&bull;</span>
                      <span>Threat ID: {threat.threat_id.slice(0, 8)}</span>
                    </div>

                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => setSelectedThreat(threat)}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-sans font-medium transition flex items-center gap-1.5 focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none"
                        aria-label={`Investigate threat ${threat.threat_id}`}
                      >
                        <Eye className="w-3.5 h-3.5 text-cyan-400" />
                        <span>Investigate</span>
                      </button>

                      {onSelectTab && (
                        <button
                          onClick={() => onSelectTab('decisions', threat.request_id)}
                          className="px-2.5 py-1 rounded bg-cyan-950/40 hover:bg-cyan-900/60 border border-cyan-500/30 text-cyan-300 text-xs font-sans font-medium transition flex items-center gap-1 focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none"
                          title="Navigate to Security Decisions for this request"
                        >
                          <span>View Decision</span>
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

      {/* Technical Detail Investigation Drawer */}
      {selectedThreat && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="threat-drawer-title"
          className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 bg-black/80 backdrop-blur-sm"
        >
          <div className="relative w-full max-w-2xl bg-slate-900 border border-slate-700 rounded-2xl p-6 space-y-5 max-h-[90vh] overflow-y-auto shadow-2xl">
            {/* Drawer Header */}
            <div className="flex items-start justify-between gap-3 border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400">
                  <ShieldAlert className="w-5 h-5" />
                </div>
                <div>
                  <h3 id="threat-drawer-title" className="text-base font-bold text-white">
                    Threat Signal Investigation
                  </h3>
                  <p className="text-xs text-slate-400">
                    Deterministic security telemetry and sanitized forensic evidence
                  </p>
                </div>
              </div>
              <button
                onClick={() => setSelectedThreat(null)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none"
                aria-label="Close threat investigation drawer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* IDENTITY SECTION */}
            <div className="space-y-2">
              <div className="text-[10px] font-mono uppercase font-bold text-slate-400 tracking-wider">
                Identity &amp; Classification
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
                <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800">
                  <div className="text-slate-500 text-[10px]">Threat Type</div>
                  <div className="text-white font-bold">{selectedThreat.threat_type}</div>
                </div>
                <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800">
                  <div className="text-slate-500 text-[10px]">Detector Engine</div>
                  <div className="text-white font-bold">{selectedThreat.detector}</div>
                </div>
                <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800 sm:col-span-2">
                  <div className="text-slate-500 text-[10px]">Correlation / Request ID</div>
                  <div className="text-cyan-400 font-bold break-all">{selectedThreat.request_id}</div>
                </div>
                <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800 sm:col-span-2">
                  <div className="text-slate-500 text-[10px]">Threat ID</div>
                  <div className="text-slate-300 break-all">{selectedThreat.threat_id}</div>
                </div>
              </div>
            </div>

            {/* TIMELINE & CONFIDENCE */}
            <div className="space-y-2">
              <div className="text-[10px] font-mono uppercase font-bold text-slate-400 tracking-wider">
                Forensic Context
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
                <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800">
                  <div className="text-slate-500 text-[10px]">Severity Level</div>
                  <div className="mt-1">
                    <SeverityBadge severity={selectedThreat.severity} />
                  </div>
                </div>
                <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800">
                  <div className="text-slate-500 text-[10px]">Confidence Rating</div>
                  <div className="text-white font-bold text-sm mt-0.5">
                    {(selectedThreat.confidence * 100).toFixed(1)}%
                  </div>
                </div>
                <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800 sm:col-span-2">
                  <div className="text-slate-500 text-[10px]">Recorded Timestamp</div>
                  <div className="text-slate-300">
                    {new Date(selectedThreat.timestamp).toISOString()} ({new Date(selectedThreat.timestamp).toLocaleString()})
                  </div>
                </div>
              </div>
            </div>

            {/* SUMMARY */}
            <div className="space-y-1 text-xs">
              <div className="text-[10px] font-mono uppercase font-bold text-slate-400 tracking-wider">
                Signal Summary
              </div>
              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
                <div className="font-semibold text-slate-100">{selectedThreat.title}</div>
                <p className="text-slate-300 leading-relaxed">{selectedThreat.description}</p>
              </div>
            </div>

            {/* SANITIZED EVIDENCE OBJECT */}
            {selectedThreat.metadata && Object.keys(selectedThreat.metadata).length > 0 && (
              <div className="space-y-1 text-xs">
                <div className="text-[10px] font-mono uppercase font-bold text-slate-400 tracking-wider">
                  Sanitized Metadata &amp; Signals
                </div>
                <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-[11px] font-mono max-h-48 overflow-y-auto">
                  <pre className="text-slate-300 whitespace-pre-wrap">
                    {JSON.stringify(sanitizeTelemetryData(selectedThreat.metadata), null, 2)}
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
                      const reqId = selectedThreat.request_id;
                      setSelectedThreat(null);
                      onSelectTab('decisions', reqId);
                    }}
                    className="px-3 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold transition flex items-center gap-1.5 focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none"
                  >
                    <span>View Security Decision</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>

                  <button
                    onClick={() => {
                      const reqId = selectedThreat.request_id;
                      setSelectedThreat(null);
                      onSelectTab('executions', reqId);
                    }}
                    className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold transition border border-slate-700 flex items-center gap-1.5 focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none"
                  >
                    <span>View Executions</span>
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
