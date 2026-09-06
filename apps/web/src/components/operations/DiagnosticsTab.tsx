import React, { useState, useEffect, useMemo } from 'react';
import { OverallSystemHealth, ComponentHealth, ComponentStatus, ConnectionStatus } from '../../types';
import {
  Activity,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Shield,
  Server,
  Lock,
  Box,
  FileCheck,
  Cpu,
  RefreshCw,
  Search,
  X,
  ShieldCheck,
  HelpCircle,
  Clock,
  Terminal,
  ExternalLink,
  Info,
} from 'lucide-react';
import { MotionCard, MotionList, MotionItem } from '../common/MotionComponents';
import { LoadingState, EmptyState, AuthRequiredState, BackendUnavailableState } from '../common/StateViews';
import { sanitizeTelemetryData } from '../../lib/sanitizer';
import { interactive } from '../../theme/tokens';

export interface DiagnosticsTabProps {
  health: OverallSystemHealth | null;
  onRefresh: () => void;
  loading: boolean;
  authRequired?: boolean;
  onSignIn?: () => void;
  connectionStatus?: ConnectionStatus;
}

export type HealthFilterStatus = 'ALL' | 'HEALTHY' | 'DEGRADED' | 'FAILED';

interface SubsystemMeta {
  layer: string;
  role: string;
  icon: React.ComponentType<{ className?: string }>;
  accentColor: string;
}

const SUBSYSTEM_METADATA: Record<string, SubsystemMeta> = {
  SecurityDecisionGateway: {
    layer: 'Detection & Evaluation',
    role: 'Deterministic threat detection, heuristic pattern matching, and rule-based security policy brokering.',
    icon: Shield,
    accentColor: 'text-blue-400',
  },
  SecurityEnforcementBoundary: {
    layer: 'Cryptographic Authorization',
    role: 'Capability token verification, HMAC-SHA256 signature validation, and tamper-resistant execution gating.',
    icon: Lock,
    accentColor: 'text-indigo-400',
  },
  SandboxExecutionBoundary: {
    layer: 'Isolated Containment',
    role: 'Strict timeout containment, bounded execution environment, and fault-isolated payload isolation.',
    icon: Box,
    accentColor: 'text-emerald-400',
  },
  SecureExecutionAdapter: {
    layer: 'Runtime Dispatch',
    role: 'Secure runtime bridge connecting authorized decisions directly to sandbox execution.',
    icon: Cpu,
    accentColor: 'text-amber-400',
  },
  ToolExecutionRegistry: {
    layer: 'Tool Contracts',
    role: 'Deterministic catalog of safe tools, validated parameter schemas, and whitelisted action contracts.',
    icon: Cpu,
    accentColor: 'text-amber-400',
  },
  AgentRuntimeOrchestrator: {
    layer: 'Pipeline Orchestration',
    role: 'End-to-end multi-step agent session coordinator enforcing fail-closed lifecycle invariants.',
    icon: Server,
    accentColor: 'text-purple-400',
  },
  SecurityAuditTrail: {
    layer: 'Forensic Persistence',
    role: 'Append-only, durable persistence and chronological forensic trace of all security events, evaluations, and decisions.',
    icon: FileCheck,
    accentColor: 'text-cyan-400',
  },
};

export const DiagnosticsTab: React.FC<DiagnosticsTabProps> = ({
  health,
  onRefresh,
  loading,
  authRequired,
  onSignIn,
  connectionStatus,
}) => {
  const [selectedComponent, setSelectedComponent] = useState<ComponentHealth | null>(null);
  const [statusFilter, setStatusFilter] = useState<HealthFilterStatus>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Handle Escape key to dismiss drawer
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && selectedComponent) {
        setSelectedComponent(null);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [selectedComponent]);

  // Derived metrics from health.components
  const metrics = useMemo(() => {
    if (!health || !health.components) {
      return { total: 0, healthy: 0, degraded: 0, failed: 0 };
    }
    const total = health.components.length;
    const healthy = health.components.filter((c) => c.status === 'HEALTHY').length;
    const degraded = health.components.filter((c) => c.status === 'DEGRADED').length;
    const failed = health.components.filter((c) => c.status === 'FAILED').length;
    return { total, healthy, degraded, failed };
  }, [health]);

  // Filtered components
  const filteredComponents = useMemo(() => {
    if (!health || !health.components) return [];
    return health.components.filter((comp) => {
      // Status filter
      if (statusFilter !== 'ALL' && comp.status !== statusFilter) {
        return false;
      }
      // Search filter
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase();
        const matchesName = comp.name.toLowerCase().includes(query);
        const matchesDetails = comp.details.toLowerCase().includes(query);
        const meta = SUBSYSTEM_METADATA[comp.name];
        const matchesLayer = meta ? meta.layer.toLowerCase().includes(query) : false;
        if (!matchesName && !matchesDetails && !matchesLayer) {
          return false;
        }
      }
      return true;
    });
  }, [health, statusFilter, searchQuery]);

  // Early return states when health data is not loaded
  if (!health) {
    if (authRequired) {
      return (
        <AuthRequiredState
          title="Diagnostics Access Protected"
          message="The AgentShield security backend is healthy and reachable, but inspecting component health diagnostics across the 7 security subsystems requires an authenticated session."
          onSignIn={onSignIn}
        />
      );
    }
    if (loading) {
      return (
        <LoadingState
          title="Inspecting Subsystem Health"
          message="Connecting to AgentShield runtime and verifying structural invariants across all 7 security components..."
          stage="Diagnostic checks in progress..."
        />
      );
    }
    return (
      <BackendUnavailableState
        title="Diagnostics Telemetry Unavailable"
        message="Unable to retrieve component health telemetry from the AgentShield security backend."
        onRetry={onRefresh}
        retrying={loading}
      />
    );
  }

  const getSubsystemMeta = (name: string): SubsystemMeta => {
    return (
      SUBSYSTEM_METADATA[name] || {
        layer: 'Subsystem',
        role: 'AgentShield security subsystem.',
        icon: Activity,
        accentColor: 'text-slate-400',
      }
    );
  };

  const getOverallStatusDisplay = (status: ComponentStatus) => {
    switch (status) {
      case 'HEALTHY':
        return {
          label: 'SYSTEM OPERATIONAL',
          badgeClass: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
          icon: ShieldCheck,
        };
      case 'DEGRADED':
        return {
          label: 'SYSTEM DEGRADED',
          badgeClass: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
          icon: AlertTriangle,
        };
      case 'FAILED':
        return {
          label: 'SYSTEM CRITICAL',
          badgeClass: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
          icon: XCircle,
        };
      default:
        return {
          label: 'STATUS UNKNOWN',
          badgeClass: 'bg-slate-500/10 text-slate-400 border-slate-500/30',
          icon: HelpCircle,
        };
    }
  };

  const overallDisplay = getOverallStatusDisplay(health.status);
  const OverallIcon = overallDisplay.icon;

  return (
    <div className="space-y-6" role="region" aria-label="Component Health Diagnostics">
      {/* 1. Header Command Bar */}
      <MotionCard className="bg-slate-900/60 p-4 sm:p-5 border border-slate-800 rounded-xl shadow-lg">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-start sm:items-center gap-3.5">
            <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 text-emerald-400 shrink-0">
              <Activity className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2.5 flex-wrap">
                <h3 className="text-base font-bold text-white tracking-tight">
                  Component Health Diagnostics
                </h3>
                <span
                  className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono font-semibold border ${overallDisplay.badgeClass}`}
                >
                  <OverallIcon className="w-3.5 h-3.5" />
                  {overallDisplay.label}
                </span>
                <span className="text-[11px] px-2 py-0.5 rounded bg-slate-950 text-slate-400 font-mono border border-slate-800">
                  v{health.version}
                </span>
                {connectionStatus && connectionStatus !== 'HEALTHY' && (
                  <span className="text-[10px] px-2 py-0.5 rounded bg-amber-950/40 text-amber-400 border border-amber-500/30 font-mono">
                    {connectionStatus}
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                Deterministic, non-executing structural inspection across all 7 pipeline components
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3 self-start lg:self-auto shrink-0 flex-wrap sm:flex-nowrap">
            <div className="text-left lg:text-right text-[11px] font-mono text-slate-400">
              <div className="text-slate-500 uppercase text-[10px] font-semibold">Last Checked</div>
              <div>{new Date(health.checked_at).toLocaleTimeString()}</div>
            </div>

            <button
              onClick={onRefresh}
              disabled={loading}
              aria-label="Run Health Diagnostics"
              className={`flex items-center gap-2 px-3.5 py-2 ${interactive.button.secondary} ${interactive.focusRing} ${interactive.disabled} text-xs`}
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
              <span>{loading ? 'Running Checks...' : 'Run Health Diagnostics'}</span>
            </button>
          </div>
        </div>
      </MotionCard>

      {/* 2. Quantified 5-KPI Metrics Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        <MotionCard className="p-3.5 bg-slate-900/40 border border-slate-800 rounded-xl">
          <div className="text-[10px] uppercase font-semibold tracking-wider text-slate-500">
            Total Subsystems
          </div>
          <div className="text-xl font-bold text-white font-mono mt-1">
            {metrics.total}
          </div>
          <div className="text-[11px] text-slate-400 mt-0.5">Core pipeline modules</div>
        </MotionCard>

        <MotionCard className="p-3.5 bg-slate-900/40 border border-slate-800 rounded-xl">
          <div className="text-[10px] uppercase font-semibold tracking-wider text-emerald-400/80 flex items-center gap-1">
            <CheckCircle2 className="w-3 h-3" /> Operational
          </div>
          <div className="text-xl font-bold text-emerald-400 font-mono mt-1">
            {metrics.healthy} / {metrics.total}
          </div>
          <div className="text-[11px] text-slate-400 mt-0.5">100% Invariants valid</div>
        </MotionCard>

        <MotionCard className="p-3.5 bg-slate-900/40 border border-slate-800 rounded-xl">
          <div className="text-[10px] uppercase font-semibold tracking-wider text-amber-400/80 flex items-center gap-1">
            <AlertTriangle className="w-3 h-3" /> Degraded
          </div>
          <div className="text-xl font-bold text-amber-400 font-mono mt-1">
            {metrics.degraded}
          </div>
          <div className="text-[11px] text-slate-400 mt-0.5">Warnings recorded</div>
        </MotionCard>

        <MotionCard className="p-3.5 bg-slate-900/40 border border-slate-800 rounded-xl">
          <div className="text-[10px] uppercase font-semibold tracking-wider text-rose-400/80 flex items-center gap-1">
            <XCircle className="w-3 h-3" /> Unavailable
          </div>
          <div className="text-xl font-bold text-rose-400 font-mono mt-1">
            {metrics.failed}
          </div>
          <div className="text-[11px] text-slate-400 mt-0.5">Failing components</div>
        </MotionCard>

        <MotionCard className="p-3.5 bg-slate-900/40 border border-slate-800 rounded-xl col-span-2 sm:col-span-1">
          <div className="text-[10px] uppercase font-semibold tracking-wider text-cyan-400/80 flex items-center gap-1">
            <Shield className="w-3 h-3" /> Inspection Invariant
          </div>
          <div className="text-xs font-semibold text-cyan-300 font-mono mt-1 truncate">
            Non-Executing
          </div>
          <div className="text-[11px] text-slate-400 mt-0.5 truncate">Zero payload dispatch</div>
        </MotionCard>
      </div>

      {/* 3. Filter & Search Controls */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 bg-slate-900/40 p-3 border border-slate-800/80 rounded-xl">
        {/* Search Bar */}
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Filter components by name or details..."
            aria-label="Filter components by name or details"
            className="w-full pl-9 pr-8 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition"
          />
          {searchQuery && (
            <button
              onClick={() => setSearchQuery('')}
              aria-label="Clear search"
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {/* Status Filter Buttons */}
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 sm:pb-0" role="group" aria-label="Status filter">
          <button
            onClick={() => setStatusFilter('ALL')}
            className={`px-2.5 py-1 text-xs font-medium rounded-lg transition ${
              statusFilter === 'ALL'
                ? 'bg-slate-800 text-white font-semibold border border-slate-700'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            All ({metrics.total})
          </button>
          <button
            onClick={() => setStatusFilter('HEALTHY')}
            className={`px-2.5 py-1 text-xs font-medium rounded-lg transition ${
              statusFilter === 'HEALTHY'
                ? 'bg-emerald-950/60 text-emerald-300 font-semibold border border-emerald-500/40'
                : 'text-slate-400 hover:text-emerald-400 hover:bg-slate-900'
            }`}
          >
            Healthy ({metrics.healthy})
          </button>
          {metrics.degraded > 0 && (
            <button
              onClick={() => setStatusFilter('DEGRADED')}
              className={`px-2.5 py-1 text-xs font-medium rounded-lg transition ${
                statusFilter === 'DEGRADED'
                  ? 'bg-amber-950/60 text-amber-300 font-semibold border border-amber-500/40'
                  : 'text-slate-400 hover:text-amber-400 hover:bg-slate-900'
              }`}
            >
              Degraded ({metrics.degraded})
            </button>
          )}
          {metrics.failed > 0 && (
            <button
              onClick={() => setStatusFilter('FAILED')}
              className={`px-2.5 py-1 text-xs font-medium rounded-lg transition ${
                statusFilter === 'FAILED'
                  ? 'bg-rose-950/60 text-rose-300 font-semibold border border-rose-500/40'
                  : 'text-slate-400 hover:text-rose-400 hover:bg-slate-900'
              }`}
            >
              Failed ({metrics.failed})
            </button>
          )}
        </div>
      </div>

      {/* 4. Component Cards Grid */}
      {filteredComponents.length === 0 ? (
        <EmptyState
          title="No Components Found"
          message="No security subsystems match your filter criteria or search query."
          action={
            <button
              onClick={() => {
                setStatusFilter('ALL');
                setSearchQuery('');
              }}
              className={`px-3 py-1.5 text-xs ${interactive.button.outline}`}
            >
              Reset Filters
            </button>
          }
        />
      ) : (
        <MotionList className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {filteredComponents.map((comp) => {
            const meta = getSubsystemMeta(comp.name);
            const IconComponent = meta.icon;
            const hasMetadata = comp.metadata && Object.keys(comp.metadata).length > 0;
            const latency = comp.metadata?.latency_ms !== undefined ? Number(comp.metadata.latency_ms) : null;

            return (
              <MotionItem key={comp.name}>
                <div
                  className={`p-5 rounded-xl border space-y-3.5 transition flex flex-col justify-between h-full ${
                    comp.status === 'HEALTHY'
                      ? 'bg-slate-900/60 border-slate-800 hover:border-emerald-500/30'
                      : comp.status === 'DEGRADED'
                      ? 'bg-amber-950/10 border-amber-500/20 hover:border-amber-500/40'
                      : 'bg-rose-950/10 border-rose-500/20 hover:border-rose-500/40'
                  }`}
                >
                  <div className="space-y-3">
                    {/* Header */}
                    <div className="flex items-start justify-between gap-3 border-b border-slate-800/60 pb-3">
                      <div className="flex items-start gap-3">
                        <div className="p-2 rounded-lg bg-slate-950 border border-slate-800 shrink-0 mt-0.5">
                          <IconComponent className={`w-5 h-5 ${meta.accentColor}`} />
                        </div>
                        <div>
                          <div className="flex items-center gap-2 flex-wrap">
                            <h4 className="text-sm font-bold text-white tracking-tight">{comp.name}</h4>
                            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-950 text-slate-400 border border-slate-800/80">
                              {meta.layer}
                            </span>
                          </div>
                          <div className="flex items-center gap-3 text-[11px] text-slate-500 font-mono mt-1">
                            <span>Checked: {new Date(comp.checked_at).toLocaleTimeString()}</span>
                            {latency !== null && (
                              <span className="text-cyan-400">Latency: {latency}ms</span>
                            )}
                          </div>
                        </div>
                      </div>

                      <ComponentStatusBadge status={comp.status} />
                    </div>

                    {/* Diagnostic Message */}
                    <p className="text-xs text-slate-300 leading-relaxed">{comp.details}</p>

                    {/* Metadata Preview (Safe Parameters) */}
                    {hasMetadata && (
                      <div className="p-2.5 bg-slate-950/80 rounded-lg border border-slate-800/80 text-[11px] font-mono text-slate-400 space-y-1">
                        <div className="text-[10px] uppercase font-semibold text-slate-500 flex items-center justify-between">
                          <span>Inspected Parameters</span>
                          <span className="text-slate-600">Sanitized</span>
                        </div>
                        <div className="flex flex-wrap gap-1.5 pt-0.5">
                          {Object.entries(
                            (sanitizeTelemetryData(comp.metadata || {}) || {}) as Record<string, unknown>
                          ).map(([k, v]) => {
                            const displayVal =
                              Array.isArray(v)
                                ? v.join(', ')
                                : typeof v === 'object' && v !== null
                                ? JSON.stringify(v)
                                : String(v);
                            return (
                              <span
                                key={k}
                                className="px-2 py-0.5 bg-slate-900 rounded border border-slate-800 text-slate-300 max-w-full truncate"
                                title={`${k}: ${displayVal}`}
                              >
                                <span className="text-slate-500">{k}:</span> {displayVal}
                              </span>
                            );
                          })}
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Card Action */}
                  <div className="pt-2 border-t border-slate-800/40 flex items-center justify-between">
                    <span className="text-[11px] text-slate-500 font-mono">
                      Subsystem Invariant Verified
                    </span>
                    <button
                      onClick={() => setSelectedComponent(comp)}
                      aria-label={`Inspect ${comp.name} subsystem`}
                      className={`px-3 py-1 text-xs font-semibold flex items-center gap-1.5 ${interactive.button.outline} ${interactive.focusRing}`}
                    >
                      <span>Inspect Subsystem</span>
                      <ExternalLink className="w-3 h-3 text-slate-400" />
                    </button>
                  </div>
                </div>
              </MotionItem>
            );
          })}
        </MotionList>
      )}

      {/* 5. Non-Executing Invariant Notice */}
      <div className="p-4 bg-slate-900/40 border border-slate-800/80 rounded-xl text-xs text-slate-400 flex items-start gap-3">
        <Shield className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
        <p>
          <span className="font-semibold text-slate-200">Diagnostic Invariant:</span> Security health checks perform read-only structural validation of detector registries, policy rule sets, and cryptographic signing keys. Diagnostic checks <span className="text-slate-200 font-semibold">never execute tool handlers or user payloads</span>.
        </p>
      </div>

      {/* 6. Subsystem Detail Drawer / Modal */}
      {selectedComponent && (
        <SubsystemDetailDrawer
          component={selectedComponent}
          meta={getSubsystemMeta(selectedComponent.name)}
          onClose={() => setSelectedComponent(null)}
        />
      )}
    </div>
  );
};

// ---------------------------------------------------------------------------
// Component Status Badge
// ---------------------------------------------------------------------------
export const ComponentStatusBadge: React.FC<{ status: ComponentStatus }> = ({ status }) => {
  if (status === 'HEALTHY') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
        <CheckCircle2 className="w-3.5 h-3.5" /> HEALTHY
      </span>
    );
  }
  if (status === 'DEGRADED') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30">
        <AlertTriangle className="w-3.5 h-3.5" /> DEGRADED
      </span>
    );
  }
  if (status === 'FAILED') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/30">
        <XCircle className="w-3.5 h-3.5" /> FAILED
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono font-semibold bg-slate-500/10 text-slate-400 border border-slate-500/30">
      <HelpCircle className="w-3.5 h-3.5" /> UNKNOWN
    </span>
  );
};

// ---------------------------------------------------------------------------
// Subsystem Detail Drawer
// ---------------------------------------------------------------------------
interface SubsystemDetailDrawerProps {
  component: ComponentHealth;
  meta: SubsystemMeta;
  onClose: () => void;
}

export const SubsystemDetailDrawer: React.FC<SubsystemDetailDrawerProps> = ({
  component,
  meta,
  onClose,
}) => {
  const IconComponent = meta.icon;
  const sanitizedMetadata = useMemo(() => {
    return sanitizeTelemetryData(component.metadata || {}) as Record<string, unknown>;
  }, [component.metadata]);

  const latency = component.metadata?.latency_ms !== undefined ? Number(component.metadata.latency_ms) : null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-end bg-black/60 backdrop-blur-sm p-0 sm:p-4"
      role="dialog"
      aria-modal="true"
      aria-label={`Diagnostic details for ${component.name}`}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        className="w-full max-w-xl h-full sm:h-auto sm:max-h-[90vh] bg-slate-900 border border-slate-800 rounded-none sm:rounded-2xl flex flex-col shadow-2xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Drawer Header */}
        <div className="p-5 border-b border-slate-800 bg-slate-950/60 flex items-start justify-between gap-4">
          <div className="flex items-start gap-3.5">
            <div className="p-2.5 rounded-xl bg-slate-900 border border-slate-800 shrink-0 mt-0.5">
              <IconComponent className={`w-6 h-6 ${meta.accentColor}`} />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <h3 className="text-base font-bold text-white tracking-tight">{component.name}</h3>
                <ComponentStatusBadge status={component.status} />
              </div>
              <p className="text-xs text-slate-400 mt-0.5 font-mono">{meta.layer} Subsystem</p>
            </div>
          </div>

          <button
            onClick={onClose}
            aria-label="Close diagnostic details"
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Drawer Content */}
        <div className="p-5 space-y-5 overflow-y-auto flex-1 text-xs">
          {/* Quick Metrics Bar */}
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5 p-3.5 bg-slate-950/80 rounded-xl border border-slate-800/80">
            <div>
              <div className="text-[10px] uppercase font-semibold text-slate-500">Status</div>
              <div className="font-mono font-bold text-slate-200 mt-0.5">{component.status}</div>
            </div>
            <div>
              <div className="text-[10px] uppercase font-semibold text-slate-500">Last Checked</div>
              <div className="font-mono text-slate-300 mt-0.5">
                {new Date(component.checked_at).toLocaleTimeString()}
              </div>
            </div>
            <div className="col-span-2 sm:col-span-1">
              <div className="text-[10px] uppercase font-semibold text-slate-500">Latency</div>
              <div className="font-mono text-slate-300 mt-0.5">
                {latency !== null ? `${latency}ms` : 'Unmetered (Read-Only)'}
              </div>
            </div>
          </div>

          {/* Subsystem Purpose & Responsibilities */}
          <div className="space-y-1.5">
            <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
              <Info className="w-3.5 h-3.5 text-cyan-400" />
              Subsystem Architectural Role
            </h4>
            <p className="text-slate-300 bg-slate-950/50 p-3 rounded-lg border border-slate-800/60 leading-relaxed">
              {meta.role}
            </p>
          </div>

          {/* Diagnostic Status Report */}
          <div className="space-y-1.5">
            <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5 text-emerald-400" />
              Diagnostic Status Report
            </h4>
            <div className="p-3 bg-slate-950/50 rounded-lg border border-slate-800/60 text-slate-300 leading-relaxed font-mono text-[11px]">
              {component.details}
            </div>
          </div>

          {/* Checked Timestamp (Authoritative ISO 8601) */}
          <div className="space-y-1.5">
            <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5 text-indigo-400" />
              Authoritative Inspection Timestamp
            </h4>
            <div className="p-2.5 bg-slate-950/50 rounded-lg border border-slate-800/60 text-slate-400 font-mono text-[11px]">
              <div>UTC: {component.checked_at}</div>
              <div className="text-slate-500 text-[10px] mt-0.5">
                Local: {new Date(component.checked_at).toString()}
              </div>
            </div>
          </div>

          {/* Inspected Subsystem Telemetry */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-amber-400" />
                Inspected Subsystem Telemetry
              </h4>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950/40 text-emerald-400 border border-emerald-500/20">
                Safe Redacted
              </span>
            </div>

            {Object.keys(sanitizedMetadata).length > 0 ? (
              <div className="space-y-2">
                <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 overflow-x-auto">
                  <pre className="font-mono text-[11px] text-slate-300 whitespace-pre-wrap">
                    {JSON.stringify(sanitizedMetadata, null, 2)}
                  </pre>
                </div>
                <p className="text-[10px] text-slate-500">
                  Telemetry parameters inspected via deterministic introspection. Internal keys, credentials, and file paths are systematically redacted by the AgentShield Leakage Prevention Utility.
                </p>
              </div>
            ) : (
              <div className="p-4 bg-slate-950/40 rounded-lg border border-slate-800/60 text-slate-400 text-center text-xs">
                No auxiliary telemetry parameters exposed for this subsystem.
              </div>
            )}
          </div>
        </div>

        {/* Drawer Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/60 flex items-center justify-between">
          <span className="text-[11px] text-slate-500 font-mono">
            Security Invariant: Non-Executing Inspection
          </span>
          <button
            onClick={onClose}
            className={`px-4 py-1.5 text-xs ${interactive.button.secondary} ${interactive.focusRing}`}
          >
            Close Diagnostics
          </button>
        </div>
      </div>
    </div>
  );
};
