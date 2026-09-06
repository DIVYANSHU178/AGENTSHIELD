import React from 'react';
import {
  OperationsOverview,
  SecurityDecisionType,
  Severity,
  ApprovalRequest,
  SecurityEvent,
} from '../../types';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Activity,
  Terminal,
  Lock,
  UserCheck,
  FileText,
  ChevronRight,
  ChevronDown,
  ArrowRight,
} from 'lucide-react';
import { MotionCard } from '../common/MotionComponents';
import { LoadingState, AuthRequiredState } from '../common/StateViews';
import { useMotion } from '../../context/MotionContext';

interface OverviewTabProps {
  overview: OperationsOverview | null;
  onSelectTab: (tab: string, filterQuery?: string) => void;
  authRequired?: boolean;
  onSignIn?: () => void;
  approvals?: ApprovalRequest[];
  auditEvents?: SecurityEvent[];
}

export const OverviewTab: React.FC<OverviewTabProps> = ({
  overview,
  onSelectTab,
  authRequired,
  onSignIn,
  approvals = [],
}) => {
  const { isReducedMotion } = useMotion();

  // 1. Loading & Auth-Required Fallback Views
  if (!overview) {
    if (authRequired) {
      return (
        <AuthRequiredState
          title="Operations Data Locked"
          message="Please sign in with your AgentShield identity to view operational metrics, threat streams, and security decisions."
          onSignIn={onSignIn}
        />
      );
    }
    return (
      <LoadingState
        title="Processing Security Operations Overview"
        message="Retrieving telemetry from the AgentShield authoritative security gateway..."
        stage="Telemetry Gateway Sync"
      />
    );
  }

  const { overall_health, metrics, recent_threats, recent_decisions, recent_executions } = overview;
  const pendingApprovalsCount = Array.isArray(approvals)
    ? approvals.filter((a) => a.status === 'PENDING').length
    : 0;

  // 2. Core Security Enforcement Pipeline Definition
  // THREAT -> RISK -> POLICY -> APPROVAL -> ENFORCEMENT -> EXECUTION -> AUDIT
  const pipelineStages = [
    {
      id: 'threat',
      name: 'THREAT',
      phaseNumber: '01',
      subtitle: 'Deterministic Detection',
      metric: `${metrics.detected_threats} Detected`,
      detail: `${metrics.critical_threats} Critical • 4 Detectors Active`,
      status: metrics.critical_threats > 0 ? 'danger' : metrics.detected_threats > 0 ? 'warning' : 'healthy',
      icon: ShieldAlert,
      tab: 'threats',
    },
    {
      id: 'risk',
      name: 'RISK',
      phaseNumber: '02',
      subtitle: 'Risk Engine Evaluation',
      metric: 'Scored',
      detail: 'Multi-signal heuristic & pattern weighting',
      status: metrics.critical_threats > 0 ? 'danger' : 'info',
      icon: AlertTriangle,
      tab: 'decisions',
    },
    {
      id: 'policy',
      name: 'POLICY',
      phaseNumber: '03',
      subtitle: 'Decision Gateway',
      metric: `${metrics.total_requests} Decisions`,
      detail: `${metrics.allowed} Allowed • ${metrics.blocked} Blocked`,
      status: metrics.blocked > 0 ? 'warning' : 'healthy',
      icon: Shield,
      tab: 'decisions',
    },
    {
      id: 'approval',
      name: 'APPROVAL',
      phaseNumber: '04',
      subtitle: 'Human Review Authority',
      metric: `${pendingApprovalsCount} Pending Review`,
      detail: `${pendingApprovalsCount > 0 ? 'Human Action Required' : 'Queue Clear'} • Dual-Custody RBAC`,
      status: pendingApprovalsCount > 0 ? 'warning' : 'healthy',
      icon: UserCheck,
      tab: 'approvals',
    },
    {
      id: 'enforcement',
      name: 'ENFORCEMENT',
      phaseNumber: '05',
      subtitle: 'Security Boundary',
      metric: `${metrics.authorized} Authorized`,
      detail: 'Cryptographic HMAC Token Verification',
      status: 'healthy' as const,
      icon: Lock,
      tab: 'diagnostics',
    },
    {
      id: 'execution',
      name: 'EXECUTION',
      phaseNumber: '06',
      subtitle: 'Sandbox Containment',
      metric: `${metrics.successful_execution} Completed`,
      detail: `${metrics.failed_execution} Failed • Container Isolation`,
      status: metrics.failed_execution > 0 ? 'warning' : 'healthy',
      icon: Terminal,
      tab: 'executions',
    },
    {
      id: 'audit',
      name: 'AUDIT',
      phaseNumber: '07',
      subtitle: 'Immutable Ledger',
      metric: `${metrics.audit_events} Records`,
      detail: 'Durable Event Persistence & Forensic Trace',
      status: 'info' as const,
      icon: FileText,
      tab: 'audit',
    },
  ];

  return (
    <div className="space-y-6">
      {/* 1. Global System Status Strip */}
      <MotionCard
        className={`p-5 rounded-2xl border flex flex-col md:flex-row md:items-center justify-between gap-4 transition-all shadow-lg ${
          overall_health.status === 'HEALTHY'
            ? 'bg-emerald-950/20 border-emerald-500/30 text-emerald-300 shadow-emerald-950/10'
            : overall_health.status === 'DEGRADED'
            ? 'bg-amber-950/20 border-amber-500/30 text-amber-300 shadow-amber-950/10'
            : 'bg-rose-950/20 border-rose-500/30 text-rose-300 shadow-rose-950/10'
        }`}
      >
        <div className="flex items-center gap-4">
          <div
            className={`p-3 rounded-xl border flex-shrink-0 ${
              overall_health.status === 'HEALTHY'
                ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400 shadow-[0_0_15px_rgba(16,185,129,0.15)]'
                : overall_health.status === 'DEGRADED'
                ? 'bg-amber-500/10 border-amber-500/30 text-amber-400 shadow-[0_0_15px_rgba(245,158,11,0.15)]'
                : 'bg-rose-500/10 border-rose-500/30 text-rose-400 shadow-[0_0_15px_rgba(244,63,94,0.15)]'
            }`}
          >
            {overall_health.status === 'HEALTHY' ? (
              <ShieldCheck className="w-7 h-7" />
            ) : overall_health.status === 'DEGRADED' ? (
              <AlertTriangle className="w-7 h-7" />
            ) : (
              <ShieldAlert className="w-7 h-7" />
            )}
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h2 className="text-lg font-bold text-white tracking-tight">
                System Status: {overall_health.status}
              </h2>
              <span className="text-[11px] px-2 py-0.5 rounded bg-slate-900 text-slate-300 font-mono border border-slate-700/60 font-semibold">
                v{overall_health.version}
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                7/7 Components Operational
              </span>
            </div>
            <p className="text-xs text-slate-300 mt-1 leading-relaxed">
              {overall_health.summary}
            </p>
          </div>
        </div>
        <button
          onClick={() => onSelectTab('diagnostics')}
          className="px-3.5 py-2 bg-slate-900 hover:bg-slate-800 text-slate-200 rounded-lg text-xs font-semibold border border-slate-700 transition self-start md:self-auto focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none flex items-center gap-1.5 whitespace-nowrap"
        >
          <span>View Component Diagnostics ({overall_health.components.length})</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </button>
      </MotionCard>

      {/* 2. Security Enforcement Pipeline (Visual Centerpiece) */}
      <section
        className="bg-slate-900/50 border border-slate-800/90 rounded-2xl p-5 space-y-4 shadow-xl"
        role="region"
        aria-label="Security Enforcement Pipeline"
      >
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
          <div>
            <h3 className="text-sm font-mono font-bold tracking-wider text-white uppercase flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              Security Enforcement Pipeline
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Authoritative request trajectory from deterministic detection to immutable audit ledger
            </p>
          </div>
          <div className="flex items-center gap-1.5 self-start sm:self-auto text-[10px] font-mono text-slate-400 bg-slate-950/60 px-2.5 py-1 rounded-md border border-slate-800">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
            <span>Deterministic • Fail-Closed</span>
          </div>
        </div>

        {/* Sequential Stages Grid */}
        <ol className="grid grid-cols-1 md:grid-cols-7 gap-2.5">
          {pipelineStages.map((stage, idx) => {
            const Icon = stage.icon;
            const isLast = idx === pipelineStages.length - 1;

            const statusColors = {
              healthy: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300 hover:border-emerald-500/60',
              warning: 'bg-amber-500/10 border-amber-500/30 text-amber-300 hover:border-amber-500/60',
              danger: 'bg-rose-500/10 border-rose-500/30 text-rose-300 hover:border-rose-500/60',
              info: 'bg-cyan-500/10 border-cyan-500/30 text-cyan-300 hover:border-cyan-500/60',
            }[stage.status];

            const iconColors = {
              healthy: 'text-emerald-400 bg-emerald-950/40 border-emerald-500/20',
              warning: 'text-amber-400 bg-amber-950/40 border-amber-500/20',
              danger: 'text-rose-400 bg-rose-950/40 border-rose-500/20',
              info: 'text-cyan-400 bg-cyan-950/40 border-cyan-500/20',
            }[stage.status];

            return (
              <li key={stage.id} className="relative flex flex-col">
                <button
                  onClick={() => onSelectTab(stage.tab)}
                  className={`flex-1 p-3.5 rounded-xl border text-left transition-all group flex flex-col justify-between space-y-3 focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none ${statusColors} ${
                    !isReducedMotion ? 'hover:scale-[1.02]' : ''
                  }`}
                  aria-label={`Pipeline Stage ${stage.phaseNumber}: ${stage.name}. ${stage.subtitle}. Current status: ${stage.metric}`}
                >
                  <div className="flex items-start justify-between gap-1 w-full">
                    <span className="font-mono text-[10px] font-bold text-slate-500 group-hover:text-slate-300 transition">
                      {stage.phaseNumber}
                    </span>
                    <div className={`p-1.5 rounded-lg border ${iconColors}`}>
                      <Icon className="w-3.5 h-3.5" />
                    </div>
                  </div>

                  <div>
                    <div className="font-mono text-xs font-bold text-white tracking-wider uppercase group-hover:text-cyan-300 transition">
                      {stage.name}
                    </div>
                    <div className="text-[10px] text-slate-400 leading-tight line-clamp-1 mt-0.5">
                      {stage.subtitle}
                    </div>
                  </div>

                  <div className="pt-2 border-t border-slate-800/60 w-full">
                    <div className="font-mono text-[11px] font-bold text-slate-200">
                      {stage.metric}
                    </div>
                    <div className="text-[9px] text-slate-400 line-clamp-1 mt-0.5">
                      {stage.detail}
                    </div>
                  </div>
                </button>

                {/* Flow Connector Arrow */}
                {!isLast && (
                  <>
                    <div
                      className="hidden md:flex absolute -right-2 top-1/2 -translate-y-1/2 z-10 text-slate-600 pointer-events-none"
                      aria-hidden="true"
                    >
                      <ChevronRight className="w-3.5 h-3.5 text-slate-500" />
                    </div>
                    <div
                      className="md:hidden flex justify-center py-1 text-slate-600 pointer-events-none"
                      aria-hidden="true"
                    >
                      <ChevronDown className="w-4 h-4 text-slate-500" />
                    </div>
                  </>
                )}
              </li>
            );
          })}
        </ol>
      </section>

      {/* 3. Key Security KPI Counters */}
      <section aria-label="Security Metrics and Counters">
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
          <MetricCard
            label="Total Evaluations"
            value={metrics.total_requests}
            color="blue"
            icon={Activity}
          />
          <MetricCard
            label="Allowed Requests"
            value={metrics.allowed}
            color="emerald"
            icon={ShieldCheck}
          />
          <MetricCard
            label="Approval-Gated Decisions"
            value={metrics.require_approval}
            color="amber"
            icon={UserCheck}
            subtext="Cumulative policy evaluations"
          />
          <MetricCard
            label="Blocked Requests"
            value={metrics.blocked}
            color="rose"
            icon={ShieldAlert}
            highlight={metrics.blocked > 0}
          />
          <MetricCard
            label="Authorized Credentials"
            value={metrics.authorized}
            color="indigo"
            icon={Lock}
          />
          <MetricCard
            label="Successful Executions"
            value={metrics.successful_execution}
            color="emerald"
            icon={Terminal}
          />
          <MetricCard
            label="Failed Executions"
            value={metrics.failed_execution}
            color="rose"
            icon={AlertTriangle}
            highlight={metrics.failed_execution > 0}
          />
          <MetricCard
            label="Timed Out"
            value={metrics.timed_out_execution}
            color="amber"
            icon={Activity}
          />
          <MetricCard
            label="Denied Executions"
            value={metrics.denied_execution}
            color="slate"
            icon={ShieldAlert}
          />
          <MetricCard
            label="Threats Detected"
            value={metrics.detected_threats}
            color="rose"
            icon={AlertTriangle}
            highlight={metrics.detected_threats > 0}
          />
          <MetricCard
            label="Critical Threats"
            value={metrics.critical_threats}
            color="rose"
            icon={ShieldAlert}
            highlight={metrics.critical_threats > 0}
            badgeText={metrics.critical_threats > 0 ? 'Urgent' : undefined}
          />
          <MetricCard
            label="Audit Trail Records"
            value={metrics.audit_events}
            color="blue"
            icon={FileText}
          />
        </div>
      </section>

      {/* 4. Three-Column Snapshot: Recent Threats, Decisions, Executions */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Threats */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 space-y-4 shadow-md">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <h3 className="font-semibold text-white text-sm flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-rose-400" /> Recent Threat Signals
            </h3>
            <button
              onClick={() => onSelectTab('threats')}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-medium transition focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none rounded px-1.5 py-0.5"
            >
              View All &rarr;
            </button>
          </div>

          {recent_threats.length === 0 ? (
            <div className="p-8 text-center text-xs text-slate-500 bg-slate-950/40 rounded-xl border border-slate-800/40">
              No threat signals recorded.
            </div>
          ) : (
            <div className="space-y-2.5">
              {recent_threats.slice(0, 5).map((t) => (
                <div
                  key={t.threat_id}
                  className="p-3 bg-slate-950/60 border border-slate-800/80 rounded-xl space-y-1.5 text-xs hover:border-slate-700/80 transition"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-slate-300 font-semibold truncate">{t.threat_type}</span>
                    <SeverityBadge severity={t.severity} />
                  </div>
                  <p className="text-slate-400 line-clamp-1">{t.title}</p>
                  <div className="flex items-center justify-between text-[10px] text-slate-500 font-mono pt-1 border-t border-slate-900">
                    <span className="truncate">Detector: {t.detector}</span>
                    <button
                      onClick={() => onSelectTab('threats', t.request_id)}
                      className="text-cyan-400 hover:text-cyan-300 transition flex items-center gap-0.5 ml-2 shrink-0 font-sans"
                      title={`Inspect threat for ${t.request_id}`}
                    >
                      <span>Inspect</span>
                      <ArrowRight className="w-2.5 h-2.5" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Recent Decisions */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 space-y-4 shadow-md">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <h3 className="font-semibold text-white text-sm flex items-center gap-2">
              <Shield className="w-4 h-4 text-blue-400" /> Security Decisions
            </h3>
            <button
              onClick={() => onSelectTab('decisions')}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-medium transition focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none rounded px-1.5 py-0.5"
            >
              View All &rarr;
            </button>
          </div>

          {recent_decisions.length === 0 ? (
            <div className="p-8 text-center text-xs text-slate-500 bg-slate-950/40 rounded-xl border border-slate-800/40">
              No security decisions recorded yet.
            </div>
          ) : (
            <div className="space-y-2.5">
              {recent_decisions.slice(0, 5).map((d) => (
                <div
                  key={d.decision_id}
                  className="p-3 bg-slate-950/60 border border-slate-800/80 rounded-xl space-y-1.5 text-xs hover:border-slate-700/80 transition"
                >
                  <div className="flex items-center justify-between gap-2">
                    <DecisionBadge decision={d.decision} />
                    <span className="text-slate-400 font-mono text-[11px]">
                      Risk: {d.risk_score.toFixed(1)}
                    </span>
                  </div>
                  <p className="text-slate-400 line-clamp-1">{d.reason}</p>
                  <div className="flex items-center justify-between text-[10px] text-slate-500 font-mono pt-1 border-t border-slate-900">
                    <span className="truncate">Policy: {d.policy_id}</span>
                    <div className="flex items-center gap-2 shrink-0">
                      <span>Threats: {d.threat_count}</span>
                      <button
                        onClick={() => onSelectTab('decisions', d.request_id)}
                        className="text-cyan-400 hover:text-cyan-300 transition flex items-center gap-0.5 font-sans"
                        title={`Inspect decision for ${d.request_id}`}
                      >
                        <span>Inspect</span>
                        <ArrowRight className="w-2.5 h-2.5" />
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Recent Executions */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 space-y-4 shadow-md">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <h3 className="font-semibold text-white text-sm flex items-center gap-2">
              <Terminal className="w-4 h-4 text-emerald-400" /> Sandbox Executions
            </h3>
            <button
              onClick={() => onSelectTab('executions')}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-medium transition focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none rounded px-1.5 py-0.5"
            >
              View All &rarr;
            </button>
          </div>

          {recent_executions.length === 0 ? (
            <div className="p-8 text-center text-xs text-slate-500 bg-slate-950/40 rounded-xl border border-slate-800/40">
              No runtime tool executions recorded yet.
            </div>
          ) : (
            <div className="space-y-2.5">
              {recent_executions.slice(0, 5).map((e) => (
                <div
                  key={e.execution_id}
                  className="p-3 bg-slate-950/60 border border-slate-800/80 rounded-xl space-y-1.5 text-xs hover:border-slate-700/80 transition"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-slate-300 font-semibold truncate">{e.tool_name}</span>
                    <ExecutionStatusBadge status={e.status} />
                  </div>
                  <div className="flex items-center justify-between text-[10px] text-slate-500 font-mono pt-1 border-t border-slate-900">
                    <span className="truncate">{e.action} ({e.tool_category})</span>
                    <div className="flex items-center gap-2 shrink-0">
                      <span>{e.duration_ms.toFixed(1)} ms</span>
                      <button
                        onClick={() => onSelectTab('executions', e.request_id)}
                        className="text-cyan-400 hover:text-cyan-300 transition flex items-center gap-0.5 font-sans"
                        title={`Inspect execution for ${e.request_id}`}
                      >
                        <span>Inspect</span>
                        <ArrowRight className="w-2.5 h-2.5" />
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

const MetricCard: React.FC<{
  label: string;
  value: number;
  color: 'blue' | 'emerald' | 'amber' | 'rose' | 'indigo' | 'slate';
  highlight?: boolean;
  icon?: React.ComponentType<{ className?: string }>;
  badgeText?: string;
  subtext?: string;
}> = ({ label, value, color, highlight, icon: Icon, badgeText, subtext }) => {
  const colorMap = {
    blue: 'text-blue-400 border-blue-500/20 bg-blue-950/15 hover:border-blue-500/40',
    emerald: 'text-emerald-400 border-emerald-500/20 bg-emerald-950/15 hover:border-emerald-500/40',
    amber: 'text-amber-400 border-amber-500/20 bg-amber-950/15 hover:border-amber-500/40',
    rose: 'text-rose-400 border-rose-500/20 bg-rose-950/15 hover:border-rose-500/40',
    indigo: 'text-indigo-400 border-indigo-500/20 bg-indigo-950/15 hover:border-indigo-500/40',
    slate: 'text-slate-400 border-slate-700/40 bg-slate-900/30 hover:border-slate-600/60',
  };

  return (
    <div
      className={`p-3.5 rounded-xl border transition-all ${colorMap[color]} ${
        highlight ? 'ring-1 ring-rose-500/50' : ''
      }`}
    >
      <div className="flex items-center justify-between gap-1">
        <span className="text-[11px] font-medium text-slate-400 truncate" title={label}>{label}</span>
        {badgeText ? (
          <span className="px-1.5 py-0.2 rounded text-[9px] font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30">
            {badgeText}
          </span>
        ) : Icon ? (
          <Icon className="w-3.5 h-3.5 opacity-60 flex-shrink-0" />
        ) : null}
      </div>
      <div className="text-xl font-bold text-white mt-1.5 font-mono">{value}</div>
      {subtext && (
        <div className="text-[10px] text-slate-400 font-sans mt-0.5 truncate" title={subtext}>
          {subtext}
        </div>
      )}
    </div>
  );
};

export const SeverityBadge: React.FC<{ severity: Severity }> = ({ severity }) => {
  const styles: Record<Severity, string> = {
    INFO: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
    LOW: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
    MEDIUM: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
    HIGH: 'bg-orange-500/10 text-orange-400 border-orange-500/30',
    CRITICAL: 'bg-rose-500/10 text-rose-400 border-rose-500/30 font-bold',
  };

  return (
    <span className={`px-2 py-0.5 text-[10px] font-mono rounded border ${styles[severity] || styles.INFO}`}>
      {severity}
    </span>
  );
};

export const DecisionBadge: React.FC<{ decision: SecurityDecisionType }> = ({ decision }) => {
  const styles: Record<SecurityDecisionType, string> = {
    ALLOW: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
    REQUIRE_APPROVAL: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
    BLOCK: 'bg-rose-500/10 text-rose-400 border-rose-500/30 font-bold',
  };

  return (
    <span className={`px-2 py-0.5 text-[10px] font-mono rounded border ${styles[decision] || styles.ALLOW}`}>
      {decision}
    </span>
  );
};

export const ExecutionStatusBadge: React.FC<{ status: string }> = ({ status }) => {
  const styles: Record<string, string> = {
    COMPLETED: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
    DENIED: 'bg-slate-500/10 text-slate-400 border-slate-500/30',
    TIMED_OUT: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
    FAILED: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
    PENDING: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
    AUTHORIZED: 'bg-indigo-500/10 text-indigo-400 border-indigo-500/30',
  };

  return (
    <span className={`px-2 py-0.5 text-[10px] font-mono rounded border ${styles[status] || styles.DENIED}`}>
      {status}
    </span>
  );
};
