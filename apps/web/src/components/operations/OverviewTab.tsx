import React from 'react';
import {
  OperationsOverview,
  SecurityDecisionType,
  Severity,
} from '../../types';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Activity,
  Terminal,
} from 'lucide-react';

interface OverviewTabProps {
  overview: OperationsOverview | null;
  onSelectTab: (tab: string) => void;
}

export const OverviewTab: React.FC<OverviewTabProps> = ({ overview, onSelectTab }) => {
  if (!overview) {
    return (
      <div className="p-12 text-center text-slate-400 bg-slate-900/40 border border-slate-800 rounded-xl">
        <Activity className="w-8 h-8 mx-auto mb-3 text-slate-500 animate-pulse" />
        <p>Loading security operations overview...</p>
      </div>
    );
  }

  const { overall_health, metrics, recent_threats, recent_decisions, recent_executions } = overview;

  return (
    <div className="space-y-6">
      {/* 1. Global Health Banner */}
      <div
        className={`p-6 rounded-xl border flex flex-col md:flex-row md:items-center justify-between gap-4 ${
          overall_health.status === 'HEALTHY'
            ? 'bg-emerald-950/20 border-emerald-500/30 text-emerald-300'
            : overall_health.status === 'DEGRADED'
            ? 'bg-amber-950/20 border-amber-500/30 text-amber-300'
            : 'bg-rose-950/20 border-rose-500/30 text-rose-300'
        }`}
      >
        <div className="flex items-center gap-4">
          <div
            className={`p-3 rounded-xl border ${
              overall_health.status === 'HEALTHY'
                ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                : overall_health.status === 'DEGRADED'
                ? 'bg-amber-500/10 border-amber-500/30 text-amber-400'
                : 'bg-rose-500/10 border-rose-500/30 text-rose-400'
            }`}
          >
            {overall_health.status === 'HEALTHY' ? (
              <ShieldCheck className="w-8 h-8" />
            ) : overall_health.status === 'DEGRADED' ? (
              <AlertTriangle className="w-8 h-8" />
            ) : (
              <ShieldAlert className="w-8 h-8" />
            )}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-xl font-bold text-white">
                System Status: {overall_health.status}
              </h2>
              <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                v{overall_health.version}
              </span>
            </div>
            <p className="text-sm opacity-90 mt-0.5">{overall_health.summary}</p>
          </div>
        </div>
        <button
          onClick={() => onSelectTab('diagnostics')}
          className="px-4 py-2 bg-slate-800/80 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold border border-slate-700 transition self-start md:self-auto"
        >
          View Component Diagnostics ({overall_health.components.length})
        </button>
      </div>

      {/* 2. Key Security Counters (16 deterministic metrics) */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <MetricCard label="Total Evaluations" value={metrics.total_requests} color="blue" />
        <MetricCard label="Allowed Requests" value={metrics.allowed} color="emerald" />
        <MetricCard label="Awaiting Approval" value={metrics.require_approval} color="amber" />
        <MetricCard label="Blocked Requests" value={metrics.blocked} color="rose" />
        <MetricCard label="Authorized Credentials" value={metrics.authorized} color="indigo" />
        <MetricCard label="Successful Executions" value={metrics.successful_execution} color="emerald" />
        <MetricCard label="Failed Executions" value={metrics.failed_execution} color="rose" />
        <MetricCard label="Timed Out" value={metrics.timed_out_execution} color="amber" />
        <MetricCard label="Denied Executions" value={metrics.denied_execution} color="slate" />
        <MetricCard label="Threats Detected" value={metrics.detected_threats} color="rose" />
        <MetricCard label="Critical Threats" value={metrics.critical_threats} color="rose" highlight={metrics.critical_threats > 0} />
        <MetricCard label="Audit Trail Records" value={metrics.audit_events} color="blue" />
      </div>

      {/* 3. Three-Column Snapshot: Threats, Decisions, Executions */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Threats */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="font-semibold text-white text-sm flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-rose-400" /> Recent Threat Signals
            </h3>
            <button
              onClick={() => onSelectTab('threats')}
              className="text-xs text-blue-400 hover:text-blue-300 transition"
            >
              View All &rarr;
            </button>
          </div>

          {recent_threats.length === 0 ? (
            <div className="p-6 text-center text-xs text-slate-500 bg-slate-950/40 rounded-lg">
              No threat signals recorded.
            </div>
          ) : (
            <div className="space-y-2">
              {recent_threats.slice(0, 5).map((t) => (
                <div
                  key={t.threat_id}
                  className="p-3 bg-slate-950/60 border border-slate-800/80 rounded-lg space-y-1 text-xs"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-slate-300 font-semibold">{t.threat_type}</span>
                    <SeverityBadge severity={t.severity} />
                  </div>
                  <p className="text-slate-400 line-clamp-1">{t.title}</p>
                  <div className="flex items-center justify-between text-[10px] text-slate-500 font-mono pt-1">
                    <span>Detector: {t.detector}</span>
                    <span>Req: {t.request_id.slice(0, 12)}...</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Recent Decisions */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="font-semibold text-white text-sm flex items-center gap-2">
              <Shield className="w-4 h-4 text-blue-400" /> Security Decisions
            </h3>
            <button
              onClick={() => onSelectTab('decisions')}
              className="text-xs text-blue-400 hover:text-blue-300 transition"
            >
              View All &rarr;
            </button>
          </div>

          {recent_decisions.length === 0 ? (
            <div className="p-6 text-center text-xs text-slate-500 bg-slate-950/40 rounded-lg">
              No security decisions recorded yet.
            </div>
          ) : (
            <div className="space-y-2">
              {recent_decisions.slice(0, 5).map((d) => (
                <div
                  key={d.decision_id}
                  className="p-3 bg-slate-950/60 border border-slate-800/80 rounded-lg space-y-1 text-xs"
                >
                  <div className="flex items-center justify-between">
                    <DecisionBadge decision={d.decision} />
                    <span className="text-slate-400 font-mono text-[11px]">
                      Risk: {d.risk_score.toFixed(1)}
                    </span>
                  </div>
                  <p className="text-slate-400 line-clamp-1">{d.reason}</p>
                  <div className="flex items-center justify-between text-[10px] text-slate-500 font-mono pt-1">
                    <span>Policy: {d.policy_id}</span>
                    <span>Threats: {d.threat_count}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Recent Executions */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="font-semibold text-white text-sm flex items-center gap-2">
              <Terminal className="w-4 h-4 text-emerald-400" /> Sandbox Executions
            </h3>
            <button
              onClick={() => onSelectTab('executions')}
              className="text-xs text-blue-400 hover:text-blue-300 transition"
            >
              View All &rarr;
            </button>
          </div>

          {recent_executions.length === 0 ? (
            <div className="p-6 text-center text-xs text-slate-500 bg-slate-950/40 rounded-lg">
              No runtime tool executions recorded yet.
            </div>
          ) : (
            <div className="space-y-2">
              {recent_executions.slice(0, 5).map((e) => (
                <div
                  key={e.execution_id}
                  className="p-3 bg-slate-950/60 border border-slate-800/80 rounded-lg space-y-1 text-xs"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-slate-300 font-semibold">{e.tool_name}</span>
                    <ExecutionStatusBadge status={e.status} />
                  </div>
                  <div className="flex items-center justify-between text-[10px] text-slate-500 font-mono pt-1">
                    <span>{e.action} ({e.tool_category})</span>
                    <span>{e.duration_ms.toFixed(1)} ms</span>
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
}> = ({ label, value, color, highlight }) => {
  const colorMap = {
    blue: 'text-blue-400 border-blue-500/20 bg-blue-950/10',
    emerald: 'text-emerald-400 border-emerald-500/20 bg-emerald-950/10',
    amber: 'text-amber-400 border-amber-500/20 bg-amber-950/10',
    rose: 'text-rose-400 border-rose-500/20 bg-rose-950/10',
    indigo: 'text-indigo-400 border-indigo-500/20 bg-indigo-950/10',
    slate: 'text-slate-400 border-slate-700/40 bg-slate-900/30',
  };

  return (
    <div
      className={`p-3.5 rounded-xl border ${colorMap[color]} ${
        highlight ? 'ring-1 ring-rose-500/50 animate-pulse' : ''
      }`}
    >
      <div className="text-[11px] font-medium text-slate-400 truncate">{label}</div>
      <div className="text-xl font-bold text-white mt-1 font-mono">{value}</div>
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
