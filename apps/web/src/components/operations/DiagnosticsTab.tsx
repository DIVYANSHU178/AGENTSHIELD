import React from 'react';
import { OverallSystemHealth, ComponentStatus } from '../../types';
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
} from 'lucide-react';

interface DiagnosticsTabProps {
  health: OverallSystemHealth | null;
  onRefresh: () => void;
  loading: boolean;
}

export const DiagnosticsTab: React.FC<DiagnosticsTabProps> = ({
  health,
  onRefresh,
  loading,
}) => {
  if (!health) {
    return (
      <div className="p-12 text-center text-slate-400 bg-slate-900/40 border border-slate-800 rounded-xl space-y-2">
        <Activity className="w-8 h-8 mx-auto text-slate-500 animate-pulse" />
        <p>Loading component diagnostics...</p>
      </div>
    );
  }

  const getComponentIcon = (name: string) => {
    switch (name) {
      case 'SecurityDecisionGateway':
        return <Shield className="w-5 h-5 text-blue-400" />;
      case 'SecurityEnforcementBoundary':
        return <Lock className="w-5 h-5 text-indigo-400" />;
      case 'SandboxExecutionBoundary':
        return <Box className="w-5 h-5 text-emerald-400" />;
      case 'SecureExecutionAdapter':
      case 'ToolExecutionRegistry':
        return <Cpu className="w-5 h-5 text-amber-400" />;
      case 'AgentRuntimeOrchestrator':
        return <Server className="w-5 h-5 text-purple-400" />;
      case 'SecurityAuditTrail':
        return <FileCheck className="w-5 h-5 text-cyan-400" />;
      default:
        return <Activity className="w-5 h-5 text-slate-400" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/60 p-4 border border-slate-800 rounded-xl">
        <div className="flex items-center gap-2">
          <Activity className="w-5 h-5 text-emerald-400" />
          <div>
            <h3 className="text-sm font-semibold text-white">Component Health Diagnostics</h3>
            <p className="text-xs text-slate-400">
              Deterministic, non-executing structural inspection across all 7 pipeline components
            </p>
          </div>
        </div>

        <button
          onClick={onRefresh}
          disabled={loading}
          className="flex items-center gap-2 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold border border-slate-700 transition self-start md:self-auto disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Run Health Diagnostics
        </button>
      </div>

      {/* Component Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {health.components.map((comp) => (
          <div
            key={comp.name}
            className={`p-5 rounded-xl border space-y-3 transition ${
              comp.status === 'HEALTHY'
                ? 'bg-slate-900/60 border-slate-800 hover:border-emerald-500/30'
                : comp.status === 'DEGRADED'
                ? 'bg-amber-950/10 border-amber-500/20 hover:border-amber-500/40'
                : 'bg-rose-950/10 border-rose-500/20 hover:border-rose-500/40'
            }`}
          >
            <div className="flex items-center justify-between border-b border-slate-800/60 pb-3">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-lg bg-slate-950 border border-slate-800">
                  {getComponentIcon(comp.name)}
                </div>
                <div>
                  <h4 className="text-sm font-bold text-white">{comp.name}</h4>
                  <div className="text-[10px] text-slate-500 font-mono">
                    Checked: {new Date(comp.checked_at).toLocaleTimeString()}
                  </div>
                </div>
              </div>

              <ComponentStatusBadge status={comp.status} />
            </div>

            <p className="text-xs text-slate-300">{comp.details}</p>

            {/* Metadata Badges */}
            {comp.metadata && Object.keys(comp.metadata).length > 0 && (
              <div className="p-2.5 bg-slate-950/80 rounded-lg border border-slate-800/80 text-[11px] font-mono text-slate-400 space-y-1">
                <div className="text-[10px] uppercase font-semibold text-slate-500">
                  Inspected Parameters
                </div>
                <div className="flex flex-wrap gap-2 pt-0.5">
                  {Object.entries(comp.metadata).map(([k, v]) => (
                    <span
                      key={k}
                      className="px-2 py-0.5 bg-slate-900 rounded border border-slate-800 text-slate-300"
                    >
                      {k}: {Array.isArray(v) ? v.join(', ') : String(v)}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Non-Executing Invariant Notice */}
      <div className="p-4 bg-slate-900/40 border border-slate-800/80 rounded-xl text-xs text-slate-400 flex items-start gap-3">
        <Shield className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
        <p>
          <span className="font-semibold text-slate-200">Diagnostic Invariant:</span> Security health checks perform read-only structural validation of detector registries, policy rule sets, and cryptographic signing keys. Diagnostic checks <span className="text-slate-200 font-semibold">never execute tool handlers or user payloads</span>.
        </p>
      </div>
    </div>
  );
};

const ComponentStatusBadge: React.FC<{ status: ComponentStatus }> = ({ status }) => {
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
  return (
    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/30">
      <XCircle className="w-3.5 h-3.5" /> FAILED
    </span>
  );
};
