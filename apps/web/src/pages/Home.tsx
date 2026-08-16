import React, { useState, useEffect, useCallback } from 'react';
import {
  Shield,
  ShieldAlert,
  FileText,
  Terminal,
  Cpu,
  RefreshCw,
  Clock,
  Layers,
  UserCheck,
} from 'lucide-react';
import {
  fetchOperationsOverview,
  fetchSystemHealth,
  fetchThreats,
  fetchDecisions,
  fetchExecutions,
  fetchAuditEvents,
  fetchApprovals,
} from '../lib/api';
import {
  OperationsOverview,
  OverallSystemHealth,
  ThreatActivityItem,
  SecurityDecisionItem,
  ExecutionActivityItem,
  SecurityEvent,
  ApprovalRequest,
} from '../types';
import { OverviewTab } from '../components/operations/OverviewTab';
import { ThreatsTab } from '../components/operations/ThreatsTab';
import { DecisionsTab } from '../components/operations/DecisionsTab';
import { ExecutionsTab } from '../components/operations/ExecutionsTab';
import { AuditTab } from '../components/operations/AuditTab';
import { DiagnosticsTab } from '../components/operations/DiagnosticsTab';
import { ApprovalsTab } from '../components/operations/ApprovalsTab';

export function Home() {
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [lastRefreshed, setLastRefreshed] = useState<Date>(new Date());
  const [autoRefresh, setAutoRefresh] = useState<boolean>(true);

  // Operations Data States
  const [overview, setOverview] = useState<OperationsOverview | null>(null);
  const [health, setHealth] = useState<OverallSystemHealth | null>(null);
  const [threats, setThreats] = useState<ThreatActivityItem[]>([]);
  const [decisions, setDecisions] = useState<SecurityDecisionItem[]>([]);
  const [executions, setExecutions] = useState<ExecutionActivityItem[]>([]);
  const [auditEvents, setAuditEvents] = useState<SecurityEvent[]>([]);
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);

  const loadAllData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      // 1. Fetch unified overview, health, and operational streams
      const [overviewData, healthData, threatsData, decisionsData, executionsData, auditData, approvalsData] =
        await Promise.all([
          fetchOperationsOverview().catch(() => null),
          fetchSystemHealth().catch(() => null),
          fetchThreats(100).catch(() => []),
          fetchDecisions(100).catch(() => []),
          fetchExecutions(100).catch(() => []),
          fetchAuditEvents(100).catch(() => []),
          fetchApprovals().catch(() => []),
        ]);

      if (overviewData) setOverview(overviewData);
      if (healthData) setHealth(healthData);
      setThreats(threatsData);
      setDecisions(decisionsData);
      setExecutions(executionsData);
      setAuditEvents(auditData);
      setApprovals(approvalsData);
      setLastRefreshed(new Date());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Backend connection error');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAllData();
  }, [loadAllData]);

  // Auto-refresh interval (5 seconds)
  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(() => {
      loadAllData();
    }, 5000);
    return () => clearInterval(interval);
  }, [autoRefresh, loadAllData]);

  return (
    <div className="min-h-screen bg-[#090d16] text-slate-100 flex flex-col font-sans">
      {/* Header Navigation */}
      <header className="border-b border-slate-800 bg-slate-900/60 backdrop-blur sticky top-0 z-50 px-6 py-3.5 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-blue-500/10 border border-blue-500/30 rounded-lg text-blue-400">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="font-bold text-lg text-white leading-tight">AgentShield</h1>
              <span className="px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/20">
                Phase 10 Operations Console
              </span>
            </div>
            <p className="text-xs text-slate-400">Security Operations &amp; Live Inspection Center</p>
          </div>
        </div>

        {/* Global Controls & Status */}
        <div className="flex items-center gap-3">
          {/* Status Badge */}
          <span
            className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono font-semibold border ${
              overview?.overall_health.status === 'HEALTHY'
                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                : overview?.overall_health.status === 'DEGRADED'
                ? 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                : 'bg-rose-500/10 text-rose-400 border-rose-500/20'
            }`}
          >
            <span
              className={`w-2 h-2 rounded-full ${
                overview?.overall_health.status === 'HEALTHY'
                  ? 'bg-emerald-400 animate-pulse'
                  : 'bg-amber-400'
              }`}
            />
            {overview?.overall_health.status || 'CONNECTING'}
          </span>

          {/* Auto Refresh Toggle */}
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold border transition flex items-center gap-1.5 ${
              autoRefresh
                ? 'bg-blue-950/40 text-blue-400 border-blue-500/30'
                : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-slate-200'
            }`}
          >
            <Clock className="w-3.5 h-3.5" />
            {autoRefresh ? 'Live (5s)' : 'Paused'}
          </button>

          {/* Manual Refresh */}
          <button
            onClick={loadAllData}
            disabled={loading}
            className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg border border-slate-700 transition disabled:opacity-50"
            title="Refresh now"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </header>

      {/* Navigation Tabs */}
      <nav className="border-b border-slate-800 bg-slate-950/50 px-6 overflow-x-auto">
        <div className="max-w-7xl mx-auto flex items-center gap-1 py-2">
          <TabButton
            active={activeTab === 'overview'}
            onClick={() => setActiveTab('overview')}
            icon={<Layers className="w-4 h-4" />}
            label="Overview"
          />
          <TabButton
            active={activeTab === 'threats'}
            onClick={() => setActiveTab('threats')}
            icon={<ShieldAlert className="w-4 h-4" />}
            label="Threat Activity"
            count={overview?.metrics.detected_threats || threats.length}
          />
          <TabButton
            active={activeTab === 'decisions'}
            onClick={() => setActiveTab('decisions')}
            icon={<Shield className="w-4 h-4" />}
            label="Security Decisions"
            count={overview?.metrics.total_requests || decisions.length}
          />
          <TabButton
            active={activeTab === 'approvals'}
            onClick={() => setActiveTab('approvals')}
            icon={<UserCheck className="w-4 h-4" />}
            label="Approvals"
            count={approvals.filter((a) => a.status === 'PENDING').length}
          />
          <TabButton
            active={activeTab === 'executions'}
            onClick={() => setActiveTab('executions')}
            icon={<Terminal className="w-4 h-4" />}
            label="Executions"
            count={executions.length}
          />
          <TabButton
            active={activeTab === 'audit'}
            onClick={() => setActiveTab('audit')}
            icon={<FileText className="w-4 h-4" />}
            label="Audit Trail"
            count={overview?.metrics.audit_events || auditEvents.length}
          />
          <TabButton
            active={activeTab === 'diagnostics'}
            onClick={() => setActiveTab('diagnostics')}
            icon={<Cpu className="w-4 h-4" />}
            label="Diagnostics"
            count={overview?.overall_health.components.length || 7}
          />
        </div>
      </nav>

      {/* Main Console Body */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-6 md:p-8 space-y-6">
        {/* Error Alert Banner */}
        {error && (
          <div className="p-4 bg-rose-950/30 border border-rose-500/30 rounded-xl text-rose-300 text-xs flex items-center justify-between gap-4">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-rose-400 flex-shrink-0" />
              <span>{error}</span>
            </div>
            <button
              onClick={loadAllData}
              className="px-3 py-1 bg-rose-500/20 hover:bg-rose-500/30 text-rose-200 rounded border border-rose-500/30 text-xs font-semibold"
            >
              Retry
            </button>
          </div>
        )}

        {/* Tab Views */}
        {activeTab === 'overview' && (
          <OverviewTab overview={overview} onSelectTab={(tab) => setActiveTab(tab)} />
        )}
        {activeTab === 'threats' && <ThreatsTab threats={threats} />}
        {activeTab === 'decisions' && <DecisionsTab decisions={decisions} />}
        {activeTab === 'approvals' && (
          <ApprovalsTab approvals={approvals} onRefresh={loadAllData} />
        )}
        {activeTab === 'executions' && <ExecutionsTab executions={executions} />}
        {activeTab === 'audit' && <AuditTab events={auditEvents} />}
        {activeTab === 'diagnostics' && (
          <DiagnosticsTab health={health} onRefresh={loadAllData} loading={loading} />
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 py-4 px-6 text-center text-xs text-slate-500 flex flex-col sm:flex-row items-center justify-between gap-2">
        <div>
          AgentShield Security Operations Console &bull; Phase 11 Verified
        </div>
        <div className="font-mono text-[11px] text-slate-600">
          Last Synced: {lastRefreshed.toLocaleTimeString()}
        </div>
      </footer>
    </div>
  );
}

const TabButton: React.FC<{
  active: boolean;
  onClick: () => void;
  icon: React.ReactNode;
  label: string;
  count?: number;
}> = ({ active, onClick, icon, label, count }) => {
  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition whitespace-nowrap ${
        active
          ? 'bg-slate-800 text-white border border-slate-700 shadow-sm'
          : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
      }`}
    >
      {icon}
      <span>{label}</span>
      {count !== undefined && count > 0 && (
        <span
          className={`px-1.5 py-0.2 rounded-full text-[10px] font-mono ${
            active ? 'bg-slate-700 text-blue-300' : 'bg-slate-900 text-slate-400'
          }`}
        >
          {count}
        </span>
      )}
    </button>
  );
};
