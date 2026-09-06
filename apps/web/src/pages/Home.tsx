import React, { useState, useEffect, useCallback, useRef } from 'react';
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
  FlaskConical,
  Lock,
  LogIn,
  Menu,
  X,
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  fetchOperationsOverview,
  fetchSystemHealth,
  fetchThreats,
  fetchDecisions,
  fetchExecutions,
  fetchAuditEvents,
  fetchApprovals,
  fetchHealthStatus,
  classifyError,
} from '../lib/api';
import {
  OperationsOverview,
  OverallSystemHealth,
  ThreatActivityItem,
  SecurityDecisionItem,
  ExecutionActivityItem,
  SecurityEvent,
  ApprovalRequest,
  ConnectionStatus,
} from '../types';
import { OverviewTab } from '../components/operations/OverviewTab';
import { ThreatsTab } from '../components/operations/ThreatsTab';
import { DecisionsTab } from '../components/operations/DecisionsTab';
import { ExecutionsTab } from '../components/operations/ExecutionsTab';
import { AuditTab } from '../components/operations/AuditTab';
import { DiagnosticsTab } from '../components/operations/DiagnosticsTab';
import { ApprovalsTab } from '../components/operations/ApprovalsTab';
import { ScenarioLabTab } from '../components/operations/ScenarioLabTab';
import { useAuth } from '../context/AuthContext';
import { UserBadge } from '../components/auth/UserBadge';
import { LoginModal } from '../components/auth/LoginModal';
import { EnvironmentBadge } from '../components/common/EnvironmentBadge';
import { MotionTabPanel } from '../components/common/MotionComponents';
import { useMotion } from '../context/MotionContext';



export function Home() {
  const { showLoginModal, setShowLoginModal, isAuthenticated } = useAuth();
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [targetSearchQuery, setTargetSearchQuery] = useState<string>('');
  const [connectionStatus, setConnectionStatus] = useState<ConnectionStatus>('CONNECTING');
  const [backendEnvironment, setBackendEnvironment] = useState<string | undefined>(undefined);

  const handleSelectTab = useCallback((tab: string, filterQuery?: string) => {
    setActiveTab(tab);
    if (filterQuery !== undefined) {
      setTargetSearchQuery(filterQuery);
    }
  }, []);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [authRequired, setAuthRequired] = useState<boolean>(false);
  const [lastRefreshed, setLastRefreshed] = useState<Date>(new Date());
  const [autoRefresh, setAutoRefresh] = useState<boolean>(true);
  const isPollingRef = useRef<boolean>(false);

  // Operations Data States
  const [overview, setOverview] = useState<OperationsOverview | null>(null);
  const [health, setHealth] = useState<OverallSystemHealth | null>(null);
  const [threats, setThreats] = useState<ThreatActivityItem[]>([]);
  const [decisions, setDecisions] = useState<SecurityDecisionItem[]>([]);
  const [executions, setExecutions] = useState<ExecutionActivityItem[]>([]);
  const [auditEvents, setAuditEvents] = useState<SecurityEvent[]>([]);
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);

  const loadAllData = useCallback(async () => {
    if (isPollingRef.current) return;
    isPollingRef.current = true;
    setLoading(true);

    try {
      // 1. Fetch unified overview, health, and operational streams concurrently
      const [
        healthCheckResult,
        overviewResult,
        healthResult,
        threatsResult,
        decisionsResult,
        executionsResult,
        auditResult,
        approvalsResult,
      ] = await Promise.all([
        fetchHealthStatus().then(
          (data) => ({ ok: true as const, data }),
          (err) => ({ ok: false as const, error: err, classification: classifyError(err) })
        ),
        fetchOperationsOverview().then(
          (data) => ({ ok: true as const, data }),
          (err) => ({ ok: false as const, error: err, classification: classifyError(err) })
        ),
        fetchSystemHealth().then(
          (data) => ({ ok: true as const, data }),
          (err) => ({ ok: false as const, error: err, classification: classifyError(err) })
        ),
        fetchThreats(100).then(
          (data) => ({ ok: true as const, data }),
          (err) => ({ ok: false as const, error: err, classification: classifyError(err) })
        ),
        fetchDecisions(100).then(
          (data) => ({ ok: true as const, data }),
          (err) => ({ ok: false as const, error: err, classification: classifyError(err) })
        ),
        fetchExecutions(100).then(
          (data) => ({ ok: true as const, data }),
          (err) => ({ ok: false as const, error: err, classification: classifyError(err) })
        ),
        fetchAuditEvents(100).then(
          (data) => ({ ok: true as const, data }),
          (err) => ({ ok: false as const, error: err, classification: classifyError(err) })
        ),
        fetchApprovals().then(
          (data) => ({ ok: true as const, data }),
          (err) => ({ ok: false as const, error: err, classification: classifyError(err) })
        ),
      ]);

      // Determine backend reachability:
      // A successful health check OR any HTTP response from the server (including 401/403/500) proves connectivity.
      // Only pure network/fetch failures indicate genuine disconnection.
      const isReachable =
        healthCheckResult.ok ||
        overviewResult.ok ||
        healthResult.ok ||
        (!healthCheckResult.ok && healthCheckResult.classification !== 'NETWORK_ERROR') ||
        (!overviewResult.ok && overviewResult.classification !== 'NETWORK_ERROR') ||
        (!healthResult.ok && healthResult.classification !== 'NETWORK_ERROR');

      if (!isReachable) {
        // Backend unavailable: preserve previous metrics and data (do not reset state)
        setConnectionStatus('DISCONNECTED');
        setError('Backend connection lost. Retrying automatically...');
        return;
      }

      // Backend is healthy and reachable
      setConnectionStatus('HEALTHY');
      setLastRefreshed(new Date());

      if (healthCheckResult.ok && healthCheckResult.data.environment) {
        setBackendEnvironment(healthCheckResult.data.environment);
      }

      // Check for authentication requirement (HTTP 401 on protected endpoints)
      const requiresAuth =
        (!overviewResult.ok && overviewResult.classification === 'AUTH_REQUIRED') ||
        (!healthResult.ok && healthResult.classification === 'AUTH_REQUIRED');

      if (requiresAuth && !isAuthenticated) {
        setAuthRequired(true);
        setError(null);
        // Protected data is locked/unavailable when unauthenticated
        setOverview(null);
        setHealth(null);
        setThreats([]);
        setDecisions([]);
        setExecutions([]);
        setAuditEvents([]);
        setApprovals([]);
        return;
      }

      // Authenticated or public success: update operational states
      setAuthRequired(false);
      setError(null);

      if (overviewResult.ok) setOverview(overviewResult.data);
      if (healthResult.ok) setHealth(healthResult.data);
      if (threatsResult.ok) setThreats(threatsResult.data);
      if (decisionsResult.ok) setDecisions(decisionsResult.data);
      if (executionsResult.ok) setExecutions(executionsResult.data);
      if (auditResult.ok) setAuditEvents(auditResult.data);
      if (approvalsResult.ok) setApprovals(approvalsResult.data);

    } catch (err) {
      const classification = classifyError(err);
      if (classification === 'AUTH_REQUIRED') {
        setConnectionStatus('HEALTHY');
        setAuthRequired(true);
        setError(null);
      } else {
        setConnectionStatus('DISCONNECTED');
        setError(err instanceof Error ? err.message : 'Backend connection error');
      }
    } finally {
      setLoading(false);
      isPollingRef.current = false;
    }
  }, [isAuthenticated]);

  useEffect(() => {
    loadAllData();
  }, [loadAllData, isAuthenticated]);

  // Auto-refresh interval (5 seconds)
  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(() => {
      loadAllData();
    }, 5000);
    return () => clearInterval(interval);
  }, [autoRefresh, loadAllData]);

  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState<boolean>(false);
  const { getVariant, isReducedMotion } = useMotion();
  const toastVariant = getVariant('toast');

  // Close mobile navigation menu on Escape key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isMobileMenuOpen) {
        setIsMobileMenuOpen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isMobileMenuOpen]);

  const tabDefinitions = [
    {
      id: 'overview',
      label: 'Overview',
      icon: Layers,
      count: undefined,
    },
    {
      id: 'threats',
      label: 'Threat Activity',
      icon: ShieldAlert,
      count: overview?.metrics?.detected_threats ?? (Array.isArray(threats) ? threats.length : 0),
    },
    {
      id: 'decisions',
      label: 'Security Decisions',
      icon: Shield,
      count: overview?.metrics?.total_requests ?? (Array.isArray(decisions) ? decisions.length : 0),
    },
    {
      id: 'approvals',
      label: 'Approvals',
      icon: UserCheck,
      count: Array.isArray(approvals) ? approvals.filter((a) => a.status === 'PENDING').length : 0,
    },
    {
      id: 'executions',
      label: 'Executions',
      icon: Terminal,
      count: Array.isArray(executions) ? executions.length : 0,
    },
    {
      id: 'audit',
      label: 'Audit Trail',
      icon: FileText,
      count: overview?.metrics?.audit_events ?? (Array.isArray(auditEvents) ? auditEvents.length : 0),
    },
    {
      id: 'diagnostics',
      label: 'Diagnostics',
      icon: Cpu,
      count: overview?.overall_health?.components?.length ?? 7,
    },
    {
      id: 'laboratory',
      label: 'Scenario Lab',
      icon: FlaskConical,
      count: 20,
    },
  ];

  const handleTabKeyDown = (e: React.KeyboardEvent) => {
    const currentIndex = tabDefinitions.findIndex((t) => t.id === activeTab);
    if (currentIndex === -1) return;

    let targetIndex = -1;
    if (e.key === 'ArrowRight') {
      targetIndex = (currentIndex + 1) % tabDefinitions.length;
    } else if (e.key === 'ArrowLeft') {
      targetIndex = (currentIndex - 1 + tabDefinitions.length) % tabDefinitions.length;
    } else if (e.key === 'Home') {
      targetIndex = 0;
    } else if (e.key === 'End') {
      targetIndex = tabDefinitions.length - 1;
    }

    if (targetIndex !== -1) {
      e.preventDefault();
      const target = tabDefinitions[targetIndex];
      setActiveTab(target.id);
      const el = document.getElementById(`tab-${target.id}`);
      el?.focus();
    }
  };

  return (
    <div className="min-h-screen bg-[#090d16] text-slate-100 flex flex-col font-sans">
      {/* Header Navigation */}
      <header className="relative border-b border-slate-800/90 bg-slate-900/80 backdrop-blur-md sticky top-0 z-50 px-4 sm:px-6 py-3 flex flex-wrap items-center justify-between gap-3 shadow-lg shadow-black/20">
        {/* Subtle Ambient Cyan Accent Line */}
        <div
          className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-cyan-500/50 to-transparent pointer-events-none"
          aria-hidden="true"
        />

        {/* Brand Group */}
        <div className="flex items-center gap-3">
          <div
            className="w-9 h-9 rounded-lg bg-cyan-950/40 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.15)] flex-shrink-0 transition-transform hover:scale-105"
            aria-hidden="true"
          >
            <Shield className="w-5 h-5 text-cyan-400" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h1 className="font-bold text-lg text-white leading-tight">AgentShield</h1>
              <span className="px-2.5 py-0.5 rounded-md text-[11px] font-mono font-semibold bg-cyan-950/40 text-cyan-300 border border-cyan-500/25">
                Security Operations Console
              </span>
            </div>
            <p className="text-xs text-slate-400 hidden sm:block mt-0.5">
              Autonomous Security Gateway &bull; Fail-Closed Runtime
            </p>
          </div>
        </div>

        {/* Global Controls & Status */}
        <div className="flex items-center gap-2 sm:gap-3 flex-wrap">
          {/* Environment Indicator Badge */}
          <EnvironmentBadge environment={backendEnvironment} />

          {/* User Identity & Role Badge */}
          <UserBadge />

          {/* Connection Status Badge */}
          <span
            data-testid="connection-status-badge"
            className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-mono font-medium border transition ${
              connectionStatus === 'HEALTHY'
                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/25'
                : connectionStatus === 'CONNECTING'
                ? 'bg-slate-500/10 text-slate-400 border-slate-500/25'
                : 'bg-rose-500/10 text-rose-400 border-rose-500/25'
            }`}
            title={`Gateway Connection: ${connectionStatus}`}
          >
            <span
              className={`w-2 h-2 rounded-full ${
                connectionStatus === 'HEALTHY'
                  ? 'bg-emerald-400 animate-pulse'
                  : connectionStatus === 'CONNECTING'
                  ? 'bg-slate-400 animate-pulse'
                  : 'bg-rose-400'
              }`}
            />
            {connectionStatus}
          </span>

          {/* Auth Required Companion Pill */}
          {authRequired && !isAuthenticated && connectionStatus === 'HEALTHY' && (
            <span
              data-testid="auth-required-pill"
              className="hidden md:inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-mono font-medium bg-blue-500/10 text-blue-300 border border-blue-500/20"
              title="Operations API requires authenticated session"
            >
              <Lock className="w-3 h-3 text-blue-400" />
              <span>AUTH REQUIRED</span>
            </span>
          )}

          {/* Auto Refresh Toggle */}
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`hidden sm:inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border transition focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none ${
              autoRefresh
                ? 'bg-cyan-950/40 text-cyan-300 border-cyan-500/30 shadow-sm'
                : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-slate-200'
            }`}
            title={autoRefresh ? 'Live refresh active (5s)' : 'Live refresh paused'}
            aria-pressed={autoRefresh}
          >
            <Clock className="w-3.5 h-3.5" />
            <span>{autoRefresh ? 'Live (5s)' : 'Paused'}</span>
          </button>

          {/* Manual Refresh */}
          <button
            onClick={loadAllData}
            disabled={loading}
            className="p-1.5 bg-slate-800 hover:bg-slate-700 active:bg-slate-600 text-slate-200 rounded-lg border border-slate-700 transition disabled:opacity-50 focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none"
            title="Refresh now"
            aria-label="Refresh now"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>

          {/* Mobile Navigation Menu Toggle */}
          <button
            onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
            className="md:hidden p-1.5 bg-slate-800 hover:bg-slate-700 active:bg-slate-600 text-slate-200 rounded-lg border border-slate-700 transition focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none"
            aria-label={isMobileMenuOpen ? 'Close console navigation menu' : 'Open console navigation menu'}
            aria-expanded={isMobileMenuOpen}
            data-testid="mobile-menu-toggle"
          >
            {isMobileMenuOpen ? <X className="w-4 h-4" /> : <Menu className="w-4 h-4" />}
          </button>
        </div>
      </header>

      {/* Mobile Navigation Drawer */}
      <AnimatePresence>
        {isMobileMenuOpen && (
          <motion.nav
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: isReducedMotion ? 0.01 : 0.2, ease: [0.16, 1, 0.3, 1] }}
            className="md:hidden border-b border-slate-800 bg-slate-900/95 backdrop-blur-md px-4 py-3 space-y-2 overflow-hidden shadow-xl"
            data-testid="mobile-nav-drawer"
            role="navigation"
            aria-label="Mobile Navigation"
          >
            <div className="text-[10px] font-mono uppercase tracking-wider text-slate-400 px-1 font-semibold flex items-center justify-between">
              <span>Console Navigation</span>
              <span className="text-slate-500">ESC to close</span>
            </div>
            <div className="grid grid-cols-2 gap-1.5">
              {tabDefinitions.map((tab) => {
                const Icon = tab.icon;
                const active = activeTab === tab.id;
                return (
                  <button
                    key={tab.id}
                    onClick={() => {
                      setActiveTab(tab.id);
                      setIsMobileMenuOpen(false);
                    }}
                    role="tab"
                    aria-selected={active}
                    className={`flex items-center justify-between px-3 py-2 rounded-lg text-xs font-semibold transition text-left ${
                      active
                        ? 'bg-slate-800 text-white border border-cyan-500/40 shadow-sm'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent'
                    }`}
                  >
                    <div className="flex items-center gap-2 truncate">
                      <Icon className="w-3.5 h-3.5 flex-shrink-0 text-cyan-400" />
                      <span className="truncate">{tab.label}</span>
                    </div>
                    {tab.count !== undefined && tab.count > 0 && (
                      <span
                        className={`px-1.5 py-0.2 rounded-full text-[10px] font-mono ml-1.5 flex-shrink-0 ${
                          active
                            ? 'bg-cyan-950 text-cyan-300 border border-cyan-500/30'
                            : 'bg-slate-800 text-slate-400'
                        }`}
                      >
                        {tab.count}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
            <div className="pt-2 border-t border-slate-800 flex items-center justify-between px-1">
              <button
                onClick={() => setAutoRefresh(!autoRefresh)}
                className="text-xs text-slate-400 hover:text-slate-200 flex items-center gap-1.5 py-1"
              >
                <Clock className="w-3.5 h-3.5" />
                <span>{autoRefresh ? 'Live refresh (5s)' : 'Live refresh paused'}</span>
              </button>
            </div>
          </motion.nav>
        )}
      </AnimatePresence>

      {/* Navigation Tabs */}
      <nav
        role="tablist"
        aria-label="Console Navigation"
        onKeyDown={handleTabKeyDown}
        className="border-b border-slate-800 bg-slate-950/60 backdrop-blur px-4 sm:px-6 overflow-x-auto scrollbar-thin scrollbar-thumb-slate-800"
      >
        <div className="max-w-[1536px] mx-auto flex items-center gap-1 py-2">
          {tabDefinitions.map((tab) => {
            const Icon = tab.icon;
            return (
              <TabButton
                key={tab.id}
                id={`tab-${tab.id}`}
                panelId={`console-panel-${tab.id}`}
                active={activeTab === tab.id}
                onClick={() => setActiveTab(tab.id)}
                icon={<Icon className="w-4 h-4" />}
                label={tab.label}
                count={tab.count}
              />
            );
          })}
        </div>
      </nav>

      {/* Main Console Body */}
      <main className="flex-1 max-w-[1536px] w-full mx-auto p-4 sm:p-6 md:p-8 space-y-6 overflow-x-hidden">
        {/* Disconnected / Network Error Alert Banner */}
        <AnimatePresence>
          {connectionStatus === 'DISCONNECTED' && error && (
            <motion.div
              key="disconnected-banner"
              variants={toastVariant}
              initial="initial"
              animate="animate"
              exit="exit"
              className="p-3.5 bg-rose-950/30 border border-rose-500/30 rounded-xl text-rose-300 text-xs flex items-center justify-between gap-4 shadow-[0_0_15px_rgba(244,63,94,0.1)]"
              role="alert"
              aria-live="assertive"
            >
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-rose-400 flex-shrink-0" />
                <span>{error}</span>
              </div>
              <button
                onClick={loadAllData}
                disabled={loading}
                className="px-3 py-1 bg-rose-500/20 hover:bg-rose-500/30 text-rose-200 rounded border border-rose-500/30 text-xs font-semibold transition disabled:opacity-50 focus-visible:ring-2 focus-visible:ring-rose-400 focus-visible:outline-none"
              >
                Retry
              </button>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Authentication Required Banner (Clean, non-error state when backend is healthy) */}
        <AnimatePresence>
          {authRequired && !isAuthenticated && connectionStatus === 'HEALTHY' && (
            <motion.div
              key="auth-required-banner"
              variants={toastVariant}
              initial="initial"
              animate="animate"
              exit="exit"
              className="p-4 bg-blue-950/30 border border-blue-500/30 rounded-xl text-blue-200 text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-[0_0_15px_rgba(59,130,246,0.1)]"
              role="status"
              aria-live="polite"
            >
              <div className="flex items-center gap-3">
                <div className="p-2 bg-blue-500/10 border border-blue-500/20 rounded-lg text-blue-400">
                  <Lock className="w-4 h-4" />
                </div>
                <div>
                  <p className="font-semibold text-white">Authentication Required</p>
                  <p className="text-slate-400 mt-0.5">
                    The AgentShield backend is healthy and reachable, but operations data requires an authenticated session.
                  </p>
                </div>
              </div>
              <button
                onClick={() => setShowLoginModal(true)}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold transition flex items-center gap-1.5 self-start sm:self-auto shadow-sm focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none active:scale-[0.98]"
              >
                <LogIn className="w-3.5 h-3.5" />
                <span>Sign In</span>
              </button>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Tab Views */}
        <div
          role="tabpanel"
          id={`console-panel-${activeTab}`}
          aria-labelledby={`tab-${activeTab}`}
          tabIndex={0}
          className="outline-none"
        >
          <AnimatePresence mode="wait">
            <MotionTabPanel key={activeTab} tabKey={activeTab}>
              {activeTab === 'overview' && (
                <OverviewTab
                  overview={overview}
                  onSelectTab={handleSelectTab}
                  authRequired={authRequired && !isAuthenticated}
                  onSignIn={() => setShowLoginModal(true)}
                  approvals={approvals}
                  auditEvents={auditEvents}
                />
              )}
              {activeTab === 'threats' && (
                <ThreatsTab
                  threats={threats}
                  onRefresh={loadAllData}
                  loading={loading}
                  authRequired={authRequired && !isAuthenticated}
                  onSignIn={() => setShowLoginModal(true)}
                  onSelectTab={handleSelectTab}
                  initialSearch={targetSearchQuery}
                />
              )}
              {activeTab === 'decisions' && (
                <DecisionsTab
                  decisions={decisions}
                  onRefresh={loadAllData}
                  loading={loading}
                  authRequired={authRequired && !isAuthenticated}
                  onSignIn={() => setShowLoginModal(true)}
                  onSelectTab={handleSelectTab}
                  initialSearch={targetSearchQuery}
                />
              )}
              {activeTab === 'approvals' && (
                <ApprovalsTab
                  approvals={approvals}
                  onRefresh={loadAllData}
                  loading={loading}
                  authRequired={authRequired && !isAuthenticated}
                  onSignIn={() => setShowLoginModal(true)}
                  error={error}
                  initialSearch={targetSearchQuery}
                />
              )}
              {activeTab === 'executions' && (
                <ExecutionsTab
                  executions={executions}
                  onRefresh={loadAllData}
                  loading={loading}
                  authRequired={authRequired && !isAuthenticated}
                  onSignIn={() => setShowLoginModal(true)}
                  onSelectTab={handleSelectTab}
                  initialSearch={targetSearchQuery}
                />
              )}
              {activeTab === 'audit' && (
                <AuditTab
                  events={auditEvents}
                  onRefresh={loadAllData}
                  loading={loading}
                  authRequired={authRequired && !isAuthenticated}
                  onSignIn={() => setShowLoginModal(true)}
                  onSelectTab={handleSelectTab}
                  initialSearch={targetSearchQuery}
                />
              )}
              {activeTab === 'diagnostics' && (
                <DiagnosticsTab
                  health={health}
                  onRefresh={loadAllData}
                  loading={loading}
                  authRequired={authRequired && !isAuthenticated}
                  onSignIn={() => setShowLoginModal(true)}
                  connectionStatus={connectionStatus}
                />
              )}
              {activeTab === 'laboratory' && <ScenarioLabTab onSelectTab={handleSelectTab} />}
            </MotionTabPanel>
          </AnimatePresence>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 py-4 px-6 text-center text-xs text-slate-500 flex flex-col sm:flex-row items-center justify-between gap-2">
        <div>
          AgentShield Security Operations Console
        </div>

        <div className="font-mono text-[11px] text-slate-600">
          Last Synced: {lastRefreshed.toLocaleTimeString()}
        </div>
      </footer>

      {/* Authentication Login Modal */}
      <LoginModal
        isOpen={showLoginModal}
        onClose={() => setShowLoginModal(false)}
        backendEnvironment={backendEnvironment}
      />
    </div>
  );
}

const TabButton: React.FC<{
  id: string;
  panelId: string;
  active: boolean;
  onClick: () => void;
  icon: React.ReactNode;
  label: string;
  count?: number;
}> = ({ id, panelId, active, onClick, icon, label, count }) => {
  return (
    <button
      id={id}
      onClick={onClick}
      role="tab"
      aria-selected={active}
      aria-controls={panelId}
      tabIndex={active ? 0 : -1}
      className={`relative flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition whitespace-nowrap focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:ring-offset-2 focus-visible:ring-offset-slate-950 focus-visible:outline-none ${
        active
          ? 'bg-slate-800 text-white border border-slate-700 shadow-sm text-cyan-50'
          : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60 border border-transparent'
      }`}
    >
      <span className={active ? 'text-cyan-400' : 'text-slate-400'}>{icon}</span>
      <span>{label}</span>
      {count !== undefined && count > 0 && (
        <span
          className={`px-1.5 py-0.5 rounded-full text-[10px] font-mono transition-colors ${
            active
              ? 'bg-cyan-950/80 text-cyan-300 border border-cyan-500/30'
              : 'bg-slate-900 text-slate-400 border border-slate-800'
          }`}
        >
          {count}
        </span>
      )}
      {active && (
        <span
          className="absolute bottom-0 left-2 right-2 h-[2px] bg-cyan-400 rounded-full"
          aria-hidden="true"
        />
      )}
    </button>
  );
};
