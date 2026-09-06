import React, { useState, useEffect } from 'react';
import {
  ApprovalRequest,
  ApprovalStatus,
} from '../../types';
import { SeverityBadge } from './OverviewTab';
import {
  CheckCircle2,
  XCircle,
  Clock,
  Ban,
  Search,
  Check,
  X,
  AlertTriangle,
  FileCode,
  Fingerprint,
  UserCheck,
  ArrowRight,
  RefreshCw,
  ChevronDown,
  ChevronUp,
  ShieldCheck,
} from 'lucide-react';
import { approveApproval, rejectApproval, cancelApproval } from '../../lib/api';
import { useAuth } from '../../context/AuthContext';
import { MotionCard } from '../common/MotionComponents';
import {
  LoadingState,
  EmptyState,
  AuthRequiredState,
} from '../common/StateViews';

export interface ApprovalsTabProps {
  approvals: ApprovalRequest[];
  onRefresh: () => void;
  loading?: boolean;
  authRequired?: boolean;
  onSignIn?: () => void;
  error?: string | null;
  initialSearch?: string;
}

export const StatusBadge: React.FC<{ status: ApprovalStatus }> = ({ status }) => {
  switch (status) {
    case 'PENDING':
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-300 border border-amber-500/30">
          <Clock className="w-3.5 h-3.5 text-amber-400 shrink-0" />
          <span>PENDING</span>
          <span className="text-[10px] font-mono opacity-80 uppercase tracking-wider">(ACTION REQUIRED)</span>
        </span>
      );
    case 'APPROVED':
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-300 border border-emerald-500/30">
          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
          <span>APPROVED</span>
          <span className="text-[10px] font-mono opacity-80 uppercase tracking-wider">(AUTHORIZED)</span>
        </span>
      );
    case 'REJECTED':
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-rose-500/10 text-rose-300 border border-rose-500/30">
          <XCircle className="w-3.5 h-3.5 text-rose-400 shrink-0" />
          <span>REJECTED</span>
          <span className="text-[10px] font-mono opacity-80 uppercase tracking-wider">(BLOCKED)</span>
        </span>
      );
    case 'EXPIRED':
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-slate-500/10 text-slate-400 border border-slate-500/30">
          <Clock className="w-3.5 h-3.5 text-slate-400 shrink-0" />
          <span>EXPIRED</span>
        </span>
      );
    case 'CANCELLED':
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-zinc-500/10 text-zinc-400 border border-zinc-500/30">
          <Ban className="w-3.5 h-3.5 text-zinc-400 shrink-0" />
          <span>CANCELLED</span>
        </span>
      );
    default:
      return null;
  }
};

export const ApprovalsTab: React.FC<ApprovalsTabProps> = ({
  approvals = [],
  onRefresh,
  loading = false,
  authRequired = false,
  onSignIn,
  error,
  initialSearch = '',
}) => {
  const { user, canResolveApprovals, canCancelApproval, roles } = useAuth();

  // Filter states
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [searchTerm, setSearchTerm] = useState<string>(initialSearch);

  // Sync initialSearch if provided
  useEffect(() => {
    if (initialSearch) {
      setSearchTerm(initialSearch);
    }
  }, [initialSearch]);

  // Expand and review states
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [activeReviewId, setActiveReviewId] = useState<string | null>(null);
  const [confirmationType, setConfirmationType] = useState<'NONE' | 'APPROVE' | 'REJECT' | 'CANCEL'>('NONE');

  // Review form states
  const [reviewerId, setReviewerId] = useState<string>('');
  const [reviewerName, setReviewerName] = useState<string>('');
  const [reviewerRole, setReviewerRole] = useState<string>('');
  const [reviewReason, setReviewReason] = useState<string>('');
  const [actionLoading, setActionLoading] = useState<boolean>(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [liveAnnouncement, setLiveAnnouncement] = useState<string | null>(null);

  // Synchronize reviewer info with current authenticated identity
  useEffect(() => {
    if (user) {
      setReviewerId(user.user_id);
      setReviewerName(user.display_name || user.username);
      setReviewerRole(roles[0] || 'SECURITY_REVIEWER');
    } else {
      setReviewerId('sec-lead-01');
      setReviewerName('Security Officer');
      setReviewerRole('security_reviewer');
    }
  }, [user, roles]);

  // Handle Authentication Required state
  if (authRequired) {
    return (
      <AuthRequiredState
        title="Operations Require Authentication"
        message="The AgentShield security backend is healthy and reachable, but human approval review requires an authenticated reviewer session."
        onSignIn={onSignIn}
      />
    );
  }

  // Handle Initial Loading State when no approvals loaded yet
  if (loading && approvals.length === 0) {
    return (
      <LoadingState
        title="Processing Approval Workflow Queue"
        message="Retrieving pending human-in-the-loop authorization requests from AgentShield security gateway..."
        stage="Authoritative Review Sync"
      />
    );
  }

  // Quantified metrics
  const pendingCount = approvals.filter((a) => a.status === 'PENDING').length;
  const approvedCount = approvals.filter((a) => a.status === 'APPROVED').length;
  const rejectedCount = approvals.filter((a) => a.status === 'REJECTED').length;
  const expiredCount = approvals.filter((a) => a.status === 'EXPIRED' || a.status === 'CANCELLED').length;

  // Filtered dataset
  const filteredApprovals = approvals.filter((a) => {
    if (statusFilter !== 'ALL' && a.status !== statusFilter) return false;
    if (severityFilter !== 'ALL' && a.severity !== severityFilter) return false;
    if (categoryFilter !== 'ALL' && a.tool_category !== categoryFilter) return false;
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      const reviewerMatch =
        a.resolution?.reviewer?.reviewer_name?.toLowerCase().includes(term) ||
        a.resolution?.reviewer?.reviewer_id?.toLowerCase().includes(term);
      return (
        a.tool_name.toLowerCase().includes(term) ||
        a.target.toLowerCase().includes(term) ||
        a.request_id.toLowerCase().includes(term) ||
        a.approval_id.toLowerCase().includes(term) ||
        (a.destination && a.destination.toLowerCase().includes(term)) ||
        (a.threat_summary && a.threat_summary.toLowerCase().includes(term)) ||
        Boolean(reviewerMatch)
      );
    }
    return true;
  });

  // Separate active pending items from resolved historical records
  const pendingApprovals = filteredApprovals.filter((a) => a.status === 'PENDING');
  const historicalApprovals = filteredApprovals.filter((a) => a.status !== 'PENDING');

  // Trigger Review Confirmation step
  const handleTriggerApprove = () => {
    if (!reviewReason.trim()) {
      setActionError('Approval justification is required.');
      return;
    }
    setActionError(null);
    setConfirmationType('APPROVE');
  };

  const handleTriggerReject = () => {
    if (!reviewReason.trim()) {
      setActionError('Rejection justification is required.');
      return;
    }
    setActionError(null);
    setConfirmationType('REJECT');
  };

  const handleTriggerCancel = () => {
    setActionError(null);
    setConfirmationType('CANCEL');
  };

  // Consequential Action Execution
  const handleExecuteResolution = async (approvalId: string, decision: 'APPROVE' | 'REJECT') => {
    setActionLoading(true);
    setActionError(null);
    try {
      if (decision === 'APPROVE') {
        await approveApproval(approvalId, reviewerId, reviewerName, reviewerRole, reviewReason.trim());
        setLiveAnnouncement(`Approval request ${approvalId} successfully authorized.`);
      } else {
        await rejectApproval(approvalId, reviewerId, reviewerName, reviewerRole, reviewReason.trim());
        setLiveAnnouncement(`Approval request ${approvalId} successfully rejected.`);
      }
      setActiveReviewId(null);
      setConfirmationType('NONE');
      setReviewReason('');
      onRefresh();
    } catch (err: any) {
      setActionError(err.message || `Failed to ${decision.toLowerCase()} request.`);
      setConfirmationType('NONE');
    } finally {
      setActionLoading(false);
    }
  };

  const handleExecuteCancel = async (approvalId: string) => {
    setActionLoading(true);
    setActionError(null);
    try {
      await cancelApproval(approvalId, 'Cancelled by operator');
      setLiveAnnouncement(`Approval request ${approvalId} successfully cancelled.`);
      setActiveReviewId(null);
      setConfirmationType('NONE');
      onRefresh();
    } catch (err: any) {
      setActionError(err.message || 'Failed to cancel request.');
      setConfirmationType('NONE');
    } finally {
      setActionLoading(false);
    }
  };

  // Remaining time calculation helper
  const getExpirationBadge = (expiresAt: string, status: ApprovalStatus) => {
    if (status !== 'PENDING') return null;
    const expiryTime = new Date(expiresAt).getTime();
    const now = Date.now();
    const diffMs = expiryTime - now;
    if (diffMs <= 0) {
      return (
        <span className="text-[11px] font-mono text-rose-400 bg-rose-500/10 px-2 py-0.5 rounded border border-rose-500/30">
          Expired (Awaiting Sync)
        </span>
      );
    }
    const minutes = Math.floor(diffMs / 60000);
    const seconds = Math.floor((diffMs % 60000) / 1000);
    if (minutes < 5) {
      return (
        <span className="text-[11px] font-mono text-amber-400 bg-amber-500/10 px-2 py-0.5 rounded border border-amber-500/30 font-semibold">
          Expires soon ({minutes}m {seconds}s)
        </span>
      );
    }
    return (
      <span className="text-[11px] font-mono text-slate-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
        Expires in {minutes}m
      </span>
    );
  };

  return (
    <div className="space-y-6" role="region" aria-label="Security Approval Workflow Queue">
      {/* ARIA Live Region for accessible announcements */}
      <div className="sr-only" aria-live="polite" aria-atomic="true">
        {liveAnnouncement}
      </div>

      {/* Optional Top Error Banner */}
      {error && (
        <div className="p-3 bg-rose-950/30 border border-rose-500/30 rounded-xl text-rose-300 text-xs flex items-center gap-2" role="alert">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* 1. Header & Workflow Breadcrumb */}
      <MotionCard className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 space-y-4 shadow-lg">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-400 shadow-[0_0_15px_rgba(245,158,11,0.15)]">
              <UserCheck className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white tracking-tight flex items-center gap-2">
                Approval Workflow Queue
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/20 font-semibold">
                  Dual-Custody Gateway
                </span>
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Human-in-the-loop validation for REQUIRE_APPROVAL policies
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 self-start md:self-center">
            <button
              onClick={onRefresh}
              disabled={loading}
              className="px-3 py-1.5 text-xs font-semibold text-slate-300 hover:text-white bg-slate-950 border border-slate-800 hover:border-slate-700 rounded-lg transition flex items-center gap-1.5 focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none disabled:opacity-50"
              aria-label="Refresh approval queue data"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
              <span>Refresh Queue</span>
            </button>
          </div>
        </div>

        {/* Security Workflow Trajectory Breadcrumb */}
        <div className="pt-3 border-t border-slate-800/80">
          <div className="flex items-center gap-1.5 overflow-x-auto text-[10px] font-mono text-slate-400 pb-1">
            <span className="text-slate-500 flex-shrink-0">PIPELINE:</span>
            <span className="px-1.5 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-300 flex-shrink-0">SECURITY REQUEST</span>
            <ArrowRight className="w-3 h-3 text-slate-600 flex-shrink-0" />
            <span className="px-1.5 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-300 flex-shrink-0">POLICY EVALUATION</span>
            <ArrowRight className="w-3 h-3 text-slate-600 flex-shrink-0" />
            <span className="px-1.5 py-0.5 rounded bg-amber-950/60 border border-amber-500/40 text-amber-300 font-semibold flex-shrink-0">HUMAN APPROVAL REQUIRED</span>
            <ArrowRight className="w-3 h-3 text-slate-600 flex-shrink-0" />
            <span className="px-1.5 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-300 flex-shrink-0">AUTHORIZED REVIEWER</span>
            <ArrowRight className="w-3 h-3 text-slate-600 flex-shrink-0" />
            <span className="px-1.5 py-0.5 rounded bg-slate-950 border border-slate-800 text-emerald-300 flex-shrink-0">APPROVED / REJECTED</span>
            <ArrowRight className="w-3 h-3 text-slate-600 flex-shrink-0" />
            <span className="px-1.5 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-300 flex-shrink-0">AUDIT ATTRIBUTION</span>
          </div>
        </div>
      </MotionCard>

      {/* 2. Quantified Metric KPI Counters */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 sm:gap-4">
        <div className={`p-4 rounded-xl border transition-all ${
          pendingCount > 0
            ? 'bg-amber-950/20 border-amber-500/40 shadow-[0_0_15px_rgba(245,158,11,0.1)]'
            : 'bg-slate-900/60 border-slate-800'
        }`}>
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-amber-400 flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5" /> Pending Review
            </span>
            <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded font-bold ${
              pendingCount > 0
                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                : 'bg-slate-800 text-slate-400'
            }`}>
              {pendingCount > 0 ? 'Action Required' : 'Queue Clear'}
            </span>
          </div>
          <div className="text-2xl font-bold text-white mt-1.5 font-mono">{pendingCount}</div>
        </div>

        <div className="bg-slate-900/60 p-4 border border-emerald-500/30 rounded-xl">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-emerald-400 flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5" /> Approved
            </span>
            <span className="text-[10px] font-mono px-1.5 py-0.2 rounded font-semibold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
              Authorized
            </span>
          </div>
          <div className="text-2xl font-bold text-white mt-1.5 font-mono">{approvedCount}</div>
        </div>

        <div className="bg-slate-900/60 p-4 border border-rose-500/30 rounded-xl">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-rose-400 flex items-center gap-1.5">
              <XCircle className="w-3.5 h-3.5" /> Rejected
            </span>
            <span className="text-[10px] font-mono px-1.5 py-0.2 rounded font-semibold bg-rose-500/20 text-rose-300 border border-rose-500/30">
              Blocked
            </span>
          </div>
          <div className="text-2xl font-bold text-white mt-1.5 font-mono">{rejectedCount}</div>
        </div>

        <div className="bg-slate-900/60 p-4 border border-slate-800 rounded-xl">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 flex items-center gap-1.5">
              <Ban className="w-3.5 h-3.5" /> Expired / Cancelled
            </span>
            <span className="text-[10px] font-mono px-1.5 py-0.2 rounded font-semibold bg-slate-800 text-slate-400 border border-slate-700">
              Terminal
            </span>
          </div>
          <div className="text-2xl font-bold text-white mt-1.5 font-mono">{expiredCount}</div>
        </div>
      </div>

      {/* 3. Operational Filter & Search Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 bg-slate-900/60 p-4 border border-slate-800 rounded-xl">
        <div className="flex flex-wrap items-center gap-2">
          {/* Status Filter */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="py-1.5 px-3 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-amber-500 font-medium"
            aria-label="Filter approvals by lifecycle status"
          >
            <option value="ALL">All Statuses ({approvals.length})</option>
            <option value="PENDING">PENDING ({pendingCount})</option>
            <option value="APPROVED">APPROVED ({approvedCount})</option>
            <option value="REJECTED">REJECTED ({rejectedCount})</option>
            <option value="EXPIRED">EXPIRED</option>
            <option value="CANCELLED">CANCELLED</option>
          </select>

          {/* Severity Filter */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="py-1.5 px-3 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-amber-500"
            aria-label="Filter approvals by severity level"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
          </select>

          {/* Tool Category Filter */}
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="py-1.5 px-3 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-amber-500"
            aria-label="Filter approvals by tool category"
          >
            <option value="ALL">All Categories</option>
            <option value="SYSTEM">SYSTEM</option>
            <option value="FILE_SYSTEM">FILE_SYSTEM</option>
            <option value="NETWORK">NETWORK</option>
            <option value="DATABASE">DATABASE</option>
            <option value="AGENT">AGENT</option>
          </select>
        </div>

        {/* Search Bar */}
        <div className="relative w-full md:w-72">
          <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search approvals..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-9 pr-8 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-amber-500 transition"
            aria-label="Search approvals..."
          />
          {searchTerm && (
            <button
              onClick={() => setSearchTerm('')}
              className="absolute right-2.5 top-2 text-slate-500 hover:text-slate-300"
              aria-label="Clear search"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* 4. Approval List / Queue Presentation */}
      {filteredApprovals.length === 0 ? (
        <EmptyState
          title={searchTerm ? 'No Approvals Matching Filter' : 'No Approval Requests'}
          message={
            searchTerm
              ? `No approval records matched "${searchTerm}". Try resetting your search or filter options.`
              : 'There are currently no security approval requests recorded in the system.'
          }
          icon={UserCheck}
        />
      ) : statusFilter === 'ALL' ? (
        <div className="space-y-6">
          {/* SECTION A: Active Review Queue (High Priority) */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-mono font-bold tracking-wider text-amber-400 uppercase flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-amber-400 animate-pulse" />
                Active Review Queue ({pendingApprovals.length} Awaiting Authorization)
              </h3>
              <span className="text-[11px] text-slate-400 font-mono">
                Authoritative Human Gate
              </span>
            </div>

            {pendingApprovals.length === 0 ? (
              <div className="p-6 bg-slate-950/40 border border-slate-800/60 rounded-xl text-center text-xs text-slate-500">
                Active review queue clear. No security requests are currently waiting for authorization.
              </div>
            ) : (
              <div className="bg-slate-900/40 border border-amber-500/20 rounded-xl overflow-hidden divide-y divide-slate-800/60 shadow-lg">
                {pendingApprovals.map((app) => renderApprovalCard(app))}
              </div>
            )}
          </div>

          {/* SECTION B: Resolved Approval History (Audit Trail) */}
          <div className="space-y-3 pt-4 border-t border-slate-800/60">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-mono font-bold tracking-wider text-slate-400 uppercase flex items-center gap-2">
                <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
                Approval History &amp; Audit Trail ({historicalApprovals.length} Resolved)
              </h3>
              <span className="text-[11px] text-slate-500 font-mono">
                Immutable Ledger Records
              </span>
            </div>

            {historicalApprovals.length === 0 ? (
              <div className="p-6 bg-slate-950/40 border border-slate-800/60 rounded-xl text-center text-xs text-slate-500">
                No resolved approval history recorded yet.
              </div>
            ) : (
              <div className="bg-slate-900/40 border border-slate-800 rounded-xl overflow-hidden divide-y divide-slate-800/60">
                {historicalApprovals.map((app) => renderApprovalCard(app))}
              </div>
            )}
          </div>
        </div>
      ) : (
        /* Specific Filter View */
        <div className="bg-slate-900/40 border border-slate-800 rounded-xl overflow-hidden divide-y divide-slate-800/60">
          {filteredApprovals.map((app) => renderApprovalCard(app))}
        </div>
      )}
    </div>
  );

  // Helper to render individual approval card
  function renderApprovalCard(app: ApprovalRequest) {
    const isExpanded = expandedId === app.approval_id;
    const isReviewing = activeReviewId === app.approval_id;
    const isPending = app.status === 'PENDING';

    return (
      <div
        key={app.approval_id}
        className={`p-4 transition-colors ${
          isPending
            ? 'bg-slate-950/30 hover:bg-slate-900/50'
            : 'hover:bg-slate-900/40'
        }`}
      >
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-2 flex-1">
            {/* Status & Tool Identity Strip */}
            <div className="flex flex-wrap items-center gap-2">
              <StatusBadge status={app.status} />
              <SeverityBadge severity={app.severity} />
              <span className="font-mono text-xs text-slate-200 bg-slate-950 px-2.5 py-0.5 rounded border border-slate-800 font-bold">
                {app.tool_name}
              </span>
              <span className="text-xs text-slate-400 font-mono">
                Action: <strong className="text-slate-200">{app.action}</strong>
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800">
                [{app.tool_category}]
              </span>
            </div>

            {/* Target & Destination */}
            <div className="text-xs text-slate-300 leading-relaxed">
              <span className="text-slate-500 font-medium">Target:</span>{' '}
              <span className="font-mono text-slate-200 bg-slate-950/60 px-1.5 py-0.5 rounded border border-slate-800/80">
                {app.target}
              </span>
              {app.destination && (
                <span className="ml-2 text-slate-400">
                  &rarr; Dest:{' '}
                  <span className="font-mono text-slate-200 bg-slate-950/60 px-1.5 py-0.5 rounded border border-slate-800/80">
                    {app.destination}
                  </span>
                </span>
              )}
            </div>

            {/* Threat & Risk Evaluation Summary */}
            {app.threat_summary && (
              <p className="text-xs text-slate-400 leading-relaxed max-w-3xl">
                {app.threat_summary}
              </p>
            )}

            {/* Metadata & Timestamps Strip */}
            <div className="flex flex-wrap items-center gap-3 text-[11px] text-slate-500 pt-1">
              <span>
                Approval ID: <span className="font-mono text-slate-400">{app.approval_id.slice(0, 8)}...</span>
              </span>
              <span>
                Request ID: <span className="font-mono text-slate-400">{app.request_id}</span>
              </span>
              <span>
                Risk:{' '}
                <span className={`font-semibold ${
                  app.risk_score >= 80 ? 'text-rose-400' : app.risk_score >= 50 ? 'text-amber-400' : 'text-slate-300'
                }`}>
                  {app.risk_score.toFixed(1)}
                </span>
              </span>
              <span>Created: {new Date(app.created_at).toLocaleTimeString()}</span>
              <span>Expires: {new Date(app.expires_at).toLocaleTimeString()}</span>
              {getExpirationBadge(app.expires_at, app.status)}
            </div>

            {/* Terminal Reviewer Attribution (when resolved) */}
            {app.resolution && (
              <div className="mt-3 text-xs bg-slate-950/80 p-3.5 rounded-xl border border-slate-800/80 space-y-2">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2 text-slate-200 font-medium">
                    <UserCheck className="w-4 h-4 text-cyan-400" />
                    <span>Reviewer Attribution:</span>
                    <span className="font-semibold text-white font-mono">
                      {app.resolution.reviewer.reviewer_name || app.resolution.reviewer.reviewer_id}
                    </span>
                    <span className="text-[11px] font-mono px-1.5 py-0.5 rounded bg-slate-900 border border-slate-700 text-cyan-300">
                      {app.resolution.reviewer.role || 'reviewer'}
                    </span>
                  </div>
                  <span className="text-slate-400 font-mono text-[11px]">
                    Resolved: {new Date(app.resolution.resolved_at).toLocaleTimeString()}
                  </span>
                </div>
                <div className="text-slate-300 italic bg-slate-900/60 p-2 rounded border border-slate-800 text-[11px]">
                  "{app.resolution.reason}"
                </div>
                <div className="text-[10px] text-slate-500 font-mono flex items-center gap-1.5">
                  <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                  <span>Security Trajectory: Authenticated Reviewer &rarr; Approval Resolution &rarr; Audit Attribution</span>
                </div>
              </div>
            )}
          </div>

          {/* Action & Toggle Controls */}
          <div className="flex items-center gap-2 self-end md:self-center flex-shrink-0">
            {isPending && !isReviewing && (
              <button
                onClick={() => {
                  setActiveReviewId(app.approval_id);
                  setConfirmationType('NONE');
                  setReviewReason('');
                  setActionError(null);
                }}
                className="px-3.5 py-1.5 text-xs font-semibold text-white bg-amber-600 hover:bg-amber-500 rounded-lg transition-colors shadow-md flex items-center gap-1.5 focus-visible:ring-2 focus-visible:ring-amber-400 focus-visible:outline-none"
              >
                <UserCheck className="w-3.5 h-3.5" />
                <span>Review Request</span>
              </button>
            )}

            <button
              onClick={() => setExpandedId(isExpanded ? null : app.approval_id)}
              className="px-2.5 py-1.5 text-xs text-slate-300 hover:text-white bg-slate-950 border border-slate-800 hover:border-slate-700 rounded-lg transition-colors flex items-center gap-1 focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none"
              aria-label={isExpanded ? 'Hide Details' : 'Details'}
            >
              <span>{isExpanded ? 'Hide Details' : 'Details'}</span>
              {isExpanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
            </button>
          </div>
        </div>

        {/* Review Form Drawer / Modal for PENDING Requests */}
        {isReviewing && (
          <div className="mt-4 p-5 bg-slate-950 border border-amber-500/40 rounded-xl space-y-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
              <div className="text-xs font-bold text-amber-400 flex items-center gap-2 uppercase tracking-wide font-mono">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                Authorize or Reject Tool Execution
              </div>
              <button
                onClick={() => {
                  setActiveReviewId(null);
                  setConfirmationType('NONE');
                }}
                className="text-slate-500 hover:text-slate-300 text-xs p-1 focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none rounded"
                aria-label="Dismiss review form"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Read-Only Banner for Unauthorized Identities */}
            {!canResolveApprovals && (
              <div className="p-3 bg-amber-500/10 border border-amber-500/20 rounded-lg text-xs text-amber-300 flex items-start gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                <div>
                  <strong className="font-semibold">Read-Only View:</strong> Current identity ({user ? `${user.username} [${roles[0] || 'VIEWER'}]` : 'Unauthenticated'}) lacks <code className="font-mono text-[11px] bg-amber-950/60 px-1 py-0.5 rounded">RESOLVE_APPROVALS</code> capability. Approval resolution controls are disabled.
                </div>
              </div>
            )}

            {/* Reviewer Identity Fields */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div>
                <label className="text-[11px] font-semibold text-slate-400 block mb-1">Reviewer ID</label>
                <input
                  type="text"
                  value={reviewerId}
                  onChange={(e) => setReviewerId(e.target.value)}
                  disabled={!canResolveApprovals || confirmationType !== 'NONE'}
                  className="w-full px-2.5 py-1.5 text-xs bg-slate-900 border border-slate-800 rounded-lg text-slate-200 disabled:opacity-50 font-mono"
                />
              </div>
              <div>
                <label className="text-[11px] font-semibold text-slate-400 block mb-1">Reviewer Name</label>
                <input
                  type="text"
                  value={reviewerName}
                  onChange={(e) => setReviewerName(e.target.value)}
                  disabled={!canResolveApprovals || confirmationType !== 'NONE'}
                  className="w-full px-2.5 py-1.5 text-xs bg-slate-900 border border-slate-800 rounded-lg text-slate-200 disabled:opacity-50"
                />
              </div>
              <div>
                <label className="text-[11px] font-semibold text-slate-400 block mb-1">Role</label>
                <input
                  type="text"
                  value={reviewerRole}
                  onChange={(e) => setReviewerRole(e.target.value)}
                  disabled={!canResolveApprovals || confirmationType !== 'NONE'}
                  className="w-full px-2.5 py-1.5 text-xs bg-slate-900 border border-slate-800 rounded-lg text-slate-200 disabled:opacity-50 font-mono"
                />
              </div>
            </div>

            {/* Justification Textarea */}
            <div>
              <label className="text-[11px] font-semibold text-slate-300 block mb-1">
                Review Justification / Reason *
              </label>
              <textarea
                rows={2}
                value={reviewReason}
                onChange={(e) => setReviewReason(e.target.value)}
                disabled={!canResolveApprovals || confirmationType !== 'NONE'}
                placeholder={
                  canResolveApprovals
                    ? 'Provide explicit operational rationale for approval or rejection...'
                    : 'Resolution justification disabled for read-only role'
                }
                className="w-full px-3 py-2 text-xs bg-slate-900 border border-slate-800 rounded-lg text-slate-200 placeholder-slate-600 focus:outline-none focus:border-amber-500 disabled:opacity-50 transition"
              />
            </div>

            {/* Action Error Banner */}
            {actionError && (
              <div className="text-xs text-rose-400 bg-rose-500/10 p-2.5 rounded-lg border border-rose-500/20 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>{actionError}</span>
              </div>
            )}

            {/* Consequential Action Confirmation Interactions */}
            {confirmationType === 'APPROVE' ? (
              <div className="p-4 bg-emerald-950/40 border border-emerald-500/40 rounded-xl space-y-3 animate-in fade-in">
                <div className="flex items-center gap-2 text-emerald-400 font-semibold text-xs">
                  <CheckCircle2 className="w-4 h-4" />
                  <span>Confirm Security Approval &amp; Authorization</span>
                </div>
                <div className="text-xs text-slate-300 space-y-1">
                  <p>
                    You are approving execution of <strong className="font-mono text-emerald-300">{app.tool_name}</strong> targeting <span className="font-mono">{app.target}</span>.
                  </p>
                  <p className="text-[11px] text-slate-400">
                    Risk Score: <span className="text-amber-400 font-semibold">{app.risk_score.toFixed(1)}</span> &bull; Severity: {app.severity}
                  </p>
                  <p className="text-[11px] text-emerald-300 italic pt-1">
                    Justification: "{reviewReason.trim()}"
                  </p>
                  <p className="text-[10px] text-slate-500 pt-1 border-t border-emerald-900/60 font-mono">
                    Authoritative Note: This resolution issues a cryptographic HMAC token to unseal the execution boundary.
                  </p>
                </div>
                <div className="flex items-center justify-end gap-2 pt-1">
                  <button
                    onClick={() => setConfirmationType('NONE')}
                    disabled={actionLoading}
                    className="px-3 py-1.5 text-xs text-slate-300 hover:text-white bg-slate-900 border border-slate-700 rounded-lg transition"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={() => handleExecuteResolution(app.approval_id, 'APPROVE')}
                    disabled={actionLoading}
                    className="px-4 py-1.5 text-xs font-semibold text-white bg-emerald-600 hover:bg-emerald-500 rounded-lg transition shadow-md flex items-center gap-1.5 focus-visible:ring-2 focus-visible:ring-emerald-400 focus-visible:outline-none"
                  >
                    {actionLoading ? (
                      <>
                        <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                        <span>Authorizing...</span>
                      </>
                    ) : (
                      <>
                        <Check className="w-3.5 h-3.5" />
                        <span>Confirm Approval</span>
                      </>
                    )}
                  </button>
                </div>
              </div>
            ) : confirmationType === 'REJECT' ? (
              <div className="p-4 bg-rose-950/40 border border-rose-500/40 rounded-xl space-y-3 animate-in fade-in">
                <div className="flex items-center gap-2 text-rose-400 font-semibold text-xs">
                  <XCircle className="w-4 h-4" />
                  <span>Confirm Security Rejection</span>
                </div>
                <div className="text-xs text-slate-300 space-y-1">
                  <p>
                    You are rejecting execution of <strong className="font-mono text-rose-300">{app.tool_name}</strong> targeting <span className="font-mono">{app.target}</span>.
                  </p>
                  <p className="text-[11px] text-slate-400">
                    Risk Score: <span className="text-amber-400 font-semibold">{app.risk_score.toFixed(1)}</span> &bull; Severity: {app.severity}
                  </p>
                  <p className="text-[11px] text-rose-300 italic pt-1">
                    Justification: "{reviewReason.trim()}"
                  </p>
                  <p className="text-[10px] text-slate-500 pt-1 border-t border-rose-900/60 font-mono">
                    Authoritative Note: This request will be marked REJECTED and tool execution will remain strictly blocked.
                  </p>
                </div>
                <div className="flex items-center justify-end gap-2 pt-1">
                  <button
                    onClick={() => setConfirmationType('NONE')}
                    disabled={actionLoading}
                    className="px-3 py-1.5 text-xs text-slate-300 hover:text-white bg-slate-900 border border-slate-700 rounded-lg transition"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={() => handleExecuteResolution(app.approval_id, 'REJECT')}
                    disabled={actionLoading}
                    className="px-4 py-1.5 text-xs font-semibold text-white bg-rose-600 hover:bg-rose-500 rounded-lg transition shadow-md flex items-center gap-1.5 focus-visible:ring-2 focus-visible:ring-rose-400 focus-visible:outline-none"
                  >
                    {actionLoading ? (
                      <>
                        <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                        <span>Rejecting...</span>
                      </>
                    ) : (
                      <>
                        <X className="w-3.5 h-3.5" />
                        <span>Confirm Rejection</span>
                      </>
                    )}
                  </button>
                </div>
              </div>
            ) : confirmationType === 'CANCEL' ? (
              <div className="p-4 bg-zinc-950/60 border border-zinc-700 rounded-xl space-y-3 animate-in fade-in">
                <div className="flex items-center gap-2 text-zinc-300 font-semibold text-xs">
                  <Ban className="w-4 h-4" />
                  <span>Confirm Request Cancellation</span>
                </div>
                <p className="text-xs text-slate-400">
                  Cancel pending approval request <strong className="font-mono text-slate-300">{app.approval_id}</strong>.
                </p>
                <div className="flex items-center justify-end gap-2 pt-1">
                  <button
                    onClick={() => setConfirmationType('NONE')}
                    disabled={actionLoading}
                    className="px-3 py-1.5 text-xs text-slate-300 hover:text-white bg-slate-900 border border-slate-700 rounded-lg transition"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={() => handleExecuteCancel(app.approval_id)}
                    disabled={actionLoading}
                    className="px-4 py-1.5 text-xs font-semibold text-white bg-zinc-700 hover:bg-zinc-600 rounded-lg transition shadow-md flex items-center gap-1.5"
                  >
                    {actionLoading ? 'Cancelling...' : 'Confirm Cancellation'}
                  </button>
                </div>
              </div>
            ) : (
              /* Standard Initial Action Buttons */
              <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
                <button
                  onClick={handleTriggerCancel}
                  disabled={actionLoading || !canCancelApproval}
                  title={!canCancelApproval ? 'Requires CANCEL_APPROVAL permission' : undefined}
                  className="px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200 bg-slate-900 border border-slate-800 rounded-lg transition-colors disabled:opacity-40 disabled:cursor-not-allowed focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none"
                >
                  Cancel Request
                </button>

                <div className="flex items-center gap-2">
                  <button
                    onClick={handleTriggerReject}
                    disabled={actionLoading || !canResolveApprovals}
                    title={!canResolveApprovals ? 'Requires RESOLVE_APPROVALS permission' : undefined}
                    className="px-3.5 py-1.5 text-xs font-semibold text-rose-300 bg-rose-950/80 border border-rose-800 hover:bg-rose-900/80 rounded-lg transition-colors flex items-center gap-1.5 disabled:opacity-40 disabled:cursor-not-allowed focus-visible:ring-2 focus-visible:ring-rose-400 focus-visible:outline-none"
                  >
                    <X className="w-3.5 h-3.5" />
                    <span>Reject Request</span>
                  </button>
                  <button
                    onClick={handleTriggerApprove}
                    disabled={actionLoading || !canResolveApprovals}
                    title={!canResolveApprovals ? 'Requires RESOLVE_APPROVALS permission' : undefined}
                    className="px-4 py-1.5 text-xs font-semibold text-white bg-emerald-600 hover:bg-emerald-500 rounded-lg transition-colors flex items-center gap-1.5 shadow-md disabled:opacity-40 disabled:cursor-not-allowed focus-visible:ring-2 focus-visible:ring-emerald-400 focus-visible:outline-none"
                  >
                    <Check className="w-3.5 h-3.5" />
                    <span>Approve Request</span>
                  </button>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Expanded Technical Inspection Details Drawer */}
        {isExpanded && (
          <div className="mt-3 pt-3 border-t border-slate-800/80 text-xs space-y-3 animate-in fade-in">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <span className="text-slate-400 block mb-1 font-semibold flex items-center gap-1.5">
                  <Fingerprint className="w-3.5 h-3.5 text-cyan-400" />
                  Cryptographic Request Fingerprint:
                </span>
                <div className="font-mono text-[11px] text-slate-300 bg-slate-950 p-2.5 rounded-lg border border-slate-800 break-all select-all">
                  {app.request_fingerprint}
                </div>
              </div>

              <div>
                <span className="text-slate-400 block mb-1 font-semibold flex items-center gap-1.5">
                  <FileCode className="w-3.5 h-3.5 text-cyan-400" />
                  Sanitized Tool Parameters:
                </span>
                <pre className="font-mono text-[11px] text-slate-300 bg-slate-950 p-2.5 rounded-lg border border-slate-800 overflow-x-auto max-h-36">
                  {JSON.stringify(app.parameters, null, 2)}
                </pre>
              </div>
            </div>

            {/* Requesting Agent Identity Metadata */}
            {app.agent && (
              <div className="p-2.5 bg-slate-950/60 rounded-lg border border-slate-800/80 flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono text-slate-400">
                <span>Agent ID: <strong className="text-slate-200">{app.agent.agent_id}</strong></span>
                <span>Name: <span className="text-slate-300">{app.agent.name}</span></span>
                <span>Session: <span className="text-slate-300">{app.agent.session_id}</span></span>
              </div>
            )}
          </div>
        )}
      </div>
    );
  }
};
