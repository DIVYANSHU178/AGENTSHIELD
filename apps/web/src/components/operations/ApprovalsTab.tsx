import React, { useState } from 'react';
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
} from 'lucide-react';
import { approveApproval, rejectApproval, cancelApproval } from '../../lib/api';

interface ApprovalsTabProps {
  approvals: ApprovalRequest[];
  onRefresh: () => void;
}

export const StatusBadge: React.FC<{ status: ApprovalStatus }> = ({ status }) => {
  switch (status) {
    case 'PENDING':
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20 animate-pulse">
          <Clock className="w-3 h-3" />
          PENDING
        </span>
      );
    case 'APPROVED':
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
          <CheckCircle2 className="w-3 h-3" />
          APPROVED
        </span>
      );
    case 'REJECTED':
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20">
          <XCircle className="w-3 h-3" />
          REJECTED
        </span>
      );
    case 'EXPIRED':
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-semibold bg-slate-500/10 text-slate-400 border border-slate-500/20">
          <Clock className="w-3 h-3" />
          EXPIRED
        </span>
      );
    case 'CANCELLED':
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-semibold bg-zinc-500/10 text-zinc-400 border border-zinc-500/20">
          <Ban className="w-3 h-3" />
          CANCELLED
        </span>
      );
    default:
      return null;
  }
};

export const ApprovalsTab: React.FC<ApprovalsTabProps> = ({ approvals, onRefresh }) => {
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [expandedId, setExpandedId] = useState<string | null>(null);

  // Review form states
  const [activeReviewId, setActiveReviewId] = useState<string | null>(null);
  const [reviewerId, setReviewerId] = useState<string>('sec-lead-01');
  const [reviewerName, setReviewerName] = useState<string>('Security Officer');
  const [reviewerRole, setReviewerRole] = useState<string>('security_reviewer');
  const [reviewReason, setReviewReason] = useState<string>('');
  const [actionLoading, setActionLoading] = useState<boolean>(false);
  const [actionError, setActionError] = useState<string | null>(null);

  const pendingCount = approvals.filter((a) => a.status === 'PENDING').length;
  const approvedCount = approvals.filter((a) => a.status === 'APPROVED').length;
  const rejectedCount = approvals.filter((a) => a.status === 'REJECTED').length;
  const expiredCount = approvals.filter((a) => a.status === 'EXPIRED' || a.status === 'CANCELLED').length;

  const filteredApprovals = approvals.filter((a) => {
    if (statusFilter !== 'ALL' && a.status !== statusFilter) return false;
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      return (
        a.tool_name.toLowerCase().includes(term) ||
        a.target.toLowerCase().includes(term) ||
        a.request_id.toLowerCase().includes(term) ||
        a.approval_id.toLowerCase().includes(term)
      );
    }
    return true;
  });

  const handleApprove = async (approvalId: string) => {
    if (!reviewReason.trim()) {
      setActionError('Approval justification is required.');
      return;
    }
    setActionLoading(true);
    setActionError(null);
    try {
      await approveApproval(approvalId, reviewerId, reviewerName, reviewerRole, reviewReason.trim());
      setActiveReviewId(null);
      setReviewReason('');
      onRefresh();
    } catch (err: any) {
      setActionError(err.message || 'Failed to approve request.');
    } finally {
      setActionLoading(false);
    }
  };

  const handleReject = async (approvalId: string) => {
    if (!reviewReason.trim()) {
      setActionError('Rejection justification is required.');
      return;
    }
    setActionLoading(true);
    setActionError(null);
    try {
      await rejectApproval(approvalId, reviewerId, reviewerName, reviewerRole, reviewReason.trim());
      setActiveReviewId(null);
      setReviewReason('');
      onRefresh();
    } catch (err: any) {
      setActionError(err.message || 'Failed to reject request.');
    } finally {
      setActionLoading(false);
    }
  };

  const handleCancel = async (approvalId: string) => {
    setActionLoading(true);
    setActionError(null);
    try {
      await cancelApproval(approvalId, 'Cancelled by operator');
      setActiveReviewId(null);
      onRefresh();
    } catch (err: any) {
      setActionError(err.message || 'Failed to cancel request.');
    } finally {
      setActionLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Metric Counters */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="bg-slate-900/60 p-4 border border-amber-500/20 rounded-xl">
          <div className="text-xs text-amber-400 font-medium">Pending Review</div>
          <div className="text-2xl font-bold text-white mt-1">{pendingCount}</div>
        </div>
        <div className="bg-slate-900/60 p-4 border border-emerald-500/20 rounded-xl">
          <div className="text-xs text-emerald-400 font-medium">Approved</div>
          <div className="text-2xl font-bold text-white mt-1">{approvedCount}</div>
        </div>
        <div className="bg-slate-900/60 p-4 border border-rose-500/20 rounded-xl">
          <div className="text-xs text-rose-400 font-medium">Rejected</div>
          <div className="text-2xl font-bold text-white mt-1">{rejectedCount}</div>
        </div>
        <div className="bg-slate-900/60 p-4 border border-slate-800 rounded-xl">
          <div className="text-xs text-slate-400 font-medium">Expired / Cancelled</div>
          <div className="text-2xl font-bold text-white mt-1">{expiredCount}</div>
        </div>
      </div>

      {/* Header & Filter Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/60 p-4 border border-slate-800 rounded-xl">
        <div className="flex items-center gap-2">
          <UserCheck className="w-5 h-5 text-amber-400" />
          <div>
            <h3 className="text-sm font-semibold text-white">Approval Workflow Queue</h3>
            <p className="text-xs text-slate-400">
              Human-in-the-loop validation for REQUIRE_APPROVAL policies
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search approvals..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-amber-500"
            />
          </div>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="py-1.5 px-2.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-amber-500"
          >
            <option value="ALL">All Statuses</option>
            <option value="PENDING">PENDING</option>
            <option value="APPROVED">APPROVED</option>
            <option value="REJECTED">REJECTED</option>
            <option value="EXPIRED">EXPIRED</option>
            <option value="CANCELLED">CANCELLED</option>
          </select>
        </div>
      </div>

      {/* Approval List */}
      <div className="bg-slate-900/40 border border-slate-800 rounded-xl overflow-hidden divide-y divide-slate-800/60">
        {filteredApprovals.length === 0 ? (
          <div className="p-8 text-center text-slate-500 text-sm">
            No approval requests found matching the filter criteria.
          </div>
        ) : (
          filteredApprovals.map((app) => {
            const isExpanded = expandedId === app.approval_id;
            const isReviewing = activeReviewId === app.approval_id;

            return (
              <div key={app.approval_id} className="p-4 transition-colors hover:bg-slate-900/60">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                  <div className="space-y-1.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <StatusBadge status={app.status} />
                      <SeverityBadge severity={app.severity} />
                      <span className="font-mono text-xs text-slate-300 bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                        {app.tool_name}
                      </span>
                      <span className="text-xs text-slate-500 font-mono">
                        Action: <strong className="text-slate-400">{app.action}</strong>
                      </span>
                    </div>

                    <div className="text-xs text-slate-300">
                      Target: <span className="font-mono text-slate-200">{app.target}</span>
                      {app.destination && (
                        <span className="ml-2 text-slate-400">
                          &rarr; Dest: <span className="font-mono">{app.destination}</span>
                        </span>
                      )}
                    </div>

                    <div className="flex flex-wrap items-center gap-3 text-[11px] text-slate-500">
                      <span>Approval ID: <span className="font-mono text-slate-400">{app.approval_id.slice(0, 8)}...</span></span>
                      <span>Request ID: <span className="font-mono text-slate-400">{app.request_id}</span></span>
                      <span>Risk: <span className="text-amber-400 font-semibold">{app.risk_score.toFixed(1)}</span></span>
                      <span>Created: {new Date(app.created_at).toLocaleTimeString()}</span>
                      <span>Expires: {new Date(app.expires_at).toLocaleTimeString()}</span>
                    </div>

                    {app.resolution && (
                      <div className="mt-2 text-xs bg-slate-950/80 p-2.5 rounded border border-slate-800/80">
                        <div className="flex items-center gap-2 text-slate-300">
                          <span className="font-semibold text-slate-200">Reviewer:</span> {app.resolution.reviewer.reviewer_name || app.resolution.reviewer.reviewer_id} ({app.resolution.reviewer.role || 'reviewer'})
                          <span className="text-slate-500">|</span>
                          <span className="text-slate-400">{new Date(app.resolution.resolved_at).toLocaleTimeString()}</span>
                        </div>
                        <div className="mt-1 text-slate-300 italic">
                          "{app.resolution.reason}"
                        </div>
                      </div>
                    )}
                  </div>

                  <div className="flex items-center gap-2 self-end md:self-center">
                    {app.status === 'PENDING' && !isReviewing && (
                      <button
                        onClick={() => {
                          setActiveReviewId(app.approval_id);
                          setReviewReason('');
                          setActionError(null);
                        }}
                        className="px-3 py-1.5 text-xs font-semibold text-white bg-amber-600 hover:bg-amber-500 rounded-lg transition-colors shadow-sm"
                      >
                        Review Request
                      </button>
                    )}

                    <button
                      onClick={() => setExpandedId(isExpanded ? null : app.approval_id)}
                      className="px-2.5 py-1.5 text-xs text-slate-400 hover:text-slate-200 bg-slate-950 border border-slate-800 rounded-lg transition-colors"
                    >
                      {isExpanded ? 'Hide Details' : 'Details'}
                    </button>
                  </div>
                </div>

                {/* Review Form Modal/Drawer for PENDING Requests */}
                {isReviewing && (
                  <div className="mt-4 p-4 bg-slate-950 border border-amber-500/30 rounded-xl space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="text-xs font-semibold text-amber-400 flex items-center gap-1.5">
                        <AlertTriangle className="w-3.5 h-3.5" />
                        Authorize or Reject Tool Execution
                      </div>
                      <button
                        onClick={() => setActiveReviewId(null)}
                        className="text-slate-500 hover:text-slate-300 text-xs"
                      >
                        <X className="w-4 h-4" />
                      </button>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                      <div>
                        <label className="text-[11px] text-slate-400 block mb-1">Reviewer ID</label>
                        <input
                          type="text"
                          value={reviewerId}
                          onChange={(e) => setReviewerId(e.target.value)}
                          className="w-full px-2.5 py-1.5 text-xs bg-slate-900 border border-slate-800 rounded text-slate-200"
                        />
                      </div>
                      <div>
                        <label className="text-[11px] text-slate-400 block mb-1">Reviewer Name</label>
                        <input
                          type="text"
                          value={reviewerName}
                          onChange={(e) => setReviewerName(e.target.value)}
                          className="w-full px-2.5 py-1.5 text-xs bg-slate-900 border border-slate-800 rounded text-slate-200"
                        />
                      </div>
                      <div>
                        <label className="text-[11px] text-slate-400 block mb-1">Role</label>
                        <input
                          type="text"
                          value={reviewerRole}
                          onChange={(e) => setReviewerRole(e.target.value)}
                          className="w-full px-2.5 py-1.5 text-xs bg-slate-900 border border-slate-800 rounded text-slate-200"
                        />
                      </div>
                    </div>

                    <div>
                      <label className="text-[11px] text-slate-400 block mb-1">Review Justification / Reason *</label>
                      <textarea
                        rows={2}
                        value={reviewReason}
                        onChange={(e) => setReviewReason(e.target.value)}
                        placeholder="Provide explicit operational rationale for approval or rejection..."
                        className="w-full px-2.5 py-1.5 text-xs bg-slate-900 border border-slate-800 rounded text-slate-200 placeholder-slate-600 focus:outline-none focus:border-amber-500"
                      />
                    </div>

                    {actionError && (
                      <div className="text-xs text-rose-400 bg-rose-500/10 p-2 rounded border border-rose-500/20">
                        {actionError}
                      </div>
                    )}

                    <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
                      <button
                        onClick={() => handleCancel(app.approval_id)}
                        disabled={actionLoading}
                        className="px-3 py-1 text-xs text-slate-400 hover:text-slate-200 bg-slate-900 border border-slate-800 rounded transition-colors"
                      >
                        Cancel Request
                      </button>

                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => handleReject(app.approval_id)}
                          disabled={actionLoading}
                          className="px-3 py-1.5 text-xs font-semibold text-rose-300 bg-rose-950/80 border border-rose-800 hover:bg-rose-900/80 rounded transition-colors flex items-center gap-1"
                        >
                          <X className="w-3.5 h-3.5" />
                          Reject Request
                        </button>
                        <button
                          onClick={() => handleApprove(app.approval_id)}
                          disabled={actionLoading}
                          className="px-3 py-1.5 text-xs font-semibold text-white bg-emerald-600 hover:bg-emerald-500 rounded transition-colors flex items-center gap-1 shadow-sm"
                        >
                          <Check className="w-3.5 h-3.5" />
                          Approve Request
                        </button>
                      </div>
                    </div>
                  </div>
                )}

                {/* Expanded Technical Inspection Details */}
                {isExpanded && (
                  <div className="mt-3 pt-3 border-t border-slate-800/80 text-xs space-y-2">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      <div>
                        <span className="text-slate-500 block mb-1 font-semibold flex items-center gap-1">
                          <Fingerprint className="w-3 h-3 text-slate-400" />
                          Request Fingerprint:
                        </span>
                        <div className="font-mono text-[11px] text-slate-400 bg-slate-950 p-2 rounded border border-slate-800 break-all">
                          {app.request_fingerprint}
                        </div>
                      </div>

                      <div>
                        <span className="text-slate-500 block mb-1 font-semibold flex items-center gap-1">
                          <FileCode className="w-3 h-3 text-slate-400" />
                          Parameters:
                        </span>
                        <pre className="font-mono text-[11px] text-slate-400 bg-slate-950 p-2 rounded border border-slate-800 overflow-x-auto max-h-32">
                          {JSON.stringify(app.parameters, null, 2)}
                        </pre>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
