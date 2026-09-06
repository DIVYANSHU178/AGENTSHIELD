import React, { useState, useEffect, useMemo } from 'react';
import { SecurityEvent, EventType, TabType } from '../../types';
import {
  FileText,
  Search,
  Clock,
  User,
  Shield,
  ShieldAlert,
  ShieldCheck,
  XCircle,
  AlertTriangle,
  Lock,
  Key,
  Terminal,
  UserCheck,
  Ban,
  ArrowRight,
  X,
  Eye,
  RefreshCw,
  RotateCcw,
  SlidersHorizontal,
  Layers,
  Fingerprint,
  Database,
} from 'lucide-react';
import { MotionCard, MotionList, MotionItem } from '../common/MotionComponents';
import { LoadingState, EmptyState, AuthRequiredState } from '../common/StateViews';
import { sanitizeTelemetryData } from '../../lib/sanitizer';

export interface AuditTabProps {
  events: SecurityEvent[];
  onRefresh?: () => void;
  loading?: boolean;
  authRequired?: boolean;
  onSignIn?: () => void;
  onSelectTab?: (tab: TabType, filterQuery?: string) => void;
  initialSearch?: string;
}

export type EventCategory = 'ALL' | 'GATEWAY' | 'EXECUTION' | 'APPROVAL' | 'IDENTITY' | 'SYSTEM';

export function getEventCategory(type: EventType): EventCategory {
  switch (type) {
    case 'REQUESTED':
    case 'ANALYZED':
    case 'ALLOWED':
    case 'BLOCKED':
    case 'APPROVAL_REQUIRED':
      return 'GATEWAY';
    case 'EXECUTED':
    case 'FAILED':
    case 'DENIED':
      return 'EXECUTION';
    case 'APPROVAL_APPROVED':
    case 'APPROVAL_REJECTED':
    case 'APPROVAL_EXPIRED':
    case 'APPROVAL_CANCELLED':
    case 'APPROVAL_AUTHORIZED':
    case 'APPROVAL_AUTHORIZATION_DENIED':
      return 'APPROVAL';
    case 'AUTHENTICATION_SUCCESS':
    case 'AUTHENTICATION_FAILURE':
    case 'SESSION_CREATED':
    case 'SESSION_REVOKED':
    case 'AUTHORIZATION_ALLOWED':
    case 'AUTHORIZATION_DENIED':
    case 'ROLE_CHANGE':
    case 'IDENTITY_DISABLED':
      return 'IDENTITY';
    default:
      return 'SYSTEM';
  }
}

export const EventTypeBadge: React.FC<{ type: EventType }> = ({ type }) => {
  const styles: Record<EventType, string> = {
    REQUESTED: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
    ANALYZED: 'bg-indigo-500/10 text-indigo-400 border-indigo-500/30',
    ALLOWED: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
    APPROVAL_REQUIRED: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
    APPROVAL_APPROVED: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 font-semibold',
    APPROVAL_REJECTED: 'bg-rose-500/10 text-rose-400 border-rose-500/30 font-semibold',
    APPROVAL_EXPIRED: 'bg-slate-500/10 text-slate-400 border-slate-500/30',
    APPROVAL_CANCELLED: 'bg-zinc-500/10 text-zinc-400 border-zinc-500/30',
    BLOCKED: 'bg-rose-500/10 text-rose-400 border-rose-500/30 font-bold',
    EXECUTED: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
    FAILED: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
    DENIED: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
    AUTHENTICATION_SUCCESS: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
    AUTHENTICATION_FAILURE: 'bg-rose-500/10 text-rose-400 border-rose-500/30 font-bold',
    SESSION_CREATED: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
    SESSION_REVOKED: 'bg-zinc-500/10 text-zinc-400 border-zinc-500/30',
    AUTHORIZATION_ALLOWED: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
    AUTHORIZATION_DENIED: 'bg-rose-500/10 text-rose-400 border-rose-500/30 font-bold',
    ROLE_CHANGE: 'bg-purple-500/10 text-purple-400 border-purple-500/30',
    IDENTITY_DISABLED: 'bg-rose-500/10 text-rose-400 border-rose-500/30 font-bold',
    APPROVAL_AUTHORIZED: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 font-semibold',
    APPROVAL_AUTHORIZATION_DENIED: 'bg-rose-500/10 text-rose-400 border-rose-500/30 font-bold',
  };

  const getCategoryIcon = (t: EventType) => {
    switch (t) {
      case 'AUTHENTICATION_SUCCESS':
      case 'SESSION_CREATED':
      case 'AUTHORIZATION_ALLOWED':
        return <Key className="w-3 h-3 text-emerald-400 shrink-0" />;
      case 'AUTHENTICATION_FAILURE':
      case 'AUTHORIZATION_DENIED':
      case 'IDENTITY_DISABLED':
        return <Lock className="w-3 h-3 text-rose-400 shrink-0" />;
      case 'APPROVAL_APPROVED':
      case 'APPROVAL_AUTHORIZED':
        return <UserCheck className="w-3 h-3 text-emerald-400 shrink-0" />;
      case 'APPROVAL_REJECTED':
      case 'APPROVAL_AUTHORIZATION_DENIED':
        return <XCircle className="w-3 h-3 text-rose-400 shrink-0" />;
      case 'APPROVAL_REQUIRED':
      case 'APPROVAL_EXPIRED':
        return <Clock className="w-3 h-3 text-amber-400 shrink-0" />;
      case 'APPROVAL_CANCELLED':
        return <Ban className="w-3 h-3 text-zinc-400 shrink-0" />;
      case 'BLOCKED':
        return <ShieldAlert className="w-3 h-3 text-rose-400 shrink-0" />;
      case 'ALLOWED':
        return <ShieldCheck className="w-3 h-3 text-emerald-400 shrink-0" />;
      case 'EXECUTED':
        return <Terminal className="w-3 h-3 text-emerald-400 shrink-0" />;
      case 'FAILED':
      case 'DENIED':
        return <AlertTriangle className="w-3 h-3 text-rose-400 shrink-0" />;
      default:
        return <Layers className="w-3 h-3 text-cyan-400 shrink-0" />;
    }
  };

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 text-[10px] font-mono rounded border ${
        styles[type] || styles.REQUESTED
      }`}
    >
      {getCategoryIcon(type)}
      <span>{type}</span>
    </span>
  );
};

export const AuditTab: React.FC<AuditTabProps> = ({
  events = [],
  onRefresh,
  loading = false,
  authRequired = false,
  onSignIn,
  onSelectTab,
  initialSearch = '',
}) => {
  const [eventTypeFilter, setEventTypeFilter] = useState<string>('ALL');
  const [categoryFilter, setCategoryFilter] = useState<EventCategory>('ALL');
  const [actorFilter, setActorFilter] = useState<string>('ALL');
  const [searchTerm, setSearchTerm] = useState<string>(initialSearch);
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);

  // Sync initialSearch if provided
  useEffect(() => {
    if (initialSearch) {
      setSearchTerm(initialSearch);
    }
  }, [initialSearch]);

  // Close detail drawer on Escape key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && selectedEvent) {
        setSelectedEvent(null);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [selectedEvent]);

  // Derived list of unique actors from events
  const availableActors = useMemo(() => {
    const actors = new Set<string>();
    events.forEach((ev) => {
      if (ev.actor) actors.add(ev.actor);
    });
    return Array.from(actors).sort();
  }, [events]);

  // Quantified metrics
  const totalEvents = events.length;
  const gatewayEventsCount = useMemo(
    () => events.filter((e) => getEventCategory(e.event_type) === 'GATEWAY').length,
    [events]
  );
  const executionEventsCount = useMemo(
    () => events.filter((e) => getEventCategory(e.event_type) === 'EXECUTION').length,
    [events]
  );
  const approvalEventsCount = useMemo(
    () => events.filter((e) => getEventCategory(e.event_type) === 'APPROVAL').length,
    [events]
  );
  const identityEventsCount = useMemo(
    () => events.filter((e) => getEventCategory(e.event_type) === 'IDENTITY').length,
    [events]
  );
  const uniqueActorsCount = availableActors.length;

  // Filtered events
  const filteredEvents = useMemo(() => {
    return events.filter((ev) => {
      if (eventTypeFilter !== 'ALL' && ev.event_type !== eventTypeFilter) return false;
      if (categoryFilter !== 'ALL' && getEventCategory(ev.event_type) !== categoryFilter) return false;
      if (actorFilter !== 'ALL' && ev.actor !== actorFilter) return false;
      if (searchTerm) {
        const term = searchTerm.toLowerCase();
        return (
          ev.request_id.toLowerCase().includes(term) ||
          ev.actor.toLowerCase().includes(term) ||
          ev.event_id.toLowerCase().includes(term) ||
          ev.event_type.toLowerCase().includes(term) ||
          JSON.stringify(ev.details || {}).toLowerCase().includes(term) ||
          JSON.stringify(ev.metadata || {}).toLowerCase().includes(term)
        );
      }
      return true;
    });
  }, [events, eventTypeFilter, categoryFilter, actorFilter, searchTerm]);

  // Reset all filters
  const handleResetFilters = () => {
    setEventTypeFilter('ALL');
    setCategoryFilter('ALL');
    setActorFilter('ALL');
    setSearchTerm('');
  };

  const hasActiveFilters =
    eventTypeFilter !== 'ALL' ||
    categoryFilter !== 'ALL' ||
    actorFilter !== 'ALL' ||
    searchTerm.trim().length > 0;

  // Derive concise event summary description from event details
  const getEventSummary = (ev: SecurityEvent): string => {
    const details = ev.details || {};
    if (ev.event_type === 'REQUESTED') {
      const tool = details.tool_name || details.target || 'tool';
      const action = details.action || 'invocation';
      return `Agent requested ${action} on ${tool}`;
    }
    if (ev.event_type === 'ANALYZED') {
      const threats = details.threat_count !== undefined ? details.threat_count : 0;
      const score = details.risk_score !== undefined ? Number(details.risk_score).toFixed(1) : 'N/A';
      return `Security analysis completed: ${threats} threat signal(s), Risk Score ${score}/100`;
    }
    if (ev.event_type === 'ALLOWED') {
      return `Policy evaluation rendered verdict: ALLOW (Authorization granted for dispatch)`;
    }
    if (ev.event_type === 'BLOCKED') {
      const reason = details.reason ? `: ${details.reason}` : '';
      return `Terminal enforcement rendered verdict: BLOCK${reason}`;
    }
    if (ev.event_type === 'APPROVAL_REQUIRED') {
      return `Policy evaluation held invocation: REQUIRE_APPROVAL (Awaiting Human Reviewer)`;
    }
    if (ev.event_type === 'APPROVAL_APPROVED') {
      return `Authorized reviewer approved request execution for dispatch`;
    }
    if (ev.event_type === 'APPROVAL_REJECTED') {
      return `Authorized reviewer rejected request execution: invocation blocked`;
    }
    if (ev.event_type === 'EXECUTED') {
      const tool = details.tool_name || 'tool';
      const dur = details.duration_ms !== undefined ? `${Number(details.duration_ms).toFixed(1)}ms` : '';
      return `Sandbox execution completed successfully for ${tool} ${dur}`;
    }
    if (ev.event_type === 'FAILED') {
      const err = details.error ? `: ${details.error}` : '';
      return `Execution encountered contained runtime fault${err}`;
    }
    if (ev.event_type === 'DENIED') {
      return `Sandbox boundary denied execution: invocation blocked`;
    }
    if (ev.event_type === 'AUTHENTICATION_SUCCESS') {
      return `User session authenticated successfully`;
    }
    if (ev.event_type === 'AUTHENTICATION_FAILURE') {
      return `Authentication failed: invalid credentials rejected`;
    }
    if (ev.event_type === 'AUTHORIZATION_ALLOWED') {
      const perm = details.permission || 'permission';
      return `RBAC authorization check passed for ${perm}`;
    }
    if (ev.event_type === 'AUTHORIZATION_DENIED') {
      const perm = details.permission || 'permission';
      return `RBAC authorization denied for ${perm}`;
    }
    return `Security event recorded for correlation request`;
  };

  // Auth Required State
  if (authRequired) {
    return (
      <AuthRequiredState
        title="Audit Trail Telemetry Requires Authentication"
        message="The AgentShield security backend is healthy and reachable, but forensic audit logs require an authenticated session."
        onSignIn={onSignIn}
      />
    );
  }

  // Loading State
  if (loading && events.length === 0) {
    return (
      <LoadingState
        title="Synchronizing Audit Trail"
        message="Connecting to SecurityAuditTrail and retrieving immutable chronological forensic event records..."
        stage="Forensic Snapshot Retrieval"
      />
    );
  }

  return (
    <div className="space-y-6">
      {/* Header & Integrity Attestation */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/60 p-4 border border-slate-800 rounded-xl">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center text-indigo-400 shrink-0">
            <FileText className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h3 className="text-sm font-semibold text-white">
                Security Audit Trail &amp; Evidence Timeline
              </h3>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-950/60 border border-indigo-500/30 text-indigo-300">
                Stage 7 of 7: Forensic Verification
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Immutable chronological record of all security boundary events
            </p>
          </div>
        </div>

        {/* Integrity State & Refresh */}
        <div className="flex items-center gap-2 flex-wrap">
          {/* Integrity Attestation Pill */}
          <div
            className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-300"
            title="Durable append-only audit persistence. (Cryptographic chain verification is not exposed by current API)"
          >
            <Database className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
            <span className="text-slate-400">Storage:</span>
            <span className="text-emerald-400 font-semibold">PERSISTED</span>
            <span className="text-slate-600">&bull;</span>
            <span className="text-slate-400 text-[10px]">API verify unavail</span>
          </div>

          {onRefresh && (
            <button
              onClick={onRefresh}
              disabled={loading}
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 active:bg-slate-600 text-slate-200 rounded-lg border border-slate-700 text-xs font-semibold transition flex items-center gap-1.5 disabled:opacity-50"
              title="Refresh audit event stream"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              <span>Sync Audit</span>
            </button>
          )}
        </div>
      </div>

      {/* Quantified Metrics KPI Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <MotionCard className="p-3.5 bg-slate-900/50 border border-slate-800 rounded-xl">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium">Total Events</span>
            <Layers className="w-4 h-4 text-cyan-400 opacity-80" />
          </div>
          <div className="text-2xl font-bold font-mono text-white mt-1">{totalEvents}</div>
          <div className="text-[10px] font-mono text-slate-500 mt-0.5">Recorded in ledger</div>
        </MotionCard>

        <MotionCard className="p-3.5 bg-slate-900/50 border border-blue-500/20 rounded-xl">
          <div className="flex items-center justify-between text-blue-400">
            <span className="text-xs font-medium">Gateway Lifecycle</span>
            <Shield className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-blue-300 mt-1">{gatewayEventsCount}</div>
          <div className="text-[10px] font-mono text-blue-400/70 mt-0.5">Evaluations &amp; policies</div>
        </MotionCard>

        <MotionCard className="p-3.5 bg-slate-900/50 border border-emerald-500/20 rounded-xl">
          <div className="flex items-center justify-between text-emerald-400">
            <span className="text-xs font-medium">Executions</span>
            <Terminal className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-300 mt-1">{executionEventsCount}</div>
          <div className="text-[10px] font-mono text-emerald-400/70 mt-0.5">Runtime containment</div>
        </MotionCard>

        <MotionCard className="p-3.5 bg-slate-900/50 border border-amber-500/20 rounded-xl">
          <div className="flex items-center justify-between text-amber-400">
            <span className="text-xs font-medium">Approvals</span>
            <UserCheck className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-300 mt-1">{approvalEventsCount}</div>
          <div className="text-[10px] font-mono text-amber-400/70 mt-0.5">Human review actions</div>
        </MotionCard>

        <MotionCard className="p-3.5 bg-slate-900/50 border border-purple-500/20 rounded-xl">
          <div className="flex items-center justify-between text-purple-400">
            <span className="text-xs font-medium">Identity &amp; Auth</span>
            <Key className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-purple-300 mt-1">{identityEventsCount}</div>
          <div className="text-[10px] font-mono text-purple-400/70 mt-0.5">RBAC &amp; sessions</div>
        </MotionCard>

        <MotionCard className="p-3.5 bg-slate-900/50 border border-slate-800 rounded-xl col-span-2 sm:col-span-1">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium">Unique Actors</span>
            <User className="w-4 h-4 text-cyan-400 opacity-80" />
          </div>
          <div className="text-2xl font-bold font-mono text-white mt-1">{uniqueActorsCount}</div>
          <div className="text-[10px] font-mono text-slate-500 mt-0.5">Attributed identities</div>
        </MotionCard>
      </div>

      {/* Filter Toolbar */}
      <div className="p-4 bg-slate-900/70 border border-slate-800 rounded-xl space-y-3">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-300">
            <SlidersHorizontal className="w-3.5 h-3.5 text-cyan-400" />
            <span>Forensic Event Filters</span>
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
              placeholder="Search by Request ID, Actor..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              aria-label="Search audit events"
              className="w-full pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>

          {/* Category Select */}
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value as EventCategory)}
            aria-label="Filter by Event Category"
            className="w-full py-1.5 px-2.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Categories</option>
            <option value="GATEWAY">GATEWAY (Policy &amp; Decision)</option>
            <option value="EXECUTION">EXECUTION (Sandbox Runtime)</option>
            <option value="APPROVAL">APPROVAL (Human Review)</option>
            <option value="IDENTITY">IDENTITY (Auth &amp; RBAC)</option>
            <option value="SYSTEM">SYSTEM</option>
          </select>

          {/* Event Type Select */}
          <select
            value={eventTypeFilter}
            onChange={(e) => setEventTypeFilter(e.target.value)}
            aria-label="Filter by Event Type"
            className="w-full py-1.5 px-2.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Event Types</option>
            <option value="REQUESTED">REQUESTED</option>
            <option value="ANALYZED">ANALYZED</option>
            <option value="ALLOWED">ALLOWED</option>
            <option value="APPROVAL_REQUIRED">APPROVAL_REQUIRED</option>
            <option value="APPROVAL_APPROVED">APPROVAL_APPROVED</option>
            <option value="APPROVAL_REJECTED">APPROVAL_REJECTED</option>
            <option value="APPROVAL_EXPIRED">APPROVAL_EXPIRED</option>
            <option value="APPROVAL_CANCELLED">APPROVAL_CANCELLED</option>
            <option value="BLOCKED">BLOCKED</option>
            <option value="EXECUTED">EXECUTED</option>
            <option value="FAILED">FAILED</option>
            <option value="DENIED">DENIED</option>
            <option value="AUTHENTICATION_SUCCESS">AUTHENTICATION_SUCCESS</option>
            <option value="AUTHENTICATION_FAILURE">AUTHENTICATION_FAILURE</option>
            <option value="SESSION_CREATED">SESSION_CREATED</option>
            <option value="SESSION_REVOKED">SESSION_REVOKED</option>
            <option value="AUTHORIZATION_ALLOWED">AUTHORIZATION_ALLOWED</option>
            <option value="AUTHORIZATION_DENIED">AUTHORIZATION_DENIED</option>
            <option value="ROLE_CHANGE">ROLE_CHANGE</option>
            <option value="IDENTITY_DISABLED">IDENTITY_DISABLED</option>
            <option value="APPROVAL_AUTHORIZED">APPROVAL_AUTHORIZED</option>
            <option value="APPROVAL_AUTHORIZATION_DENIED">APPROVAL_AUTHORIZATION_DENIED</option>
          </select>

          {/* Actor Select */}
          <select
            value={actorFilter}
            onChange={(e) => setActorFilter(e.target.value)}
            aria-label="Filter by Actor"
            className="w-full py-1.5 px-2.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Actors ({availableActors.length})</option>
            {availableActors.map((act) => (
              <option key={act} value={act}>
                {act}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Events Timeline */}
      {filteredEvents.length === 0 ? (
        <EmptyState
          icon={FileText}
          title={hasActiveFilters ? 'No audit events matching filter' : 'No audit events recorded'}
          message={
            hasActiveFilters
              ? 'Try modifying or clearing your active investigation filters above.'
              : 'No security audit events have been recorded in this session.'
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
        <div className="relative pl-6 sm:pl-8 border-l-2 border-slate-800 space-y-4">
          <MotionList className="space-y-4">
            {filteredEvents.map((ev) => {
              const summary = getEventSummary(ev);

              return (
                <MotionItem key={ev.event_id}>
                  <div className="relative p-4 bg-slate-900/60 border border-slate-800 rounded-xl space-y-3 hover:border-slate-700 transition">
                    {/* Timeline Bullet Connector */}
                    <div className="absolute -left-[31px] sm:-left-[39px] top-5 w-3.5 h-3.5 rounded-full border-2 border-[#090d16] bg-cyan-500 shadow-[0_0_8px_rgba(6,182,212,0.4)]" />

                    {/* Top Row: Event Type, Actor, Timestamp */}
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/60 pb-2">
                      <div className="flex items-center gap-2 flex-wrap">
                        <EventTypeBadge type={ev.event_type} />
                        <span className="text-xs text-slate-300 font-mono flex items-center gap-1">
                          <User className="w-3 h-3 text-slate-500" />
                          <span>Actor: {ev.actor}</span>
                        </span>
                      </div>

                      <div className="text-xs text-slate-400 font-mono flex items-center gap-1.5">
                        <Clock className="w-3 h-3 text-slate-500" />
                        <span>{new Date(ev.timestamp).toLocaleTimeString()}</span>
                        <span className="text-slate-600">&bull;</span>
                        <span className="text-slate-500">{new Date(ev.timestamp).toLocaleDateString()}</span>
                      </div>
                    </div>

                    {/* Concise Narrative Summary */}
                    <div className="text-xs text-slate-200 font-medium leading-relaxed">
                      {summary}
                    </div>

                    {/* Sanitized Details JSON preview (if present) */}
                    {ev.details && Object.keys(ev.details).length > 0 && (
                      <div className="p-2.5 bg-slate-950/80 rounded-lg border border-slate-800/80 text-[11px] font-mono text-slate-300 space-y-1">
                        <div className="text-[10px] uppercase font-semibold text-slate-500 flex items-center justify-between">
                          <span>Forensic Event Context</span>
                          <span className="text-[10px] text-emerald-400/80">Sanitized</span>
                        </div>
                        <pre className="overflow-x-auto whitespace-pre-wrap max-h-32 text-[11px]">
                          {JSON.stringify(sanitizeTelemetryData(ev.details), null, 2)}
                        </pre>
                      </div>
                    )}

                    {/* Footer: Correlation IDs & Actions */}
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-[11px] text-slate-500 font-mono pt-1">
                      <div className="flex items-center gap-3 flex-wrap">
                        <span className="break-all">Correlation ID: {ev.request_id}</span>
                        <span>&bull;</span>
                        <span className="break-all">Event ID: {ev.event_id}</span>
                      </div>

                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => setSelectedEvent(ev)}
                          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-sans font-medium transition flex items-center gap-1.5 focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none"
                          aria-label={`Inspect event ${ev.event_id}`}
                        >
                          <Eye className="w-3.5 h-3.5 text-cyan-400" />
                          <span>Inspect</span>
                        </button>

                        {onSelectTab && ev.request_id && (
                          <button
                            onClick={() => onSelectTab('decisions', ev.request_id)}
                            className="px-2.5 py-1 rounded bg-cyan-950/40 hover:bg-cyan-900/60 border border-cyan-500/30 text-cyan-300 text-xs font-sans font-medium transition flex items-center gap-1 focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none"
                            title="Navigate to Security Decision for this request"
                          >
                            <span>Decision</span>
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
        </div>
      )}

      {/* Forensic Detail Drawer */}
      {selectedEvent && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="audit-drawer-title"
          className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 bg-black/80 backdrop-blur-sm"
        >
          <div className="relative w-full max-w-2xl bg-slate-900 border border-slate-700 rounded-2xl p-6 space-y-5 max-h-[90vh] overflow-y-auto shadow-2xl">
            {/* Drawer Header */}
            <div className="flex items-start justify-between gap-3 border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-lg bg-indigo-500/10 border border-indigo-500/30 text-indigo-400">
                  <Fingerprint className="w-5 h-5" />
                </div>
                <div>
                  <h3 id="audit-drawer-title" className="text-base font-bold text-white">
                    Forensic Audit Event Record
                  </h3>
                  <p className="text-xs text-slate-400">
                    Immutable chronological evidence and security context
                  </p>
                </div>
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none"
                aria-label="Close audit detail drawer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* IDENTITY SECTION */}
            <div className="space-y-2">
              <div className="text-[10px] font-mono uppercase font-bold text-slate-400 tracking-wider">
                Event Classification &amp; Identity
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
                <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800">
                  <div className="text-slate-500 text-[10px]">Event Type</div>
                  <div className="mt-1">
                    <EventTypeBadge type={selectedEvent.event_type} />
                  </div>
                </div>
                <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800">
                  <div className="text-slate-500 text-[10px]">Attributed Actor</div>
                  <div className="text-white font-bold mt-0.5">{selectedEvent.actor}</div>
                </div>
                <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800 sm:col-span-2">
                  <div className="text-slate-500 text-[10px]">Correlation / Request ID</div>
                  <div className="text-cyan-400 font-bold break-all">{selectedEvent.request_id}</div>
                </div>
                <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800 sm:col-span-2">
                  <div className="text-slate-500 text-[10px]">Audit Event ID</div>
                  <div className="text-slate-300 break-all">{selectedEvent.event_id}</div>
                </div>
              </div>
            </div>

            {/* TIMELINE & PERSISTENCE ATTESTATION */}
            <div className="space-y-2">
              <div className="text-[10px] font-mono uppercase font-bold text-slate-400 tracking-wider">
                Timeline &amp; Persistence Attestation
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
                <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800">
                  <div className="text-slate-500 text-[10px]">Recorded Timestamp (UTC)</div>
                  <div className="text-slate-200 mt-0.5">{selectedEvent.timestamp}</div>
                </div>
                <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800">
                  <div className="text-slate-500 text-[10px]">Local Representation</div>
                  <div className="text-slate-200 mt-0.5">
                    {new Date(selectedEvent.timestamp).toLocaleString()}
                  </div>
                </div>
                <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800 sm:col-span-2">
                  <div className="text-slate-500 text-[10px] flex items-center justify-between">
                    <span>Integrity &amp; Storage Guarantee</span>
                    <span className="text-emerald-400 font-semibold">PERSISTED</span>
                  </div>
                  <div className="text-slate-300 text-[11px] mt-1 leading-relaxed">
                    Durable append-only storage in SecurityAuditTrail database table (<code className="text-cyan-400">security_audit_events</code>). Cryptographic chain/hash verification is not exposed by the current API.
                  </div>
                </div>
              </div>
            </div>

            {/* NARRATIVE SUMMARY */}
            <div className="space-y-1 text-xs">
              <div className="text-[10px] font-mono uppercase font-bold text-slate-400 tracking-wider">
                Event Narrative
              </div>
              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-slate-200 leading-relaxed font-sans text-sm">
                {getEventSummary(selectedEvent)}
              </div>
            </div>

            {/* SANITIZED DETAILS */}
            {selectedEvent.details && Object.keys(selectedEvent.details).length > 0 && (
              <div className="space-y-1 text-xs">
                <div className="text-[10px] font-mono uppercase font-bold text-slate-400 tracking-wider">
                  Sanitized Event Payload
                </div>
                <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-[11px] font-mono max-h-48 overflow-y-auto">
                  <pre className="text-slate-300 whitespace-pre-wrap">
                    {JSON.stringify(sanitizeTelemetryData(selectedEvent.details), null, 2)}
                  </pre>
                </div>
              </div>
            )}

            {/* SANITIZED METADATA */}
            {selectedEvent.metadata && Object.keys(selectedEvent.metadata).length > 0 && (
              <div className="space-y-1 text-xs">
                <div className="text-[10px] font-mono uppercase font-bold text-slate-400 tracking-wider">
                  Sanitized Metadata
                </div>
                <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-[11px] font-mono max-h-48 overflow-y-auto">
                  <pre className="text-slate-300 whitespace-pre-wrap">
                    {JSON.stringify(sanitizeTelemetryData(selectedEvent.metadata), null, 2)}
                  </pre>
                </div>
              </div>
            )}

            {/* LIFECYCLE NAVIGATION */}
            {onSelectTab && selectedEvent.request_id && (
              <div className="space-y-2 pt-2 border-t border-slate-800">
                <div className="text-[10px] font-mono uppercase font-bold text-slate-400 tracking-wider">
                  Forensic Lifecycle Navigation
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <button
                    onClick={() => {
                      const reqId = selectedEvent.request_id;
                      setSelectedEvent(null);
                      onSelectTab('decisions', reqId);
                    }}
                    className="px-3 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold transition flex items-center gap-1.5 focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none"
                  >
                    <span>View Security Decision</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>

                  <button
                    onClick={() => {
                      const reqId = selectedEvent.request_id;
                      setSelectedEvent(null);
                      onSelectTab('executions', reqId);
                    }}
                    className="px-3 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold transition flex items-center gap-1.5 focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none"
                  >
                    <span>View Executions</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>

                  <button
                    onClick={() => {
                      const reqId = selectedEvent.request_id;
                      setSelectedEvent(null);
                      onSelectTab('threats', reqId);
                    }}
                    className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold transition border border-slate-700 flex items-center gap-1.5 focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none"
                  >
                    <span>View Threats</span>
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
