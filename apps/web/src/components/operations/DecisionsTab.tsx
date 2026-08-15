import React, { useState } from 'react';
import { SecurityDecisionItem } from '../../types';
import { DecisionBadge, SeverityBadge } from './OverviewTab';
import { Shield, CheckCircle2, Clock, Ban, Search } from 'lucide-react';

interface DecisionsTabProps {
  decisions: SecurityDecisionItem[];
}

export const DecisionsTab: React.FC<DecisionsTabProps> = ({ decisions }) => {
  const [decisionFilter, setDecisionFilter] = useState<string>('ALL');
  const [searchTerm, setSearchTerm] = useState<string>('');

  const filteredDecisions = decisions.filter((d) => {
    if (decisionFilter !== 'ALL' && d.decision !== decisionFilter) return false;
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      return (
        d.reason.toLowerCase().includes(term) ||
        d.policy_id.toLowerCase().includes(term) ||
        d.request_id.toLowerCase().includes(term)
      );
    }
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Header & Filter Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/60 p-4 border border-slate-800 rounded-xl">
        <div className="flex items-center gap-2">
          <Shield className="w-5 h-5 text-blue-400" />
          <div>
            <h3 className="text-sm font-semibold text-white">Security Decisions Ledger</h3>
            <p className="text-xs text-slate-400">
              Deterministic Phase 4/5 policy decisions &amp; risk evaluations
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search decisions..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          <select
            value={decisionFilter}
            onChange={(e) => setDecisionFilter(e.target.value)}
            className="py-1.5 px-2.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-blue-500"
          >
            <option value="ALL">All Decisions</option>
            <option value="ALLOW">ALLOW</option>
            <option value="REQUIRE_APPROVAL">REQUIRE_APPROVAL</option>
            <option value="BLOCK">BLOCK</option>
          </select>
        </div>
      </div>

      {/* Decisions List */}
      {filteredDecisions.length === 0 ? (
        <div className="p-12 text-center text-slate-400 bg-slate-900/40 border border-slate-800 rounded-xl space-y-2">
          <Shield className="w-10 h-10 mx-auto text-slate-600" />
          <h4 className="text-sm font-semibold text-slate-200">No decisions recorded</h4>
          <p className="text-xs text-slate-500">
            No policy evaluation decisions match the selected criteria.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {filteredDecisions.map((dec) => (
            <div
              key={dec.decision_id}
              className={`p-5 rounded-xl border space-y-4 transition ${
                dec.decision === 'ALLOW'
                  ? 'bg-slate-900/60 border-slate-800 hover:border-emerald-500/30'
                  : dec.decision === 'REQUIRE_APPROVAL'
                  ? 'bg-amber-950/10 border-amber-500/20 hover:border-amber-500/40'
                  : 'bg-rose-950/10 border-rose-500/20 hover:border-rose-500/40'
              }`}
            >
              {/* Decision Header */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/60 pb-3">
                <div className="flex items-center gap-2.5">
                  <DecisionBadge decision={dec.decision} />
                  <SeverityBadge severity={dec.severity} />
                  <span className="text-xs px-2.5 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                    Policy: {dec.policy_id}
                  </span>
                </div>
                <div className="text-xs text-slate-400 font-mono">
                  Risk Score: <span className="text-white font-bold">{dec.risk_score.toFixed(1)}/100</span> &bull;{' '}
                  {new Date(dec.timestamp).toLocaleTimeString()}
                </div>
              </div>

              {/* Rationale */}
              <div className="space-y-1 text-xs">
                <div className="text-slate-400 font-medium">Policy Rationale:</div>
                <p className="text-slate-200 text-sm">{dec.reason}</p>
              </div>

              {/* REQUIRE_APPROVAL Status Banner (Strict Phase 10 / Phase 11 Invariant) */}
              {dec.decision === 'REQUIRE_APPROVAL' && (
                <div className="p-3 bg-amber-950/30 border border-amber-500/30 rounded-lg flex items-center justify-between gap-3 text-xs text-amber-300">
                  <div className="flex items-center gap-2">
                    <Clock className="w-4 h-4 text-amber-400 flex-shrink-0 animate-pulse" />
                    <div>
                      <span className="font-semibold">Status:</span> Awaiting Approval Workflow (Phase 11) &bull;{' '}
                      <span className="text-amber-400 font-mono">Execution: NOT STARTED</span>
                    </div>
                  </div>
                  <span className="text-[11px] px-2 py-0.5 rounded bg-amber-500/10 border border-amber-500/20 text-amber-400">
                    Phase 10 Read-Only Observer
                  </span>
                </div>
              )}

              {/* BLOCK Status Banner (Strict Terminal Invariant) */}
              {dec.decision === 'BLOCK' && (
                <div className="p-3 bg-rose-950/30 border border-rose-500/30 rounded-lg flex items-center justify-between gap-3 text-xs text-rose-300">
                  <div className="flex items-center gap-2">
                    <Ban className="w-4 h-4 text-rose-400 flex-shrink-0" />
                    <div>
                      <span className="font-semibold">Status:</span> TERMINAL - BLOCK &bull;{' '}
                      <span className="text-rose-400 font-mono">Execution: NOT STARTED &bull; Authorization: NOT ISSUED</span>
                    </div>
                  </div>
                  <span className="text-[11px] px-2 py-0.5 rounded bg-rose-500/10 border border-rose-500/20 text-rose-400">
                    Zero Override Allowed
                  </span>
                </div>
              )}

              {/* ALLOW Status Banner */}
              {dec.decision === 'ALLOW' && (
                <div className="p-2.5 bg-emerald-950/20 border border-emerald-500/20 rounded-lg flex items-center gap-2 text-xs text-emerald-300">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                  <span>Enforcement Authorization Granted &bull; Dispatched to Sandbox Boundary</span>
                </div>
              )}

              {/* Footer Identifiers */}
              <div className="flex items-center justify-between text-[11px] text-slate-500 font-mono pt-1">
                <span>Correlation ID: {dec.request_id}</span>
                <span>Decision ID: {dec.decision_id.slice(0, 8)}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
