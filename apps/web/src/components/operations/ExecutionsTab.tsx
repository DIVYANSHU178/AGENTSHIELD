import React, { useState } from 'react';
import { ExecutionActivityItem } from '../../types';
import { ExecutionStatusBadge } from './OverviewTab';
import { Terminal, CheckCircle2, Search } from 'lucide-react';

interface ExecutionsTabProps {
  executions: ExecutionActivityItem[];
}

export const ExecutionsTab: React.FC<ExecutionsTabProps> = ({ executions }) => {
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [searchTerm, setSearchTerm] = useState<string>('');

  const filteredExecutions = executions.filter((e) => {
    if (statusFilter !== 'ALL' && e.status !== statusFilter) return false;
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      return (
        e.tool_name.toLowerCase().includes(term) ||
        e.request_id.toLowerCase().includes(term) ||
        e.tool_category.toLowerCase().includes(term) ||
        (e.error && e.error.toLowerCase().includes(term))
      );
    }
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Header & Filter Toolbar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/60 p-4 border border-slate-800 rounded-xl">
        <div className="flex items-center gap-2">
          <Terminal className="w-5 h-5 text-emerald-400" />
          <div>
            <h3 className="text-sm font-semibold text-white">Sandbox Execution Activity</h3>
            <p className="text-xs text-slate-400">
              Bounded runtime execution containment outcomes &amp; metrics
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search tool executions..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="py-1.5 px-2.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-blue-500"
          >
            <option value="ALL">All Outcomes</option>
            <option value="COMPLETED">COMPLETED</option>
            <option value="DENIED">DENIED</option>
            <option value="TIMED_OUT">TIMED_OUT</option>
            <option value="FAILED">FAILED</option>
          </select>
        </div>
      </div>

      {/* Execution Cards */}
      {filteredExecutions.length === 0 ? (
        <div className="p-12 text-center text-slate-400 bg-slate-900/40 border border-slate-800 rounded-xl space-y-2">
          <Terminal className="w-10 h-10 mx-auto text-slate-600" />
          <h4 className="text-sm font-semibold text-slate-200">No executions recorded</h4>
          <p className="text-xs text-slate-500">
            No sandboxed tool executions match the current filter.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {filteredExecutions.map((exec) => (
            <div
              key={exec.execution_id}
              className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl space-y-3 hover:border-slate-700 transition"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/60 pb-2">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-sm font-bold text-white">{exec.tool_name}</span>
                  <ExecutionStatusBadge status={exec.status} />
                  <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                    {exec.action} ({exec.tool_category})
                  </span>
                </div>
                <div className="text-xs text-slate-400 font-mono">
                  Duration: <span className="text-white font-semibold">{exec.duration_ms.toFixed(2)} ms</span> &bull;{' '}
                  {new Date(exec.timestamp).toLocaleTimeString()}
                </div>
              </div>

              {/* Execution Status / Error Container */}
              {exec.error ? (
                <div className="p-3 bg-rose-950/20 border border-rose-500/20 rounded-lg text-xs text-rose-300 font-mono space-y-1">
                  <div className="text-[10px] uppercase font-bold text-rose-400">
                    Contained Fault / Error
                  </div>
                  <div>{exec.error}</div>
                </div>
              ) : (
                <div className="p-2.5 bg-emerald-950/20 border border-emerald-500/20 rounded-lg text-xs text-emerald-300 flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                  <span>Sandbox Tool Execution Successful within containment limits</span>
                </div>
              )}

              {/* Metadata */}
              {exec.metadata && Object.keys(exec.metadata).length > 0 && (
                <div className="flex flex-wrap gap-2 text-[11px] text-slate-400 font-mono">
                  {Object.entries(exec.metadata).map(([k, v]) => (
                    <span key={k} className="px-2 py-0.5 bg-slate-950 rounded border border-slate-800">
                      {k}: {String(v)}
                    </span>
                  ))}
                </div>
              )}

              <div className="flex items-center justify-between text-[11px] text-slate-500 font-mono pt-1">
                <span>Correlation ID: {exec.request_id}</span>
                <span>Exec ID: {exec.execution_id.slice(0, 8)}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
