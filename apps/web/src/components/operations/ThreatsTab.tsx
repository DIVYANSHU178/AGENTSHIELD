import React, { useState } from 'react';
import { ThreatActivityItem } from '../../types';
import { SeverityBadge } from './OverviewTab';
import { ShieldAlert, Search, ShieldCheck } from 'lucide-react';

interface ThreatsTabProps {
  threats: ThreatActivityItem[];
}

export const ThreatsTab: React.FC<ThreatsTabProps> = ({ threats }) => {
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [typeFilter, setTypeFilter] = useState<string>('ALL');
  const [searchTerm, setSearchTerm] = useState<string>('');

  const filteredThreats = threats.filter((t) => {
    if (severityFilter !== 'ALL' && t.severity !== severityFilter) return false;
    if (typeFilter !== 'ALL' && t.threat_type !== typeFilter) return false;
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      return (
        t.title.toLowerCase().includes(term) ||
        t.description.toLowerCase().includes(term) ||
        t.request_id.toLowerCase().includes(term) ||
        t.detector.toLowerCase().includes(term)
      );
    }
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Header and Filter Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/60 p-4 border border-slate-800 rounded-xl">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-5 h-5 text-rose-400" />
          <div>
            <h3 className="text-sm font-semibold text-white">Threat Activity Stream</h3>
            <p className="text-xs text-slate-400">
              Deterministic threat signals with full credential & token redaction
            </p>
          </div>
        </div>

        {/* Filter Toolbar */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Search Box */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search threats..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          {/* Severity Select */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="py-1.5 px-2.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-blue-500"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
            <option value="INFO">INFO</option>
          </select>

          {/* Threat Type Select */}
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="py-1.5 px-2.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-blue-500"
          >
            <option value="ALL">All Threat Types</option>
            <option value="CREDENTIAL_ACCESS">CREDENTIAL_ACCESS</option>
            <option value="PROMPT_INJECTION">PROMPT_INJECTION</option>
            <option value="SENSITIVE_DATA_ACCESS">SENSITIVE_DATA_ACCESS</option>
            <option value="DATA_EXFILTRATION">DATA_EXFILTRATION</option>
            <option value="DANGEROUS_ACTION">DANGEROUS_ACTION</option>
            <option value="MALICIOUS_DESTINATION">MALICIOUS_DESTINATION</option>
          </select>
        </div>
      </div>

      {/* Threats Ledger */}
      {filteredThreats.length === 0 ? (
        <div className="p-12 text-center text-slate-400 bg-slate-900/40 border border-slate-800 rounded-xl space-y-2">
          <ShieldCheck className="w-10 h-10 mx-auto text-emerald-500/80" />
          <h4 className="text-sm font-semibold text-slate-200">No threats matching filter</h4>
          <p className="text-xs text-slate-500">
            All agent interactions are currently clean or filtered out.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {filteredThreats.map((threat) => (
            <div
              key={threat.threat_id}
              className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl space-y-3 hover:border-slate-700 transition"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/60 pb-2">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-sm font-bold text-white">
                    {threat.threat_type}
                  </span>
                  <SeverityBadge severity={threat.severity} />
                  <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                    {threat.detector}
                  </span>
                </div>
                <div className="text-xs text-slate-400 font-mono">
                  Confidence: {(threat.confidence * 100).toFixed(0)}% &bull;{' '}
                  {new Date(threat.timestamp).toLocaleTimeString()}
                </div>
              </div>

              <div className="space-y-1 text-xs">
                <div className="font-medium text-slate-200">{threat.title}</div>
                <p className="text-slate-400">{threat.description}</p>
              </div>

              {/* Sanitized Evidence & Metadata Inspection */}
              {threat.metadata && Object.keys(threat.metadata).length > 0 && (
                <div className="p-2.5 bg-slate-950/80 rounded-lg border border-slate-800/80 text-[11px] font-mono text-slate-400 space-y-1">
                  <div className="text-[10px] uppercase font-semibold text-slate-500">
                    Sanitized Evidence & Signals
                  </div>
                  <pre className="overflow-x-auto text-slate-300 whitespace-pre-wrap">
                    {JSON.stringify(threat.metadata, null, 2)}
                  </pre>
                </div>
              )}

              <div className="flex items-center justify-between text-[11px] text-slate-500 font-mono pt-1">
                <span>Correlation ID: {threat.request_id}</span>
                <span>Threat ID: {threat.threat_id.slice(0, 8)}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
