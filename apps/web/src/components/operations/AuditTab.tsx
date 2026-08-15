import React, { useState } from 'react';
import { SecurityEvent, EventType } from '../../types';
import { FileText, Search } from 'lucide-react';

interface AuditTabProps {
  events: SecurityEvent[];
}

export const AuditTab: React.FC<AuditTabProps> = ({ events }) => {
  const [eventTypeFilter, setEventTypeFilter] = useState<string>('ALL');
  const [searchTerm, setSearchTerm] = useState<string>('');

  const filteredEvents = events.filter((ev) => {
    if (eventTypeFilter !== 'ALL' && ev.event_type !== eventTypeFilter) return false;
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      return (
        ev.request_id.toLowerCase().includes(term) ||
        ev.actor.toLowerCase().includes(term) ||
        JSON.stringify(ev.details || {}).toLowerCase().includes(term)
      );
    }
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Header & Filter Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/60 p-4 border border-slate-800 rounded-xl">
        <div className="flex items-center gap-2">
          <FileText className="w-5 h-5 text-blue-400" />
          <div>
            <h3 className="text-sm font-semibold text-white">Security Audit Trail &amp; Evidence Timeline</h3>
            <p className="text-xs text-slate-400">
              Immutable chronological record of all security boundary events
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search by Request ID, Actor..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          <select
            value={eventTypeFilter}
            onChange={(e) => setEventTypeFilter(e.target.value)}
            className="py-1.5 px-2.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-blue-500"
          >
            <option value="ALL">All Event Types</option>
            <option value="REQUESTED">REQUESTED</option>
            <option value="ANALYZED">ANALYZED</option>
            <option value="ALLOWED">ALLOWED</option>
            <option value="APPROVAL_REQUIRED">APPROVAL_REQUIRED</option>
            <option value="BLOCKED">BLOCKED</option>
            <option value="EXECUTED">EXECUTED</option>
            <option value="FAILED">FAILED</option>
          </select>
        </div>
      </div>

      {/* Events Timeline */}
      {filteredEvents.length === 0 ? (
        <div className="p-12 text-center text-slate-400 bg-slate-900/40 border border-slate-800 rounded-xl space-y-2">
          <FileText className="w-10 h-10 mx-auto text-slate-600" />
          <h4 className="text-sm font-semibold text-slate-200">No audit events recorded</h4>
          <p className="text-xs text-slate-500">
            No security audit events match the current filter.
          </p>
        </div>
      ) : (
        <div className="relative pl-6 border-l-2 border-slate-800 space-y-4">
          {filteredEvents.map((ev) => (
            <div
              key={ev.event_id}
              className="relative p-4 bg-slate-900/60 border border-slate-800 rounded-xl space-y-3 hover:border-slate-700 transition"
            >
              {/* Timeline Bullet */}
              <div className="absolute -left-[31px] top-4 w-3.5 h-3.5 rounded-full border-2 border-slate-900 bg-blue-500" />

              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/60 pb-2">
                <div className="flex items-center gap-2">
                  <EventTypeBadge type={ev.event_type} />
                  <span className="text-xs text-slate-300 font-mono">Actor: {ev.actor}</span>
                </div>
                <div className="text-xs text-slate-400 font-mono">
                  {new Date(ev.timestamp).toLocaleTimeString()} &bull;{' '}
                  <span className="text-slate-500">{new Date(ev.timestamp).toLocaleDateString()}</span>
                </div>
              </div>

              {/* Event Details */}
              {ev.details && Object.keys(ev.details).length > 0 && (
                <div className="p-2.5 bg-slate-950/80 rounded-lg border border-slate-800/80 text-[11px] font-mono text-slate-300">
                  <pre className="overflow-x-auto whitespace-pre-wrap">
                    {JSON.stringify(ev.details, null, 2)}
                  </pre>
                </div>
              )}

              <div className="flex items-center justify-between text-[11px] text-slate-500 font-mono pt-1">
                <span>Correlation ID: {ev.request_id}</span>
                <span>Event ID: {ev.event_id.slice(0, 8)}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export const EventTypeBadge: React.FC<{ type: EventType }> = ({ type }) => {
  const styles: Record<EventType, string> = {
    REQUESTED: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
    ANALYZED: 'bg-indigo-500/10 text-indigo-400 border-indigo-500/30',
    ALLOWED: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
    APPROVAL_REQUIRED: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
    BLOCKED: 'bg-rose-500/10 text-rose-400 border-rose-500/30 font-bold',
    EXECUTED: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
    FAILED: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
  };

  return (
    <span className={`px-2.5 py-0.5 text-[10px] font-mono rounded border ${styles[type] || styles.REQUESTED}`}>
      {type}
    </span>
  );
};
