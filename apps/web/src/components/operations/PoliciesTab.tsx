import React, { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../../context/AuthContext';
import { fetchPolicies, createPolicy, deletePolicy } from '../../lib/api';
import {
  Sliders,
  Plus,
  ShieldCheck,
  CheckCircle2,
  AlertCircle,
  Loader2,
  RefreshCw,
} from 'lucide-react';

interface PolicyItem {
  policy_id: string;
  name: string;
  description: string;
  rule_type: string;
  priority: number;
  conditions: Record<string, any>;
  action: 'BLOCK' | 'REQUIRE_APPROVAL' | 'ALLOW';
  is_enabled: boolean;
  created_at: string;
}

export const PoliciesTab: React.FC = () => {
  const { canManageIdentities } = useAuth();
  const isAdmin = canManageIdentities; // Admin privileges

  const [policies, setPolicies] = useState<PolicyItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  // Create Policy Modal State
  const [showCreateModal, setShowCreateModal] = useState<boolean>(false);
  const [policyId, setPolicyId] = useState<string>('');
  const [name, setName] = useState<string>('');
  const [description, setDescription] = useState<string>('');
  const [ruleType] = useState<string>('custom_rule');
  const [priority, setPriority] = useState<number>(60);
  const [action, setAction] = useState<'BLOCK' | 'REQUIRE_APPROVAL' | 'ALLOW'>('REQUIRE_APPROVAL');
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);

  const loadPolicies = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchPolicies();
      setPolicies(data);
    } catch (err: any) {
      setError(err?.message || 'Failed to load security policies.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadPolicies();
  }, [loadPolicies]);

  const handleCreatePolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!policyId.trim() || !name.trim()) {
      setError('Policy ID and Name are required.');
      return;
    }
    setIsSubmitting(true);
    setError(null);
    try {
      await createPolicy({
        policy_id: policyId.trim(),
        name: name.trim(),
        description: description.trim(),
        rule_type: ruleType,
        priority: Number(priority),
        action,
        is_enabled: true,
      });
      setActionSuccess(`Policy '${name.trim()}' created successfully.`);
      setShowCreateModal(false);
      setPolicyId('');
      setName('');
      setDescription('');
      loadPolicies();
    } catch (err: any) {
      setError(err?.message || 'Failed to create policy.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDeletePolicy = async (targetId: string, targetName: string) => {
    if (!confirm(`Are you sure you want to disable policy '${targetName}'?`)) return;
    try {
      await deletePolicy(targetId);
      setActionSuccess(`Policy '${targetName}' has been disabled.`);
      loadPolicies();
    } catch (err: any) {
      setError(err?.message || 'Failed to disable policy.');
    }
  };

  return (
    <div className="space-y-6" data-testid="policies-tab">
      {/* Console Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 bg-slate-900/60 border border-slate-800 rounded-2xl">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-cyan-500/10 border border-cyan-500/20 rounded-xl text-cyan-400">
            <Sliders className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-white tracking-tight">Security Policy Governance</h1>
            <p className="text-xs text-slate-400">
              Authoritative security enforcement policies evaluated in strict priority order (highest to lowest).
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={loadPolicies}
            disabled={loading}
            className="p-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-mono transition flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
            title="Refresh policies"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Sync</span>
          </button>

          {isAdmin && (
            <button
              onClick={() => setShowCreateModal(true)}
              className="py-2 px-3.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold shadow-lg shadow-blue-500/20 transition flex items-center gap-1.5 cursor-pointer"
            >
              <Plus className="w-4 h-4" />
              <span>New Policy</span>
            </button>
          )}
        </div>
      </div>

      {/* Fail-Closed Architectural Invariant Banner */}
      <div className="p-4 bg-slate-900/80 border border-cyan-500/30 rounded-2xl flex items-start gap-3 shadow-[0_0_15px_rgba(6,182,212,0.08)]">
        <ShieldCheck className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <div className="text-xs font-bold text-white tracking-wide uppercase font-mono">
            Fail-Closed Security Architecture (SEC-05 Active)
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            Every autonomous agent action is evaluated sequentially down the policy priority chain. Any action not explicitly matched and approved by an authorized capability policy is blocked at Priority 0 (<code className="text-cyan-300">policy.default.deny</code>).
          </p>
        </div>
      </div>

      {/* Alert Notices */}
      {actionSuccess && (
        <div className="p-3.5 bg-emerald-950/30 border border-emerald-500/40 rounded-xl text-emerald-200 text-xs flex items-center justify-between">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <span>{actionSuccess}</span>
          </div>
          <button onClick={() => setActionSuccess(null)} className="text-slate-400 hover:text-slate-200 text-xs">Dismiss</button>
        </div>
      )}

      {error && (
        <div className="p-3.5 bg-rose-950/30 border border-rose-500/40 rounded-xl text-rose-200 text-xs flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-rose-400" />
            <span>{error}</span>
          </div>
          <button onClick={() => setError(null)} className="text-slate-400 hover:text-slate-200 text-xs">Dismiss</button>
        </div>
      )}

      {/* Policy Pipeline List */}
      <div className="space-y-3">
        {loading && policies.length === 0 ? (
          <div className="p-12 text-center text-slate-500 flex flex-col items-center gap-3 bg-[#0d131f] border border-slate-800 rounded-2xl">
            <Loader2 className="w-6 h-6 animate-spin text-cyan-400" />
            <span className="text-xs font-mono">Loading active policy registry...</span>
          </div>
        ) : (
          policies.map((p) => {
            const isDefaultDeny = p.policy_id === 'policy.default.deny';
            return (
              <div
                key={p.policy_id}
                className={`p-4 rounded-2xl border transition ${
                  isDefaultDeny
                    ? 'bg-rose-950/10 border-rose-500/30 hover:border-rose-500/50'
                    : 'bg-[#0d131f] border-slate-800 hover:border-slate-700'
                } flex flex-col sm:flex-row sm:items-center justify-between gap-4`}
              >
                <div className="flex items-start gap-3.5">
                  <div className="flex flex-col items-center justify-center p-2 rounded-xl bg-slate-900 border border-slate-800 min-w-[54px]">
                    <span className="text-[9px] font-mono text-slate-400 uppercase">PRIORITY</span>
                    <span className="text-sm font-mono font-bold text-cyan-400">{p.priority}</span>
                  </div>

                  <div className="space-y-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm font-semibold text-white">{p.name}</span>
                      <span className="text-[10px] font-mono text-slate-400 bg-slate-800/80 px-2 py-0.5 rounded">
                        {p.policy_id}
                      </span>
                      {isDefaultDeny && (
                        <span className="text-[10px] font-mono font-bold text-rose-400 bg-rose-950/40 border border-rose-500/30 px-2 py-0.5 rounded">
                          FAIL-CLOSED CATCH-ALL
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-slate-400 leading-relaxed">{p.description}</p>
                    {p.conditions && Object.keys(p.conditions).length > 0 && (
                      <div className="text-[11px] font-mono text-slate-400 pt-0.5">
                        Conditions: <span className="text-slate-300">{JSON.stringify(p.conditions)}</span>
                      </div>
                    )}
                  </div>
                </div>

                <div className="flex items-center gap-3 self-end sm:self-center">
                  <span
                    className={`px-2.5 py-1 rounded-full text-[10px] font-mono font-bold tracking-wider uppercase border ${
                      p.action === 'BLOCK'
                        ? 'bg-rose-950/40 text-rose-300 border-rose-500/30'
                        : p.action === 'REQUIRE_APPROVAL'
                        ? 'bg-purple-950/40 text-purple-300 border-purple-500/30'
                        : 'bg-emerald-950/40 text-emerald-300 border-emerald-500/30'
                    }`}
                  >
                    {p.action}
                  </span>

                  {p.is_enabled ? (
                    <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/30 border border-emerald-500/20 px-2 py-0.5 rounded">
                      ACTIVE
                    </span>
                  ) : (
                    <span className="text-[10px] font-mono text-slate-500 bg-slate-900 border border-slate-800 px-2 py-0.5 rounded">
                      DISABLED
                    </span>
                  )}

                  {isAdmin && !isDefaultDeny && p.is_enabled && (
                    <button
                      onClick={() => handleDeletePolicy(p.policy_id, p.name)}
                      className="text-rose-400 hover:text-rose-300 text-[11px] font-mono px-2 py-1 rounded bg-rose-950/20 border border-rose-500/20 hover:border-rose-500/40 transition cursor-pointer"
                    >
                      Disable
                    </button>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Create Policy Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="bg-[#0d131f] border border-slate-800 rounded-2xl p-6 w-full max-w-md space-y-4 shadow-2xl">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Plus className="w-5 h-5 text-cyan-400" />
              <span>Define Security Policy</span>
            </h3>

            <form onSubmit={handleCreatePolicy} className="space-y-3">
              <div>
                <label className="block text-[11px] font-mono text-slate-400 uppercase mb-1">Policy Identifier</label>
                <input
                  type="text"
                  value={policyId}
                  onChange={(e) => setPolicyId(e.target.value)}
                  placeholder="e.g. policy.custom.network_restriction"
                  required
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-100 focus:border-cyan-500 focus:outline-none font-mono"
                />
              </div>

              <div>
                <label className="block text-[11px] font-mono text-slate-400 uppercase mb-1">Policy Name</label>
                <input
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g. Restrict High-Volume Network Egress"
                  required
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-100 focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-[11px] font-mono text-slate-400 uppercase mb-1">Description</label>
                <textarea
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Operational rule rationale and constraints..."
                  rows={2}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-100 focus:border-cyan-500 focus:outline-none resize-none"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-[11px] font-mono text-slate-400 uppercase mb-1">Priority (0-100)</label>
                  <input
                    type="number"
                    min="1"
                    max="99"
                    value={priority}
                    onChange={(e) => setPriority(Number(e.target.value))}
                    required
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-100 focus:border-cyan-500 focus:outline-none font-mono"
                  />
                </div>

                <div>
                  <label className="block text-[11px] font-mono text-slate-400 uppercase mb-1">Action Decision</label>
                  <select
                    value={action}
                    onChange={(e) => setAction(e.target.value as any)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-100 focus:border-cyan-500 focus:outline-none font-mono"
                  >
                    <option value="REQUIRE_APPROVAL">REQUIRE_APPROVAL</option>
                    <option value="BLOCK">BLOCK</option>
                    <option value="ALLOW">ALLOW</option>
                  </select>
                </div>
              </div>

              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="py-2 px-4 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-semibold"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="py-2 px-4 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold flex items-center gap-1.5"
                >
                  {isSubmitting && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                  <span>Save Policy</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
