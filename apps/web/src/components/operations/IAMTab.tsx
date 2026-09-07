import React, { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../../context/AuthContext';
import { UserIdentity, Role } from '../../types';
import { fetchIdentities, createIdentity, disableIdentity, updateIdentityRoles } from '../../lib/api';
import {
  Users,
  UserPlus,
  CheckCircle2,
  XCircle,
  AlertCircle,
  Loader2,
  RefreshCw,
  Lock,
} from 'lucide-react';

export const IAMTab: React.FC = () => {
  const { canManageIdentities, user: currentUser } = useAuth();
  const [identities, setIdentities] = useState<UserIdentity[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  // Create User Form Modal State
  const [showCreateModal, setShowCreateModal] = useState<boolean>(false);
  const [newUsername, setNewUsername] = useState<string>('');
  const [newDisplayName, setNewDisplayName] = useState<string>('');
  const [newPassword, setNewPassword] = useState<string>('');
  const [newRole, setNewRole] = useState<Role>(Role.OPERATOR);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);

  const loadUsers = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchIdentities();
      setIdentities(data);
    } catch (err: any) {
      setError(err?.message || 'Failed to load user identities.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadUsers();
  }, [loadUsers]);

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newUsername.trim() || !newPassword || !newDisplayName.trim()) {
      setError('All fields are required.');
      return;
    }
    setIsSubmitting(true);
    setError(null);
    try {
      await createIdentity({
        username: newUsername.trim(),
        display_name: newDisplayName.trim(),
        password: newPassword,
        roles: [newRole],
        is_active: true,
      });
      setActionSuccess(`User '${newUsername.trim()}' created successfully.`);
      setShowCreateModal(false);
      setNewUsername('');
      setNewDisplayName('');
      setNewPassword('');
      loadUsers();
    } catch (err: any) {
      setError(err?.message || 'Failed to create user identity.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDisableUser = async (userId: string, username: string) => {
    if (!confirm(`Are you sure you want to disable operator '${username}'?`)) return;
    try {
      await disableIdentity(userId);
      setActionSuccess(`User '${username}' has been deactivated.`);
      loadUsers();
    } catch (err: any) {
      setError(err?.message || 'Failed to disable user identity.');
    }
  };

  const handleRoleChange = async (userId: string, targetRole: Role) => {
    try {
      await updateIdentityRoles(userId, [targetRole]);
      setActionSuccess(`Role updated to ${targetRole} for user.`);
      loadUsers();
    } catch (err: any) {
      setError(err?.message || 'Failed to update roles.');
    }
  };

  return (
    <div className="space-y-6" data-testid="iam-tab">
      {/* Console Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 bg-slate-900/60 border border-slate-800 rounded-2xl">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-blue-500/10 border border-blue-500/20 rounded-xl text-blue-400">
            <Users className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-white tracking-tight">Identity &amp; Access Management (IAM)</h1>
            <p className="text-xs text-slate-400">
              Authoritative operator identities, RBAC role assignments, and authentication governance.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={loadUsers}
            disabled={loading}
            className="p-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-mono transition flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
            title="Refresh identities"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Sync</span>
          </button>

          {canManageIdentities && (
            <button
              onClick={() => setShowCreateModal(true)}
              className="py-2 px-3.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold shadow-lg shadow-blue-500/20 transition flex items-center gap-1.5 cursor-pointer"
            >
              <UserPlus className="w-4 h-4" />
              <span>Create Identity</span>
            </button>
          )}
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

      {!canManageIdentities && (
        <div className="p-3.5 bg-amber-950/30 border border-amber-500/30 rounded-xl text-amber-200 text-xs flex items-center gap-2">
          <Lock className="w-4 h-4 text-amber-400" />
          <span>Read-Only Mode: Your identity does not possess the <code>MANAGE_IDENTITIES</code> permission required to modify operator credentials.</span>
        </div>
      )}

      {/* Users Table */}
      <div className="bg-[#0d131f] border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <h2 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider">
            Registered Identities ({identities.length})
          </h2>
          <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/40 border border-cyan-500/20 px-2 py-0.5 rounded">
            RBAC AUTHORITATIVE
          </span>
        </div>

        {loading && identities.length === 0 ? (
          <div className="p-12 text-center text-slate-500 flex flex-col items-center gap-3">
            <Loader2 className="w-6 h-6 animate-spin text-cyan-400" />
            <span className="text-xs font-mono">Loading identities from database...</span>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-900/60 text-[10px] font-mono text-slate-400 uppercase tracking-wider border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">Operator</th>
                  <th className="py-3 px-4">User ID</th>
                  <th className="py-3 px-4">Roles</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Created</th>
                  {canManageIdentities && <th className="py-3 px-4 text-right">Actions</th>}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-sans">
                {identities.map((u) => {
                  const isCurrent = currentUser?.user_id === u.user_id;
                  return (
                    <tr key={u.user_id} className="hover:bg-slate-800/30 transition">
                      <td className="py-3 px-4">
                        <div className="font-semibold text-white flex items-center gap-2">
                          <span>{u.display_name}</span>
                          {isCurrent && (
                            <span className="text-[9px] font-mono text-cyan-400 bg-cyan-950/40 border border-cyan-500/30 px-1.5 py-0.5 rounded">
                              YOU
                            </span>
                          )}
                        </div>
                        <div className="text-[11px] font-mono text-slate-400">{u.username}</div>
                      </td>
                      <td className="py-3 px-4 font-mono text-[11px] text-slate-400">{u.user_id}</td>
                      <td className="py-3 px-4">
                        <div className="flex flex-wrap gap-1">
                          {u.roles.map((r) => (
                            <span
                              key={r}
                              className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold tracking-wider ${
                                r === Role.ADMIN
                                  ? 'bg-rose-950/40 text-rose-300 border border-rose-500/30'
                                  : r === Role.SECURITY_REVIEWER
                                  ? 'bg-purple-950/40 text-purple-300 border border-purple-500/30'
                                  : r === Role.OPERATOR
                                  ? 'bg-blue-950/40 text-blue-300 border border-blue-500/30'
                                  : 'bg-slate-800 text-slate-300 border border-slate-700'
                              }`}
                            >
                              {r}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        {u.is_active ? (
                          <span className="inline-flex items-center gap-1.5 text-[11px] text-emerald-400 font-mono">
                            <CheckCircle2 className="w-3.5 h-3.5" />
                            <span>ACTIVE</span>
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1.5 text-[11px] text-rose-400 font-mono">
                            <XCircle className="w-3.5 h-3.5" />
                            <span>DISABLED</span>
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4 font-mono text-[11px] text-slate-400">
                        {u.created_at ? new Date(u.created_at).toLocaleDateString() : '—'}
                      </td>
                      {canManageIdentities && (
                        <td className="py-3 px-4 text-right space-x-2">
                          <select
                            value={u.roles[0] || Role.VIEWER}
                            onChange={(e) => handleRoleChange(u.user_id, e.target.value as Role)}
                            disabled={isCurrent}
                            className="bg-slate-900 border border-slate-700 text-slate-200 text-[11px] font-mono rounded px-2 py-1 focus:outline-none focus:border-cyan-500 disabled:opacity-40"
                          >
                            <option value={Role.VIEWER}>VIEWER</option>
                            <option value={Role.OPERATOR}>OPERATOR</option>
                            <option value={Role.SECURITY_REVIEWER}>SECURITY_REVIEWER</option>
                            <option value={Role.ADMIN}>ADMIN</option>
                          </select>
                          {u.is_active && !isCurrent && (
                            <button
                              onClick={() => handleDisableUser(u.user_id, u.username)}
                              className="text-rose-400 hover:text-rose-300 font-mono text-[11px] px-2 py-1 rounded bg-rose-950/20 border border-rose-500/20 hover:border-rose-500/40 transition cursor-pointer"
                            >
                              Disable
                            </button>
                          )}
                        </td>
                      )}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Create User Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="bg-[#0d131f] border border-slate-800 rounded-2xl p-6 w-full max-w-md space-y-4 shadow-2xl">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <UserPlus className="w-5 h-5 text-blue-400" />
              <span>Create Operator Identity</span>
            </h3>

            <form onSubmit={handleCreateUser} className="space-y-3">
              <div>
                <label className="block text-[11px] font-mono text-slate-400 uppercase mb-1">Username</label>
                <input
                  type="text"
                  value={newUsername}
                  onChange={(e) => setNewUsername(e.target.value)}
                  placeholder="e.g. analyst_lead"
                  required
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-100 focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-[11px] font-mono text-slate-400 uppercase mb-1">Display Name</label>
                <input
                  type="text"
                  value={newDisplayName}
                  onChange={(e) => setNewDisplayName(e.target.value)}
                  placeholder="e.g. Security Analyst"
                  required
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-100 focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-[11px] font-mono text-slate-400 uppercase mb-1">Initial Password</label>
                <input
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="••••••••••••"
                  required
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-100 focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-[11px] font-mono text-slate-400 uppercase mb-1">Initial Role</label>
                <select
                  value={newRole}
                  onChange={(e) => setNewRole(e.target.value as Role)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-100 focus:border-cyan-500 focus:outline-none font-mono"
                >
                  <option value={Role.VIEWER}>VIEWER (Read-Only Auditor)</option>
                  <option value={Role.OPERATOR}>OPERATOR (Tool Executor)</option>
                  <option value={Role.SECURITY_REVIEWER}>SECURITY_REVIEWER (Approver)</option>
                  <option value={Role.ADMIN}>ADMIN (Full Control)</option>
                </select>
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
                  <span>Create Operator</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
