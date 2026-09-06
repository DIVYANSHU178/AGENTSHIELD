import React from 'react';
import { useAuth } from '../../context/AuthContext';
import { Role } from '../../types';
import {
  User,
  LogOut,
  LogIn,
} from 'lucide-react';

export const getRoleBadgeClass = (role?: Role | string): string => {
  switch (role) {
    case 'ADMIN':
      return 'bg-rose-500/15 text-rose-300 border-rose-500/30';
    case 'SECURITY_REVIEWER':
      return 'bg-purple-500/15 text-purple-300 border-purple-500/30';
    case 'OPERATOR':
      return 'bg-blue-500/15 text-blue-300 border-blue-500/30';
    case 'VIEWER':
      return 'bg-slate-700/50 text-slate-300 border-slate-600/40';
    default:
      return 'bg-slate-800 text-slate-400 border-slate-700';
  }
};

export const getRoleTooltip = (role?: Role | string): string => {
  switch (role) {
    case 'ADMIN':
      return 'System Administrator (Full Privileges)';
    case 'SECURITY_REVIEWER':
      return 'Security Reviewer (Approval Resolution Authority)';
    case 'OPERATOR':
      return 'Security Operator (Action Execution Authority)';
    case 'VIEWER':
      return 'Read-Only Auditor (Inspection Only)';
    default:
      return 'Operator Identity';
  }
};

export const UserBadge: React.FC = () => {
  const { isAuthenticated, user, roles, logout, setShowLoginModal } = useAuth();

  if (!isAuthenticated || !user) {
    return (
      <div className="flex items-center gap-2" data-testid="unauthenticated-badge">
        <span className="hidden sm:inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono font-medium bg-slate-800/80 text-slate-400 border border-slate-700/60 shadow-sm">
          <span className="w-1.5 h-1.5 rounded-full bg-slate-500" />
          Unauthenticated
        </span>
        <button
          onClick={() => setShowLoginModal(true)}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white shadow-sm transition focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:ring-offset-2 focus-visible:ring-offset-slate-950 focus-visible:outline-none active:scale-[0.98]"
          aria-label="Sign In"
        >
          <LogIn className="w-3.5 h-3.5" />
          <span>Sign In</span>
        </button>
      </div>
    );
  }

  const primaryRole = roles[0] || 'VIEWER';

  return (
    <div className="flex items-center gap-2 sm:gap-3" data-testid="authenticated-user-badge">
      {/* Identity & Role Badge */}
      <div
        className="flex items-center gap-2 px-2.5 py-1 rounded-lg bg-slate-900/90 border border-slate-800/90 shadow-sm hover:border-slate-700/80 transition"
        title={`Authenticated: ${user.display_name || user.username} (${primaryRole})`}
      >
        <div className="relative p-1 bg-slate-800 rounded-md text-slate-300">
          <User className="w-3.5 h-3.5" />
          <span
            className="absolute -top-0.5 -right-0.5 w-1.5 h-1.5 rounded-full bg-emerald-400"
            title="Session Active"
            aria-label="Session Active"
          />
        </div>
        <div className="flex flex-col sm:flex-row sm:items-center gap-0.5 sm:gap-2 min-w-0">
          <span
            className="text-xs font-semibold text-white truncate max-w-[100px] sm:max-w-[140px] md:max-w-[160px]"
            title={user.display_name || user.username}
          >
            {user.display_name || user.username}
          </span>
          <span
            className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase border tracking-wider flex-shrink-0 ${getRoleBadgeClass(
              primaryRole
            )}`}
            data-testid="user-role-badge"
            title={getRoleTooltip(primaryRole)}
          >
            {primaryRole}
          </span>
        </div>
      </div>

      {/* Logout Button */}
      <button
        onClick={() => logout()}
        className="p-1.5 text-slate-400 hover:text-rose-300 hover:bg-rose-950/20 border border-transparent hover:border-rose-500/30 rounded-lg transition focus-visible:ring-2 focus-visible:ring-rose-400 focus-visible:ring-offset-2 focus-visible:ring-offset-slate-950 focus-visible:outline-none active:scale-95"
        title="Sign Out"
        aria-label="Sign Out"
      >
        <LogOut className="w-4 h-4" />
      </button>
    </div>
  );
};
