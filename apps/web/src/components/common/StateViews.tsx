/**
 * Shared State Visual Language
 * Phase 14J-C1 UI Hardening Foundation
 *
 * Distinctive, accessible visual treatments for:
 * - Loading
 * - Success
 * - Empty
 * - Authentication Required
 * - Forbidden / Access Restricted
 * - Backend Unavailable / Disconnected
 * - Server / Security Gateway Error
 */

import React from 'react';
import {
  Loader2,
  CheckCircle2,
  Inbox,
  Lock,
  ShieldAlert,
  WifiOff,
  AlertTriangle,
  LogIn,
  RefreshCw,
} from 'lucide-react';
import { MotionCard } from './MotionComponents';
import { interactive } from '../../theme/tokens';

export interface BaseStateProps {
  title?: string;
  message?: string;
  action?: React.ReactNode;
  className?: string;
}

// ---------------------------------------------------------------------------
// 1. Loading State
// ---------------------------------------------------------------------------
export interface LoadingStateProps extends BaseStateProps {
  stage?: string;
}

export const LoadingState: React.FC<LoadingStateProps> = ({
  title = 'Processing Security Operations',
  message = 'Connecting to AgentShield runtime and verifying cryptographic telemetry...',
  stage,
  className = '',
}) => {
  return (
    <MotionCard
      className={`p-8 sm:p-12 text-center rounded-2xl bg-slate-900/60 border border-slate-800/80 backdrop-blur flex flex-col items-center justify-center space-y-4 ${className}`}
      role="status"
      aria-live="polite"
      aria-busy="true"
    >
      <div className="relative">
        <div className="p-3.5 bg-blue-500/10 border border-blue-500/30 rounded-2xl text-blue-400">
          <Loader2 className="w-8 h-8 animate-spin" />
        </div>
      </div>
      <div className="max-w-md space-y-1.5">
        <h3 className="text-base font-bold text-white tracking-tight">{title}</h3>
        <p className="text-xs text-slate-400 leading-relaxed">{message}</p>
        {stage && (
          <div className="pt-2">
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono text-cyan-400 bg-cyan-950/40 border border-cyan-500/30">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
              {stage}
            </span>
          </div>
        )}
      </div>
    </MotionCard>
  );
};

// ---------------------------------------------------------------------------
// 2. Success State
// ---------------------------------------------------------------------------
export interface SuccessStateProps extends BaseStateProps {
  details?: Record<string, any>;
}

export const SuccessState: React.FC<SuccessStateProps> = ({
  title = 'Operation Completed Successfully',
  message = 'Security telemetry recorded and policy evaluation verified.',
  action,
  details,
  className = '',
}) => {
  return (
    <MotionCard
      className={`p-8 sm:p-10 text-center rounded-2xl bg-emerald-950/20 border border-emerald-500/30 backdrop-blur flex flex-col items-center justify-center space-y-4 ${className}`}
      role="status"
      aria-live="polite"
    >
      <div className="p-3.5 bg-emerald-500/15 border border-emerald-500/30 rounded-2xl text-emerald-400 shadow-[0_0_20px_rgba(16,185,129,0.2)]">
        <CheckCircle2 className="w-8 h-8" />
      </div>
      <div className="max-w-md space-y-1.5">
        <h3 className="text-base font-bold text-white tracking-tight">{title}</h3>
        <p className="text-xs text-slate-300 leading-relaxed">{message}</p>
        {details && Object.keys(details).length > 0 && (
          <div className="mt-3 p-2.5 bg-slate-950/60 border border-slate-800 rounded-lg text-left text-xs font-mono text-slate-300">
            {Object.entries(details).map(([k, v]) => (
              <div key={k} className="flex justify-between py-0.5">
                <span className="text-slate-500">{k}:</span>
                <span className="text-emerald-400 font-semibold">{String(v)}</span>
              </div>
            ))}
          </div>
        )}
      </div>
      {action && <div className="pt-2">{action}</div>}
    </MotionCard>
  );
};

// ---------------------------------------------------------------------------
// 3. Empty State
// ---------------------------------------------------------------------------
export interface EmptyStateProps extends BaseStateProps {
  icon?: React.ComponentType<{ className?: string }>;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  title = 'No Records Found',
  message = 'There is currently no activity matching the active filter criteria.',
  icon: Icon = Inbox,
  action,
  className = '',
}) => {
  return (
    <MotionCard
      className={`p-8 sm:p-12 text-center rounded-2xl bg-slate-900/40 border border-slate-800/60 flex flex-col items-center justify-center space-y-4 ${className}`}
      role="status"
    >
      <div className="p-3.5 bg-slate-800/50 border border-slate-700/50 rounded-2xl text-slate-400">
        <Icon className="w-8 h-8" />
      </div>
      <div className="max-w-sm space-y-1.5">
        <h3 className="text-sm font-bold text-slate-200">{title}</h3>
        <p className="text-xs text-slate-400 leading-relaxed">{message}</p>
      </div>
      {action && <div className="pt-2">{action}</div>}
    </MotionCard>
  );
};

// ---------------------------------------------------------------------------
// 4. Authentication Required State
// ---------------------------------------------------------------------------
export interface AuthRequiredStateProps extends BaseStateProps {
  onSignIn?: () => void;
}

export const AuthRequiredState: React.FC<AuthRequiredStateProps> = ({
  title = 'Authentication Required',
  message = 'The AgentShield security backend is healthy and reachable, but this operations view requires an authenticated session.',
  onSignIn,
  action,
  className = '',
}) => {
  return (
    <MotionCard
      className={`p-8 sm:p-10 text-center rounded-2xl bg-blue-950/20 border border-blue-500/30 backdrop-blur flex flex-col items-center justify-center space-y-4 ${className}`}
      role="status"
    >
      <div className="p-3.5 bg-blue-500/15 border border-blue-500/30 rounded-2xl text-blue-400 shadow-[0_0_20px_rgba(59,130,246,0.2)]">
        <Lock className="w-8 h-8" />
      </div>
      <div className="max-w-md space-y-1.5">
        <h3 className="text-base font-bold text-white tracking-tight">{title}</h3>
        <p className="text-xs text-slate-300 leading-relaxed">{message}</p>
      </div>
      {action ? (
        <div className="pt-2">{action}</div>
      ) : onSignIn ? (
        <div className="pt-2">
          <button
            onClick={onSignIn}
            className={`px-4 py-2 flex items-center gap-2 ${interactive.button.primary} ${interactive.focusRing}`}
          >
            <LogIn className="w-4 h-4" />
            <span>Sign In to Access</span>
          </button>
        </div>
      ) : null}
    </MotionCard>
  );
};

// ---------------------------------------------------------------------------
// 5. Forbidden / Access Restricted State
// ---------------------------------------------------------------------------
export interface ForbiddenStateProps extends BaseStateProps {
  requiredPermission?: string;
}

export const ForbiddenState: React.FC<ForbiddenStateProps> = ({
  title = 'Access Restricted',
  message = 'Your authenticated role does not possess the authorization required for this operational action.',
  requiredPermission,
  action,
  className = '',
}) => {
  return (
    <MotionCard
      className={`p-8 sm:p-10 text-center rounded-2xl bg-purple-950/20 border border-purple-500/30 backdrop-blur flex flex-col items-center justify-center space-y-4 ${className}`}
      role="alert"
    >
      <div className="p-3.5 bg-purple-500/15 border border-purple-500/30 rounded-2xl text-purple-400 shadow-[0_0_20px_rgba(168,85,247,0.2)]">
        <ShieldAlert className="w-8 h-8" />
      </div>
      <div className="max-w-md space-y-1.5">
        <h3 className="text-base font-bold text-white tracking-tight">{title}</h3>
        <p className="text-xs text-slate-300 leading-relaxed">{message}</p>
        {requiredPermission && (
          <div className="pt-2">
            <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-mono text-purple-300 bg-purple-950/40 border border-purple-500/30">
              Required: {requiredPermission}
            </span>
          </div>
        )}
      </div>
      {action && <div className="pt-2">{action}</div>}
    </MotionCard>
  );
};

// ---------------------------------------------------------------------------
// 6. Backend Unavailable State
// ---------------------------------------------------------------------------
export interface BackendUnavailableStateProps extends BaseStateProps {
  onRetry?: () => void;
  retrying?: boolean;
}

export const BackendUnavailableState: React.FC<BackendUnavailableStateProps> = ({
  title = 'Backend Unavailable',
  message = 'Unable to establish connection to the AgentShield API server. Please ensure the backend is running.',
  onRetry,
  retrying = false,
  action,
  className = '',
}) => {
  return (
    <MotionCard
      className={`p-8 sm:p-10 text-center rounded-2xl bg-rose-950/25 border border-rose-500/30 backdrop-blur flex flex-col items-center justify-center space-y-4 ${className}`}
      role="alert"
    >
      <div className="p-3.5 bg-rose-500/15 border border-rose-500/30 rounded-2xl text-rose-400 shadow-[0_0_20px_rgba(244,63,94,0.2)]">
        <WifiOff className="w-8 h-8" />
      </div>
      <div className="max-w-md space-y-1.5">
        <h3 className="text-base font-bold text-white tracking-tight">{title}</h3>
        <p className="text-xs text-rose-200/90 leading-relaxed">{message}</p>
      </div>
      {action ? (
        <div className="pt-2">{action}</div>
      ) : onRetry ? (
        <div className="pt-2">
          <button
            onClick={onRetry}
            disabled={retrying}
            className={`px-4 py-2 flex items-center gap-2 ${interactive.button.danger} ${interactive.focusRing} ${interactive.disabled}`}
          >
            <RefreshCw className={`w-4 h-4 ${retrying ? 'animate-spin' : ''}`} />
            <span>{retrying ? 'Reconnecting...' : 'Retry Connection'}</span>
          </button>
        </div>
      ) : null}
    </MotionCard>
  );
};

// ---------------------------------------------------------------------------
// 7. Server / Security Gateway Error State
// ---------------------------------------------------------------------------
export interface ServerErrorStateProps extends BaseStateProps {
  errorDetails?: string;
  onRetry?: () => void;
}

export const ServerErrorState: React.FC<ServerErrorStateProps> = ({
  title = 'Security Gateway Error',
  message = 'An unexpected server error occurred during security evaluation processing.',
  errorDetails,
  onRetry,
  action,
  className = '',
}) => {
  return (
    <MotionCard
      className={`p-8 sm:p-10 text-center rounded-2xl bg-amber-950/25 border border-amber-500/30 backdrop-blur flex flex-col items-center justify-center space-y-4 ${className}`}
      role="alert"
    >
      <div className="p-3.5 bg-amber-500/15 border border-amber-500/30 rounded-2xl text-amber-400 shadow-[0_0_20px_rgba(245,158,11,0.2)]">
        <AlertTriangle className="w-8 h-8" />
      </div>
      <div className="max-w-md space-y-1.5">
        <h3 className="text-base font-bold text-white tracking-tight">{title}</h3>
        <p className="text-xs text-amber-200/90 leading-relaxed">{message}</p>
        {errorDetails && (
          <div className="mt-3 p-3 bg-slate-950 border border-slate-800 rounded-lg text-left text-xs font-mono text-rose-300 break-all max-h-32 overflow-y-auto">
            {errorDetails}
          </div>
        )}
      </div>
      {action ? (
        <div className="pt-2">{action}</div>
      ) : onRetry ? (
        <div className="pt-2">
          <button
            onClick={onRetry}
            className={`px-4 py-2 flex items-center gap-2 ${interactive.button.outline} ${interactive.focusRing}`}
          >
            <RefreshCw className="w-4 h-4" />
            <span>Retry Evaluation</span>
          </button>
        </div>
      ) : null}
    </MotionCard>
  );
};

// ---------------------------------------------------------------------------
// 8. Unified StateView Dispatcher
// ---------------------------------------------------------------------------
export type StateVariant =
  | 'loading'
  | 'success'
  | 'empty'
  | 'auth-required'
  | 'forbidden'
  | 'backend-unavailable'
  | 'server-error';

export interface StateViewProps extends BaseStateProps {
  variant: StateVariant;
  stage?: string;
  details?: Record<string, any>;
  icon?: React.ComponentType<{ className?: string }>;
  requiredPermission?: string;
  onSignIn?: () => void;
  onRetry?: () => void;
  retrying?: boolean;
  errorDetails?: string;
}

export const StateView: React.FC<StateViewProps> = ({ variant, ...props }) => {
  switch (variant) {
    case 'loading':
      return <LoadingState {...props} />;
    case 'success':
      return <SuccessState {...props} />;
    case 'empty':
      return <EmptyState {...props} />;
    case 'auth-required':
      return <AuthRequiredState {...props} />;
    case 'forbidden':
      return <ForbiddenState {...props} />;
    case 'backend-unavailable':
      return <BackendUnavailableState {...props} />;
    case 'server-error':
      return <ServerErrorState {...props} />;
    default:
      return null;
  }
};
