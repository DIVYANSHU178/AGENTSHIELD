/**
 * AgentShield Login & Authentication Gateway Experience
 * Phase 14J-C2 Experience Hardening
 *
 * Cinematic, restrained, accessible security operations authentication console.
 * Integrates authoritative Phase 14 authentication and RBAC identity contracts
 * with C1 design tokens and motion orchestration.
 */

import React, { useState, useEffect, useRef, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useAuth } from '../../context/AuthContext';
import { useMotion } from '../../context/MotionContext';
import { EnvironmentBadge } from '../common/EnvironmentBadge';
import { fetchHealthStatus } from '../../lib/api';
import {
  Shield,
  Lock,
  User,
  X,
  AlertCircle,
  KeyRound,
  Loader2,
  CheckCircle2,
  Eye,
  EyeOff,
} from 'lucide-react';

interface LoginModalProps {
  isOpen: boolean;
  onClose: () => void;
  showDemoPresets?: boolean;
  backendEnvironment?: string;
}

interface ClassifiedAuthError {
  title: string;
  message: string;
}

interface DemoProfile {
  username: string;
  password: string;
  label: string;
  role: string;
  dotColor: string;
  cardClasses: string;
}

// Development & QA profile presets.
// Dead-code eliminated in production builds when import.meta.env.DEV is false.
const DEMO_PROFILES: DemoProfile[] = import.meta.env.DEV
  ? [
      {
        username: 'security_lead',
        password: 'ReviewerPass123!',
        label: 'Security Lead',
        role: 'SECURITY_REVIEWER',
        dotColor: 'bg-purple-400',
        cardClasses:
          'bg-purple-950/20 border-purple-500/30 hover:border-purple-500/60 active:bg-purple-950/40 text-purple-300',
      },
      {
        username: 'ops_user',
        password: 'OperatorPass123!',
        label: 'Operator',
        role: 'OPERATOR',
        dotColor: 'bg-blue-400',
        cardClasses:
          'bg-blue-950/20 border-blue-500/30 hover:border-blue-500/60 active:bg-blue-950/40 text-blue-300',
      },
      {
        username: 'admin',
        password: 'AdminPass123!',
        label: 'Admin',
        role: 'ADMIN',
        dotColor: 'bg-rose-400',
        cardClasses:
          'bg-rose-950/20 border-rose-500/30 hover:border-rose-500/60 active:bg-rose-950/40 text-rose-300',
      },
      {
        username: 'viewer_user',
        password: 'ViewerPass123!',
        label: 'Viewer',
        role: 'VIEWER (Read-Only)',
        dotColor: 'bg-slate-400',
        cardClasses:
          'bg-slate-800/40 border-slate-700/60 hover:border-slate-500 active:bg-slate-800/60 text-slate-300',
      },
    ]
  : [];

function classifyAuthError(err: any): ClassifiedAuthError {
  if (!err) {
    return {
      title: 'Authentication Error',
      message: 'An unexpected authentication error occurred.',
    };
  }

  const rawMessage = typeof err === 'string' ? err : err.message || '';
  const status = err.status;

  if (rawMessage.toLowerCase().includes('please provide')) {
    return {
      title: 'Missing Required Fields',
      message: rawMessage,
    };
  }

  if (
    status === 401 ||
    rawMessage.toLowerCase().includes('invalid username') ||
    rawMessage.toLowerCase().includes('unauthorized') ||
    rawMessage.toLowerCase().includes('credentials')
  ) {
    return {
      title: 'Authentication Failed',
      message: 'Invalid username or password.',
    };
  }

  if (
    err.name === 'TypeError' ||
    rawMessage.toLowerCase().includes('fetch') ||
    rawMessage.toLowerCase().includes('network') ||
    rawMessage.toLowerCase().includes('econnrefused') ||
    rawMessage.toLowerCase().includes('failed to connect') ||
    rawMessage.toLowerCase().includes('unable to connect')
  ) {
    return {
      title: 'Gateway Unreachable',
      message: 'Unable to connect to the AgentShield authentication gateway. Ensure the backend is online.',
    };
  }

  if (status && status >= 500) {
    return {
      title: 'Gateway Server Error',
      message: 'The security gateway encountered an internal server error during authentication.',
    };
  }

  // Sanitized fallback without leaking stack traces or internal filesystem details
  const cleanMessage = rawMessage.replace(/at\s+.*\(.*:\d+:\d+\)/g, '').trim();
  return {
    title: 'Authentication Rejected',
    message: cleanMessage || 'Authentication could not be completed.',
  };
}

export const LoginModal: React.FC<LoginModalProps> = ({
  isOpen,
  onClose,
  showDemoPresets = import.meta.env.DEV,
  backendEnvironment,
}) => {
  const { login, error: contextError, clearError } = useAuth();
  const { isReducedMotion } = useMotion();

  const [resolvedEnv, setResolvedEnv] = useState<string | undefined>(backendEnvironment);

  useEffect(() => {
    if (backendEnvironment !== undefined) {
      setResolvedEnv(backendEnvironment);
    } else if (isOpen && import.meta.env.DEV) {
      fetchHealthStatus()
        .then((res) => {
          if (res?.environment) {
            setResolvedEnv(res.environment);
          }
        })
        .catch(() => {
          // Fallback gracefully without breaking modal
        });
    }
  }, [isOpen, backendEnvironment]);

  const isProductionBackend =
    Boolean(resolvedEnv && (resolvedEnv.toLowerCase() === 'production' || resolvedEnv.toLowerCase() === 'prod'));
  const canShowPresets =
    import.meta.env.DEV && showDemoPresets && !isProductionBackend && DEMO_PROFILES.length > 0;

  const [username, setUsername] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [showPassword, setShowPassword] = useState<boolean>(false);
  const [submitting, setSubmitting] = useState<boolean>(false);
  const [isSuccess, setIsSuccess] = useState<boolean>(false);
  const [localError, setLocalError] = useState<ClassifiedAuthError | null>(null);


  const successTimerRef = useRef<NodeJS.Timeout | null>(null);
  const usernameInputRef = useRef<HTMLInputElement | null>(null);
  const prevIsOpenRef = useRef<boolean>(false);

  // Focus management when modal opens
  useEffect(() => {
    if (isOpen && !prevIsOpenRef.current) {
      setIsSuccess(false);
      setSubmitting(false);
      setLocalError(null);
      clearError();
      const timer = setTimeout(() => {
        usernameInputRef.current?.focus();
      }, 50);
      prevIsOpenRef.current = true;
      return () => clearTimeout(timer);
    }
    if (!isOpen) {
      prevIsOpenRef.current = false;
    }
  }, [isOpen, clearError]);


  // Clean up timer on unmount
  useEffect(() => {
    return () => {
      if (successTimerRef.current) {
        clearTimeout(successTimerRef.current);
      }
    };
  }, []);

  // Keyboard Escape listener
  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !submitting && !isSuccess) {
        onClose();
      }
    },
    [onClose, submitting, isSuccess]
  );

  useEffect(() => {
    if (!isOpen) return;
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, handleKeyDown]);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password) {
      setLocalError({
        title: 'Missing Required Fields',
        message: 'Please provide both username and password.',
      });
      return;
    }

    setSubmitting(true);
    setLocalError(null);
    clearError();

    try {
      await login(username.trim(), password);
      setIsSuccess(true);
      // Brief, restrained success transition before dashboard becomes active
      const delay = isReducedMotion ? 0 : 300;
      successTimerRef.current = setTimeout(() => {
        setUsername('');
        setPassword('');
        setIsSuccess(false);
        setSubmitting(false);
        onClose();
      }, delay);
    } catch (err: any) {
      setIsSuccess(false);
      setSubmitting(false);
      const classified = classifyAuthError(err);
      setLocalError(classified);
    }
  };

  const handleQuickPreset = (presetUser: string, presetPass: string) => {
    if (submitting || isSuccess) return;
    setUsername(presetUser);
    setPassword(presetPass);
    setLocalError(null);
    clearError();
    usernameInputRef.current?.focus();
  };

  const classifiedError = localError
    ? localError
    : contextError
    ? classifyAuthError(contextError)
    : null;

  // Framer-motion variant definitions
  const backdropVariants = {
    initial: { opacity: 0 },
    animate: { opacity: 1, transition: { duration: isReducedMotion ? 0.05 : 0.2, ease: [0.16, 1, 0.3, 1] } },
    exit: { opacity: 0, transition: { duration: 0.1 } },
  };

  const modalVariants = {
    initial: { opacity: 0, y: isReducedMotion ? 0 : 10, scale: isReducedMotion ? 1 : 0.98 },
    animate: {
      opacity: 1,
      y: 0,
      scale: 1,
      transition: {
        duration: isReducedMotion ? 0.05 : 0.25,
        ease: [0.16, 1, 0.3, 1],
        staggerChildren: isReducedMotion ? 0 : 0.04,
        delayChildren: isReducedMotion ? 0 : 0.02,
      },
    },
    exit: {
      opacity: 0,
      y: isReducedMotion ? 0 : 6,
      scale: isReducedMotion ? 1 : 0.98,
      transition: { duration: 0.15 },
    },
  };

  const itemVariants = {
    initial: { opacity: 0, y: isReducedMotion ? 0 : 6 },
    animate: {
      opacity: 1,
      y: 0,
      transition: { duration: isReducedMotion ? 0.05 : 0.2, ease: [0.16, 1, 0.3, 1] },
    },
  };

  return (
    <AnimatePresence>
      <motion.div
        variants={backdropVariants}
        initial="initial"
        animate="animate"
        exit="exit"
        className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 md:p-6 bg-black/80 backdrop-blur-md overflow-y-auto"
        data-testid="login-modal"
        onClick={(e) => {
          if (e.target === e.currentTarget && !submitting && !isSuccess) {
            onClose();
          }
        }}
      >
        <motion.div
          variants={modalVariants}
          role="dialog"
          aria-modal="true"
          aria-labelledby="login-modal-title"
          aria-describedby="login-modal-desc"
          className="relative w-full max-w-md my-auto bg-[#0d131f] border border-slate-800 rounded-2xl shadow-2xl shadow-black/80 p-5 sm:p-7 space-y-5 overflow-hidden"
        >
          {/* Subtle top ambient console accent line */}
          <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-cyan-500/50 to-transparent pointer-events-none" />

          {/* Close Button */}
          <button
            onClick={onClose}
            disabled={submitting || isSuccess}
            className="absolute top-4 right-4 p-2 text-slate-400 hover:text-slate-200 hover:bg-slate-800/80 rounded-lg transition focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none disabled:opacity-30 disabled:cursor-not-allowed"
            aria-label="Close authentication modal"
          >
            <X className="w-5 h-5" />
          </button>

          {/* 1. Brand / Identity Header */}
          <motion.div variants={itemVariants} className="space-y-2">
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <div className="p-2.5 bg-cyan-500/10 border border-cyan-500/30 rounded-xl text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.15)]">
                  <Shield className="w-6 h-6" />
                </div>
                <div>
                  <h2
                    id="login-modal-title"
                    className="text-lg font-bold text-white tracking-tight leading-tight"
                  >
                    AgentShield Identity
                  </h2>
                  <span className="text-[11px] font-mono text-cyan-400/90 font-medium">
                    Security Gateway Access
                  </span>
                </div>
              </div>

              {/* Environment Indicator in Header */}
              <EnvironmentBadge environment={resolvedEnv} className="hidden sm:inline-flex" />
            </div>

            <p id="login-modal-desc" className="text-xs text-slate-400 leading-relaxed pt-1">
              Sign in to access authorized operational controls and cryptographic telemetry.
            </p>
          </motion.div>

          {/* 2. Error Alert Banner */}
          {classifiedError && !submitting && !isSuccess && (
            <motion.div
              variants={itemVariants}
              className="p-3.5 bg-rose-950/40 border border-rose-500/40 rounded-xl text-rose-200 text-xs flex items-start gap-2.5 shadow-[0_0_15px_rgba(244,63,94,0.15)]"
              role="alert"
              aria-live="assertive"
            >
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-rose-400" />
              <div className="flex-1 space-y-0.5">
                <div className="font-semibold text-rose-300 uppercase tracking-wide text-[10px]">
                  {classifiedError.title}
                </div>
                <div className="text-slate-200 leading-relaxed">{classifiedError.message}</div>
              </div>
            </motion.div>
          )}

          {/* 3. Authenticating State Banner */}
          {submitting && !isSuccess && (
            <motion.div
              variants={itemVariants}
              className="p-3 bg-cyan-950/30 border border-cyan-500/40 rounded-xl text-xs font-mono text-cyan-200 flex items-center gap-3 shadow-[0_0_15px_rgba(6,182,212,0.15)]"
              role="status"
              aria-live="polite"
            >
              <Loader2 className="w-4 h-4 animate-spin shrink-0 text-cyan-400" />
              <div className="flex-1 min-w-0">
                <div className="font-bold tracking-wider uppercase text-[10px] text-cyan-400">
                  Authenticating
                </div>
                <div className="text-[11px] text-slate-300 truncate">
                  Validating identity &amp; establishing secure session...
                </div>
              </div>
            </motion.div>
          )}

          {/* 4. Success State Transition Banner */}
          {isSuccess && (
            <motion.div
              variants={itemVariants}
              className="p-3 bg-emerald-950/30 border border-emerald-500/50 rounded-xl text-xs font-mono text-emerald-200 flex items-center gap-3 shadow-[0_0_20px_rgba(16,185,129,0.2)]"
              role="status"
              aria-live="polite"
            >
              <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
              <div className="flex-1 min-w-0">
                <div className="font-bold tracking-wider uppercase text-[10px] text-emerald-400">
                  Authentication Accepted
                </div>
                <div className="text-[11px] text-slate-200 truncate">
                  Session established — launching console...
                </div>
              </div>
            </motion.div>
          )}

          {/* 5. Login Form */}
          <form onSubmit={handleSubmit} noValidate className="space-y-4">
            <motion.div variants={itemVariants}>
              <label
                htmlFor="auth-username"
                className="block text-[11px] font-mono font-bold text-slate-300 tracking-wider uppercase mb-1.5"
              >
                Operator ID / Username
              </label>
              <div className="relative">
                <User
                  className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none"
                  aria-hidden="true"
                />
                <input
                  ref={usernameInputRef}
                  id="auth-username"
                  name="username"
                  type="text"
                  value={username}
                  onChange={(e) => {
                    setUsername(e.target.value);
                    if (localError) setLocalError(null);
                  }}
                  placeholder="Enter username (e.g. security_lead)"
                  disabled={submitting || isSuccess}
                  className="w-full bg-slate-950 border border-slate-800 focus:border-cyan-500 focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:ring-offset-2 focus-visible:ring-offset-slate-950 focus-visible:outline-none rounded-lg pl-9 pr-3 py-2.5 text-sm text-slate-100 placeholder:text-slate-600 transition disabled:opacity-50"
                  autoComplete="username"
                  autoFocus
                />
              </div>
            </motion.div>

            <motion.div variants={itemVariants}>
              <label
                htmlFor="auth-password"
                className="block text-[11px] font-mono font-bold text-slate-300 tracking-wider uppercase mb-1.5"
              >
                Security Credential / Password
              </label>
              <div className="relative">
                <Lock
                  className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none"
                  aria-hidden="true"
                />
                <input
                  id="auth-password"
                  name="password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => {
                    setPassword(e.target.value);
                    if (localError) setLocalError(null);
                  }}
                  placeholder="••••••••••••"
                  disabled={submitting || isSuccess}
                  className="w-full bg-slate-950 border border-slate-800 focus:border-cyan-500 focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:ring-offset-2 focus-visible:ring-offset-slate-950 focus-visible:outline-none rounded-lg pl-9 pr-10 py-2.5 text-sm text-slate-100 placeholder:text-slate-600 transition disabled:opacity-50"
                  autoComplete="current-password"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  disabled={submitting || isSuccess}
                  aria-label={showPassword ? 'Hide credential' : 'Show credential'}
                  title={showPassword ? 'Hide password' : 'Show password'}
                  aria-pressed={showPassword}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 p-1 text-slate-500 hover:text-slate-300 focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none rounded transition disabled:opacity-40 cursor-pointer"
                  tabIndex={0}
                >

                  {showPassword ? (
                    <EyeOff className="w-4 h-4" aria-hidden="true" />
                  ) : (
                    <Eye className="w-4 h-4" aria-hidden="true" />
                  )}
                </button>
              </div>
            </motion.div>

            {/* 6. Primary Action Button */}
            <motion.div variants={itemVariants}>
              <button
                type="submit"
                data-testid="login-submit-button"
                disabled={submitting || isSuccess}
                className="w-full py-2.5 px-4 bg-blue-600 hover:bg-blue-500 active:bg-blue-700 text-white font-semibold text-sm rounded-lg shadow-lg shadow-blue-500/20 transition duration-150 disabled:opacity-50 flex items-center justify-center gap-2 mt-2 focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none cursor-pointer disabled:cursor-not-allowed min-h-[44px]"
              >
                {submitting && !isSuccess ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin text-cyan-200" />
                    <span>Authenticating...</span>
                  </>
                ) : isSuccess ? (
                  <>
                    <CheckCircle2 className="w-4 h-4 text-emerald-300" />
                    <span>Session Authorized</span>
                  </>
                ) : (
                  <>
                    <KeyRound className="w-4 h-4" />
                    <span>Sign In</span>
                  </>
                )}
              </button>
            </motion.div>
          </form>

          {/* 7. Demo Presets: Development & QA Profiles */}
          {canShowPresets && (
            <motion.div variants={itemVariants} className="pt-3 border-t border-slate-800/80 space-y-2.5">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono font-bold text-slate-400 tracking-wider uppercase">
                  Development / QA Profiles
                </span>
                <span className="text-[10px] font-mono text-cyan-400/80 bg-cyan-950/40 border border-cyan-500/20 px-2 py-0.5 rounded">
                  TEST IDENTITIES
                </span>
              </div>
              <div className="grid grid-cols-2 gap-2 text-xs">
                {DEMO_PROFILES.map((profile) => (
                  <button
                    key={profile.username}
                    type="button"
                    disabled={submitting || isSuccess}
                    onClick={() => handleQuickPreset(profile.username, profile.password)}
                    className={`p-2.5 rounded-xl border text-left transition focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none disabled:opacity-50 group cursor-pointer ${profile.cardClasses}`}
                  >
                    <div className="font-semibold text-slate-200 flex items-center justify-between">
                      <span>{profile.label}</span>
                      <span className={`w-1.5 h-1.5 rounded-full ${profile.dotColor} opacity-60 group-hover:opacity-100`} />
                    </div>
                    <div className="text-[10px] opacity-80 mt-0.5">{profile.role}</div>
                  </button>
                ))}
              </div>
            </motion.div>
          )}
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
};
