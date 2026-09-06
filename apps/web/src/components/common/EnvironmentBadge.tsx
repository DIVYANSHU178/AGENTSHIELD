/**
 * Environment Indicator Badge
 * Phase 14J-C1 UI Hardening Foundation
 *
 * Provides a subtle, non-intrusive environment indicator in the operations console
 * header to ensure operators and testers always know whether they are operating
 * in QA, Development, or Production.
 *
 * Strictly prevents disclosure of secrets, passwords, or backend credentials.
 */

import React from 'react';
import { StatusPulse } from './MotionComponents';

export type AppEnvironment = 'qa' | 'development' | 'production' | 'test' | 'unknown';

interface EnvironmentBadgeProps {
  environment?: string;
  className?: string;
}

/**
 * Resolves current application environment safely from environment variables or hostname.
 */
export function resolveEnvironment(override?: string): AppEnvironment {
  if (override) {
    const clean = override.trim().toLowerCase();
    if (clean === 'qa') return 'qa';
    if (clean === 'development' || clean === 'dev' || clean === 'local') return 'development';
    if (clean === 'production' || clean === 'prod') return 'production';
    if (clean === 'test' || clean === 'testing') return 'test';
  }

  // 1. Check Vite env variable
  try {
    const viteEnv = (import.meta as any).env?.VITE_ENVIRONMENT || (import.meta as any).env?.MODE;
    if (viteEnv) {
      const clean = String(viteEnv).trim().toLowerCase();
      if (clean === 'qa') return 'qa';
      if (clean === 'development' || clean === 'dev') return 'development';
      if (clean === 'production' || clean === 'prod') return 'production';
      if (clean === 'test') return 'test';
    }
  } catch {
    // Ignore in non-Vite testing environments
  }

  // 2. Check window hostname
  if (typeof window !== 'undefined' && window.location) {
    const host = window.location.hostname.toLowerCase();
    if (host.includes('qa')) return 'qa';
    if (host === 'localhost' || host === '127.0.0.1' || host.startsWith('192.168.') || host.startsWith('172.')) {
      return 'development';
    }
  }

  return 'development';
}

export const EnvironmentBadge: React.FC<EnvironmentBadgeProps> = ({ environment: propEnv, className = '' }) => {
  const env = resolveEnvironment(propEnv);

  const envConfig: Record<
    AppEnvironment,
    {
      label: string;
      title: string;
      color: 'amber' | 'blue' | 'emerald' | 'slate';
      badgeClass: string;
    }
  > = {
    qa: {
      label: 'QA ENVIRONMENT',
      title: 'Active testing profile: isolated persistence (agentshield_qa.db)',
      color: 'amber',
      badgeClass: 'bg-amber-500/10 text-amber-300 border-amber-500/30 hover:border-amber-500/50',
    },
    development: {
      label: 'DEV CONSOLE',
      title: 'Local development profile: live security console',
      color: 'blue',
      badgeClass: 'bg-blue-500/10 text-blue-300 border-blue-500/30 hover:border-blue-500/50',
    },
    production: {
      label: 'PRODUCTION',
      title: 'Production security profile: live telemetry inspection',
      color: 'emerald',
      badgeClass: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30 hover:border-emerald-500/50',
    },
    test: {
      label: 'TEST HARNESS',
      title: 'Automated test execution profile',
      color: 'slate',
      badgeClass: 'bg-slate-800 text-slate-300 border-slate-700',
    },
    unknown: {
      label: 'CONSOLE',
      title: 'Security console',
      color: 'slate',
      badgeClass: 'bg-slate-800 text-slate-400 border-slate-700',
    },
  };

  const config = envConfig[env] || envConfig.development;

  return (
    <div
      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-mono font-bold tracking-wider uppercase border transition cursor-default shadow-sm ${config.badgeClass} ${className}`}
      title={config.title}
      aria-label={`Environment: ${config.label}`}
      data-testid="environment-badge"
    >
      <StatusPulse color={config.color} size="sm" />
      <span>{config.label}</span>
    </div>
  );
};
