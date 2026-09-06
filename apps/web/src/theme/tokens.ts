/**
 * AgentShield Design System Tokens
 * Phase 14J-C1 UI Hardening Foundation
 *
 * Centralized, strongly-typed visual tokens preserving the dark security-console
 * aesthetic with high contrast, accessibility compliance, and precision ergonomics.
 */

export const typography = {
  fontFamily: {
    sans: "system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif",
    mono: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace",
  },
  fontSize: {
    '2xs': '0.6875rem', // 11px
    xs: '0.75rem',      // 12px
    sm: '0.875rem',     // 14px
    base: '1rem',       // 16px
    lg: '1.125rem',     // 18px
    xl: '1.25rem',      // 20px
    '2xl': '1.5rem',     // 24px
    '3xl': '1.875rem',   // 30px
  },
  fontWeight: {
    normal: '400',
    medium: '500',
    semibold: '600',
    bold: '700',
    extrabold: '800',
  },
  letterSpacing: {
    tighter: '-0.03em',
    tight: '-0.015em',
    normal: '0',
    wide: '0.025em',
    wider: '0.05em',
    widest: '0.1em',
  },
} as const;

export const surfaces = {
  canvas: '#090d16',       // Deep-space root console canvas
  panel: '#0d131f',        // Primary container / tab panel surface
  card: '#111827',         // Standard card surface
  cardSubtle: '#0f172a',   // Recessed sub-card surface
  elevated: '#1e293b',     // Elevated card / modal / dropdown surface
  elevatedHover: '#273549',// Elevated hover state
  overlay: 'rgba(3, 7, 18, 0.80)', // Backdrop blur scrim
  glass: 'rgba(15, 23, 42, 0.75)',  // Translucent backdrop surface
  glassBorder: 'rgba(51, 65, 85, 0.5)',
} as const;

export const borders = {
  subtle: 'border-slate-800/60',
  default: 'border-slate-800',
  medium: 'border-slate-700',
  strong: 'border-slate-600',
  focus: 'border-cyan-500',
  glowCyan: 'border-cyan-500/30',
  glowEmerald: 'border-emerald-500/30',
  glowAmber: 'border-amber-500/30',
  glowRose: 'border-rose-500/30',
  glowPurple: 'border-purple-500/30',
} as const;

export const radii = {
  none: '0',
  xs: '0.25rem',  // 4px
  sm: '0.375rem', // 6px
  md: '0.5rem',   // 8px
  lg: '0.75rem',  // 12px
  xl: '1rem',     // 16px
  '2xl': '1.25rem', // 20px
  full: '9999px',
} as const;

export const shadows = {
  none: 'none',
  sm: '0 1px 2px 0 rgba(0, 0, 0, 0.5)',
  md: '0 4px 6px -1px rgba(0, 0, 0, 0.6), 0 2px 4px -1px rgba(0, 0, 0, 0.4)',
  lg: '0 10px 15px -3px rgba(0, 0, 0, 0.7), 0 4px 6px -2px rgba(0, 0, 0, 0.5)',
  xl: '0 20px 25px -5px rgba(0, 0, 0, 0.8), 0 10px 10px -5px rgba(0, 0, 0, 0.6)',
  glowCyan: '0 0 15px rgba(6, 182, 212, 0.25)',
  glowEmerald: '0 0 15px rgba(16, 185, 129, 0.25)',
  glowAmber: '0 0 15px rgba(245, 158, 11, 0.25)',
  glowRose: '0 0 15px rgba(244, 63, 94, 0.25)',
  glowBlue: '0 0 15px rgba(59, 130, 246, 0.25)',
} as const;

export const statusTokens = {
  healthy: {
    color: '#10b981',
    bg: 'bg-emerald-500/10',
    border: 'border-emerald-500/25',
    text: 'text-emerald-400',
    glow: 'shadow-[0_0_12px_rgba(16,185,129,0.2)]',
    dot: 'bg-emerald-400',
  },
  warning: {
    color: '#f59e0b',
    bg: 'bg-amber-500/10',
    border: 'border-amber-500/25',
    text: 'text-amber-400',
    glow: 'shadow-[0_0_12px_rgba(245,158,11,0.2)]',
    dot: 'bg-amber-400',
  },
  danger: {
    color: '#f43f5e',
    bg: 'bg-rose-500/10',
    border: 'border-rose-500/25',
    text: 'text-rose-400',
    glow: 'shadow-[0_0_12px_rgba(244,63,94,0.2)]',
    dot: 'bg-rose-400',
  },
  info: {
    color: '#38bdf8',
    bg: 'bg-sky-500/10',
    border: 'border-sky-500/25',
    text: 'text-sky-400',
    glow: 'shadow-[0_0_12px_rgba(56,189,248,0.2)]',
    dot: 'bg-sky-400',
  },
  neutral: {
    color: '#94a3b8',
    bg: 'bg-slate-500/10',
    border: 'border-slate-500/25',
    text: 'text-slate-400',
    glow: 'none',
    dot: 'bg-slate-400',
  },
  purple: {
    color: '#c084fc',
    bg: 'bg-purple-500/10',
    border: 'border-purple-500/25',
    text: 'text-purple-400',
    glow: 'shadow-[0_0_12px_rgba(192,132,252,0.2)]',
    dot: 'bg-purple-400',
  },
} as const;

export const interactive = {
  focusRing:
    'focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:ring-offset-2 focus-visible:ring-offset-slate-950 focus-visible:outline-none',
  disabled:
    'disabled:opacity-50 disabled:cursor-not-allowed disabled:pointer-events-none',
  button: {
    primary:
      'bg-blue-600 hover:bg-blue-500 active:bg-blue-700 text-white font-semibold transition-colors duration-150 rounded-lg shadow-sm',
    secondary:
      'bg-slate-800 hover:bg-slate-700 active:bg-slate-600 text-slate-100 font-semibold border border-slate-700 transition-colors duration-150 rounded-lg',
    danger:
      'bg-rose-600 hover:bg-rose-500 active:bg-rose-700 text-white font-semibold transition-colors duration-150 rounded-lg shadow-sm',
    ghost:
      'bg-transparent hover:bg-slate-800/80 active:bg-slate-800 text-slate-300 hover:text-white transition-colors duration-150 rounded-lg',
    outline:
      'bg-transparent hover:bg-slate-800/40 text-slate-200 border border-slate-700 hover:border-slate-600 transition-colors duration-150 rounded-lg',
  },
} as const;

export const tokens = {
  typography,
  surfaces,
  borders,
  radii,
  shadows,
  status: statusTokens,
  interactive,
} as const;

export default tokens;
