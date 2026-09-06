import { describe, it, expect } from 'vitest';
import {
  typography,
  surfaces,
  borders,
  radii,
  shadows,
  statusTokens,
  interactive,
  tokens,
} from './tokens';

describe('AgentShield Design System Tokens', () => {
  it('exports typography tokens with required sans and mono font families', () => {
    expect(typography.fontFamily.sans).toContain('system-ui');
    expect(typography.fontFamily.mono).toContain('monospace');
    expect(typography.fontSize.xs).toBe('0.75rem');
    expect(typography.fontSize['2xl']).toBe('1.5rem');
    expect(typography.fontWeight.bold).toBe('700');
  });

  it('exports dark console surfaces hierarchy', () => {
    expect(surfaces.canvas).toBe('#090d16');
    expect(surfaces.panel).toBe('#0d131f');
    expect(surfaces.card).toBe('#111827');
    expect(surfaces.cardSubtle).toBe('#0f172a');
    expect(surfaces.elevated).toBe('#1e293b');
    expect(surfaces.overlay).toContain('rgba');
  });

  it('exports standard border, radius, and shadow definitions', () => {
    expect(borders.default).toBe('border-slate-800');
    expect(borders.glowCyan).toContain('cyan');
    expect(radii.sm).toBe('0.375rem');
    expect(radii.lg).toBe('0.75rem');
    expect(radii.full).toBe('9999px');
    expect(shadows.glowCyan).toContain('rgba(6, 182, 212');
  });


  it('exports status tokens covering healthy, warning, danger, info, neutral, and purple', () => {
    const requiredStatuses = ['healthy', 'warning', 'danger', 'info', 'neutral', 'purple'] as const;
    requiredStatuses.forEach((status) => {
      const entry = statusTokens[status];
      expect(entry).toBeDefined();
      expect(entry.color).toMatch(/^#[0-9a-fA-F]{6}$/);
      expect(entry.bg).toContain('bg-');
      expect(entry.border).toContain('border-');
      expect(entry.text).toContain('text-');
      expect(entry.dot).toContain('bg-');
    });
  });

  it('exports interactive tokens for focus rings, disabled states, and button variants', () => {
    expect(interactive.focusRing).toContain('focus-visible:ring-cyan-400');
    expect(interactive.disabled).toContain('disabled:opacity-50');
    expect(interactive.button.primary).toContain('bg-blue-600');
    expect(interactive.button.danger).toContain('bg-rose-600');
    expect(interactive.button.secondary).toContain('bg-slate-800');
  });

  it('exports unified tokens bundle object', () => {
    expect(tokens.typography).toBe(typography);
    expect(tokens.surfaces).toBe(surfaces);
    expect(tokens.status).toBe(statusTokens);
    expect(tokens.interactive).toBe(interactive);
  });
});
