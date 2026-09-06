import { render, screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { EnvironmentBadge, resolveEnvironment } from './EnvironmentBadge';


describe('EnvironmentBadge and resolveEnvironment', () => {
  it('resolves explicit environment overrides correctly', () => {
    expect(resolveEnvironment('qa')).toBe('qa');
    expect(resolveEnvironment('QA')).toBe('qa');
    expect(resolveEnvironment('dev')).toBe('development');
    expect(resolveEnvironment('development')).toBe('development');
    expect(resolveEnvironment('local')).toBe('development');
    expect(resolveEnvironment('prod')).toBe('production');
    expect(resolveEnvironment('production')).toBe('production');
    expect(resolveEnvironment('test')).toBe('test');
    expect(resolveEnvironment('testing')).toBe('test');
  });

  it('renders QA ENVIRONMENT badge with amber styling and accessible label', () => {
    render(<EnvironmentBadge environment="qa" />);
    const badge = screen.getByTestId('environment-badge');
    expect(badge).toBeInTheDocument();
    expect(screen.getByText('QA ENVIRONMENT')).toBeInTheDocument();
    expect(badge).toHaveAttribute('aria-label', 'Environment: QA ENVIRONMENT');
    expect(badge.className).toContain('text-amber-300');
  });

  it('renders DEV CONSOLE badge with blue styling', () => {
    render(<EnvironmentBadge environment="development" />);
    const badge = screen.getByTestId('environment-badge');
    expect(badge).toBeInTheDocument();
    expect(screen.getByText('DEV CONSOLE')).toBeInTheDocument();
    expect(badge.className).toContain('text-blue-300');
  });

  it('renders PRODUCTION badge with emerald styling', () => {
    render(<EnvironmentBadge environment="production" />);
    const badge = screen.getByTestId('environment-badge');
    expect(badge).toBeInTheDocument();
    expect(screen.getByText('PRODUCTION')).toBeInTheDocument();
    expect(badge.className).toContain('text-emerald-300');
  });

  it('renders TEST HARNESS badge with slate styling', () => {
    render(<EnvironmentBadge environment="test" />);
    const badge = screen.getByTestId('environment-badge');
    expect(badge).toBeInTheDocument();
    expect(screen.getByText('TEST HARNESS')).toBeInTheDocument();
    expect(badge.className).toContain('text-slate-300');
  });
});
