import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Home } from './Home';
import { AuthProvider } from '../context/AuthContext';
import { MotionProvider } from '../context/MotionContext';
import { clearStoredToken } from '../lib/api';

const mockOverviewData = {
  overall_health: {
    status: 'HEALTHY',
    components: [
      {
        name: 'SecurityDecisionGateway',
        status: 'HEALTHY',
        details: 'Gateway active',
        checked_at: new Date().toISOString(),
        metadata: {},
      },
      {
        name: 'SecurityEnforcementBoundary',
        status: 'HEALTHY',
        details: 'Enforcement boundary active',
        checked_at: new Date().toISOString(),
        metadata: {},
      },
      {
        name: 'SandboxExecutionBoundary',
        status: 'HEALTHY',
        details: 'Sandbox boundary active',
        checked_at: new Date().toISOString(),
        metadata: {},
      },
      {
        name: 'SecureExecutionAdapter',
        status: 'HEALTHY',
        details: 'Adapter active',
        checked_at: new Date().toISOString(),
        metadata: {},
      },
      {
        name: 'ToolExecutionRegistry',
        status: 'HEALTHY',
        details: 'Registry active',
        checked_at: new Date().toISOString(),
        metadata: {},
      },
      {
        name: 'AgentRuntimeOrchestrator',
        status: 'HEALTHY',
        details: 'Orchestrator active',
        checked_at: new Date().toISOString(),
        metadata: {},
      },
      {
        name: 'SecurityAuditTrail',
        status: 'HEALTHY',
        details: 'Audit trail active',
        checked_at: new Date().toISOString(),
        metadata: {},
      },
    ],
    checked_at: new Date().toISOString(),
    version: '1.0.0',
    summary: 'All security components operational',
  },
  metrics: {
    total_requests: 25,
    allowed: 20,
    require_approval: 3,
    blocked: 2,
    authorized: 20,
    denied_execution: 5,
    successful_execution: 18,
    failed_execution: 2,
    timed_out_execution: 0,
    detected_threats: 4,
    critical_threats: 1,
    high_threats: 1,
    audit_events: 50,
    runtime_requests: 25,
    runtime_failures: 2,
    calculated_at: new Date().toISOString(),
  },
  recent_threats: [
    {
      threat_id: 'thr-101',
      threat_type: 'CREDENTIAL_ACCESS',
      severity: 'CRITICAL',
      detector: 'cred_detector',
      request_id: 'req-101',
      title: 'Credential Access',
      description: 'Attempted to read secrets',
      confidence: 0.98,
      timestamp: new Date().toISOString(),
      metadata: {},
    },
  ],
  recent_decisions: [
    {
      decision_id: 'dec-101',
      request_id: 'req-101',
      decision: 'BLOCK',
      risk_score: 90.0,
      severity: 'CRITICAL',
      policy_id: 'policy.block.critical',
      reason: 'Critical credential access blocked',
      threat_count: 1,
      timestamp: new Date().toISOString(),
      metadata: {},
    },
  ],
  recent_executions: [
    {
      execution_id: 'exec-101',
      request_id: 'req-101',
      tool_name: 'calculator.compute',
      tool_category: 'SYSTEM',
      action: 'EXECUTE',
      status: 'COMPLETED',
      success: true,
      duration_ms: 10,
      error: null,
      timestamp: new Date().toISOString(),
      metadata: {},
    },
  ],
  retrieved_at: new Date().toISOString(),
};

const renderHome = () => {
  return render(
    <AuthProvider>
      <MotionProvider>
        <Home />
      </MotionProvider>
    </AuthProvider>
  );
};

describe('AgentShield Console Shell, Navigation & Badges (Phase 14J-C3)', () => {
  beforeEach(() => {
    window.scrollTo = vi.fn();
    clearStoredToken();
    vi.restoreAllMocks();

    global.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes('/overview')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(mockOverviewData),
        });
      }
      if (url.includes('/health')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(mockOverviewData.overall_health),
        });
      }
      if (url.includes('/threats')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(mockOverviewData.recent_threats),
        });
      }
      if (url.includes('/decisions')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(mockOverviewData.recent_decisions),
        });
      }
      if (url.includes('/executions')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(mockOverviewData.recent_executions),
        });
      }
      if (url.includes('/approvals')) {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve([
              {
                approval_id: 'app-01',
                request_id: 'req-01',
                agent: { agent_id: 'ag-01', name: 'PromptAgent' },
                tool_name: 'calculator.compute',
                tool_category: 'SYSTEM',
                action: 'EXECUTE',
                target: 'system.prompt',
                parameters: {},
                request_fingerprint: 'sha256_dummy',
                risk_score: 60.0,
                severity: 'HIGH',
                threat_summary: 'Pending approval evaluation',
                created_at: new Date().toISOString(),
                expires_at: new Date(Date.now() + 3600000).toISOString(),
                status: 'PENDING',
              },
            ]),
        });
      }
      if (url.includes('/audit')) {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve([
              {
                event_id: 'evt-01',
                event_type: 'AUTHENTICATION_SUCCESS',
                timestamp: new Date().toISOString(),
                source_component: 'AuthenticationService',
                action_attempted: 'LOGIN',
                decision: 'ALLOW',
                details: {},
                risk_level: 'LOW',
              },
            ]),
        });
      }
      if (url.includes('/laboratory/scenarios')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve([]),
        });
      }
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ status: 'ok', service: 'agentshield' }),
      });
    });
  });

  it('1. Renders elevated console header command bar with brand, environment, and status', async () => {
    renderHome();

    // Brand and console title
    expect(screen.getByText('AgentShield')).toBeInTheDocument();
    expect(screen.getByText('Security Operations Console')).toBeInTheDocument();
    expect(screen.getByText(/Autonomous Security Gateway/i)).toBeInTheDocument();

    // Environment Indicator
    expect(screen.getByTestId('environment-badge')).toBeInTheDocument();

    // Connection status badge
    await waitFor(() => {
      const connBadge = screen.getByTestId('connection-status-badge');
      expect(connBadge).toHaveTextContent('HEALTHY');
    });

    // Auto-refresh control and manual refresh button
    expect(screen.getByText('Live (5s)')).toBeInTheDocument();
    expect(screen.getByTitle('Refresh now')).toBeInTheDocument();
  });

  it('2. Renders all 8 console navigation tabs with accessible ARIA tablist structure', async () => {
    renderHome();

    const tablist = screen.getByRole('tablist', { name: /console navigation/i });
    expect(tablist).toBeInTheDocument();

    const tabs = screen.getAllByRole('tab');
    expect(tabs.length).toBeGreaterThanOrEqual(8);

    // Verify key tabs exist
    expect(screen.getByText('Overview')).toBeInTheDocument();
    expect(screen.getByText('Threat Activity')).toBeInTheDocument();
    expect(screen.getByText('Security Decisions')).toBeInTheDocument();
    expect(screen.getByText('Approvals')).toBeInTheDocument();
    expect(screen.getByText('Executions')).toBeInTheDocument();
    expect(screen.getByText('Audit Trail')).toBeInTheDocument();
    expect(screen.getByText('Diagnostics')).toBeInTheDocument();
    expect(screen.getByText('Scenario Lab')).toBeInTheDocument();

    // Initial active tab is Overview
    const overviewTab = screen.getByRole('tab', { name: /overview/i });
    expect(overviewTab).toHaveAttribute('aria-selected', 'true');

    // Associated tabpanel
    const panel = screen.getByRole('tabpanel');
    expect(panel).toHaveAttribute('id', 'console-panel-overview');
  });

  it('3. Supports full keyboard navigation across tabs (ArrowRight, ArrowLeft, Home, End)', async () => {
    renderHome();

    const tablist = screen.getByRole('tablist', { name: /console navigation/i });

    // Focus first tab (Overview)
    const overviewTab = screen.getByRole('tab', { name: /overview/i });
    overviewTab.focus();
    expect(overviewTab).toHaveAttribute('aria-selected', 'true');

    // Press ArrowRight -> moves to Threat Activity
    fireEvent.keyDown(tablist, { key: 'ArrowRight' });
    await waitFor(() => {
      const threatTab = screen.getByRole('tab', { name: /threat activity/i });
      expect(threatTab).toHaveAttribute('aria-selected', 'true');
    });

    // Press ArrowLeft -> moves back to Overview
    fireEvent.keyDown(tablist, { key: 'ArrowLeft' });
    await waitFor(() => {
      expect(screen.getByRole('tab', { name: /overview/i })).toHaveAttribute('aria-selected', 'true');
    });

    // Press End -> moves to last tab (Scenario Lab)
    fireEvent.keyDown(tablist, { key: 'End' });
    await waitFor(() => {
      expect(screen.getByRole('tab', { name: /scenario lab/i })).toHaveAttribute('aria-selected', 'true');
    });

    // Press Home -> moves to first tab (Overview)
    fireEvent.keyDown(tablist, { key: 'Home' });
    await waitFor(() => {
      expect(screen.getByRole('tab', { name: /overview/i })).toHaveAttribute('aria-selected', 'true');
    });
  });

  it('4. Toggles responsive mobile navigation drawer and dismisses on Escape key', async () => {
    renderHome();

    // Mobile menu toggle button
    const toggleBtn = screen.getByTestId('mobile-menu-toggle');
    expect(toggleBtn).toHaveAttribute('aria-expanded', 'false');
    expect(screen.queryByTestId('mobile-nav-drawer')).not.toBeInTheDocument();

    // Click to open mobile menu
    fireEvent.click(toggleBtn);
    expect(toggleBtn).toHaveAttribute('aria-expanded', 'true');

    await waitFor(() => {
      expect(screen.getByTestId('mobile-nav-drawer')).toBeInTheDocument();
    });

    // Verify drawer contains tabs
    const drawer = screen.getByTestId('mobile-nav-drawer');
    expect(drawer).toHaveTextContent('Console Navigation');
    expect(drawer).toHaveTextContent('ESC to close');

    // Press Escape to dismiss
    fireEvent.keyDown(window, { key: 'Escape' });
    await waitFor(() => {
      expect(screen.queryByTestId('mobile-nav-drawer')).not.toBeInTheDocument();
    });
    expect(toggleBtn).toHaveAttribute('aria-expanded', 'false');
  });

  it('5. Toggles auto-refresh state with accessible aria-pressed feedback', async () => {
    renderHome();

    const autoRefreshBtn = screen.getByText('Live (5s)').closest('button');
    expect(autoRefreshBtn).toBeInTheDocument();
    expect(autoRefreshBtn).toHaveAttribute('aria-pressed', 'true');

    // Toggle off
    fireEvent.click(autoRefreshBtn!);
    expect(screen.getByText('Paused')).toBeInTheDocument();
    expect(autoRefreshBtn).toHaveAttribute('aria-pressed', 'false');

    // Toggle on
    fireEvent.click(autoRefreshBtn!);
    expect(screen.getByText('Live (5s)')).toBeInTheDocument();
    expect(autoRefreshBtn).toHaveAttribute('aria-pressed', 'true');
  });

  it('6. Semantic connection state distinction: displays AUTH REQUIRED companion pill when unauthenticated and backend is healthy', async () => {
    // Unauthenticated mock: protected endpoints return 401, health check returns 200
    global.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.endsWith('/health')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ status: 'ok', service: 'agentshield' }),
        });
      }
      if (url.includes('/api/v1/auth/me')) {
        return Promise.resolve({
          ok: false,
          status: 401,
          json: () => Promise.resolve({ detail: 'Not authenticated' }),
        });
      }
      if (url.includes('/operations/')) {
        return Promise.resolve({
          ok: false,
          status: 401,
          json: () => Promise.resolve({ detail: 'Authentication required' }),
        });
      }
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve({}),
      });
    });

    renderHome();

    // 1. Connection status remains HEALTHY
    await waitFor(() => {
      const connBadge = screen.getByTestId('connection-status-badge');
      expect(connBadge).toHaveTextContent('HEALTHY');
    });

    // 2. Auth Required companion pill is visible in the header
    await waitFor(() => {
      expect(screen.getByTestId('auth-required-pill')).toBeInTheDocument();
      expect(screen.getByTestId('auth-required-pill')).toHaveTextContent('AUTH REQUIRED');
    });

    // 3. Informative banner is shown
    expect(screen.getByText('Authentication Required')).toBeInTheDocument();
    expect(screen.getByText(/operations data requires an authenticated session/i)).toBeInTheDocument();
  });

  it('7. Security UI Audit: shell never renders sensitive tokens, authorization headers, or database paths', async () => {
    const { container } = renderHome();

    await waitFor(() => {
      expect(screen.getByText('AgentShield')).toBeInTheDocument();
    });

    const html = container.innerHTML;

    // Zero credential leakage in DOM
    expect(html).not.toMatch(/Bearer\s+[A-Za-z0-9-_]+/);
    expect(html).not.toMatch(/Authorization/i);
    expect(html).not.toMatch(/agentshield\.db/i);
    expect(html).not.toMatch(/C:\\/i);
    expect(html).not.toMatch(/\/var\/log/i);
    expect(html).not.toMatch(/Traceback/i);
  });

  it('8. Switches tabs cleanly and dynamically updates active tabpanel ARIA linkage', async () => {
    renderHome();

    await waitFor(() => {
      expect(screen.getByText('Approvals')).toBeInTheDocument();
    });

    // Click Approvals tab
    fireEvent.click(screen.getByRole('tab', { name: /approvals/i }));

    await waitFor(() => {
      const approvalsTab = screen.getByRole('tab', { name: /approvals/i });
      expect(approvalsTab).toHaveAttribute('aria-selected', 'true');
      const panel = screen.getByRole('tabpanel');
      expect(panel).toHaveAttribute('id', 'console-panel-approvals');
      expect(panel).toHaveAttribute('aria-labelledby', 'tab-approvals');
      expect(screen.getByText('Approval Workflow Queue')).toBeInTheDocument();
    });
  });

  it('9. Renders authenticated user identity with active session indicator and role badge', async () => {
    global.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes('/api/v1/auth/me')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () =>
            Promise.resolve({
              user_id: 'usr-sec-lead',
              username: 'lead_reviewer',
              display_name: 'Lead Reviewer',
              email: 'lead@agentshield.internal',
              roles: ['SECURITY_REVIEWER'],
              is_active: true,
              created_at: new Date().toISOString(),
            }),
        });
      }
      if (url.includes('/overview')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(mockOverviewData),
        });
      }
      if (url.includes('/health')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(mockOverviewData.overall_health),
        });
      }
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve([]),
      });
    });

    // Simulate stored token
    const { setStoredToken } = await import('../lib/api');
    setStoredToken('test-active-session-token');

    renderHome();

    await waitFor(() => {
      const userBadge = screen.getByTestId('authenticated-user-badge');
      expect(userBadge).toBeInTheDocument();
      expect(screen.getByText('Lead Reviewer')).toBeInTheDocument();
      const roleBadge = screen.getByTestId('user-role-badge');
      expect(roleBadge).toHaveTextContent('SECURITY_REVIEWER');
      expect(screen.getByLabelText('Session Active')).toBeInTheDocument();
    });
  });

  it('10. Operates reliably when prefers-reduced-motion is active', async () => {
    // Mock reduced motion
    window.matchMedia = vi.fn().mockImplementation((query: string) => ({
      matches: query.includes('prefers-reduced-motion: reduce'),
      media: query,
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn(),
    }));

    renderHome();

    // Verify console mounts and navigation functions instantaneously without animation errors
    expect(screen.getByText('AgentShield')).toBeInTheDocument();
    const threatsTab = screen.getByRole('tab', { name: /threat activity/i });
    fireEvent.click(threatsTab);

    await waitFor(() => {
      expect(threatsTab).toHaveAttribute('aria-selected', 'true');
    });
  });
});
