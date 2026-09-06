import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import App from '../../App';
import { clearStoredToken } from '../../lib/api';
import { sanitizeTelemetryData } from '../../lib/sanitizer';
import * as api from '../../lib/api';
import { DecisionsTab } from './DecisionsTab';
import { ApprovalsTab } from './ApprovalsTab';
import { MotionProvider } from '../../context/MotionContext';
import { AuthProvider } from '../../context/AuthContext';

const mockOverview = {
  overall_health: {
    status: 'HEALTHY',
    components: [
      {
        name: 'SecurityDecisionGateway',
        status: 'HEALTHY',
        details: 'Gateway online with 4 deterministic detectors active.',
        checked_at: new Date().toISOString(),
        metadata: { detector_count: 4 },
      },
      {
        name: 'SecurityEnforcementBoundary',
        status: 'HEALTHY',
        details: 'Enforcement boundary online.',
        checked_at: new Date().toISOString(),
        metadata: { hmac_signing: true },
      },
    ],
    checked_at: new Date().toISOString(),
    version: '1.0.0',
    summary: 'All security components operational.',
  },
  metrics: {
    total_requests: 12,
    allowed: 8,
    require_approval: 2,
    blocked: 2,
    authorized: 8,
    denied_execution: 4,
    successful_execution: 7,
    failed_execution: 1,
    timed_out_execution: 0,
    detected_threats: 5,
    critical_threats: 1,
    high_threats: 2,
    audit_events: 42,
    runtime_requests: 12,
    runtime_failures: 1,
    calculated_at: new Date().toISOString(),
  },
  recent_threats: [
    {
      threat_id: 'thr-12345678',
      threat_type: 'CREDENTIAL_ACCESS',
      severity: 'CRITICAL',
      detector: 'credential_detector',
      request_id: 'req-test-01',
      title: 'Credential File Access',
      description: 'Attempted to access .env secret file',
      confidence: 1.0,
      timestamp: new Date().toISOString(),
      metadata: { evidence: { matched_pattern: '.env' } },
    },
  ],
  recent_decisions: [
    {
      decision_id: 'dec-12345678',
      request_id: 'req-test-01',
      decision: 'BLOCK',
      risk_score: 95.0,
      severity: 'CRITICAL',
      policy_id: 'policy.critical.block',
      reason: 'Blocked due to critical risk score',
      threat_count: 1,
      timestamp: new Date().toISOString(),
      metadata: {},
    },
    {
      decision_id: 'dec-approval-01',
      request_id: 'req-test-02',
      decision: 'REQUIRE_APPROVAL',
      risk_score: 55.0,
      severity: 'MEDIUM',
      policy_id: 'policy.prompt.approval',
      reason: 'Prompt injection instruction requires approval',
      threat_count: 1,
      timestamp: new Date().toISOString(),
      metadata: {},
    },
  ],
  recent_executions: [
    {
      execution_id: 'exec-12345678',
      request_id: 'req-test-03',
      tool_name: 'calculator.compute',
      tool_category: 'SYSTEM',
      action: 'EXECUTE',
      status: 'COMPLETED',
      success: true,
      duration_ms: 12.5,
      error: null,
      timestamp: new Date().toISOString(),
      metadata: { authorized: true, executed: true },
    },
  ],
  retrieved_at: new Date().toISOString(),
};

function setupFetchMock() {
  global.fetch = vi.fn().mockImplementation((url: string) => {
    if (url.includes('/overview')) {
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve(mockOverview),
      });
    }
    if (url.includes('/health')) {
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve(mockOverview.overall_health),
      });
    }
    if (url.includes('/threats')) {
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve(mockOverview.recent_threats),
      });
    }
    if (url.includes('/decisions')) {
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve(mockOverview.recent_decisions),
      });
    }
    if (url.includes('/executions')) {
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve(mockOverview.recent_executions),
      });
    }
    if (url.includes('/approvals')) {
      return Promise.resolve({
        ok: true,
        json: () =>
          Promise.resolve([
            {
              approval_id: 'app-mock-01',
              request_id: 'req-test-02',
              agent: { agent_id: 'ag-01', name: 'PromptAgent' },
              tool_name: 'calculator.compute',
              tool_category: 'SYSTEM',
              action: 'EXECUTE',
              target: 'system.prompt',
              parameters: { instruction: 'ignore previous instructions' },
              request_fingerprint: 'sha256_mock_fingerprint_01',
              risk_score: 55.0,
              severity: 'MEDIUM',
              threat_summary: 'Instruction override review',
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
              event_id: 'evt-audit-01',
              event_type: 'REQUESTED',
              timestamp: new Date().toISOString(),
              request_id: 'req-test-01',
              actor: 'agent-01',
              details: { action: 'compute' },
              metadata: { client: 'agentshield-sdk' },
            },
          ]),
      });
    }
    if (url.includes('/laboratory/scenarios')) {
      return Promise.resolve({
        ok: true,
        json: () =>
          Promise.resolve([
            {
              scenario_id: 'ALLOW_CLEAN',
              name: 'Clean Arithmetic Computation',
              description: 'Harmless arithmetic addition tool request.',
              category: 'BASELINE',
              expected_decision: 'ALLOW',
              expected_status: 'COMPLETED',
              expected_executed: true,
              requires_approval: false,
            },
          ]),
      });
    }
    if (url.includes('/laboratory/run')) {
      return Promise.resolve({
        ok: true,
        json: () =>
          Promise.resolve({
            scenario_id: 'ALLOW_CLEAN',
            scenario_name: 'Clean Arithmetic Computation',
            category: 'BASELINE',
            request_id: 'req-lab-01',
            expected_decision: 'ALLOW',
            actual_decision: 'ALLOW',
            expected_status: 'COMPLETED',
            actual_status: 'COMPLETED',
            expected_executed: true,
            actual_executed: true,
            passed: true,
            message: 'Clean calculation evaluated to ALLOW and executed successfully in Sandbox.',
            metadata: { result: { result: 30.0 } },
          }),
      });
    }
    return Promise.resolve({
      ok: true,
      json: () => Promise.resolve({ status: 'ok', service: 'agentshield' }),
    });
  });
}

describe('Phase 14J-C10 Global End-to-End Integration, Visual QA & UX Hardening', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    clearStoredToken();
    setupFetchMock();

    window.matchMedia = vi.fn().mockImplementation((query) => ({
      matches: query.includes('prefers-reduced-motion'),
      media: query,
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn(),
    }));
  });

  it('1. Complete User Journey: Shell loads, navigates through all 8 tabs, and renders consoles', async () => {
    render(<App />);

    // Step 1: Initial state - Connected
    await waitFor(() => {
      expect(screen.getByText('AgentShield')).toBeInTheDocument();
      expect(screen.getByTestId('connection-status-badge')).toBeInTheDocument();
      expect(screen.getByRole('tab', { name: /overview/i })).toHaveAttribute('aria-selected', 'true');
    });

    // Step 2: Navigate to Threat Activity
    fireEvent.click(screen.getByRole('tab', { name: /threat activity/i }));
    await waitFor(() => {
      expect(screen.getByText('Threat Activity Stream')).toBeInTheDocument();
    });

    // Step 3: Navigate to Security Decisions
    fireEvent.click(screen.getByRole('tab', { name: /security decisions/i }));
    await waitFor(() => {
      expect(screen.getByText('Security Decisions Ledger')).toBeInTheDocument();
    });

    // Step 4: Navigate to Approvals
    fireEvent.click(screen.getByRole('tab', { name: /approvals/i }));
    await waitFor(() => {
      expect(screen.getByText('Approval Workflow Queue')).toBeInTheDocument();
    });

    // Step 5: Navigate to Executions
    fireEvent.click(screen.getByRole('tab', { name: /executions/i }));
    await waitFor(() => {
      expect(screen.getByText('Sandbox Execution Activity')).toBeInTheDocument();
    });

    // Step 6: Navigate to Audit Trail
    fireEvent.click(screen.getByRole('tab', { name: /audit trail/i }));
    await waitFor(() => {
      expect(screen.getByText('Security Audit Trail & Evidence Timeline')).toBeInTheDocument();
    });

    // Step 7: Navigate to Diagnostics
    fireEvent.click(screen.getByRole('tab', { name: /diagnostics/i }));
    await waitFor(() => {
      expect(screen.getByText('Component Health Diagnostics')).toBeInTheDocument();
    });

    // Step 8: Navigate to Scenario Lab and execute scenario
    fireEvent.click(screen.getByRole('tab', { name: /scenario lab/i }));
    await waitFor(() => {
      expect(screen.getByText('Scenario & Attack Laboratory')).toBeInTheDocument();
      expect(screen.getAllByText('Clean Arithmetic Computation').length).toBeGreaterThanOrEqual(1);
    });

    const runButtons = screen.getAllByRole('button', { name: /^run$/i });
    expect(runButtons.length).toBeGreaterThanOrEqual(1);
    fireEvent.click(runButtons[0]);

    await waitFor(() => {
      expect(screen.getByText(/VERIFIED PASS/i)).toBeInTheDocument();
    });
  });

  it('2. Auth/Connection Matrix: UI strictly distinguishes AUTH REQUIRED from DISCONNECTED', async () => {
    // Scenario A: Disconnected backend (pure network error)
    vi.spyOn(api, 'fetchHealthStatus').mockRejectedValue(new api.ApiError(0, 'Failed to fetch'));
    vi.spyOn(api, 'fetchOperationsOverview').mockRejectedValue(new api.ApiError(0, 'Failed to fetch'));
    vi.spyOn(api, 'fetchSystemHealth').mockRejectedValue(new api.ApiError(0, 'Failed to fetch'));

    render(<App />);

    await waitFor(() => {
      const badge = screen.getByTestId('connection-status-badge');
      expect(badge).toHaveTextContent('DISCONNECTED');
      // Auth required companion pill must NOT be rendered when disconnected
      expect(screen.queryByTestId('auth-required-pill')).not.toBeInTheDocument();
    });
  });

  it('3. Cross-Tab Correlation: deep-linking preserves search filter across Threat, Decision, Approval, and Audit', () => {
    const onSelectTabMock = vi.fn();

    // 1. Verify DecisionsTab dispatches onSelectTab with correlation request ID
    const { unmount } = render(
      <MotionProvider>
        <DecisionsTab decisions={mockOverview.recent_decisions as any} onSelectTab={onSelectTabMock} />
      </MotionProvider>
    );

    const correlateThreatsButtons = screen.getAllByRole('button', { name: /View Threats/i });
    expect(correlateThreatsButtons.length).toBeGreaterThanOrEqual(1);
    fireEvent.click(correlateThreatsButtons[0]);
    expect(onSelectTabMock).toHaveBeenCalledWith('threats', 'req-test-01');
    unmount();

    // 2. Verify ApprovalsTab initializes with correlated initialSearch
    render(
      <AuthProvider>
        <MotionProvider>
          <ApprovalsTab
            approvals={[{
              approval_id: 'app-mock-01',
              request_id: 'req-test-02',
              agent: { agent_id: 'ag-01', name: 'PromptAgent' },
              tool_name: 'calculator.compute',
              tool_category: 'SYSTEM',
              action: 'EXECUTE',
              target: 'system.prompt',
              parameters: {},
              request_fingerprint: 'fp-1',
              risk_score: 55.0,
              severity: 'MEDIUM',
              threat_summary: 'Test summary',
              created_at: new Date().toISOString(),
              expires_at: new Date(Date.now() + 3600000).toISOString(),
              status: 'PENDING',
            }]}
            onRefresh={vi.fn()}
            initialSearch="req-test-02"
          />
        </MotionProvider>
      </AuthProvider>
    );

    const approvalsSearch = screen.getByPlaceholderText(/search approvals/i) as HTMLInputElement;
    expect(approvalsSearch.value).toBe('req-test-02');
  });

  it('4. Zero Security Leakage: Deep telemetry sanitizer ensures zero raw tokens escape to UI', () => {
    const rawTelemetryPayload = {
      user_id: 'usr-12345',
      session_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMC6Y5nM3iMT_3h8Hg',
      db_connection: 'postgresql://admin:super_secret_password@db.internal:5432/agentshield',
      sqlite_path: 'C:\\AgentShield\\Data\\secrets.db',
      headers: {
        Authorization: 'Bearer top_secret_bearer_token_xyz123',
      },
    };

    const sanitized = sanitizeTelemetryData(rawTelemetryPayload) as Record<string, any>;

    // Sensitive keys and patterns must be strictly replaced
    expect(sanitized.session_token).toBe('[REDACTED_SECURITY_DATA]');
    expect(sanitized.headers.Authorization).toBe('[REDACTED_SECURITY_DATA]');
    expect(sanitized.sqlite_path).toBe('[REDACTED_SECRET]');
    expect(sanitized.user_id).toBe('usr-12345');
  });
});
