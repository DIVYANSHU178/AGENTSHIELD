import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { DiagnosticsTab } from './DiagnosticsTab';
import { MotionProvider } from '../../context/MotionContext';
import { OverallSystemHealth } from '../../types';

const mockHealthData: OverallSystemHealth = {
  status: 'HEALTHY',
  version: '1.4.0',
  summary: 'All 7 core security enforcement components operational.',
  checked_at: '2026-09-05T12:00:00Z',
  components: [
    {
      name: 'SecurityDecisionGateway',
      status: 'HEALTHY',
      details: 'Gateway online with 4 deterministic detectors active.',
      checked_at: '2026-09-05T12:00:00Z',
      metadata: { detector_count: 4, risk_engine_active: true, latency_ms: 8.5 },
    },
    {
      name: 'SecurityEnforcementBoundary',
      status: 'HEALTHY',
      details: 'Enforcement boundary online, cryptographically verifying authorizations.',
      checked_at: '2026-09-05T12:00:00Z',
      metadata: { hmac_signing: true, token_validation: true },
    },
    {
      name: 'SandboxExecutionBoundary',
      status: 'HEALTHY',
      details: 'Sandbox containment online with default timeout 30.0s.',
      checked_at: '2026-09-05T12:00:00Z',
      metadata: { timeout_enforcement: true, default_timeout_s: 30.0 },
    },
    {
      name: 'SecureExecutionAdapter',
      status: 'HEALTHY',
      details: 'Secure execution adapter online with active enforcement boundary binding.',
      checked_at: '2026-09-05T12:00:00Z',
      metadata: { dispatch_enforcement: true, strict_boundary: true },
    },
    {
      name: 'ToolExecutionRegistry',
      status: 'HEALTHY',
      details: 'Tool registry online with 5 explicitly registered safe tool contracts.',
      checked_at: '2026-09-05T12:00:00Z',
      metadata: {
        registered_tools_count: 5,
        tools: ['calculator.compute', 'filesystem.read', 'database.query'],
        contracts_validated: true,
      },
    },
    {
      name: 'AgentRuntimeOrchestrator',
      status: 'HEALTHY',
      details: 'Runtime orchestrator online coordinating Gateway -> Enforcement -> Sandbox -> Audit.',
      checked_at: '2026-09-05T12:00:00Z',
      metadata: { pipeline_stages: 4, fail_closed: true },
    },
    {
      name: 'SecurityAuditTrail',
      status: 'HEALTHY',
      details: 'Audit trail online with 42 recorded immutable events.',
      checked_at: '2026-09-05T12:00:00Z',
      metadata: {
        event_count: 42,
        defensive_copying: true,
        secret_token: 'secret_jwt_token_12345',
        db_password: 'super_secret_db_pass',
      },
    },
  ],
};

const mockDegradedHealthData: OverallSystemHealth = {
  ...mockHealthData,
  status: 'DEGRADED',
  summary: 'One or more security components report degraded health warnings.',
  components: [
    ...mockHealthData.components.slice(0, 6),
    {
      name: 'SecurityAuditTrail',
      status: 'DEGRADED',
      details: 'Audit trail disk buffer approaching sync threshold (85% capacity).',
      checked_at: '2026-09-05T12:05:00Z',
      metadata: { event_count: 850, buffer_warning: true },
    },
  ],
};

const mockFailedHealthData: OverallSystemHealth = {
  ...mockHealthData,
  status: 'FAILED',
  summary: 'Critical subsystem failure: Enforcement boundary cryptographic verification unavailable.',
  components: [
    mockHealthData.components[0],
    {
      name: 'SecurityEnforcementBoundary',
      status: 'FAILED',
      details: 'Enforcement boundary key signing failure: cryptographic validation keys corrupted.',
      checked_at: '2026-09-05T12:10:00Z',
      metadata: { hmac_signing: false, key_error: true },
    },
    ...mockHealthData.components.slice(2),
  ],
};

describe('DiagnosticsTab System Health & Observability Console (Phase 14J-C8)', () => {
  const mockRefresh = vi.fn();
  const mockSignIn = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  const renderTab = (props = {}) => {
    return render(
      <MotionProvider>
        <DiagnosticsTab
          health={mockHealthData}
          onRefresh={mockRefresh}
          loading={false}
          {...props}
        />
      </MotionProvider>
    );
  };

  it('1. Renders Header with System Status, Invariant Notice, and Version', () => {
    renderTab();

    expect(screen.getByText('Component Health Diagnostics')).toBeInTheDocument();
    expect(screen.getByText(/SYSTEM OPERATIONAL/i)).toBeInTheDocument();
    expect(screen.getByText('v1.4.0')).toBeInTheDocument();
    expect(
      screen.getByText(/Deterministic, non-executing structural inspection across all 7 pipeline components/i)
    ).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /run health diagnostics/i })).toBeInTheDocument();
  });

  it('2. Triggers onRefresh callback when clicking Run Health Diagnostics', () => {
    renderTab();

    const refreshBtn = screen.getByRole('button', { name: /run health diagnostics/i });
    fireEvent.click(refreshBtn);
    expect(mockRefresh).toHaveBeenCalledTimes(1);
  });

  it('3. Disables refresh button and shows spinner state when loading', () => {
    renderTab({ loading: true });

    const refreshBtn = screen.getByRole('button', { name: /run health diagnostics/i });
    expect(refreshBtn).toBeDisabled();
    expect(screen.getByText(/Running Checks\.\.\./i)).toBeInTheDocument();
  });

  it('4. Renders quantified 5-KPI Metrics Strip with accurate subsystem counts', () => {
    renderTab();

    expect(screen.getByText('Total Subsystems')).toBeInTheDocument();
    expect(screen.getByText('7')).toBeInTheDocument(); // Total count
    expect(screen.getByText('7 / 7')).toBeInTheDocument(); // Operational count
    expect(screen.getByText('Non-Executing')).toBeInTheDocument(); // Inspection Invariant
    expect(screen.getByText(/Zero payload dispatch/i)).toBeInTheDocument();
  });

  it('5. Renders all 7 core security components in the grid matching architectural invariants', () => {
    renderTab();

    expect(screen.getByText('SecurityDecisionGateway')).toBeInTheDocument();
    expect(screen.getByText('SecurityEnforcementBoundary')).toBeInTheDocument();
    expect(screen.getByText('SandboxExecutionBoundary')).toBeInTheDocument();
    expect(screen.getByText('SecureExecutionAdapter')).toBeInTheDocument();
    expect(screen.getByText('ToolExecutionRegistry')).toBeInTheDocument();
    expect(screen.getByText('AgentRuntimeOrchestrator')).toBeInTheDocument();
    expect(screen.getByText('SecurityAuditTrail')).toBeInTheDocument();

    // Verify invariant note is displayed
    expect(screen.getByText(/Diagnostic checks/i)).toBeInTheDocument();
    expect(screen.getByText(/never execute tool handlers or user payloads/i)).toBeInTheDocument();
  });

  it('6. Renders subsystem layers and latency when exposed', () => {
    renderTab();

    expect(screen.getByText('Detection & Evaluation')).toBeInTheDocument();
    expect(screen.getByText('Cryptographic Authorization')).toBeInTheDocument();
    expect(screen.getByText('Isolated Containment')).toBeInTheDocument();
    expect(screen.getByText('Runtime Dispatch')).toBeInTheDocument();
    expect(screen.getByText('Tool Contracts')).toBeInTheDocument();
    expect(screen.getByText('Pipeline Orchestration')).toBeInTheDocument();
    expect(screen.getByText('Forensic Persistence')).toBeInTheDocument();

    // SecurityDecisionGateway has latency_ms: 8.5
    expect(screen.getByText('Latency: 8.5ms')).toBeInTheDocument();
  });

  it('7. Filters components by search query and clears search', () => {
    renderTab();

    const searchInput = screen.getByLabelText(/filter components by name or details/i);
    fireEvent.change(searchInput, { target: { value: 'Registry' } });

    expect(screen.getByText('ToolExecutionRegistry')).toBeInTheDocument();
    expect(screen.queryByText('SecurityDecisionGateway')).not.toBeInTheDocument();
    expect(screen.queryByText('SecurityAuditTrail')).not.toBeInTheDocument();

    // Clear search using clear button
    const clearBtn = screen.getByLabelText(/clear search/i);
    fireEvent.click(clearBtn);

    expect(screen.getByText('SecurityDecisionGateway')).toBeInTheDocument();
    expect(screen.getByText('ToolExecutionRegistry')).toBeInTheDocument();
  });

  it('8. Filters components by status and shows empty state when no matches found', () => {
    renderTab();

    // Filter by Degraded when 0 are degraded in healthy data
    const healthyFilter = screen.getByRole('button', { name: /^healthy/i });
    expect(healthyFilter).toBeInTheDocument();
    fireEvent.click(healthyFilter);

    expect(screen.getByText('SecurityDecisionGateway')).toBeInTheDocument();

    // Search for non-existing subsystem
    const searchInput = screen.getByLabelText(/filter components by name or details/i);
    fireEvent.change(searchInput, { target: { value: 'NonExistentSubsystemXYZ' } });

    expect(screen.getByText('No Components Found')).toBeInTheDocument();
    expect(screen.getByText(/No security subsystems match your filter criteria/i)).toBeInTheDocument();

    // Click Reset Filters
    const resetBtn = screen.getByRole('button', { name: /reset filters/i });
    fireEvent.click(resetBtn);

    expect(screen.getByText('SecurityDecisionGateway')).toBeInTheDocument();
  });

  it('9. Opens Subsystem Detail Drawer and dismisses via close button and Escape key', () => {
    renderTab();

    const inspectBtns = screen.getAllByRole('button', { name: /inspect .* subsystem/i });
    expect(inspectBtns.length).toBe(7);

    // Open first component detail (SecurityDecisionGateway)
    fireEvent.click(inspectBtns[0]);

    expect(screen.getByRole('dialog', { name: /diagnostic details for SecurityDecisionGateway/i })).toBeInTheDocument();
    expect(screen.getByText('Subsystem Architectural Role')).toBeInTheDocument();
    expect(screen.getByText('Diagnostic Status Report')).toBeInTheDocument();
    expect(screen.getByText('Authoritative Inspection Timestamp')).toBeInTheDocument();
    expect(screen.getByText('Inspected Subsystem Telemetry')).toBeInTheDocument();

    // Dismiss via Close button
    const closeBtn = screen.getByRole('button', { name: /close diagnostic details/i });
    fireEvent.click(closeBtn);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();

    // Reopen and dismiss via Escape key
    fireEvent.click(inspectBtns[0]);
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    fireEvent.keyDown(window, { key: 'Escape', code: 'Escape' });
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('10. Sanitizes sensitive credentials and secrets in telemetry inspection (Zero Leakage)', () => {
    renderTab();

    // Open SecurityAuditTrail which contains secret_token and db_password
    const inspectAuditBtn = screen.getByRole('button', { name: /inspect SecurityAuditTrail subsystem/i });
    fireEvent.click(inspectAuditBtn);

    expect(screen.getByRole('dialog')).toBeInTheDocument();

    // The raw secrets MUST NOT exist anywhere in the DOM
    expect(screen.queryByText(/secret_jwt_token_12345/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/super_secret_db_pass/i)).not.toBeInTheDocument();

    // Instead, redacted placeholders must be present
    expect(screen.getAllByText(/REDACTED_SECURITY_DATA/i).length).toBeGreaterThan(0);
  });

  it('11. Renders DEGRADED status correctly with warning badges and filter pill', () => {
    render(
      <MotionProvider>
        <DiagnosticsTab
          health={mockDegradedHealthData}
          onRefresh={mockRefresh}
          loading={false}
        />
      </MotionProvider>
    );

    expect(screen.getByText(/SYSTEM DEGRADED/i)).toBeInTheDocument();
    expect(screen.getByText('Degraded (1)')).toBeInTheDocument();

    // Filter to degraded
    fireEvent.click(screen.getByText('Degraded (1)'));
    expect(screen.getByText('SecurityAuditTrail')).toBeInTheDocument();
    expect(screen.queryByText('SecurityDecisionGateway')).not.toBeInTheDocument();
  });

  it('12. Renders FAILED status correctly with critical alerts and failed badges', () => {
    render(
      <MotionProvider>
        <DiagnosticsTab
          health={mockFailedHealthData}
          onRefresh={mockRefresh}
          loading={false}
        />
      </MotionProvider>
    );

    expect(screen.getByText(/SYSTEM CRITICAL/i)).toBeInTheDocument();
    expect(screen.getByText('Failed (1)')).toBeInTheDocument();

    // Filter to failed
    fireEvent.click(screen.getByText('Failed (1)'));
    expect(screen.getByText('SecurityEnforcementBoundary')).toBeInTheDocument();
    expect(screen.queryByText('SecurityDecisionGateway')).not.toBeInTheDocument();
  });

  it('13. Renders LoadingState when health is null and loading is true', () => {
    render(
      <MotionProvider>
        <DiagnosticsTab
          health={null}
          onRefresh={mockRefresh}
          loading={true}
        />
      </MotionProvider>
    );

    expect(screen.getByText('Inspecting Subsystem Health')).toBeInTheDocument();
    expect(screen.getByText(/Diagnostic checks in progress\.\.\./i)).toBeInTheDocument();
  });

  it('14. Renders AuthRequiredState when health is null and authRequired is true', () => {
    render(
      <MotionProvider>
        <DiagnosticsTab
          health={null}
          onRefresh={mockRefresh}
          loading={false}
          authRequired={true}
          onSignIn={mockSignIn}
        />
      </MotionProvider>
    );

    expect(screen.getByText('Diagnostics Access Protected')).toBeInTheDocument();
    const signInBtn = screen.getByRole('button', { name: /sign in to access/i });
    expect(signInBtn).toBeInTheDocument();
    fireEvent.click(signInBtn);
    expect(mockSignIn).toHaveBeenCalledTimes(1);
  });

  it('15. Renders BackendUnavailableState when health is null and not loading/auth', () => {
    render(
      <MotionProvider>
        <DiagnosticsTab
          health={null}
          onRefresh={mockRefresh}
          loading={false}
          authRequired={false}
        />
      </MotionProvider>
    );

    expect(screen.getByText('Diagnostics Telemetry Unavailable')).toBeInTheDocument();
    const retryBtn = screen.getByRole('button', { name: /retry connection/i });
    expect(retryBtn).toBeInTheDocument();
    fireEvent.click(retryBtn);
    expect(mockRefresh).toHaveBeenCalledTimes(1);
  });
});
