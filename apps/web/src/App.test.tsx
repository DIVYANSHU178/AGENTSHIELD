import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import App from './App';

const mockOverview = {
  overall_health: {
    status: 'HEALTHY',
    components: [
      {
        name: 'SecurityDecisionGateway',
        status: 'HEALTHY',
        details: 'Gateway online with 4 deterministic detectors active.',
        checked_at: new Date().toISOString(),
        metadata: { detector_count: 4, risk_engine_active: true },
      },
      {
        name: 'SecurityEnforcementBoundary',
        status: 'HEALTHY',
        details: 'Enforcement boundary online, cryptographically verifying authorizations.',
        checked_at: new Date().toISOString(),
        metadata: { hmac_signing: true },
      },
      {
        name: 'SandboxExecutionBoundary',
        status: 'HEALTHY',
        details: 'Sandbox containment online with default timeout 30.0s.',
        checked_at: new Date().toISOString(),
        metadata: { timeout_enforcement: true },
      },
      {
        name: 'SecureExecutionAdapter',
        status: 'HEALTHY',
        details: 'Secure execution adapter online with active enforcement boundary binding.',
        checked_at: new Date().toISOString(),
        metadata: { dispatch_enforcement: true },
      },
      {
        name: 'ToolExecutionRegistry',
        status: 'HEALTHY',
        details: 'Tool registry online with 5 explicitly registered safe tool contracts.',
        checked_at: new Date().toISOString(),
        metadata: { registered_tools_count: 5, contracts_validated: true },
      },
      {
        name: 'AgentRuntimeOrchestrator',
        status: 'HEALTHY',
        details: 'Runtime orchestrator online coordinating Gateway -> Enforcement -> Sandbox -> Audit.',
        checked_at: new Date().toISOString(),
        metadata: { pipeline_stages: 4 },
      },
      {
        name: 'SecurityAuditTrail',
        status: 'HEALTHY',
        details: 'Audit trail online with 42 recorded immutable events.',
        checked_at: new Date().toISOString(),
        metadata: { event_count: 42 },
      },
    ],
    checked_at: new Date().toISOString(),
    version: '1.0.0',
    summary: 'All 7 security components are operational.',
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

describe('Security Operations Console (Phase 10)', () => {
  beforeEach(() => {
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
      if (url.includes('/audit')) {
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

  it('renders Operations Console header and overview metrics', async () => {
    render(<App />);
    expect(screen.getByText('AgentShield')).toBeInTheDocument();
    expect(screen.getByText('Phase 10 Operations Console')).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText('Total Evaluations')).toBeInTheDocument();
      expect(screen.getByText('Allowed Requests')).toBeInTheDocument();
      expect(screen.getByText('Blocked Requests')).toBeInTheDocument();
    });
  });

  it('switches to Threats tab and renders threat stream items', async () => {
    render(<App />);
    await waitFor(() => {
      expect(screen.getByText('Threat Activity')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('Threat Activity'));

    await waitFor(() => {
      expect(screen.getByText('Threat Activity Stream')).toBeInTheDocument();
      expect(screen.getAllByText('CREDENTIAL_ACCESS').length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText('Attempted to access .env secret file')).toBeInTheDocument();
    });
  });

  it('switches to Decisions tab and verifies strict Phase 10 / Phase 11 invariants', async () => {
    render(<App />);
    await waitFor(() => {
      expect(screen.getAllByText('Security Decisions').length).toBeGreaterThanOrEqual(1);
    });

    fireEvent.click(screen.getAllByText('Security Decisions')[0]);

    await waitFor(() => {
      expect(screen.getByText('Security Decisions Ledger')).toBeInTheDocument();
      expect(screen.getByText(/Awaiting Approval Workflow \(Phase 11\)/i)).toBeInTheDocument();
      expect(screen.getAllByText(/Execution: NOT STARTED/i).length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText(/TERMINAL - BLOCK/i)).toBeInTheDocument();
      expect(screen.queryByRole('button', { name: /^approve/i })).not.toBeInTheDocument();
      expect(screen.queryByRole('button', { name: /^reject/i })).not.toBeInTheDocument();
      expect(screen.queryByRole('button', { name: /^override/i })).not.toBeInTheDocument();
    });
  });

  it('switches to Diagnostics tab and verifies component health cards', async () => {
    render(<App />);
    await waitFor(() => {
      expect(screen.getByText('Diagnostics')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('Diagnostics'));

    await waitFor(() => {
      expect(screen.getByText('Component Health Diagnostics')).toBeInTheDocument();
      expect(screen.getByText('SecurityDecisionGateway')).toBeInTheDocument();
      expect(screen.getByText('SecurityEnforcementBoundary')).toBeInTheDocument();
      expect(screen.getByText('ToolExecutionRegistry')).toBeInTheDocument();
      expect(screen.getByText(/Diagnostic checks/i)).toBeInTheDocument();
    });
  });
});
