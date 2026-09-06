import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { OverviewTab } from './OverviewTab';
import { MotionProvider } from '../../context/MotionContext';
import { OperationsOverview } from '../../types';

const mockOverview: OperationsOverview = {
  overall_health: {
    status: 'HEALTHY',
    components: [
      {
        name: 'SecurityDecisionGateway',
        status: 'HEALTHY',
        details: 'Gateway active with 4 detectors',
        checked_at: '2026-09-05T12:00:00Z',
        metadata: {},
      },
      {
        name: 'SecurityEnforcementBoundary',
        status: 'HEALTHY',
        details: 'Enforcement boundary active',
        checked_at: '2026-09-05T12:00:00Z',
        metadata: {},
      },
      {
        name: 'SandboxExecutionBoundary',
        status: 'HEALTHY',
        details: 'Sandbox boundary active',
        checked_at: '2026-09-05T12:00:00Z',
        metadata: {},
      },
      {
        name: 'SecureExecutionAdapter',
        status: 'HEALTHY',
        details: 'Adapter active',
        checked_at: '2026-09-05T12:00:00Z',
        metadata: {},
      },
      {
        name: 'ToolExecutionRegistry',
        status: 'HEALTHY',
        details: 'Registry active',
        checked_at: '2026-09-05T12:00:00Z',
        metadata: {},
      },
      {
        name: 'AgentRuntimeOrchestrator',
        status: 'HEALTHY',
        details: 'Orchestrator active',
        checked_at: '2026-09-05T12:00:00Z',
        metadata: {},
      },
      {
        name: 'SecurityAuditTrail',
        status: 'HEALTHY',
        details: 'Audit trail active',
        checked_at: '2026-09-05T12:00:00Z',
        metadata: {},
      },
    ],
    checked_at: '2026-09-05T12:00:00Z',
    version: '1.4.0',
    summary: 'All 7 core security enforcement components operational.',
  },
  metrics: {
    total_requests: 48,
    allowed: 35,
    require_approval: 4,
    blocked: 9,
    authorized: 35,
    denied_execution: 9,
    successful_execution: 34,
    failed_execution: 1,
    timed_out_execution: 0,
    detected_threats: 12,
    critical_threats: 2,
    high_threats: 3,
    audit_events: 96,
    runtime_requests: 48,
    runtime_failures: 1,
    calculated_at: '2026-09-05T12:00:00Z',
  },
  recent_threats: [
    {
      threat_id: 'thr-8899',
      threat_type: 'CREDENTIAL_ACCESS',
      severity: 'CRITICAL',
      detector: 'env_secret_detector',
      request_id: 'req-alpha-01',
      title: 'Environment Credential Exfiltration',
      description: 'Attempted read access on .env credential file',
      confidence: 0.99,
      timestamp: '2026-09-05T12:01:00Z',
      metadata: {},
    },
    {
      threat_id: 'thr-8898',
      threat_type: 'PROMPT_INJECTION',
      severity: 'HIGH',
      detector: 'instruction_override_detector',
      request_id: 'req-alpha-02',
      title: 'Instruction Override Injected',
      description: 'System prompt override pattern detected in parameters',
      confidence: 0.92,
      timestamp: '2026-09-05T12:00:30Z',
      metadata: {},
    },
  ],
  recent_decisions: [
    {
      decision_id: 'dec-8899',
      request_id: 'req-alpha-01',
      decision: 'BLOCK',
      risk_score: 95.0,
      severity: 'CRITICAL',
      policy_id: 'policy.critical.credential_access',
      reason: 'Automated block due to critical credential exposure attempt',
      threat_count: 1,
      timestamp: '2026-09-05T12:01:01Z',
      metadata: {},
    },
    {
      decision_id: 'dec-8898',
      request_id: 'req-alpha-02',
      decision: 'REQUIRE_APPROVAL',
      risk_score: 65.0,
      severity: 'HIGH',
      policy_id: 'policy.approval.prompt_override',
      reason: 'Instruction override requires security reviewer verification',
      threat_count: 1,
      timestamp: '2026-09-05T12:00:31Z',
      metadata: {},
    },
  ],
  recent_executions: [
    {
      execution_id: 'exec-8899',
      request_id: 'req-alpha-03',
      tool_name: 'safe_calculator.compute',
      tool_category: 'SYSTEM',
      action: 'EXECUTE',
      status: 'COMPLETED',
      success: true,
      duration_ms: 12.4,
      error: null,
      timestamp: '2026-09-05T12:01:10Z',
      metadata: {},
    },
  ],
  retrieved_at: '2026-09-05T12:01:15Z',
};

describe('OverviewTab Security Operations Dashboard (Phase 14J-C4)', () => {
  const mockSelectTab = vi.fn();
  const mockSignIn = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  const renderOverview = (props = {}) => {
    return render(
      <MotionProvider>
        <OverviewTab
          overview={mockOverview}
          onSelectTab={mockSelectTab}
          {...props}
        />
      </MotionProvider>
    );
  };

  it('1. Renders Global Health status strip with operational summary and diagnostics link', () => {
    renderOverview();

    expect(screen.getByText(/System Status: HEALTHY/i)).toBeInTheDocument();
    expect(screen.getByText('v1.4.0')).toBeInTheDocument();
    expect(screen.getByText(/7\/7 Components Operational/i)).toBeInTheDocument();
    expect(screen.getByText(/All 7 core security enforcement components operational/i)).toBeInTheDocument();

    const diagBtn = screen.getByRole('button', { name: /view component diagnostics \(7\)/i });
    expect(diagBtn).toBeInTheDocument();
    fireEvent.click(diagBtn);
    expect(mockSelectTab).toHaveBeenCalledWith('diagnostics');
  });

  it('2. Renders all 7 stages of the Security Enforcement Pipeline in sequence', () => {
    renderOverview();

    const pipelineRegion = screen.getByRole('region', { name: /security enforcement pipeline/i });
    expect(pipelineRegion).toBeInTheDocument();

    // Verify all 7 core stages exist in the pipeline
    expect(screen.getByText('THREAT')).toBeInTheDocument();
    expect(screen.getByText('RISK')).toBeInTheDocument();
    expect(screen.getByText('POLICY')).toBeInTheDocument();
    expect(screen.getByText('APPROVAL')).toBeInTheDocument();
    expect(screen.getByText('ENFORCEMENT')).toBeInTheDocument();
    expect(screen.getByText('EXECUTION')).toBeInTheDocument();
    expect(screen.getByText('AUDIT')).toBeInTheDocument();

    // Verify sequential phase numbers 01 to 07
    expect(screen.getByText('01')).toBeInTheDocument();
    expect(screen.getByText('02')).toBeInTheDocument();
    expect(screen.getByText('03')).toBeInTheDocument();
    expect(screen.getByText('04')).toBeInTheDocument();
    expect(screen.getByText('05')).toBeInTheDocument();
    expect(screen.getByText('06')).toBeInTheDocument();
    expect(screen.getByText('07')).toBeInTheDocument();

    // Verify stage metrics
    expect(screen.getByText('12 Detected')).toBeInTheDocument();
    expect(screen.getByText('48 Decisions')).toBeInTheDocument();
    expect(screen.getByText('0 Pending Review')).toBeInTheDocument();
    expect(screen.getByText('35 Authorized')).toBeInTheDocument();
    expect(screen.getByText('34 Completed')).toBeInTheDocument();
    expect(screen.getByText('96 Records')).toBeInTheDocument();
  });

  it('3. Clicking pipeline stages triggers drill-down navigation to the corresponding tab', () => {
    renderOverview();

    // Click THREAT stage -> navigates to threats tab
    const threatBtn = screen.getByRole('button', { name: /pipeline stage 01: threat/i });
    fireEvent.click(threatBtn);
    expect(mockSelectTab).toHaveBeenCalledWith('threats');

    // Click APPROVAL stage -> navigates to approvals tab
    const approvalBtn = screen.getByRole('button', { name: /pipeline stage 04: approval/i });
    fireEvent.click(approvalBtn);
    expect(mockSelectTab).toHaveBeenCalledWith('approvals');

    // Click AUDIT stage -> navigates to audit tab
    const auditBtn = screen.getByRole('button', { name: /pipeline stage 07: audit/i });
    fireEvent.click(auditBtn);
    expect(mockSelectTab).toHaveBeenCalledWith('audit');
  });

  it('4. Renders deterministic Security KPI counters matching backend metrics', () => {
    renderOverview();

    expect(screen.getByText('Total Evaluations')).toBeInTheDocument();
    expect(screen.getByText('Allowed Requests')).toBeInTheDocument();
    expect(screen.getByText('Approval-Gated Decisions')).toBeInTheDocument();
    expect(screen.getByText('Cumulative policy evaluations')).toBeInTheDocument();
    expect(screen.getByText('Blocked Requests')).toBeInTheDocument();
    expect(screen.getByText('Authorized Credentials')).toBeInTheDocument();
    expect(screen.getByText('Successful Executions')).toBeInTheDocument();
    expect(screen.getByText('Failed Executions')).toBeInTheDocument();
    expect(screen.getByText('Timed Out')).toBeInTheDocument();
    expect(screen.getByText('Denied Executions')).toBeInTheDocument();
    expect(screen.getByText('Threats Detected')).toBeInTheDocument();
    expect(screen.getByText('Critical Threats')).toBeInTheDocument();
    expect(screen.getByText('Audit Trail Records')).toBeInTheDocument();

    // Verify values from mock
    expect(screen.getByText('48')).toBeInTheDocument(); // total_requests
    expect(screen.getAllByText('35').length).toBeGreaterThanOrEqual(1); // allowed / authorized
    expect(screen.getAllByText('4').length).toBeGreaterThanOrEqual(1);  // require_approval
    expect(screen.getByText('96')).toBeInTheDocument(); // audit_events
  });

  it('5. Renders Recent Threats, Decisions, and Executions activity cards', () => {
    renderOverview();

    // Threat signals
    expect(screen.getByText(/Recent Threat Signals/i)).toBeInTheDocument();
    expect(screen.getByText('CREDENTIAL_ACCESS')).toBeInTheDocument();
    expect(screen.getByText('Environment Credential Exfiltration')).toBeInTheDocument();
    expect(screen.getByText('Detector: env_secret_detector')).toBeInTheDocument();

    // Security decisions
    expect(screen.getByText(/Security Decisions/i)).toBeInTheDocument();
    expect(screen.getByText(/policy\.critical\.credential_access/i)).toBeInTheDocument();
    expect(screen.getByText('Risk: 95.0')).toBeInTheDocument();

    // Executions
    expect(screen.getByText(/Sandbox Executions/i)).toBeInTheDocument();
    expect(screen.getByText('safe_calculator.compute')).toBeInTheDocument();
    expect(screen.getByText(/12.4 ms/i)).toBeInTheDocument();
  });

  it('6. Activity cards "View All" buttons navigate to the respective tabs', () => {
    renderOverview();

    const viewAllButtons = screen.getAllByRole('button', { name: /view all/i });
    expect(viewAllButtons.length).toBe(3);

    // Threats View All
    fireEvent.click(viewAllButtons[0]);
    expect(mockSelectTab).toHaveBeenCalledWith('threats');

    // Decisions View All
    fireEvent.click(viewAllButtons[1]);
    expect(mockSelectTab).toHaveBeenCalledWith('decisions');

    // Executions View All
    fireEvent.click(viewAllButtons[2]);
    expect(mockSelectTab).toHaveBeenCalledWith('executions');
  });

  it('7. Renders empty states gracefully when activity streams contain no records', () => {
    const emptyOverview: OperationsOverview = {
      ...mockOverview,
      recent_threats: [],
      recent_decisions: [],
      recent_executions: [],
    };

    render(
      <MotionProvider>
        <OverviewTab overview={emptyOverview} onSelectTab={mockSelectTab} />
      </MotionProvider>
    );

    expect(screen.getByText(/No threat signals recorded\./i)).toBeInTheDocument();
    expect(screen.getByText(/No security decisions recorded yet\./i)).toBeInTheDocument();
    expect(screen.getByText(/No runtime tool executions recorded yet\./i)).toBeInTheDocument();
  });

  it('8. Renders LoadingState when overview is null and unauthenticated is false', () => {
    render(
      <MotionProvider>
        <OverviewTab overview={null} onSelectTab={mockSelectTab} />
      </MotionProvider>
    );

    expect(screen.getByText(/Processing Security Operations Overview/i)).toBeInTheDocument();
    expect(screen.getByText(/Retrieving telemetry from the AgentShield authoritative security gateway/i)).toBeInTheDocument();
  });

  it('9. Renders AuthRequiredState with "Operations Data Locked" when authRequired is true', () => {
    render(
      <MotionProvider>
        <OverviewTab
          overview={null}
          onSelectTab={mockSelectTab}
          authRequired={true}
          onSignIn={mockSignIn}
        />
      </MotionProvider>
    );

    expect(screen.getByText('Operations Data Locked')).toBeInTheDocument();
    expect(screen.getByText(/Please sign in with your AgentShield identity/i)).toBeInTheDocument();

    const signInBtn = screen.getByRole('button', { name: /sign in/i });
    fireEvent.click(signInBtn);
    expect(mockSignIn).toHaveBeenCalled();
  });

  it('10. Security UI Audit: Overview tab never renders sensitive authorization headers, bearer tokens, or DB paths', () => {
    const { container } = renderOverview();

    const html = container.innerHTML;

    expect(html).not.toMatch(/Bearer\s+[A-Za-z0-9-_]+/);
    expect(html).not.toMatch(/Authorization/i);
    expect(html).not.toMatch(/password/i);
    expect(html).not.toMatch(/agentshield\.db/i);
    expect(html).not.toMatch(/C:\\/i);
    expect(html).not.toMatch(/\/var\/log/i);
  });

  it('11. Semantic Distinction: Distinguishes cumulative Approval-Gated Decisions from active Pending Review queue depth', () => {
    const mockApprovalsWithPending = [
      {
        approval_id: 'app-991',
        request_id: 'req-001',
        tool_name: 'privileged_access',
        action: 'EXECUTE',
        status: 'PENDING',
        severity: 'HIGH',
        risk_score: 85,
        parameters: {},
        created_at: '2026-09-05T12:00:00Z',
        expires_at: '2026-09-05T12:15:00Z',
      },
    ];

    render(
      <MotionProvider>
        <OverviewTab
          overview={{
            ...mockOverview,
            metrics: {
              ...mockOverview.metrics,
              require_approval: 2378,
            },
          }}
          onSelectTab={mockSelectTab}
          approvals={mockApprovalsWithPending as any}
        />
      </MotionProvider>
    );

    // Cumulative volume in KPI card
    expect(screen.getByText('Approval-Gated Decisions')).toBeInTheDocument();
    expect(screen.getByText('2378')).toBeInTheDocument();
    expect(screen.getByText('Cumulative policy evaluations')).toBeInTheDocument();

    // Actual active pending queue in Pipeline Stage 04
    expect(screen.getByText('1 Pending Review')).toBeInTheDocument();
    expect(screen.getByText(/Human Action Required/i)).toBeInTheDocument();
  });
});
