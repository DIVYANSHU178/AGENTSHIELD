import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { ThreatsTab } from './ThreatsTab';
import { DecisionsTab } from './DecisionsTab';
import { ExecutionsTab } from './ExecutionsTab';
import { MotionProvider } from '../../context/MotionContext';
import {
  ThreatActivityItem,
  SecurityDecisionItem,
  ExecutionActivityItem,
} from '../../types';

const mockThreats: ThreatActivityItem[] = [
  {
    threat_id: 'thr-crit-001',
    threat_type: 'CREDENTIAL_ACCESS',
    severity: 'CRITICAL',
    detector: 'credential_detector',
    request_id: 'req-corr-101',
    title: 'Credential File Access Attempt',
    description: 'Agent attempted to read system .env credentials file',
    confidence: 0.99,
    timestamp: '2026-09-05T12:00:00Z',
    metadata: {
      matched_file: '.env',
      user_password: 'super_secret_plain_text_password',
      api_token: 'secret_token_123',
    },
  },
  {
    threat_id: 'thr-high-002',
    threat_type: 'PROMPT_INJECTION',
    severity: 'HIGH',
    detector: 'injection_detector',
    request_id: 'req-corr-102',
    title: 'System Instruction Override',
    description: 'Input contained malicious prompt injection pattern',
    confidence: 0.85,
    timestamp: '2026-09-05T12:01:00Z',
    metadata: { pattern: 'ignore previous instructions' },
  },
  {
    threat_id: 'thr-med-003',
    threat_type: 'SENSITIVE_DATA_ACCESS',
    severity: 'MEDIUM',
    detector: 'pii_detector',
    request_id: 'req-corr-103',
    title: 'Customer Record Query',
    description: 'Query touched sensitive email column',
    confidence: 0.65,
    timestamp: '2026-09-05T12:02:00Z',
  },
];

const mockDecisions: SecurityDecisionItem[] = [
  {
    decision_id: 'dec-blk-001',
    request_id: 'req-corr-101',
    decision: 'BLOCK',
    risk_score: 95.0,
    severity: 'CRITICAL',
    policy_id: 'policy.critical.block',
    reason: 'Zero-tolerance block triggered by critical credential access threat.',
    threat_count: 1,
    timestamp: '2026-09-05T12:00:01Z',
    metadata: {
      rule_triggered: 'BLOCK_CREDENTIAL_ACCESS',
      secret_key: 'internal_secret_token',
    },
  },
  {
    decision_id: 'dec-app-002',
    request_id: 'req-corr-102',
    decision: 'REQUIRE_APPROVAL',
    risk_score: 65.0,
    severity: 'HIGH',
    policy_id: 'policy.prompt.approval',
    reason: 'High risk prompt injection signal requires authorized security reviewer intervention.',
    threat_count: 1,
    timestamp: '2026-09-05T12:01:01Z',
    metadata: {},
  },
  {
    decision_id: 'dec-alw-003',
    request_id: 'req-corr-103',
    decision: 'ALLOW',
    risk_score: 25.0,
    severity: 'LOW',
    policy_id: 'policy.clean.default',
    reason: 'Risk evaluation within allowable bounded thresholds.',
    threat_count: 0,
    timestamp: '2026-09-05T12:02:01Z',
    metadata: {},
  },
];

const mockExecutions: ExecutionActivityItem[] = [
  {
    execution_id: 'exec-cmp-001',
    request_id: 'req-corr-103',
    tool_name: 'database.query',
    tool_category: 'DATABASE',
    action: 'QUERY',
    status: 'COMPLETED',
    success: true,
    duration_ms: 18.4,
    error: null,
    timestamp: '2026-09-05T12:02:02Z',
    metadata: {
      rows_returned: 5,
      db_password: 'internal_db_password',
    },
  },
  {
    execution_id: 'exec-den-002',
    request_id: 'req-corr-101',
    tool_name: 'file.read',
    tool_category: 'FILESYSTEM',
    action: 'READ',
    status: 'DENIED',
    success: false,
    duration_ms: 0.8,
    error: null,
    timestamp: '2026-09-05T12:00:02Z',
  },
  {
    execution_id: 'exec-fld-003',
    request_id: 'req-corr-104',
    tool_name: 'network.fetch',
    tool_category: 'NETWORK',
    action: 'DOWNLOAD',
    status: 'FAILED',
    success: false,
    duration_ms: 120.5,
    error: 'Connection refused: destination port 8080 unreachable',
    timestamp: '2026-09-05T12:03:00Z',
  },
  {
    execution_id: 'exec-tmo-004',
    request_id: 'req-corr-105',
    tool_name: 'code.execute',
    tool_category: 'CODE_EXECUTION',
    action: 'EXECUTE',
    status: 'TIMED_OUT',
    success: false,
    duration_ms: 5000.0,
    error: 'Execution budget exceeded: 5000ms timeout',
    timestamp: '2026-09-05T12:04:00Z',
  },
];

describe('Threat Activity Console Hardening (Phase 14J-C6)', () => {
  it('1. Renders Header, Lifecycle Stage indicator, and KPI metrics strip', () => {
    render(
      <MotionProvider>
        <ThreatsTab threats={mockThreats} />
      </MotionProvider>
    );

    expect(screen.getByText('Threat Activity Stream')).toBeInTheDocument();
    expect(screen.getByText(/Stage 1 of 7: Ingestion & Detection/i)).toBeInTheDocument();
    expect(screen.getByText('Total Signals')).toBeInTheDocument();
    expect(screen.getByText('Critical Threats')).toBeInTheDocument();
    expect(screen.getByText('High Severity')).toBeInTheDocument();
    expect(screen.getByText('Active Detectors')).toBeInTheDocument();

    // Verify KPI values: 3 total, 1 critical, 1 high, 1 medium/low, 3 detectors
    expect(screen.getAllByText('3').length).toBeGreaterThanOrEqual(1); // total signals or detectors
  });

  it('2. Filters threat stream by severity, type, and search term', () => {
    render(
      <MotionProvider>
        <ThreatsTab threats={mockThreats} />
      </MotionProvider>
    );

    // Initial state shows all 3 threats
    expect(screen.getByText('Credential File Access Attempt')).toBeInTheDocument();
    expect(screen.getByText('System Instruction Override')).toBeInTheDocument();
    expect(screen.getByText('Customer Record Query')).toBeInTheDocument();

    // Filter by CRITICAL severity
    const severitySelect = screen.getByLabelText(/Filter by Severity/i);
    fireEvent.change(severitySelect, { target: { value: 'CRITICAL' } });

    expect(screen.getByText('Credential File Access Attempt')).toBeInTheDocument();
    expect(screen.queryByText('System Instruction Override')).not.toBeInTheDocument();
    expect(screen.queryByText('Customer Record Query')).not.toBeInTheDocument();

    // Reset filters
    fireEvent.click(screen.getByText(/Reset Filters/i));
    expect(screen.getByText('System Instruction Override')).toBeInTheDocument();

    // Search by correlation ID
    const searchInput = screen.getByLabelText(/Search threats/i);
    fireEvent.change(searchInput, { target: { value: 'req-corr-102' } });

    expect(screen.queryByText('Credential File Access Attempt')).not.toBeInTheDocument();
    expect(screen.getByText('System Instruction Override')).toBeInTheDocument();
  });

  it('3. Opens technical investigation detail drawer and dismisses on Escape key', () => {
    render(
      <MotionProvider>
        <ThreatsTab threats={mockThreats} />
      </MotionProvider>
    );

    // Click investigate on first threat
    const investigateBtns = screen.getAllByRole('button', { name: /^investigate/i });
    fireEvent.click(investigateBtns[0]);

    // Drawer opens
    expect(screen.getByText('Threat Signal Investigation')).toBeInTheDocument();
    expect(screen.getByText(/Forensic Context/i)).toBeInTheDocument();
    expect(screen.getByText('thr-crit-001')).toBeInTheDocument();
    expect(screen.getByText('req-corr-101')).toBeInTheDocument();

    // Dismiss with Escape key
    fireEvent.keyDown(window, { key: 'Escape' });
    expect(screen.queryByText('Threat Signal Investigation')).not.toBeInTheDocument();
  });

  it('4. Redacts sensitive keys in rendered metadata (Security UI Audit)', () => {
    render(
      <MotionProvider>
        <ThreatsTab threats={mockThreats} />
      </MotionProvider>
    );

    // Open detail drawer
    const investigateBtns = screen.getAllByRole('button', { name: /^investigate/i });
    fireEvent.click(investigateBtns[0]);

    // Ensure raw secret values are NEVER present
    expect(screen.queryByText('super_secret_plain_text_password')).not.toBeInTheDocument();
    expect(screen.queryByText('secret_token_123')).not.toBeInTheDocument();

    // Check that redaction markers are rendered
    expect(screen.getAllByText(/\[REDACTED_SECURITY_DATA\]/i).length).toBeGreaterThanOrEqual(1);
  });

  it('5. Renders AuthRequiredState and LoadingState correctly', () => {
    const onSignInMock = vi.fn();
    const { rerender } = render(
      <MotionProvider>
        <ThreatsTab threats={[]} authRequired={true} onSignIn={onSignInMock} />
      </MotionProvider>
    );

    expect(screen.getByText('Threat Telemetry Requires Authentication')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /Sign In to Access/i }));
    expect(onSignInMock).toHaveBeenCalled();

    // Test loading state
    rerender(
      <MotionProvider>
        <ThreatsTab threats={[]} loading={true} authRequired={false} />
      </MotionProvider>
    );
    expect(screen.getByText('Ingesting Threat Signals')).toBeInTheDocument();
  });

  it('6. Cross-links to related Security Decision with correlation request_id', () => {
    const onSelectTabMock = vi.fn();
    render(
      <MotionProvider>
        <ThreatsTab threats={mockThreats} onSelectTab={onSelectTabMock} />
      </MotionProvider>
    );

    const viewDecisionBtns = screen.getAllByRole('button', { name: /View Decision/i });
    fireEvent.click(viewDecisionBtns[0]);

    expect(onSelectTabMock).toHaveBeenCalledWith('decisions', 'req-corr-101');
  });
});

describe('Security Decisions Console Hardening (Phase 14J-C6)', () => {
  it('1. Renders Header, Lifecycle Stage indicator, and KPI metrics strip', () => {
    render(
      <MotionProvider>
        <DecisionsTab decisions={mockDecisions} />
      </MotionProvider>
    );

    expect(screen.getByText('Security Decisions Ledger')).toBeInTheDocument();
    expect(screen.getByText(/Stage 3 of 7: Policy & Risk Verdict/i)).toBeInTheDocument();
    expect(screen.getByText('Total Evaluations')).toBeInTheDocument();
    expect(screen.getByText('Allowed')).toBeInTheDocument();
    expect(screen.getByText('Require Approval')).toBeInTheDocument();
    expect(screen.getByText('Blocked')).toBeInTheDocument();
    expect(screen.getByText('Peak Risk Score')).toBeInTheDocument();

    // Peak score is 95.0
    expect(screen.getByText('95.0')).toBeInTheDocument();
  });

  it('2. Enforces strict Phase 10 / Phase 11 invariants (no override/approval buttons on Decisions screen)', () => {
    render(
      <MotionProvider>
        <DecisionsTab decisions={mockDecisions} />
      </MotionProvider>
    );

    // Require Approval invariant
    expect(screen.getByText(/Awaiting Human Security Approval/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Execution: NOT STARTED/i).length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText(/Non-Executing Observer/i)).toBeInTheDocument();

    // Block invariant
    expect(screen.getByText(/TERMINAL - BLOCK/i)).toBeInTheDocument();
    expect(screen.getByText(/Zero Override Allowed/i)).toBeInTheDocument();

    // Ensure zero execution/approval buttons exist on the decisions tab
    expect(screen.queryByRole('button', { name: /^approve$/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^reject$/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^override$/i })).not.toBeInTheDocument();
  });

  it('3. Filters decisions by verdict, severity, and risk band', () => {
    render(
      <MotionProvider>
        <DecisionsTab decisions={mockDecisions} />
      </MotionProvider>
    );

    // Initial shows all 3
    expect(screen.getByText(/policy.critical.block/i)).toBeInTheDocument();
    expect(screen.getByText(/policy.prompt.approval/i)).toBeInTheDocument();
    expect(screen.getByText(/policy.clean.default/i)).toBeInTheDocument();

    // Filter by BLOCK verdict
    const verdictSelect = screen.getByLabelText(/Filter by Decision Verdict/i);
    fireEvent.change(verdictSelect, { target: { value: 'BLOCK' } });

    expect(screen.getByText(/policy.critical.block/i)).toBeInTheDocument();
    expect(screen.queryByText(/policy.prompt.approval/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/policy.clean.default/i)).not.toBeInTheDocument();
  });

  it('4. Opens decision inspection drawer and navigates to Approvals for REQUIRE_APPROVAL', () => {
    const onSelectTabMock = vi.fn();
    render(
      <MotionProvider>
        <DecisionsTab decisions={mockDecisions} onSelectTab={onSelectTabMock} />
      </MotionProvider>
    );

    // Click inspect on second decision (REQUIRE_APPROVAL)
    const inspectBtns = screen.getAllByRole('button', { name: /^inspect/i });
    fireEvent.click(inspectBtns[1]);

    expect(screen.getByText('Security Decision Details')).toBeInTheDocument();
    expect(screen.getByText('Risk Evaluation Breakdown')).toBeInTheDocument();
    expect(screen.getByText('dec-app-002')).toBeInTheDocument();

    // Click Go to Approvals Queue
    const approvalQueueBtn = screen.getByRole('button', { name: /Go to Approvals Queue/i });
    fireEvent.click(approvalQueueBtn);

    expect(onSelectTabMock).toHaveBeenCalledWith('approvals', 'req-corr-102');
  });

  it('5. Redacts sensitive keys in evaluation metadata (Security UI Audit)', () => {
    render(
      <MotionProvider>
        <DecisionsTab decisions={mockDecisions} />
      </MotionProvider>
    );

    const inspectBtns = screen.getAllByRole('button', { name: /^inspect/i });
    fireEvent.click(inspectBtns[0]);

    // Ensure raw secret key is never in the DOM
    expect(screen.queryByText('internal_secret_token')).not.toBeInTheDocument();
    expect(screen.getAllByText(/\[REDACTED_SECURITY_DATA\]/i).length).toBeGreaterThanOrEqual(1);
  });
});

describe('Executions Console Hardening (Phase 14J-C6)', () => {
  it('1. Renders Header, Lifecycle Stage indicator, and KPI metrics strip', () => {
    render(
      <MotionProvider>
        <ExecutionsTab executions={mockExecutions} />
      </MotionProvider>
    );

    expect(screen.getByText('Sandbox Execution Activity')).toBeInTheDocument();
    expect(screen.getByText(/Stage 6 of 7: Controlled Execution & Containment/i)).toBeInTheDocument();
    expect(screen.getByText('Dispatched')).toBeInTheDocument();
    expect(screen.getByText('Completed')).toBeInTheDocument();
    expect(screen.getByText('Denied')).toBeInTheDocument();
    expect(screen.getByText('Timed Out')).toBeInTheDocument();
    expect(screen.getByText('Failed')).toBeInTheDocument();
    expect(screen.getByText('Avg Latency')).toBeInTheDocument();

    // KPI counts: 4 dispatched, 1 completed, 1 denied, 1 timed out, 1 failed
    expect(screen.getByText('4')).toBeInTheDocument();
  });

  it('2. Distinguishes COMPLETED, DENIED, TIMED_OUT, and FAILED status outcomes', () => {
    render(
      <MotionProvider>
        <ExecutionsTab executions={mockExecutions} />
      </MotionProvider>
    );

    expect(screen.getByText(/Sandbox Tool Execution Successful within containment limits/i)).toBeInTheDocument();
    expect(screen.getByText(/Enforcement Boundary Denied Invocation • Zero Execution In Sandbox/i)).toBeInTheDocument();
    expect(screen.getByText(/Execution Terminated • Runtime Timeout Budget Exceeded/i)).toBeInTheDocument();
    expect(screen.getByText(/Connection refused: destination port 8080 unreachable/i)).toBeInTheDocument();
  });

  it('3. Filters executions by status outcome and tool category', () => {
    render(
      <MotionProvider>
        <ExecutionsTab executions={mockExecutions} />
      </MotionProvider>
    );

    // Initial shows all 4 tools
    expect(screen.getByText('database.query')).toBeInTheDocument();
    expect(screen.getByText('file.read')).toBeInTheDocument();
    expect(screen.getByText('network.fetch')).toBeInTheDocument();
    expect(screen.getByText('code.execute')).toBeInTheDocument();

    // Filter by TIMED_OUT status
    const statusSelect = screen.getByLabelText(/Filter by Outcome Status/i);
    fireEvent.change(statusSelect, { target: { value: 'TIMED_OUT' } });

    expect(screen.getByText('code.execute')).toBeInTheDocument();
    expect(screen.queryByText('database.query')).not.toBeInTheDocument();
    expect(screen.queryByText('network.fetch')).not.toBeInTheDocument();
  });

  it('4. Opens execution containment detail drawer and renders sanitized metadata', () => {
    const onSelectTabMock = vi.fn();
    render(
      <MotionProvider>
        <ExecutionsTab executions={mockExecutions} onSelectTab={onSelectTabMock} />
      </MotionProvider>
    );

    const inspectBtns = screen.getAllByRole('button', { name: /^inspect/i });
    fireEvent.click(inspectBtns[0]); // database.query

    expect(screen.getByText('Sandbox Execution Containment Details')).toBeInTheDocument();
    expect(screen.getByText('exec-cmp-001')).toBeInTheDocument();
    expect(screen.getAllByText(/18\.40/i).length).toBeGreaterThanOrEqual(1);

    // Verify secret db_password was redacted
    expect(screen.queryByText('internal_db_password')).not.toBeInTheDocument();
    expect(screen.getAllByText(/\[REDACTED_SECURITY_DATA\]/i).length).toBeGreaterThanOrEqual(1);

    // Cross-link to Decision
    const viewDecBtn = screen.getByRole('button', { name: /View Security Decision/i });
    fireEvent.click(viewDecBtn);
    expect(onSelectTabMock).toHaveBeenCalledWith('decisions', 'req-corr-103');
  });

  it('5. Renders AuthRequiredState and LoadingState correctly', () => {
    const onSignInMock = vi.fn();
    const { rerender } = render(
      <MotionProvider>
        <ExecutionsTab executions={[]} authRequired={true} onSignIn={onSignInMock} />
      </MotionProvider>
    );

    expect(screen.getByText('Execution Activity Requires Authentication')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /Sign In to Access/i }));
    expect(onSignInMock).toHaveBeenCalled();

    rerender(
      <MotionProvider>
        <ExecutionsTab executions={[]} loading={true} authRequired={false} />
      </MotionProvider>
    );
    expect(screen.getByText('Processing Execution Stream')).toBeInTheDocument();
  });
});
