import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ApprovalsTab } from './ApprovalsTab';
import { AuthProvider } from '../../context/AuthContext';
import { MotionProvider } from '../../context/MotionContext';
import { ApprovalRequest } from '../../types';
import * as api from '../../lib/api';
import { setStoredToken, clearStoredToken } from '../../lib/api';

const mockPendingApproval: ApprovalRequest = {
  approval_id: 'app-test-01',
  request_id: 'req-test-01',
  agent: {
    agent_id: 'agent-finance-01',
    name: 'Finance Agent',
    session_id: 'sess-alpha-01',
  },
  tool_name: 'payment_gateway.charge',
  tool_category: 'SYSTEM',
  action: 'EXECUTE',
  target: 'api.stripe.com/v1/charges',
  parameters: { amount: 5000, currency: 'usd', customer: 'cust-99' },
  destination: 'https://payment.internal.net',
  request_fingerprint: 'sha256-a1b2c3d4e5f67890123456789abcdef0',
  risk_score: 85.5,
  severity: 'HIGH',
  threat_summary: 'Outbound financial transaction exceeds automated policy threshold',
  created_at: '2026-09-05T12:00:00Z',
  expires_at: new Date(Date.now() + 600000).toISOString(), // 10 minutes remaining
  status: 'PENDING',
  resolution: null,
};

const mockApprovedApproval: ApprovalRequest = {
  approval_id: 'app-test-02',
  request_id: 'req-test-02',
  agent: {
    agent_id: 'agent-devops-01',
    name: 'DevOps Agent',
    session_id: 'sess-beta-02',
  },
  tool_name: 'kubernetes.deploy',
  tool_category: 'SYSTEM',
  action: 'WRITE',
  target: 'prod-cluster-us-east',
  parameters: { replicas: 3, image: 'service:v2' },
  request_fingerprint: 'sha256-11223344556677889900aabbccddeeff',
  risk_score: 72.0,
  severity: 'MEDIUM',
  threat_summary: 'Production cluster deployment authorization',
  created_at: '2026-09-05T10:00:00Z',
  expires_at: '2026-09-05T11:00:00Z',
  status: 'APPROVED',
  resolution: {
    approval_id: 'app-test-02',
    request_id: 'req-test-02',
    reviewer: {
      reviewer_id: 'usr-rev-01',
      reviewer_name: 'Alice Security Lead',
      role: 'SECURITY_REVIEWER',
    },
    decision: 'APPROVE',
    reason: 'Verified production release artifact signatures',
    resolved_at: '2026-09-05T10:30:00Z',
  },
};

const mockRejectedApproval: ApprovalRequest = {
  approval_id: 'app-test-03',
  request_id: 'req-test-03',
  agent: {
    agent_id: 'agent-crawler-01',
    name: 'Crawler Agent',
    session_id: 'sess-gamma-03',
  },
  tool_name: 'database.drop_table',
  tool_category: 'DATABASE',
  action: 'DELETE',
  target: 'users_table',
  parameters: { table: 'users', cascade: true },
  request_fingerprint: 'sha256-ffeeddccbbaa99887766554433221100',
  risk_score: 98.0,
  severity: 'CRITICAL',
  threat_summary: 'Destructive table deletion attempted by automated worker',
  created_at: '2026-09-05T09:00:00Z',
  expires_at: '2026-09-05T10:00:00Z',
  status: 'REJECTED',
  resolution: {
    approval_id: 'app-test-03',
    request_id: 'req-test-03',
    reviewer: {
      reviewer_id: 'usr-admin-01',
      reviewer_name: 'Bob Chief SecOps',
      role: 'ADMIN',
    },
    decision: 'REJECT',
    reason: 'Dangerous schema modification blocked by SOC reviewer',
    resolved_at: '2026-09-05T09:15:00Z',
  },
};

const mockAllApprovals = [mockPendingApproval, mockApprovedApproval, mockRejectedApproval];

describe('ApprovalsTab Security & Human-in-the-Loop UX (Phase 14J-C5)', () => {
  const mockOnRefresh = vi.fn();
  const mockOnSignIn = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    clearStoredToken();
    sessionStorage.clear();
  });

  const renderApprovals = (props = {}) => {
    return render(
      <AuthProvider>
        <MotionProvider>
          <ApprovalsTab
            approvals={mockAllApprovals}
            onRefresh={mockOnRefresh}
            {...props}
          />
        </MotionProvider>
      </AuthProvider>
    );
  };

  it('1. Renders Header with dual-custody workflow pipeline breadcrumb', () => {
    renderApprovals();

    expect(screen.getByText('Approval Workflow Queue')).toBeInTheDocument();
    expect(screen.getByText(/Dual-Custody Gateway/i)).toBeInTheDocument();
    expect(screen.getByText('SECURITY REQUEST')).toBeInTheDocument();
    expect(screen.getByText('POLICY EVALUATION')).toBeInTheDocument();
    expect(screen.getByText('HUMAN APPROVAL REQUIRED')).toBeInTheDocument();
    expect(screen.getByText('AUTHORIZED REVIEWER')).toBeInTheDocument();
    expect(screen.getByText('AUDIT ATTRIBUTION')).toBeInTheDocument();
  });

  it('2. Renders accurate Quantified Metric KPI Counters', () => {
    renderApprovals();

    expect(screen.getByText('Pending Review')).toBeInTheDocument();
    expect(screen.getByText('Approved')).toBeInTheDocument();
    expect(screen.getByText('Rejected')).toBeInTheDocument();
    expect(screen.getByText('Expired / Cancelled')).toBeInTheDocument();

    // 1 pending, 1 approved, 1 rejected, 0 expired
    expect(screen.getByText('Action Required')).toBeInTheDocument();
    expect(screen.getByText('Authorized')).toBeInTheDocument();
    expect(screen.getByText('Blocked')).toBeInTheDocument();
  });

  it('3. Separates Active Review Queue from Approval History in default view', () => {
    renderApprovals();

    expect(screen.getByText(/Active Review Queue \(1 Awaiting Authorization\)/i)).toBeInTheDocument();
    expect(screen.getByText(/Approval History & Audit Trail \(2 Resolved\)/i)).toBeInTheDocument();
  });

  it('4. Filters approval requests by lifecycle status and severity', () => {
    renderApprovals();

    // Filter by PENDING
    const statusSelect = screen.getByLabelText(/filter approvals by lifecycle status/i);
    fireEvent.change(statusSelect, { target: { value: 'PENDING' } });

    expect(screen.getByText('payment_gateway.charge')).toBeInTheDocument();
    expect(screen.queryByText('kubernetes.deploy')).not.toBeInTheDocument();
    expect(screen.queryByText('database.drop_table')).not.toBeInTheDocument();

    // Filter by REJECTED
    fireEvent.change(statusSelect, { target: { value: 'REJECTED' } });
    expect(screen.getByText('database.drop_table')).toBeInTheDocument();
    expect(screen.queryByText('payment_gateway.charge')).not.toBeInTheDocument();

    // Reset to ALL and filter by CRITICAL severity
    fireEvent.change(statusSelect, { target: { value: 'ALL' } });
    const severitySelect = screen.getByLabelText(/filter approvals by severity level/i);
    fireEvent.change(severitySelect, { target: { value: 'CRITICAL' } });

    expect(screen.getByText('database.drop_table')).toBeInTheDocument();
    expect(screen.queryByText('payment_gateway.charge')).not.toBeInTheDocument();
  });

  it('5. Searches approvals dynamically by tool name, target, and reviewer', () => {
    renderApprovals();

    const searchInput = screen.getByLabelText(/search approvals/i);
    fireEvent.change(searchInput, { target: { value: 'stripe' } });

    expect(screen.getByText('payment_gateway.charge')).toBeInTheDocument();
    expect(screen.queryByText('kubernetes.deploy')).not.toBeInTheDocument();

    // Search by reviewer name
    fireEvent.change(searchInput, { target: { value: 'Alice Security Lead' } });
    expect(screen.getByText('kubernetes.deploy')).toBeInTheDocument();
    expect(screen.queryByText('payment_gateway.charge')).not.toBeInTheDocument();
  });

  it('6. Expands technical inspection details drawer for deep audit inspection', () => {
    renderApprovals();

    const detailsButtons = screen.getAllByRole('button', { name: /^details$/i });
    fireEvent.click(detailsButtons[0]);

    expect(screen.getByText(/Cryptographic Request Fingerprint:/i)).toBeInTheDocument();
    expect(screen.getByText('sha256-a1b2c3d4e5f67890123456789abcdef0')).toBeInTheDocument();
    expect(screen.getByText(/Sanitized Tool Parameters:/i)).toBeInTheDocument();
    expect(screen.getByText(/agent-finance-01/i)).toBeInTheDocument();

    // Toggle back to Hide Details
    const hideBtn = screen.getByRole('button', { name: /hide details/i });
    expect(hideBtn).toBeInTheDocument();
    fireEvent.click(hideBtn);
    expect(screen.queryByText('sha256-a1b2c3d4e5f67890123456789abcdef0')).not.toBeInTheDocument();
  });

  it('7. Displays Authenticated Reviewer Attribution on resolved requests', () => {
    renderApprovals();

    // Approved item reviewer attribution
    expect(screen.getByText('Alice Security Lead')).toBeInTheDocument();
    expect(screen.getByText(/Verified production release artifact signatures/i)).toBeInTheDocument();

    // Rejected item reviewer attribution
    expect(screen.getByText('Bob Chief SecOps')).toBeInTheDocument();
    expect(screen.getByText(/Dangerous schema modification blocked by SOC reviewer/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Security Trajectory: Authenticated Reviewer → Approval Resolution → Audit Attribution/i).length).toBe(2);
  });

  it('8. Consequential Approval Flow: requires justification, shows confirmation dialog, and executes approveApproval', async () => {
    const approveSpy = vi.spyOn(api, 'approveApproval').mockResolvedValueOnce({
      ...mockPendingApproval,
      status: 'APPROVED',
    });

    // Mock reviewer user in session
    global.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes('/api/v1/auth/me')) {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              user_id: 'usr-rev-01',
              username: 'rev_alice',
              display_name: 'Alice Security Lead',
              roles: ['SECURITY_REVIEWER'],
              permissions: ['RESOLVE_APPROVALS'],
              is_active: true,
            }),
        });
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
    });

    setStoredToken('mock-reviewer-token');

    renderApprovals();

    // Wait for reviewer identity to be authenticated
    await waitFor(() => {
      expect(screen.getByText('payment_gateway.charge')).toBeInTheDocument();
    });

    // Click Review Request
    const reviewBtn = screen.getByText('Review Request');
    fireEvent.click(reviewBtn);

    expect(screen.getByText(/Authorize or Reject Tool Execution/i)).toBeInTheDocument();

    // Verify reviewer identity is loaded
    await waitFor(() => {
      expect(screen.getByDisplayValue('usr-rev-01')).toBeInTheDocument();
    });

    // Click Approve Request without justification -> error
    const initialApproveBtn = screen.getByRole('button', { name: /approve request/i });
    expect(initialApproveBtn).not.toBeDisabled();
    fireEvent.click(initialApproveBtn);
    expect(screen.getByText('Approval justification is required.')).toBeInTheDocument();

    // Enter justification
    const textarea = screen.getByPlaceholderText(/Provide explicit operational rationale/i);
    fireEvent.change(textarea, { target: { value: 'Approved for urgent business transaction verification' } });

    // Click Approve Request -> shows confirmation interaction
    fireEvent.click(initialApproveBtn);
    expect(screen.getByText(/Confirm Security Approval & Authorization/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Approved for urgent business transaction verification/i).length).toBeGreaterThanOrEqual(1);

    // Accidental click protection: cancel button dismisses confirmation
    const cancelBtn = screen.getByRole('button', { name: /^cancel$/i });
    fireEvent.click(cancelBtn);
    expect(screen.queryByText(/Confirm Security Approval & Authorization/i)).not.toBeInTheDocument();

    // Re-trigger and confirm
    fireEvent.click(screen.getByRole('button', { name: /approve request/i }));
    const confirmApproveBtn = screen.getByRole('button', { name: /confirm approval/i });
    fireEvent.click(confirmApproveBtn);

    await waitFor(() => {
      expect(approveSpy).toHaveBeenCalledWith(
        'app-test-01',
        expect.any(String),
        expect.any(String),
        expect.any(String),
        'Approved for urgent business transaction verification'
      );
      expect(mockOnRefresh).toHaveBeenCalled();
    });
  });

  it('9. Consequential Rejection Flow: requires justification, shows confirmation dialog, and executes rejectApproval', async () => {
    const rejectSpy = vi.spyOn(api, 'rejectApproval').mockResolvedValueOnce({
      ...mockPendingApproval,
      status: 'REJECTED',
    });

    global.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes('/api/v1/auth/me')) {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              user_id: 'usr-rev-01',
              username: 'rev_alice',
              display_name: 'Alice Security Lead',
              roles: ['SECURITY_REVIEWER'],
              permissions: ['RESOLVE_APPROVALS'],
              is_active: true,
            }),
        });
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
    });

    setStoredToken('mock-reviewer-token');

    renderApprovals();

    // Wait for item to be rendered
    await waitFor(() => {
      expect(screen.getByText('payment_gateway.charge')).toBeInTheDocument();
    });

    // Click Review Request
    fireEvent.click(screen.getByText('Review Request'));

    // Wait for reviewer identity to be loaded
    await waitFor(() => {
      expect(screen.getByDisplayValue('usr-rev-01')).toBeInTheDocument();
    });

    // Enter rejection justification
    const textarea = screen.getByPlaceholderText(/Provide explicit operational rationale/i);
    fireEvent.change(textarea, { target: { value: 'Blocked: suspicious outbound destination' } });

    // Click Reject Request -> shows confirmation interaction
    const initialRejectBtn = screen.getByRole('button', { name: /reject request/i });
    expect(initialRejectBtn).not.toBeDisabled();
    fireEvent.click(initialRejectBtn);

    expect(screen.getByText(/Confirm Security Rejection/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Blocked: suspicious outbound destination/i).length).toBeGreaterThanOrEqual(1);

    // Confirm Rejection
    const confirmRejectBtn = screen.getByRole('button', { name: /confirm rejection/i });
    fireEvent.click(confirmRejectBtn);

    await waitFor(() => {
      expect(rejectSpy).toHaveBeenCalledWith(
        'app-test-01',
        expect.any(String),
        expect.any(String),
        expect.any(String),
        'Blocked: suspicious outbound destination'
      );
      expect(mockOnRefresh).toHaveBeenCalled();
    });
  });

  it('10. Renders AuthRequiredState when authRequired is true and unauthenticated', () => {
    renderApprovals({ authRequired: true, onSignIn: mockOnSignIn });

    expect(screen.getByText('Operations Require Authentication')).toBeInTheDocument();
    expect(screen.getByText(/The AgentShield security backend is healthy and reachable/i)).toBeInTheDocument();

    const signInBtn = screen.getByRole('button', { name: /sign in/i });
    fireEvent.click(signInBtn);
    expect(mockOnSignIn).toHaveBeenCalled();
  });

  it('11. Renders LoadingState when loading is true and approvals array is empty', () => {
    renderApprovals({ approvals: [], loading: true });

    expect(screen.getByText('Processing Approval Workflow Queue')).toBeInTheDocument();
    expect(screen.getByText(/Authoritative Review Sync/i)).toBeInTheDocument();
  });

  it('12. Renders EmptyState when no records match filter', () => {
    renderApprovals({ approvals: [] });

    expect(screen.getByText('No Approval Requests')).toBeInTheDocument();
    expect(screen.getByText(/There are currently no security approval requests recorded/i)).toBeInTheDocument();
  });

  it('13. Security UI Audit: Never leaks bearer tokens, passwords, secrets, or database file paths in DOM', () => {
    const { container } = renderApprovals();
    const html = container.innerHTML;

    expect(html).not.toMatch(/Bearer\s+[A-Za-z0-9-_]+/);
    expect(html).not.toMatch(/password/i);
    expect(html).not.toMatch(/agentshield\.db/i);
    expect(html).not.toMatch(/C:\\/i);
    expect(html).not.toMatch(/\/var\/log/i);
    expect(html).not.toMatch(/client_secret/i);
  });
});
