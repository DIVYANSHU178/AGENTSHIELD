import React from 'react';
import { render, screen, waitFor, fireEvent, act } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { AuthProvider, useAuth } from '../../context/AuthContext';
import { UserBadge } from './UserBadge';
import { LoginModal } from './LoginModal';
import { ApprovalsTab } from '../operations/ApprovalsTab';
import { ScenarioLabTab } from '../operations/ScenarioLabTab';
import { setStoredToken, clearStoredToken, authFetch, API_BASE_URL } from '../../lib/api';
import { ApprovalRequest, ScenarioDefinition, ScenarioCategory } from '../../types';

const mockViewerUser = {
  user_id: 'usr-viewer-01',
  username: 'viewer_user',
  email: 'viewer@agentshield.internal',
  display_name: 'Auditor Viewer',
  roles: ['VIEWER' as const],
  is_active: true,
  created_at: new Date().toISOString(),
};

const mockReviewerUser = {
  user_id: 'usr-rev-01',
  username: 'security_lead',
  email: 'reviewer@agentshield.internal',
  display_name: 'Security Lead',
  roles: ['SECURITY_REVIEWER' as const],
  is_active: true,
  created_at: new Date().toISOString(),
};

const mockAdminUser = {
  user_id: 'usr-admin-01',
  username: 'admin',
  email: 'admin@agentshield.internal',
  display_name: 'Super Admin',
  roles: ['ADMIN' as const],
  is_active: true,
  created_at: new Date().toISOString(),
};

const mockApprovalItem: ApprovalRequest = {
  approval_id: 'app-test-01',
  request_id: 'req-auth-test-01',
  agent: { agent_id: 'ag-01', name: 'PromptAgent' },
  tool_name: 'calculator.compute',
  tool_category: 'SYSTEM',
  action: 'EXECUTE',
  target: 'system.prompt',
  parameters: { instruction: 'override test' },
  request_fingerprint: 'sha256_dummy_fingerprint',
  risk_score: 65.0,
  severity: 'HIGH',
  threat_summary: 'Instruction override evaluation',
  created_at: new Date().toISOString(),
  expires_at: new Date(Date.now() + 3600000).toISOString(),
  status: 'PENDING',
};

const mockScenarioItem: ScenarioDefinition = {
  scenario_id: 'ALLOW_CLEAN',
  name: 'Clean Arithmetic Computation',
  description: 'Harmless arithmetic addition tool request.',
  category: ScenarioCategory.BASELINE,
  expected_decision: 'ALLOW',
  expected_status: 'COMPLETED',
  expected_executed: true,
  requires_approval: false,
};

// Helper test shell that connects UserBadge and LoginModal
const AuthTestApp: React.FC = () => {
  const { showLoginModal, setShowLoginModal } = useAuth();
  return (
    <div>
      <header>
        <UserBadge />
      </header>
      <LoginModal isOpen={showLoginModal} onClose={() => setShowLoginModal(false)} />
    </div>
  );
};

describe('Phase 14 Frontend Authentication & RBAC UX', () => {
  beforeEach(() => {
    clearStoredToken();
    vi.restoreAllMocks();
  });

  afterEach(() => {
    clearStoredToken();
  });

  it('1. Login success flow: stores session, updates UI, and closes modal', async () => {
    global.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes('/api/v1/auth/login')) {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              session_id: 'sess-jwt-lead-123',
              user_id: 'usr-rev-01',
              username: 'security_lead',
              roles: ['SECURITY_REVIEWER'],
              expires_at: new Date(Date.now() + 3600000).toISOString(),
            }),
        });
      }
      if (url.includes('/api/v1/auth/me')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(mockReviewerUser),
        });
      }
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({}),
      });
    });

    render(
      <AuthProvider>
        <AuthTestApp />
      </AuthProvider>
    );

    // Initially unauthenticated
    expect(screen.getByTestId('unauthenticated-badge')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument();

    // Click Sign In
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }));

    // Modal is open
    expect(screen.getByTestId('login-modal')).toBeInTheDocument();

    // Click preset for Security Lead
    fireEvent.click(screen.getByText('Security Lead'));

    // Submit form
    fireEvent.click(screen.getByTestId('login-submit-button'));

    // Modal closes and identity is rendered
    await waitFor(() => {
      expect(screen.queryByTestId('login-modal')).not.toBeInTheDocument();
      expect(screen.getByTestId('authenticated-user-badge')).toBeInTheDocument();
      expect(screen.getByText('Security Lead')).toBeInTheDocument();
      expect(screen.getByTestId('user-role-badge')).toHaveTextContent('SECURITY_REVIEWER');
    });
  });

  it('2. Invalid login failure: shows error message and preserves unauthenticated state', async () => {
    global.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes('/api/v1/auth/login')) {
        return Promise.resolve({
          ok: false,
          status: 401,
          statusText: 'Unauthorized',
          json: () => Promise.resolve({ detail: 'Invalid username or password.' }),
        });
      }
      return Promise.resolve({
        ok: false,
        status: 401,
        json: () => Promise.resolve({ detail: 'Not authenticated' }),
      });
    });

    render(
      <AuthProvider>
        <AuthTestApp />
      </AuthProvider>
    );

    // Open modal
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }));

    // Fill credentials manually
    const userInput = screen.getByLabelText(/username/i);
    const passInput = screen.getByLabelText(/password/i);
    fireEvent.change(userInput, { target: { value: 'wrong_user' } });
    fireEvent.change(passInput, { target: { value: 'wrong_password' } });

    fireEvent.click(screen.getByTestId('login-submit-button'));

    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument();
      expect(screen.getByText('Invalid username or password.')).toBeInTheDocument();
    });

    // Unauthenticated state preserved
    expect(screen.queryByTestId('authenticated-user-badge')).not.toBeInTheDocument();
  });

  it('3. Authenticated identity & role pill rendering for ADMIN and VIEWER roles', async () => {
    // Test Admin
    global.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes('/api/v1/auth/me')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(mockAdminUser),
        });
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
    });

    setStoredToken('mock-admin-token');

    const { unmount } = render(
      <AuthProvider>
        <AuthTestApp />
      </AuthProvider>
    );

    await waitFor(() => {
      expect(screen.getByTestId('authenticated-user-badge')).toBeInTheDocument();
      expect(screen.getByText('Super Admin')).toBeInTheDocument();
      expect(screen.getByTestId('user-role-badge')).toHaveTextContent('ADMIN');
    });

    unmount();
    clearStoredToken();

    // Test Viewer
    global.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes('/api/v1/auth/me')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(mockViewerUser),
        });
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
    });

    setStoredToken('mock-viewer-token');

    render(
      <AuthProvider>
        <AuthTestApp />
      </AuthProvider>
    );

    await waitFor(() => {
      expect(screen.getByTestId('authenticated-user-badge')).toBeInTheDocument();
      expect(screen.getByText('Auditor Viewer')).toBeInTheDocument();
      expect(screen.getByTestId('user-role-badge')).toHaveTextContent('VIEWER');
    });
  });

  it('4. Logout flow: revokes session, clears token, and updates UI', async () => {
    global.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes('/api/v1/auth/me')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(mockReviewerUser),
        });
      }
      if (url.includes('/api/v1/auth/logout')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ message: 'Logged out successfully', revoked: true }),
        });
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
    });

    setStoredToken('mock-token-to-logout');

    render(
      <AuthProvider>
        <AuthTestApp />
      </AuthProvider>
    );

    await waitFor(() => {
      expect(screen.getByTestId('authenticated-user-badge')).toBeInTheDocument();
    });

    // Click Sign Out
    const signOutBtn = screen.getByLabelText('Sign Out');
    fireEvent.click(signOutBtn);

    await waitFor(() => {
      expect(screen.getByTestId('unauthenticated-badge')).toBeInTheDocument();
      expect(screen.queryByTestId('authenticated-user-badge')).not.toBeInTheDocument();
    });
  });

  it('5. Stored session restore on mount: restores identity without user prompt', async () => {
    global.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes('/api/v1/auth/me')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(mockReviewerUser),
        });
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
    });

    setStoredToken('existing-valid-session');

    render(
      <AuthProvider>
        <AuthTestApp />
      </AuthProvider>
    );

    await waitFor(() => {
      expect(screen.getByText('Security Lead')).toBeInTheDocument();
      expect(screen.getByTestId('user-role-badge')).toHaveTextContent('SECURITY_REVIEWER');
    });
  });

  it('6. Revoked / expired session: 401 response triggers automatic logout', async () => {
    global.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes('/api/v1/auth/me')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(mockReviewerUser),
        });
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
    });

    setStoredToken('valid-initial-token');

    render(
      <AuthProvider>
        <AuthTestApp />
      </AuthProvider>
    );

    await waitFor(() => {
      expect(screen.getByText('Security Lead')).toBeInTheDocument();
    });

    // Simulate an operational request returning 401
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      statusText: 'Unauthorized',
    });

    // Trigger authFetch
    await act(async () => {
      await authFetch(`${API_BASE_URL}/api/v1/security/operations/overview`);
    });

    // State should reset to unauthenticated
    await waitFor(() => {
      expect(screen.getByTestId('unauthenticated-badge')).toBeInTheDocument();
      expect(screen.queryByTestId('authenticated-user-badge')).not.toBeInTheDocument();
    });
  });

  it('7. VIEWER role cannot resolve approvals in UI (actions disabled with explanation)', async () => {
    global.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes('/api/v1/auth/me')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(mockViewerUser),
        });
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
    });

    setStoredToken('viewer-token');

    render(
      <AuthProvider>
        <ApprovalsTab approvals={[mockApprovalItem]} onRefresh={() => {}} />
      </AuthProvider>
    );

    await waitFor(() => {
      expect(screen.getByText('calculator.compute')).toBeInTheDocument();
    });

    // Click Review Request
    fireEvent.click(screen.getByText('Review Request'));

    // Explanatory read-only banner should be shown
    await waitFor(() => {
      expect(screen.getByText(/Read-Only View:/i)).toBeInTheDocument();
      expect(screen.getByText(/RESOLVE_APPROVALS/i)).toBeInTheDocument();
    });

    // Approve & Reject buttons must be disabled
    const approveBtn = screen.getByRole('button', { name: /approve request/i });
    const rejectBtn = screen.getByRole('button', { name: /reject request/i });
    expect(approveBtn).toBeDisabled();
    expect(rejectBtn).toBeDisabled();
  });

  it('8. SECURITY_REVIEWER role can resolve approvals in UI with prefilled identity', async () => {
    global.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes('/api/v1/auth/me')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(mockReviewerUser),
        });
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
    });

    setStoredToken('reviewer-token');

    render(
      <AuthProvider>
        <ApprovalsTab approvals={[mockApprovalItem]} onRefresh={() => {}} />
      </AuthProvider>
    );

    await waitFor(() => {
      expect(screen.getByText('calculator.compute')).toBeInTheDocument();
    });

    // Click Review Request
    fireEvent.click(screen.getByText('Review Request'));

    // Should NOT show read-only banner
    expect(screen.queryByText(/Read-Only View:/i)).not.toBeInTheDocument();

    // Reviewer ID input should be prefilled with user_id
    const reviewerIdInput = screen.getByDisplayValue('usr-rev-01');
    expect(reviewerIdInput).toBeInTheDocument();
    expect(reviewerIdInput).not.toBeDisabled();

    // Buttons should be enabled (subject only to justification validation)
    const approveBtn = screen.getByRole('button', { name: /approve request/i });
    const rejectBtn = screen.getByRole('button', { name: /reject request/i });
    expect(approveBtn).not.toBeDisabled();
    expect(rejectBtn).not.toBeDisabled();
  });

  it('9. Scenario Lab viewer role restriction: execution buttons disabled with explanation', async () => {
    global.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes('/api/v1/auth/me')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(mockViewerUser),
        });
      }
      if (url.includes('/laboratory/scenarios')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve([mockScenarioItem]),
        });
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
    });

    setStoredToken('viewer-token');

    render(
      <AuthProvider>
        <ScenarioLabTab />
      </AuthProvider>
    );

    await waitFor(() => {
      expect(screen.getAllByText('Clean Arithmetic Computation').length).toBeGreaterThanOrEqual(1);
    });

    // Explanatory read-only banner should appear
    expect(screen.getByText(/Current identity has role/i)).toBeInTheDocument();

    // Run button is disabled
    const runButtons = screen.getAllByRole('button', { name: /^run$/i });
    expect(runButtons[0]).toBeDisabled();
  });

  it('10. Scenario Lab execution enabled for SECURITY_REVIEWER role', async () => {
    global.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes('/api/v1/auth/me')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve(mockReviewerUser),
        });
      }
      if (url.includes('/laboratory/scenarios')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve([mockScenarioItem]),
        });
      }
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({}) });
    });

    setStoredToken('reviewer-token');

    render(
      <AuthProvider>
        <ScenarioLabTab />
      </AuthProvider>
    );

    await waitFor(() => {
      expect(screen.getAllByText('Clean Arithmetic Computation').length).toBeGreaterThanOrEqual(1);
    });

    // Should NOT show read-only banner
    expect(screen.queryByText(/Current identity has role/i)).not.toBeInTheDocument();

    // Run button is enabled
    const runButtons = screen.getAllByRole('button', { name: /^run$/i });
    expect(runButtons[0]).not.toBeDisabled();
  });
});
