import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { PoliciesTab } from './PoliciesTab';
import { useAuth } from '../../context/AuthContext';
import * as api from '../../lib/api';

vi.mock('../../context/AuthContext', () => ({
  useAuth: vi.fn(),
}));

vi.mock('../../lib/api', () => ({
  fetchPolicies: vi.fn(),
  createPolicy: vi.fn(),
  deletePolicy: vi.fn(),
}));

const mockPolicies = [
  {
    policy_id: 'policy.network.ssrf_defense',
    name: 'Block SSRF Targets',
    description: 'Enforces rejection of private, link-local, and cloud metadata destinations',
    rule_type: 'network_boundary',
    priority: 95,
    conditions: { schemes: ['http', 'https'] },
    action: 'BLOCK',
    is_enabled: true,
    created_at: '2026-09-01T00:00:00Z',
  },
  {
    policy_id: 'policy.filesystem.write_approval',
    name: 'Require Approval for FS Write',
    description: 'All persistent filesystem write operations require human reviewer verification',
    rule_type: 'filesystem_boundary',
    priority: 80,
    conditions: { operation: 'write' },
    action: 'REQUIRE_APPROVAL',
    is_enabled: true,
    created_at: '2026-09-01T00:00:00Z',
  },
  {
    policy_id: 'policy.calculator.allow_math',
    name: 'Permit Arithmetic Evaluation',
    description: 'Allow mathematical expression evaluation without human intervention',
    rule_type: 'calculator_boundary',
    priority: 70,
    conditions: {},
    action: 'ALLOW',
    is_enabled: true,
    created_at: '2026-09-01T00:00:00Z',
  },
  {
    policy_id: 'policy.default.deny',
    name: 'Default Deny Catch-All',
    description: 'Fail-closed default deny catch-all policy for any action not explicitly matched',
    rule_type: 'default_deny',
    priority: 0,
    conditions: {},
    action: 'BLOCK',
    is_enabled: true,
    created_at: '2026-09-01T00:00:00Z',
  },
];

describe('PoliciesTab - Security Policy Governance UX', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (useAuth as any).mockReturnValue({
      canManageIdentities: true,
      hasRole: () => true,
    });
    (api.fetchPolicies as any).mockResolvedValue(mockPolicies);
  });

  it('1. Renders Policy Governance header and description', async () => {
    render(<PoliciesTab />);

    expect(screen.getByText('Security Policy Governance')).toBeInTheDocument();
    expect(
      screen.getByText(/Authoritative security enforcement policies evaluated in strict priority order/i)
    ).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByText('Block SSRF Targets')).toBeInTheDocument();
    });
  });

  it('2. Renders Fail-Closed architectural invariant banner (SEC-05 Active)', async () => {
    render(<PoliciesTab />);

    expect(screen.getByText(/Fail-Closed Security Architecture \(SEC-05 Active\)/i)).toBeInTheDocument();
    expect(screen.getByText(/policy\.default\.deny/i)).toBeInTheDocument();
  });

  it('3. Renders loading state while fetching policies from API', () => {
    (api.fetchPolicies as any).mockReturnValue(new Promise(() => {}));
    render(<PoliciesTab />);

    expect(screen.getByText(/Loading active policy registry/i)).toBeInTheDocument();
  });

  it('4. Renders error alert when fetching policies fails', async () => {
    (api.fetchPolicies as any).mockRejectedValue(new Error('Failed to retrieve policy rules'));
    render(<PoliciesTab />);

    await waitFor(() => {
      expect(screen.getByText('Failed to retrieve policy rules')).toBeInTheDocument();
    });
  });

  it('5. Lists all policies retrieved from backend with priority indicators and action badges', async () => {
    render(<PoliciesTab />);

    await waitFor(() => {
      expect(screen.getByText('Block SSRF Targets')).toBeInTheDocument();
      expect(screen.getByText('policy.network.ssrf_defense')).toBeInTheDocument();
      expect(screen.getByText('95')).toBeInTheDocument();

      expect(screen.getByText('Require Approval for FS Write')).toBeInTheDocument();
      expect(screen.getByText('policy.filesystem.write_approval')).toBeInTheDocument();
      expect(screen.getByText('80')).toBeInTheDocument();

      expect(screen.getByText('Permit Arithmetic Evaluation')).toBeInTheDocument();
      expect(screen.getByText('policy.calculator.allow_math')).toBeInTheDocument();
      expect(screen.getByText('70')).toBeInTheDocument();
    });
  });

  it('6. Highlights Priority 0 default deny with FAIL-CLOSED CATCH-ALL badge', async () => {
    render(<PoliciesTab />);

    await waitFor(() => {
      expect(screen.getByText('Default Deny Catch-All')).toBeInTheDocument();
      expect(screen.getByText('FAIL-CLOSED CATCH-ALL')).toBeInTheDocument();
      expect(screen.getByText('0')).toBeInTheDocument();
    });
  });

  it('7. Displays "New Policy" button when user has administrative privileges', async () => {
    render(<PoliciesTab />);

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /New Policy/i })).toBeInTheDocument();
    });
  });

  it('8. Hides "New Policy" button when user lacks administrative privileges', async () => {
    (useAuth as any).mockReturnValue({
      canManageIdentities: false,
      hasRole: () => false,
    });
    render(<PoliciesTab />);

    await waitFor(() => {
      expect(screen.queryByRole('button', { name: /New Policy/i })).not.toBeInTheDocument();
    });
  });

  it('9. Opens Define Security Policy modal when "New Policy" button is clicked', async () => {
    render(<PoliciesTab />);

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /New Policy/i })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /New Policy/i }));

    expect(screen.getByText('Define Security Policy')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('e.g. policy.custom.network_restriction')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('e.g. Restrict High-Volume Network Egress')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('Operational rule rationale and constraints...')).toBeInTheDocument();
  });

  it('10. Closes Create Policy modal when Cancel is clicked', async () => {
    render(<PoliciesTab />);

    await waitFor(() => {
      fireEvent.click(screen.getByRole('button', { name: /New Policy/i }));
    });

    expect(screen.getByText('Define Security Policy')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /Cancel/i }));

    expect(screen.queryByText('Define Security Policy')).not.toBeInTheDocument();
  });

  it('11. Submits new policy form and invokes createPolicy API', async () => {
    (api.createPolicy as any).mockResolvedValue({
      policy_id: 'policy.custom.git_control',
      name: 'Git Branch Protection',
      priority: 65,
      action: 'REQUIRE_APPROVAL',
      is_enabled: true,
    });

    render(<PoliciesTab />);

    await waitFor(() => {
      fireEvent.click(screen.getByRole('button', { name: /New Policy/i }));
    });

    fireEvent.change(screen.getByPlaceholderText('e.g. policy.custom.network_restriction'), {
      target: { value: 'policy.custom.git_control' },
    });
    fireEvent.change(screen.getByPlaceholderText('e.g. Restrict High-Volume Network Egress'), {
      target: { value: 'Git Branch Protection' },
    });
    fireEvent.change(screen.getByPlaceholderText('Operational rule rationale and constraints...'), {
      target: { value: 'Require approval for branch mutation' },
    });

    fireEvent.click(screen.getByRole('button', { name: /Save Policy/i }));

    await waitFor(() => {
      expect(api.createPolicy).toHaveBeenCalledWith({
        policy_id: 'policy.custom.git_control',
        name: 'Git Branch Protection',
        description: 'Require approval for branch mutation',
        rule_type: 'custom_rule',
        priority: 60,
        action: 'REQUIRE_APPROVAL',
        is_enabled: true,
      });
    });
  });

  it('12. Displays error banner when createPolicy rejects with error', async () => {
    (api.createPolicy as any).mockRejectedValue(new Error('Policy ID already registered'));

    render(<PoliciesTab />);

    await waitFor(() => {
      fireEvent.click(screen.getByRole('button', { name: /New Policy/i }));
    });

    fireEvent.change(screen.getByPlaceholderText('e.g. policy.custom.network_restriction'), {
      target: { value: 'policy.duplicate' },
    });
    fireEvent.change(screen.getByPlaceholderText('e.g. Restrict High-Volume Network Egress'), {
      target: { value: 'Duplicate Policy' },
    });

    fireEvent.click(screen.getByRole('button', { name: /Save Policy/i }));

    await waitFor(() => {
      expect(screen.getByText('Policy ID already registered')).toBeInTheDocument();
    });
  });

  it('13. Disables policy when Disable button is clicked and confirmed', async () => {
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    (api.deletePolicy as any).mockResolvedValue({ success: true });

    render(<PoliciesTab />);

    await waitFor(() => {
      expect(screen.getByText('Block SSRF Targets')).toBeInTheDocument();
    });

    const disableButtons = screen.getAllByRole('button', { name: /^Disable$/i });
    expect(disableButtons.length).toBeGreaterThanOrEqual(1);

    fireEvent.click(disableButtons[0]);

    expect(window.confirm).toHaveBeenCalledWith(expect.stringContaining('Block SSRF Targets'));
    await waitFor(() => {
      expect(api.deletePolicy).toHaveBeenCalledWith('policy.network.ssrf_defense');
    });
  });

  it('14. Protects Priority 0 default deny policy from being disabled', async () => {
    render(<PoliciesTab />);

    await waitFor(() => {
      expect(screen.getByText('Default Deny Catch-All')).toBeInTheDocument();
    });

    // Default deny should NOT have a disable button
    const disableButtons = screen.getAllByRole('button', { name: /^Disable$/i });
    // Exactly 3 customizable policies are enabled (SSRF, FS, Calculator), default deny has NO disable button
    expect(disableButtons.length).toBe(3);
  });

  it('15. Refreshes policy registry when Sync button is clicked', async () => {
    render(<PoliciesTab />);

    await waitFor(() => {
      expect(api.fetchPolicies).toHaveBeenCalledTimes(1);
    });

    const syncBtn = screen.getByRole('button', { name: /Sync/i });
    fireEvent.click(syncBtn);

    await waitFor(() => {
      expect(api.fetchPolicies).toHaveBeenCalledTimes(2);
    });
  });
});
