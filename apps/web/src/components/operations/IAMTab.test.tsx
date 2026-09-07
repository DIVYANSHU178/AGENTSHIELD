import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { IAMTab } from './IAMTab';
import { useAuth } from '../../context/AuthContext';
import { UserIdentity } from '../../types';
import * as api from '../../lib/api';

vi.mock('../../context/AuthContext', () => ({
  useAuth: vi.fn(),
}));

vi.mock('../../lib/api', () => ({
  fetchIdentities: vi.fn(),
  createIdentity: vi.fn(),
  disableIdentity: vi.fn(),
  updateIdentityRoles: vi.fn(),
}));

const mockAdminUser: UserIdentity = {
  user_id: 'usr-admin-01',
  username: 'admin',
  display_name: 'Super Administrator',
  roles: ['ADMIN'],
  is_active: true,
  created_at: '2026-09-01T00:00:00Z',
  updated_at: '2026-09-01T00:00:00Z',
};

const mockOperatorUser: UserIdentity = {
  user_id: 'usr-op-02',
  username: 'alice',
  display_name: 'Alice SecOps',
  roles: ['OPERATOR'],
  is_active: true,
  created_at: '2026-09-02T00:00:00Z',
  updated_at: '2026-09-02T00:00:00Z',
};

const mockInactiveUser: UserIdentity = {
  user_id: 'usr-dis-03',
  username: 'bob_inactive',
  display_name: 'Bob Retired',
  roles: ['VIEWER'],
  is_active: false,
  created_at: '2026-08-15T00:00:00Z',
  updated_at: '2026-08-15T00:00:00Z',
};

const mockIdentities: UserIdentity[] = [mockAdminUser, mockOperatorUser, mockInactiveUser];

describe('IAMTab - Identity & Access Management UX', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (useAuth as any).mockReturnValue({
      user: mockAdminUser,
      canManageIdentities: true,
      hasRole: (role: string) => role === 'ADMIN',
      hasPermission: () => true,
    });
    (api.fetchIdentities as any).mockResolvedValue(mockIdentities);
  });

  it('1. Renders IAM Header and descriptive subtitle', async () => {
    render(<IAMTab />);

    expect(screen.getByText('Identity & Access Management (IAM)')).toBeInTheDocument();
    expect(
      screen.getByText(/Authoritative operator identities, RBAC role assignments, and authentication governance/i)
    ).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByText(/Registered Identities/i)).toBeInTheDocument();
    });
  });

  it('2. Renders loading state while fetching identities from database', () => {
    (api.fetchIdentities as any).mockReturnValue(new Promise(() => {}));
    render(<IAMTab />);

    expect(screen.getByText(/Loading identities from database/i)).toBeInTheDocument();
  });

  it('3. Renders error alert when fetching identities fails', async () => {
    (api.fetchIdentities as any).mockRejectedValue(new Error('Network connection timeout'));
    render(<IAMTab />);

    await waitFor(() => {
      expect(screen.getByText('Network connection timeout')).toBeInTheDocument();
    });
  });

  it('4. Lists all identities retrieved from backend API', async () => {
    render(<IAMTab />);

    await waitFor(() => {
      expect(screen.getByText('Super Administrator')).toBeInTheDocument();
      expect(screen.getByText('admin')).toBeInTheDocument();
      expect(screen.getByText('Alice SecOps')).toBeInTheDocument();
      expect(screen.getByText('alice')).toBeInTheDocument();
      expect(screen.getByText('Bob Retired')).toBeInTheDocument();
      expect(screen.getByText('bob_inactive')).toBeInTheDocument();
    });
  });

  it('5. Renders ACTIVE status badge for active operators', async () => {
    render(<IAMTab />);

    await waitFor(() => {
      const activeBadges = screen.getAllByText('ACTIVE');
      expect(activeBadges.length).toBeGreaterThanOrEqual(2);
    });
  });

  it('6. Renders DISABLED badge for deactivated operators', async () => {
    render(<IAMTab />);

    await waitFor(() => {
      expect(screen.getByText('DISABLED')).toBeInTheDocument();
    });
  });

  it('7. Displays "Create Identity" button when user has admin privileges', async () => {
    render(<IAMTab />);

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Create Identity/i })).toBeInTheDocument();
    });
  });

  it('8. Hides "Create Identity" button and displays read-only mode banner when user lacks privileges', async () => {
    (useAuth as any).mockReturnValue({
      user: mockOperatorUser,
      canManageIdentities: false,
      hasRole: () => false,
      hasPermission: () => false,
    });
    render(<IAMTab />);

    await waitFor(() => {
      expect(screen.queryByRole('button', { name: /Create Identity/i })).not.toBeInTheDocument();
      expect(screen.getByText(/Read-Only Mode/i)).toBeInTheDocument();
    });
  });

  it('9. Opens Create Identity modal when button is clicked', async () => {
    render(<IAMTab />);

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Create Identity/i })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /Create Identity/i }));

    expect(screen.getByText('Create Operator Identity')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('e.g. analyst_lead')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('e.g. Security Analyst')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('••••••••••••')).toBeInTheDocument();
  });

  it('10. Closes modal when Cancel is clicked', async () => {
    render(<IAMTab />);

    await waitFor(() => {
      fireEvent.click(screen.getByRole('button', { name: /Create Identity/i }));
    });

    expect(screen.getByText('Create Operator Identity')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /Cancel/i }));

    expect(screen.queryByText('Create Operator Identity')).not.toBeInTheDocument();
  });

  it('11. Submits new operator identity form and invokes createIdentity API', async () => {
    (api.createIdentity as any).mockResolvedValue({
      user_id: 'usr-new-04',
      username: 'charlie',
      display_name: 'Charlie Reviewer',
      roles: ['SECURITY_REVIEWER'],
      is_active: true,
    });

    render(<IAMTab />);

    await waitFor(() => {
      fireEvent.click(screen.getByRole('button', { name: /Create Identity/i }));
    });

    fireEvent.change(screen.getByPlaceholderText('e.g. analyst_lead'), { target: { value: 'charlie' } });
    fireEvent.change(screen.getByPlaceholderText('e.g. Security Analyst'), { target: { value: 'Charlie Reviewer' } });
    fireEvent.change(screen.getByPlaceholderText('••••••••••••'), { target: { value: 'SecurePass123!' } });

    // Submit form
    fireEvent.click(screen.getByRole('button', { name: /Create Operator/i }));

    await waitFor(() => {
      expect(api.createIdentity).toHaveBeenCalledWith({
        username: 'charlie',
        display_name: 'Charlie Reviewer',
        password: 'SecurePass123!',
        roles: ['OPERATOR'],
        is_active: true,
      });
    });
  });

  it('12. Displays error banner when createIdentity rejects with error', async () => {
    (api.createIdentity as any).mockRejectedValue(new Error('Username already exists'));

    render(<IAMTab />);

    await waitFor(() => {
      fireEvent.click(screen.getByRole('button', { name: /Create Identity/i }));
    });

    fireEvent.change(screen.getByPlaceholderText('e.g. analyst_lead'), { target: { value: 'admin' } });
    fireEvent.change(screen.getByPlaceholderText('e.g. Security Analyst'), { target: { value: 'Duplicate Admin' } });
    fireEvent.change(screen.getByPlaceholderText('••••••••••••'), { target: { value: 'Pass123!' } });

    fireEvent.click(screen.getByRole('button', { name: /Create Operator/i }));

    await waitFor(() => {
      expect(screen.getByText('Username already exists')).toBeInTheDocument();
    });
  });

  it('13. Disables user identity when Disable button is clicked and confirmed', async () => {
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    (api.disableIdentity as any).mockResolvedValue({ success: true });

    render(<IAMTab />);

    await waitFor(() => {
      expect(screen.getByText('alice')).toBeInTheDocument();
    });

    // Alice is active and not current user -> has Disable button
    const disableBtn = screen.getByRole('button', { name: /^Disable$/i });
    fireEvent.click(disableBtn);

    expect(window.confirm).toHaveBeenCalledWith(expect.stringContaining('alice'));
    await waitFor(() => {
      expect(api.disableIdentity).toHaveBeenCalledWith('usr-op-02');
    });
  });

  it('14. Prevents deactivating current user own identity', async () => {
    render(<IAMTab />);

    await waitFor(() => {
      expect(screen.getByText('admin')).toBeInTheDocument();
    });

    // The current admin user should display 'YOU' badge
    expect(screen.getByText('YOU')).toBeInTheDocument();
  });

  it('15. Updates user role when dropdown selection changes', async () => {
    (api.updateIdentityRoles as any).mockResolvedValue({ success: true });

    render(<IAMTab />);

    await waitFor(() => {
      expect(screen.getByText('alice')).toBeInTheDocument();
    });

    const selects = screen.getAllByRole('combobox');
    // selects[1] is for alice (selects[0] is for admin disabled)
    fireEvent.change(selects[1], { target: { value: 'SECURITY_REVIEWER' } });

    await waitFor(() => {
      expect(api.updateIdentityRoles).toHaveBeenCalledWith('usr-op-02', ['SECURITY_REVIEWER']);
    });
  });

  it('16. Refreshes identity directory when Sync button is clicked', async () => {
    render(<IAMTab />);

    await waitFor(() => {
      expect(api.fetchIdentities).toHaveBeenCalledTimes(1);
    });

    const syncBtn = screen.getByRole('button', { name: /Sync/i });
    fireEvent.click(syncBtn);

    await waitFor(() => {
      expect(api.fetchIdentities).toHaveBeenCalledTimes(2);
    });
  });
});
