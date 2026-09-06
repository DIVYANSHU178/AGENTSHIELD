import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { LoginModal } from './LoginModal';
import { AuthProvider } from '../../context/AuthContext';
import { MotionProvider } from '../../context/MotionContext';


const TestHost: React.FC<{
  isOpen: boolean;
  onClose?: () => void;
  showDemoPresets?: boolean;
  backendEnvironment?: string;
}> = ({ isOpen, onClose = () => {}, showDemoPresets, backendEnvironment }) => {
  return (
    <MotionProvider>
      <AuthProvider>
        <LoginModal
          isOpen={isOpen}
          onClose={onClose}
          showDemoPresets={showDemoPresets}
          backendEnvironment={backendEnvironment}
        />
      </AuthProvider>
    </MotionProvider>
  );
};

describe('LoginModal Experience Hardening (Phase 14J-C2)', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('1. Renders visual hierarchy and accessibility attributes when open', () => {
    render(<TestHost isOpen={true} />);

    const dialog = screen.getByRole('dialog');
    expect(dialog).toBeInTheDocument();
    expect(dialog).toHaveAttribute('aria-modal', 'true');
    expect(dialog).toHaveAttribute('aria-labelledby', 'login-modal-title');
    expect(dialog).toHaveAttribute('aria-describedby', 'login-modal-desc');

    expect(screen.getByText('AgentShield Identity')).toBeInTheDocument();
    expect(screen.getByText('Security Gateway Access')).toBeInTheDocument();
    expect(screen.getByLabelText(/operator id \/ username/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/security credential \/ password/i)).toBeInTheDocument();
    expect(screen.getByTestId('login-submit-button')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /show credential/i })).toBeInTheDocument();

    // Presets
    expect(screen.getByText('Development / QA Profiles')).toBeInTheDocument();
    expect(screen.getByText('Security Lead')).toBeInTheDocument();
    expect(screen.getByText('Operator')).toBeInTheDocument();
    expect(screen.getByText('Admin')).toBeInTheDocument();
    expect(screen.getByText('Viewer')).toBeInTheDocument();
  });

  it('2. Does not render when isOpen is false', () => {
    render(<TestHost isOpen={false} />);
    expect(screen.queryByTestId('login-modal')).not.toBeInTheDocument();
  });

  it('3. Toggles password visibility with accessible label', () => {
    render(<TestHost isOpen={true} />);
    const passInput = screen.getByLabelText(/security credential \/ password/i);
    const toggleBtn = screen.getByRole('button', { name: /show credential/i });

    expect(passInput).toHaveAttribute('type', 'password');
    expect(toggleBtn).toHaveAttribute('aria-pressed', 'false');

    // Click to show password
    fireEvent.click(toggleBtn);
    expect(passInput).toHaveAttribute('type', 'text');
    expect(screen.getByRole('button', { name: /hide credential/i })).toHaveAttribute('aria-pressed', 'true');

    // Click to hide password
    fireEvent.click(screen.getByRole('button', { name: /hide credential/i }));
    expect(passInput).toHaveAttribute('type', 'password');
    expect(screen.getByRole('button', { name: /show credential/i })).toHaveAttribute('aria-pressed', 'false');
  });


  it('4. Populates credentials from development/QA presets and clears errors', () => {
    render(<TestHost isOpen={true} />);
    const userInput = screen.getByLabelText(/operator id \/ username/i);
    const passInput = screen.getByLabelText(/security credential \/ password/i);

    // Click Security Lead preset
    fireEvent.click(screen.getByText('Security Lead'));
    expect(userInput).toHaveValue('security_lead');
    expect(passInput).toHaveValue('ReviewerPass123!');

    // Click Admin preset
    fireEvent.click(screen.getByText('Admin'));
    expect(userInput).toHaveValue('admin');
    expect(passInput).toHaveValue('AdminPass123!');
  });

  it('5. Validates empty input fields before submission', async () => {
    render(<TestHost isOpen={true} />);
    const submitBtn = screen.getByTestId('login-submit-button');

    fireEvent.click(submitBtn);

    expect(screen.getByRole('alert')).toBeInTheDocument();
    expect(screen.getByText(/please provide both username and password/i)).toBeInTheDocument();
  });

  it('6. Keyboard Escape key dismisses the dialog', () => {
    const handleClose = vi.fn();
    render(<TestHost isOpen={true} onClose={handleClose} />);

    fireEvent.keyDown(window, { key: 'Escape' });
    expect(handleClose).toHaveBeenCalledTimes(1);
  });

  it('7. Close button (X) dismisses the dialog', () => {
    const handleClose = vi.fn();
    render(<TestHost isOpen={true} onClose={handleClose} />);

    fireEvent.click(screen.getByLabelText('Close authentication modal'));
    expect(handleClose).toHaveBeenCalledTimes(1);
  });

  it('8. Backdrop click dismisses dialog when clicking outside card', () => {
    const handleClose = vi.fn();
    render(<TestHost isOpen={true} onClose={handleClose} />);

    const backdrop = screen.getByTestId('login-modal');
    fireEvent.click(backdrop);
    expect(handleClose).toHaveBeenCalledTimes(1);
  });

  it('9. Differentiates network error from backend unavailable', async () => {
    global.fetch = vi.fn().mockRejectedValue(new TypeError('Failed to fetch'));

    render(<TestHost isOpen={true} />);
    fireEvent.click(screen.getByText('Operator'));
    fireEvent.click(screen.getByTestId('login-submit-button'));

    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument();
      expect(screen.getByText(/gateway unreachable/i)).toBeInTheDocument();
      expect(screen.getByText(/unable to connect to the agentshield authentication gateway/i)).toBeInTheDocument();
    });
  });

  it('10. Shows authenticating state and then success transition before closing', async () => {
    let resolveLogin: (val: any) => void;
    const loginPromise = new Promise((resolve) => {
      resolveLogin = resolve;
    });

    global.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes('/api/v1/auth/login')) {
        return loginPromise.then(() => ({
          ok: true,
          json: () =>
            Promise.resolve({
              session_id: 'sess-success-456',
              user_id: 'usr-lead-01',
              username: 'security_lead',
              roles: ['SECURITY_REVIEWER'],
              expires_at: new Date(Date.now() + 3600000).toISOString(),
            }),
        }));
      }
      if (url.includes('/api/v1/auth/me')) {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              user_id: 'usr-lead-01',
              username: 'security_lead',
              email: 'lead@agentshield.internal',
              display_name: 'Security Lead',
              roles: ['SECURITY_REVIEWER'],
              is_active: true,
              created_at: new Date().toISOString(),
            }),
        });
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
    });

    const handleClose = vi.fn();
    render(<TestHost isOpen={true} onClose={handleClose} />);

    fireEvent.click(screen.getByText('Security Lead'));
    fireEvent.click(screen.getByTestId('login-submit-button'));

    // Authenticating in-flight progress state
    expect(screen.getByText('Authenticating...')).toBeInTheDocument();
    expect(screen.getByText('Validating identity & establishing secure session...')).toBeInTheDocument();
    expect(screen.getByLabelText(/operator id \/ username/i)).toBeDisabled();
    expect(screen.getByLabelText(/security credential \/ password/i)).toBeDisabled();

    // Resolve login call
    await act(async () => {
      resolveLogin!({});
    });

    // Success transition appears
    await waitFor(() => {
      expect(screen.getByText('Authentication Accepted')).toBeInTheDocument();
      expect(screen.getByText(/session established — launching console/i)).toBeInTheDocument();
    });

    // Automatically closes after transition delay
    await waitFor(
      () => {
        expect(handleClose).toHaveBeenCalledTimes(1);
      },
      { timeout: 1500 }
    );
  });

  it('11. Production-mode UI strictly excludes demo preset functionality', () => {
    // Render with showDemoPresets=false to simulate non-development/production UI mode
    render(<TestHost isOpen={true} showDemoPresets={false} />);

    // Presets header and container must NOT be present
    expect(screen.queryByText('Development / QA Profiles')).not.toBeInTheDocument();
    expect(screen.queryByText('TEST IDENTITIES')).not.toBeInTheDocument();

    // Preset profile buttons must NOT be present
    expect(screen.queryByText('Security Lead')).not.toBeInTheDocument();
    expect(screen.queryByText('Operator')).not.toBeInTheDocument();
    expect(screen.queryByText('Admin')).not.toBeInTheDocument();
    expect(screen.queryByText('Viewer')).not.toBeInTheDocument();
    expect(screen.queryByText('SECURITY_REVIEWER')).not.toBeInTheDocument();
    expect(screen.queryByText('VIEWER (Read-Only)')).not.toBeInTheDocument();

    // Standard credential form remains fully available
    expect(screen.getByLabelText(/operator id \/ username/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/security credential \/ password/i)).toBeInTheDocument();
    expect(screen.getByTestId('login-submit-button')).toBeInTheDocument();
  });

  it('12. Development mode UI renders all four demo presets with proper role indicators', () => {
    // Render with showDemoPresets=true to simulate development/QA UI mode
    render(<TestHost isOpen={true} showDemoPresets={true} />);

    expect(screen.getByText('Development / QA Profiles')).toBeInTheDocument();
    expect(screen.getByText('TEST IDENTITIES')).toBeInTheDocument();

    expect(screen.getByText('Security Lead')).toBeInTheDocument();
    expect(screen.getByText('SECURITY_REVIEWER')).toBeInTheDocument();

    expect(screen.getByText('Operator')).toBeInTheDocument();
    expect(screen.getByText('OPERATOR')).toBeInTheDocument();

    expect(screen.getByText('Admin')).toBeInTheDocument();
    expect(screen.getByText('ADMIN')).toBeInTheDocument();

    expect(screen.getByText('Viewer')).toBeInTheDocument();
    expect(screen.getByText('VIEWER (Read-Only)')).toBeInTheDocument();
  });

  it('13. Production build bundles contain zero demo password literals', async () => {
    // If production dist exists, inspect all JavaScript bundles for demo passwords
    const fs = await import('fs');
    const path = await import('path');

    const distAssetsDir = path.resolve(__dirname, '../../../dist/assets');
    if (fs.existsSync(distAssetsDir)) {
      const jsFiles = fs.readdirSync(distAssetsDir).filter((f: string) => f.endsWith('.js'));
      const forbiddenStrings = [
        'AdminPass123!',
        'ReviewerPass123!',
        'OperatorPass123!',
        'ViewerPass123!',
      ];

      for (const jsFile of jsFiles) {
        const fullPath = path.join(distAssetsDir, jsFile);
        const content = fs.readFileSync(fullPath, 'utf-8');
        for (const forbidden of forbiddenStrings) {
          expect(content).not.toContain(forbidden);
        }
      }
    }
  });

  it('14. Hides demo presets when backendEnvironment is production even in development mode', () => {
    render(<TestHost isOpen={true} backendEnvironment="production" />);

    expect(screen.queryByText('Development / QA Profiles')).not.toBeInTheDocument();
    expect(screen.queryByText('Security Lead')).not.toBeInTheDocument();
    expect(screen.queryByText('Operator')).not.toBeInTheDocument();
    expect(screen.queryByText('Admin')).not.toBeInTheDocument();
    expect(screen.queryByText('Viewer')).not.toBeInTheDocument();
  });
});
