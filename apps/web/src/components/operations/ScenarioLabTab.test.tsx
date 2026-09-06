import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ScenarioLabTab } from './ScenarioLabTab';
import { MotionProvider } from '../../context/MotionContext';
import * as api from '../../lib/api';
import { ScenarioDefinition, ScenarioResult, ScenarioCategory } from '../../types';

vi.mock('../../context/AuthContext', () => ({
  useAuth: vi.fn(() => ({
    user: { username: 'test-operator', is_active: true },
    roles: ['OPERATOR'],
    canRunScenarioLab: true,
    isAuthenticated: true,
  })),
}));

const mockScenarios: ScenarioDefinition[] = [
  {
    scenario_id: 'ALLOW_CLEAN',
    name: 'Clean Arithmetic Computation',
    description: 'Harmless arithmetic addition tool request that evaluates to ALLOW and executes safely in Sandbox.',
    category: ScenarioCategory.BASELINE,
    expected_decision: 'ALLOW',
    expected_status: 'COMPLETED',
    expected_executed: true,
    requires_approval: false,
  },
  {
    scenario_id: 'REQUIRE_APPROVAL_PROMPT_INJECTION',
    name: 'Prompt Injection Instruction Override',
    description: 'Agent request containing instruction override pattern triggering REQUIRE_APPROVAL and pending review.',
    category: ScenarioCategory.BASELINE,
    expected_decision: 'REQUIRE_APPROVAL',
    expected_status: 'DENIED',
    expected_executed: false,
    requires_approval: true,
  },
  {
    scenario_id: 'APPROVED_EXECUTION',
    name: 'Approved Request Execution Flow',
    description: 'Full approval flow: REQUIRE_APPROVAL -> Operator APPROVE -> Enforcement Authorization -> Sandbox Execution.',
    category: ScenarioCategory.APPROVAL_LIFECYCLE,
    expected_decision: 'ALLOW',
    expected_status: 'COMPLETED',
    expected_executed: true,
    requires_approval: true,
  },
  {
    scenario_id: 'TAMPER_REQUEST_ID',
    name: 'Tampered Request Identifier Attack',
    description: 'Adversary alters capability token request ID before sandbox dispatch.',
    category: ScenarioCategory.ANTI_TAMPER,
    expected_decision: 'ALLOW',
    expected_status: 'DENIED',
    expected_executed: false,
    requires_approval: true,
  },
];

const mockCleanResult: ScenarioResult = {
  scenario_id: 'ALLOW_CLEAN',
  scenario_name: 'Clean Arithmetic Computation',
  category: ScenarioCategory.BASELINE,
  request_id: 'req-lab-clean-01',
  expected_decision: 'ALLOW',
  actual_decision: 'ALLOW',
  expected_status: 'COMPLETED',
  actual_status: 'COMPLETED',
  expected_executed: true,
  actual_executed: true,
  passed: true,
  message: 'Clean calculation evaluated to ALLOW and executed successfully in Sandbox.',
  metadata: {
    result: { result: 30.0 },
    secret_key: 'top_secret_auth_token_xyz',
  },
};

const mockApprovalResult: ScenarioResult = {
  scenario_id: 'APPROVED_EXECUTION',
  scenario_name: 'Approved Request Execution Flow',
  category: ScenarioCategory.APPROVAL_LIFECYCLE,
  request_id: 'req-lab-app-02',
  expected_decision: 'ALLOW',
  actual_decision: 'ALLOW',
  expected_status: 'COMPLETED',
  actual_status: 'COMPLETED',
  expected_executed: true,
  actual_executed: true,
  expected_approval_status: 'APPROVED',
  actual_approval_status: 'APPROVED',
  approval_id: 'app-lab-uuid-999',
  passed: true,
  message: 'Approval workflow completed; request authorized and executed in sandbox.',
  metadata: { authorization_id: 'auth-cap-777' },
};

const mockTamperResult: ScenarioResult = {
  scenario_id: 'TAMPER_REQUEST_ID',
  scenario_name: 'Tampered Request Identifier Attack',
  category: ScenarioCategory.ANTI_TAMPER,
  request_id: 'req-lab-tamper-03',
  expected_decision: 'ALLOW',
  actual_decision: 'ALLOW',
  expected_status: 'DENIED',
  actual_status: 'DENIED',
  expected_executed: false,
  actual_executed: false,
  expected_approval_status: 'APPROVED',
  actual_approval_status: 'APPROVED',
  approval_id: 'app-tamper-01',
  passed: true,
  message: 'Tampered request ID rejected by cryptographic enforcement boundary.',
  metadata: { signature_valid: false },
};

describe('ScenarioLabTab Adversarial Security Workbench (Phase 14J-C9)', () => {
  const mockSelectTab = vi.fn();

  beforeEach(async () => {
    vi.clearAllMocks();
    const { useAuth } = await import('../../context/AuthContext');
    (useAuth as any).mockReturnValue({
      user: { username: 'test-operator', is_active: true },
      roles: ['OPERATOR'],
      canRunScenarioLab: true,
      isAuthenticated: true,
    });
    vi.spyOn(api, 'fetchLaboratoryScenarios').mockResolvedValue(mockScenarios);
    vi.spyOn(api, 'runLaboratoryScenario').mockResolvedValue(mockCleanResult);
  });

  const renderTab = (props = {}) => {
    return render(
      <MotionProvider>
        <ScenarioLabTab onSelectTab={mockSelectTab} {...props} />
      </MotionProvider>
    );
  };

  it('1. Renders Workbench Header with title, adversarial badge, and scenario count', async () => {
    renderTab();

    await waitFor(() => {
      expect(screen.getByText('Scenario & Attack Laboratory')).toBeInTheDocument();
      expect(screen.getByText(/ADVERSARIAL WORKBENCH/i)).toBeInTheDocument();
      expect(screen.getByText(/4 Standard Scenarios/i)).toBeInTheDocument();
    });
  });

  it('2. Renders Authoritative Scenario Registry with all 4 categories and target metadata', async () => {
    renderTab();

    await waitFor(() => {
      expect(screen.getAllByText('Clean Arithmetic Computation').length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText('ALLOW_CLEAN')).toBeInTheDocument();
      expect(screen.getByText('Prompt Injection Instruction Override')).toBeInTheDocument();
      expect(screen.getByText('Approved Request Execution Flow')).toBeInTheDocument();
      expect(screen.getByText('Tampered Request Identifier Attack')).toBeInTheDocument();
    });

    // Verify expected target badges
    expect(screen.getAllByText('ALLOW').length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText('REQUIRE_APPROVAL').length).toBeGreaterThanOrEqual(1);
  });

  it('3. Filters scenarios by Category pills (Baseline, Approval, Anti-Tamper)', async () => {
    renderTab();

    await waitFor(() => {
      expect(screen.getAllByText('Clean Arithmetic Computation').length).toBeGreaterThanOrEqual(1);
    });

    // Click Anti-Tamper filter
    const antiTamperBtn = screen.getByRole('button', { name: /^Anti-Tamper/i });
    fireEvent.click(antiTamperBtn);

    await waitFor(() => {
      expect(api.fetchLaboratoryScenarios).toHaveBeenCalledWith('ANTI_TAMPER');
    });
  });

  it('4. Filters scenarios by Search Input and clears search', async () => {
    renderTab();

    await waitFor(() => {
      expect(screen.getAllByText('Clean Arithmetic Computation').length).toBeGreaterThanOrEqual(1);
    });

    const searchInput = screen.getByLabelText(/filter scenarios by name or id/i);
    fireEvent.change(searchInput, { target: { value: 'Prompt' } });

    await waitFor(() => {
      expect(screen.getAllByText('Prompt Injection Instruction Override').length).toBeGreaterThanOrEqual(1);
      expect(screen.queryByText('Clean Arithmetic Computation')).not.toBeInTheDocument();
    });

    // Clear search button
    const clearBtn = screen.getByLabelText(/clear search/i);
    fireEvent.click(clearBtn);

    await waitFor(() => {
      expect(screen.getAllByText('Clean Arithmetic Computation').length).toBeGreaterThanOrEqual(1);
    });
  });

  it('5. Executes Scenario when clicking Run, verifies running state and outcome PASS', async () => {
    renderTab();

    await waitFor(() => {
      expect(screen.getAllByText('Clean Arithmetic Computation').length).toBeGreaterThanOrEqual(1);
    });

    const runButtons = screen.getAllByRole('button', { name: /^run$/i });
    expect(runButtons.length).toBeGreaterThanOrEqual(1);

    fireEvent.click(runButtons[0]);

    // Outcome verified
    await waitFor(() => {
      expect(screen.getByText(/VERIFIED PASS/i)).toBeInTheDocument();
      expect(
        screen.getByText(/Clean calculation evaluated to ALLOW and executed successfully in Sandbox/i)
      ).toBeInTheDocument();
    });

    // Expected vs Actual comparison
    expect(screen.getByText('Outcome Summary')).toBeInTheDocument();
    expect(screen.getByText('req-lab-clean-01')).toBeInTheDocument();
  });

  it('6. Renders Attack -> Defense Pipeline Trace stages for completed result', async () => {
    renderTab();

    await waitFor(() => {
      expect(screen.getAllByText('Clean Arithmetic Computation').length).toBeGreaterThanOrEqual(1);
    });

    const runButtons = screen.getAllByRole('button', { name: /^run$/i });
    fireEvent.click(runButtons[0]);

    await waitFor(() => {
      expect(screen.getByText('Pipeline Enforcement Trace')).toBeInTheDocument();
      expect(screen.getByText('ATTACK INPUT')).toBeInTheDocument();
      expect(screen.getByText('DETECTION')).toBeInTheDocument();
      expect(screen.getByText('POLICY')).toBeInTheDocument();
      expect(screen.getByText('ENFORCEMENT')).toBeInTheDocument();
      expect(screen.getByText('OUTCOME')).toBeInTheDocument();
      expect(screen.getByText('AUDIT')).toBeInTheDocument();
    });
  });

  it('7. Opens Deep Technical Inspection Drawer and validates Formal Assertion Matrix', async () => {
    renderTab();

    await waitFor(() => {
      expect(screen.getAllByText('Clean Arithmetic Computation').length).toBeGreaterThanOrEqual(1);
    });

    const runButtons = screen.getAllByRole('button', { name: /^run$/i });
    fireEvent.click(runButtons[0]);

    await waitFor(() => {
      expect(screen.getByText(/VERIFIED PASS/i)).toBeInTheDocument();
    });

    // Click Inspect Drawer
    const inspectBtn = screen.getByRole('button', { name: /inspect drawer/i });
    fireEvent.click(inspectBtn);

    expect(screen.getByRole('dialog')).toBeInTheDocument();
    expect(screen.getByText('Formal Security Assertion Matrix')).toBeInTheDocument();
    expect(screen.getByText('Security Policy Decision Match')).toBeInTheDocument();
    expect(screen.getByText('Runtime Lifecycle Status Match')).toBeInTheDocument();
    expect(screen.getByText('Sandbox Execution Guard Match')).toBeInTheDocument();
    expect(screen.getByText('Zero-Leakage Telemetry Redaction')).toBeInTheDocument();

    // Dismiss via Close button
    const closeBtn = screen.getByRole('button', { name: /close scenario details/i });
    fireEvent.click(closeBtn);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();

    // Reopen and dismiss via Escape key
    fireEvent.click(inspectBtn);
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    fireEvent.keyDown(window, { key: 'Escape', code: 'Escape' });
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('8. Sanitizes sensitive secrets and tokens in telemetry inspection (Zero Leakage)', async () => {
    renderTab();

    await waitFor(() => {
      expect(screen.getAllByText('Clean Arithmetic Computation').length).toBeGreaterThanOrEqual(1);
    });

    const runButtons = screen.getAllByRole('button', { name: /^run$/i });
    fireEvent.click(runButtons[0]);

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /inspect drawer/i })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /inspect drawer/i }));

    expect(screen.getByRole('dialog')).toBeInTheDocument();

    // Raw secret must NOT exist anywhere in the DOM
    expect(screen.queryByText(/top_secret_auth_token_xyz/i)).not.toBeInTheDocument();
    // Instead, redacted placeholder must be rendered
    expect(screen.getAllByText(/REDACTED_SECURITY_DATA/i).length).toBeGreaterThan(0);
  });

  it('9. Renders specialized Approval-Lifecycle state machine and correlation', async () => {
    vi.spyOn(api, 'runLaboratoryScenario').mockResolvedValueOnce(mockApprovalResult);

    renderTab();

    await waitFor(() => {
      expect(screen.getAllByText('Approved Request Execution Flow').length).toBeGreaterThanOrEqual(1);
    });

    // Select and run approval scenario
    fireEvent.click(screen.getAllByText('Approved Request Execution Flow')[0]);
    const runBtn = screen.getByRole('button', { name: /execute laboratory test/i });
    fireEvent.click(runBtn);

    await waitFor(() => {
      expect(screen.getByText(/Approval Correlation • Human-in-the-Loop/i)).toBeInTheDocument();
      expect(screen.getByText('app-lab-uuid-999')).toBeInTheDocument();
      expect(screen.getAllByText('APPROVED').length).toBeGreaterThanOrEqual(1);
    });
  });

  it('10. Renders specialized Anti-Tamper cryptographic boundary verification', async () => {
    vi.spyOn(api, 'runLaboratoryScenario').mockResolvedValueOnce(mockTamperResult);

    renderTab();

    await waitFor(() => {
      expect(screen.getAllByText('Tampered Request Identifier Attack').length).toBeGreaterThanOrEqual(1);
    });

    fireEvent.click(screen.getAllByText('Tampered Request Identifier Attack')[0]);
    const runBtn = screen.getByRole('button', { name: /execute laboratory test/i });
    fireEvent.click(runBtn);

    await waitFor(() => {
      expect(screen.getByText(/Cryptographic Anti-Tamper Invariant/i)).toBeInTheDocument();
      expect(
        screen.getByText(/Tampered capability token \/ payload rejected at SecurityEnforcementBoundary/i)
      ).toBeInTheDocument();
    });
  });

  it('11. Dispatches tab correlation navigation when clicking Correlate buttons', async () => {
    renderTab();

    await waitFor(() => {
      expect(screen.getAllByText('Clean Arithmetic Computation').length).toBeGreaterThanOrEqual(1);
    });

    const runButtons = screen.getAllByRole('button', { name: /^run$/i });
    fireEvent.click(runButtons[0]);

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /^Threats$/i })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /^Threats$/i }));
    expect(mockSelectTab).toHaveBeenCalledWith('threats', 'req-lab-clean-01');

    fireEvent.click(screen.getByRole('button', { name: /^Audit$/i }));
    expect(mockSelectTab).toHaveBeenCalledWith('audit', 'req-lab-clean-01');
  });

  it('12. Records executed runs in Session Run History and allows inspection', async () => {
    renderTab();

    await waitFor(() => {
      expect(screen.getAllByText('Clean Arithmetic Computation').length).toBeGreaterThanOrEqual(1);
    });

    const runButtons = screen.getAllByRole('button', { name: /^run$/i });
    fireEvent.click(runButtons[0]);

    await waitFor(() => {
      expect(screen.getByText(/VERIFIED PASS/i)).toBeInTheDocument();
    });

    // Switch to History view
    const historyTabBtn = screen.getByRole('button', { name: /history/i });
    fireEvent.click(historyTabBtn);

    expect(screen.getByText('Laboratory Session Execution History')).toBeInTheDocument();
    expect(screen.getByText('1 Runs Recorded')).toBeInTheDocument();
    expect(screen.getByText('Clean Arithmetic Computation')).toBeInTheDocument();
    expect(screen.getByText('req-lab-clean-01')).toBeInTheDocument();

    // Inspect button restores workbench
    const inspectBtn = screen.getByRole('button', { name: /inspect/i });
    fireEvent.click(inspectBtn);

    expect(screen.getByText('Outcome Summary')).toBeInTheDocument();
  });

  it('13. Enforces Environment Lockdown when non-development environment is detected', async () => {
    const error403 = new Error('Scenario Laboratory is disabled in non-development environments.');
    (error403 as any).status = 403;
    vi.spyOn(api, 'fetchLaboratoryScenarios').mockRejectedValueOnce(error403);

    renderTab();

    await waitFor(() => {
      expect(screen.getByTestId('scenario-lab-locked')).toBeInTheDocument();
      expect(screen.getByText('SCENARIO LAB LOCKED')).toBeInTheDocument();
      expect(screen.getByText('DEVELOPMENT ENVIRONMENT REQUIRED')).toBeInTheDocument();
      expect(
        screen.getByText(/Adversarial scenario execution is restricted to isolated development environments/i)
      ).toBeInTheDocument();
    });
  });

  it('14. Disables scenario execution for Read-Only VIEWER role', async () => {
    const { useAuth } = await import('../../context/AuthContext');
    (useAuth as any).mockReturnValue({
      user: { username: 'viewer-user', is_active: true },
      roles: ['VIEWER'],
      canRunScenarioLab: false,
      isAuthenticated: true,
    });

    renderTab();

    await waitFor(() => {
      expect(screen.getAllByText('Clean Arithmetic Computation').length).toBeGreaterThanOrEqual(1);
    });

    expect(screen.getByText(/Current identity has role/i)).toBeInTheDocument();
    expect(screen.getByText(/\(Read-Only\)/i)).toBeInTheDocument();

    const runButtons = screen.getAllByRole('button', { name: /^run$/i });
    expect(runButtons[0]).toBeDisabled();
  });
});
