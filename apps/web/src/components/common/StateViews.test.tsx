import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import {

  LoadingState,
  SuccessState,
  EmptyState,
  AuthRequiredState,
  ForbiddenState,
  BackendUnavailableState,
  ServerErrorState,
  StateView,
} from './StateViews';

describe('Shared State Visual Language Components', () => {
  it('renders LoadingState with custom title, message, and stage indicator', () => {
    render(
      <LoadingState
        title="Analyzing Model Invocations"
        message="Verifying prompt safety and token limits..."
        stage="STAGE 1: CIPHER VALIDATION"
      />
    );

    expect(screen.getByText('Analyzing Model Invocations')).toBeInTheDocument();
    expect(screen.getByText('Verifying prompt safety and token limits...')).toBeInTheDocument();
    expect(screen.getByText('STAGE 1: CIPHER VALIDATION')).toBeInTheDocument();
    expect(screen.getByRole('status')).toBeInTheDocument();
  });

  it('renders SuccessState with metadata details and action button', () => {
    const onAction = vi.fn();
    render(
      <SuccessState
        title="Policy Enforced"
        message="Policy rule approved and synced."
        details={{ RuleId: 'POL-01', RiskScore: '12.5' }}
        action={<button onClick={onAction}>View Policy</button>}
      />
    );

    expect(screen.getByText('Policy Enforced')).toBeInTheDocument();
    expect(screen.getByText('Policy rule approved and synced.')).toBeInTheDocument();
    expect(screen.getByText('POL-01')).toBeInTheDocument();
    expect(screen.getByText('12.5')).toBeInTheDocument();

    fireEvent.click(screen.getByText('View Policy'));
    expect(onAction).toHaveBeenCalledTimes(1);
  });

  it('renders EmptyState with custom title and explanatory text', () => {
    render(
      <EmptyState
        title="No Security Events"
        message="No security alerts have been recorded in the current session."
      />
    );

    expect(screen.getByText('No Security Events')).toBeInTheDocument();
    expect(screen.getByText('No security alerts have been recorded in the current session.')).toBeInTheDocument();
  });

  it('renders AuthRequiredState and triggers onSignIn callback', () => {
    const handleSignIn = vi.fn();
    render(
      <AuthRequiredState
        title="Operator Authentication Required"
        message="Please authenticate to access operations controls."
        onSignIn={handleSignIn}
      />
    );

    expect(screen.getByText('Operator Authentication Required')).toBeInTheDocument();
    const btn = screen.getByRole('button', { name: /sign in to access/i });
    expect(btn).toBeInTheDocument();

    fireEvent.click(btn);
    expect(handleSignIn).toHaveBeenCalledTimes(1);
  });

  it('renders ForbiddenState with required permission badge', () => {
    render(
      <ForbiddenState
        title="Access Prohibited"
        message="You lack approval authority."
        requiredPermission="approvals:write"
      />
    );

    expect(screen.getByText('Access Prohibited')).toBeInTheDocument();
    expect(screen.getByText('Required: approvals:write')).toBeInTheDocument();
    expect(screen.getByRole('alert')).toBeInTheDocument();
  });

  it('renders BackendUnavailableState with retry action and retrying state', () => {
    const handleRetry = vi.fn();
    const { rerender } = render(
      <BackendUnavailableState
        title="Connection Lost"
        message="AgentShield backend is unreachable at http://localhost:8000"
        onRetry={handleRetry}
        retrying={false}
      />
    );

    expect(screen.getByText('Connection Lost')).toBeInTheDocument();
    const retryBtn = screen.getByRole('button', { name: /retry connection/i });
    expect(retryBtn).toBeInTheDocument();
    expect(retryBtn).not.toBeDisabled();

    fireEvent.click(retryBtn);
    expect(handleRetry).toHaveBeenCalledTimes(1);

    // Rerender in retrying state
    rerender(
      <BackendUnavailableState
        title="Connection Lost"
        message="AgentShield backend is unreachable at http://localhost:8000"
        onRetry={handleRetry}
        retrying={true}
      />
    );
    expect(screen.getByText('Reconnecting...')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /reconnecting.../i })).toBeDisabled();
  });

  it('renders ServerErrorState with stack / error details', () => {
    render(
      <ServerErrorState
        title="Security Gateway Error"
        message="Failed during risk analysis."
        errorDetails="HTTP 500: Database lock timeout on security_decisions"
      />
    );

    expect(screen.getByText('Security Gateway Error')).toBeInTheDocument();
    expect(screen.getByText(/database lock timeout/i)).toBeInTheDocument();
  });

  it('renders via unified StateView dispatcher for different variants', () => {
    const { rerender } = render(<StateView variant="loading" title="Dispatcher Loading" />);
    expect(screen.getByText('Dispatcher Loading')).toBeInTheDocument();

    rerender(<StateView variant="forbidden" title="Dispatcher Forbidden" />);
    expect(screen.getByText('Dispatcher Forbidden')).toBeInTheDocument();

    rerender(<StateView variant="server-error" title="Dispatcher Error" />);
    expect(screen.getByText('Dispatcher Error')).toBeInTheDocument();
  });
});
