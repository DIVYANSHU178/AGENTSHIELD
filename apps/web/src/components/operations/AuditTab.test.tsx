import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { AuditTab } from './AuditTab';
import { MotionProvider } from '../../context/MotionContext';
import { SecurityEvent } from '../../types';

const mockAuditEvents: SecurityEvent[] = [
  {
    event_id: 'ev-req-001',
    request_id: 'req-corr-201',
    event_type: 'REQUESTED',
    timestamp: '2026-09-05T14:00:00Z',
    actor: 'TestAgent-Alpha',
    details: {
      tool_name: 'database.query',
      action: 'QUERY',
      target: 'records_table',
    },
    metadata: {
      session_id: 'sess-abc-123',
    },
  },
  {
    event_id: 'ev-ana-002',
    request_id: 'req-corr-201',
    event_type: 'ANALYZED',
    timestamp: '2026-09-05T14:00:01Z',
    actor: 'SecurityDecisionGateway',
    details: {
      threat_count: 1,
      risk_score: 85.0,
      severity: 'HIGH',
    },
  },
  {
    event_id: 'ev-blk-003',
    request_id: 'req-corr-201',
    event_type: 'BLOCKED',
    timestamp: '2026-09-05T14:00:02Z',
    actor: 'SecurityEnforcementBoundary',
    details: {
      decision: 'BLOCK',
      reason: 'Critical policy violation detected in SQL query pattern',
      secret_api_key: 'top_secret_raw_key_123',
    },
  },
  {
    event_id: 'ev-app-004',
    request_id: 'req-corr-202',
    event_type: 'APPROVAL_APPROVED',
    timestamp: '2026-09-05T14:01:00Z',
    actor: 'SecLead01',
    details: {
      approval_id: 'app-999',
      reviewer: 'SecLead01',
      decision: 'APPROVE',
    },
  },
  {
    event_id: 'ev-exe-005',
    request_id: 'req-corr-202',
    event_type: 'EXECUTED',
    timestamp: '2026-09-05T14:01:05Z',
    actor: 'SandboxExecutionBoundary',
    details: {
      tool_name: 'calculator.compute',
      duration_ms: 15.2,
      status: 'COMPLETED',
      db_password: 'super_secret_db_password',
    },
  },
  {
    event_id: 'ev-ath-006',
    request_id: 'req-corr-203',
    event_type: 'AUTHENTICATION_SUCCESS',
    timestamp: '2026-09-05T14:02:00Z',
    actor: 'admin_user',
    details: {
      username: 'admin',
      roles: ['ADMIN'],
    },
  },
];

describe('Audit Trail & Forensic Evidence Console Hardening (Phase 14J-C7)', () => {
  it('1. Renders Header, Stage 7 breadcrumb, and honest integrity attestation', () => {
    render(
      <MotionProvider>
        <AuditTab events={mockAuditEvents} />
      </MotionProvider>
    );

    expect(screen.getByText('Security Audit Trail & Evidence Timeline')).toBeInTheDocument();
    expect(screen.getByText(/Stage 7 of 7: Forensic Verification/i)).toBeInTheDocument();

    // Honest integrity status without fabricated blockchain claims
    expect(screen.getByText('PERSISTED')).toBeInTheDocument();
    expect(screen.getByText(/API verify unavail/i)).toBeInTheDocument();

    // Quantified KPI metrics strip
    expect(screen.getByText('Total Events')).toBeInTheDocument();
    expect(screen.getByText('Gateway Lifecycle')).toBeInTheDocument();
    expect(screen.getByText('Executions')).toBeInTheDocument();
    expect(screen.getByText('Approvals')).toBeInTheDocument();
    expect(screen.getByText('Identity & Auth')).toBeInTheDocument();
    expect(screen.getByText('Unique Actors')).toBeInTheDocument();

    // Total events: 6
    expect(screen.getAllByText('6').length).toBeGreaterThanOrEqual(1);
  });

  it('2. Filters audit event stream by Category, Event Type, and Search Term', () => {
    render(
      <MotionProvider>
        <AuditTab events={mockAuditEvents} />
      </MotionProvider>
    );

    // Initial shows all events
    expect(screen.getAllByText('REQUESTED').length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText('BLOCKED').length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText('APPROVAL_APPROVED').length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText('AUTHENTICATION_SUCCESS').length).toBeGreaterThanOrEqual(1);

    // Filter by category: IDENTITY
    const categorySelect = screen.getByLabelText(/Filter by Event Category/i);
    fireEvent.change(categorySelect, { target: { value: 'IDENTITY' } });

    expect(screen.getAllByText('AUTHENTICATION_SUCCESS').length).toBeGreaterThanOrEqual(1);
    expect(screen.queryByText('ev-req-001')).not.toBeInTheDocument();
    expect(screen.queryByText('ev-app-004')).not.toBeInTheDocument();

    // Reset filters
    fireEvent.click(screen.getByText(/Reset Filters/i));
    expect(screen.getAllByText(/req-corr-201/i).length).toBeGreaterThanOrEqual(1);

    // Search by correlation request_id
    const searchInput = screen.getByLabelText(/Search audit events/i);
    fireEvent.change(searchInput, { target: { value: 'req-corr-202' } });

    expect(screen.queryByText(/ev-req-001/i)).not.toBeInTheDocument();
    expect(screen.getByText(/ev-app-004/i)).toBeInTheDocument();
    expect(screen.getByText(/ev-exe-005/i)).toBeInTheDocument();
  });

  it('3. Opens forensic detail drawer with persistence attestation and dismisses on Escape', () => {
    render(
      <MotionProvider>
        <AuditTab events={mockAuditEvents} />
      </MotionProvider>
    );

    // Click inspect on first event
    const inspectBtns = screen.getAllByRole('button', { name: /^inspect/i });
    fireEvent.click(inspectBtns[0]);

    // Drawer opens
    expect(screen.getByText('Forensic Audit Event Record')).toBeInTheDocument();
    expect(screen.getByText(/Timeline & Persistence Attestation/i)).toBeInTheDocument();
    expect(screen.getByText('ev-req-001')).toBeInTheDocument();
    expect(screen.getByText('req-corr-201')).toBeInTheDocument();
    expect(screen.getByText(/security_audit_events/i)).toBeInTheDocument();

    // Close on Escape key
    fireEvent.keyDown(window, { key: 'Escape' });
    expect(screen.queryByText('Forensic Audit Event Record')).not.toBeInTheDocument();
  });

  it('4. Redacts sensitive keys in rendered audit payloads (Security UI Audit)', () => {
    render(
      <MotionProvider>
        <AuditTab events={mockAuditEvents} />
      </MotionProvider>
    );

    // Open detail drawer for BLOCKED event which contains secret_api_key
    const inspectBtns = screen.getAllByRole('button', { name: /^inspect/i });
    fireEvent.click(inspectBtns[2]); // ev-blk-003

    // Ensure raw secret key value is never rendered
    expect(screen.queryByText('top_secret_raw_key_123')).not.toBeInTheDocument();
    expect(screen.getAllByText(/\[REDACTED_SECURITY_DATA\]/i).length).toBeGreaterThanOrEqual(1);

    // Dismiss
    fireEvent.keyDown(window, { key: 'Escape' });

    // Open drawer for EXECUTED event which contains db_password
    fireEvent.click(inspectBtns[4]); // ev-exe-005
    expect(screen.queryByText('super_secret_db_password')).not.toBeInTheDocument();
  });

  it('5. Cross-links from Audit Record to Security Decision', () => {
    const onSelectTabMock = vi.fn();
    render(
      <MotionProvider>
        <AuditTab events={mockAuditEvents} onSelectTab={onSelectTabMock} />
      </MotionProvider>
    );

    const decisionBtns = screen.getAllByRole('button', { name: /Decision/i });
    fireEvent.click(decisionBtns[0]);

    expect(onSelectTabMock).toHaveBeenCalledWith('decisions', 'req-corr-201');
  });

  it('6. Renders AuthRequiredState and LoadingState correctly', () => {
    const onSignInMock = vi.fn();
    const { rerender } = render(
      <MotionProvider>
        <AuditTab events={[]} authRequired={true} onSignIn={onSignInMock} />
      </MotionProvider>
    );

    expect(screen.getByText('Audit Trail Telemetry Requires Authentication')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /Sign In to Access/i }));
    expect(onSignInMock).toHaveBeenCalled();

    rerender(
      <MotionProvider>
        <AuditTab events={[]} loading={true} authRequired={false} />
      </MotionProvider>
    );
    expect(screen.getByText('Synchronizing Audit Trail')).toBeInTheDocument();
  });
});
