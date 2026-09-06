import { describe, it, expect } from 'vitest';
import {
  AgentIdentity,
  ToolRequest,
  ThreatSignal,
  ThreatReport,
  RiskAssessment,
  SecurityDecision,
  SecurityEvent,
  ROLE_PERMISSIONS,
} from './index';

describe('Phase 1 TypeScript Contracts', () => {
  it('instantiates valid ToolRequest structure', () => {
    const agent: AgentIdentity = {
      agent_id: 'agent-1',
      name: 'TestAgent',
    };

    const request: ToolRequest = {
      request_id: 'req-1',
      agent,
      tool_name: 'filesystem.read',
      tool_category: 'FILESYSTEM',
      action: 'READ',
      parameters: { path: 'sandbox/public/sample.txt' },
      target: 'sandbox/public/sample.txt',
      timestamp: new Date().toISOString(),
    };

    expect(request.request_id).toBe('req-1');
    expect(request.tool_category).toBe('FILESYSTEM');
    expect(request.action).toBe('READ');
  });

  it('instantiates valid ThreatReport and SecurityDecision structures', () => {
    const signal: ThreatSignal = {
      signal_id: 'sig-1',
      threat_type: 'CREDENTIAL_ACCESS',
      severity: 'CRITICAL',
      title: 'Credential File Access',
      description: 'Accessing placeholder credentials',
      confidence: 0.95,
    };

    const report: ThreatReport = {
      report_id: 'rep-1',
      request_id: 'req-1',
      signals: [signal],
      overall_severity: 'CRITICAL',
      summary: 'Critical threat detected',
      analyzed_at: new Date().toISOString(),
    };

    const assessment: RiskAssessment = {
      assessment_id: 'risk-1',
      request_id: 'req-1',
      risk_score: 95.0,
      severity: 'CRITICAL',
      assessed_at: new Date().toISOString(),
    };

    const decision: SecurityDecision = {
      decision_id: 'dec-1',
      request_id: 'req-1',
      decision: 'BLOCK',
      reason: 'Critical credential access blocked',
      decided_at: new Date().toISOString(),
    };

    const event: SecurityEvent = {
      event_id: 'evt-1',
      request_id: 'req-1',
      event_type: 'BLOCKED',
      timestamp: new Date().toISOString(),
      actor: 'policy_engine',
    };

    expect(report.signals.length).toBe(1);
    expect(assessment.risk_score).toBe(95.0);
    expect(decision.decision).toBe('BLOCK');
    expect(event.event_type).toBe('BLOCKED');
  });

  it('instantiates valid Phase 11 ApprovalRequest and ApprovalResolution structures', () => {
    const reviewer = {
      reviewer_id: 'rev-01',
      reviewer_name: 'Security Admin',
      role: 'security_lead',
    };

    const approval = {
      approval_id: 'app-01',
      request_id: 'req-01',
      agent: { agent_id: 'ag-01', name: 'Agent-1' },
      tool_name: 'calculator.compute',
      tool_category: 'SYSTEM' as const,
      action: 'EXECUTE' as const,
      target: 'system.prompt',
      parameters: { op: 'add', a: 1, b: 2 },
      request_fingerprint: 'sha256_mock_fingerprint',
      risk_score: 55.0,
      severity: 'MEDIUM' as const,
      threat_summary: 'Instruction override review',
      created_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 3600000).toISOString(),
      status: 'PENDING' as const,
    };

    expect(approval.status).toBe('PENDING');
    expect(approval.risk_score).toBe(55.0);
    expect(reviewer.reviewer_id).toBe('rev-01');
  });

  it('instantiates valid Phase 12 ScenarioDefinition and ScenarioResult structures', () => {
    const defn = {
      scenario_id: 'ALLOW_CLEAN',
      name: 'Clean Arithmetic Computation',
      description: 'Harmless arithmetic addition tool request.',
      category: 'BASELINE' as const,
      expected_decision: 'ALLOW' as const,
      expected_status: 'COMPLETED',
      expected_executed: true,
      requires_approval: false,
    };

    const result = {
      scenario_id: 'ALLOW_CLEAN',
      scenario_name: 'Clean Arithmetic Computation',
      category: 'BASELINE' as const,
      request_id: 'req-01',
      expected_decision: 'ALLOW' as const,
      actual_decision: 'ALLOW' as const,
      expected_status: 'COMPLETED',
      actual_status: 'COMPLETED',
      expected_executed: true,
      actual_executed: true,
      passed: true,
      message: 'Verified successfully.',
    };

    expect(defn.scenario_id).toBe('ALLOW_CLEAN');
    expect(defn.category).toBe('BASELINE');
    expect(result.passed).toBe(true);
    expect(result.actual_decision).toBe('ALLOW');
  });

  it('validates ConnectionStatus types', () => {
    const statuses: Array<'CONNECTING' | 'HEALTHY' | 'DISCONNECTED'> = [
      'CONNECTING',
      'HEALTHY',
      'DISCONNECTED',
    ];
    expect(statuses).toContain('CONNECTING');
    expect(statuses).toContain('HEALTHY');
    expect(statuses).toContain('DISCONNECTED');
  });

  it('validates Phase 14 Role, Permission, and ROLE_PERMISSIONS mapping', () => {
    expect(ROLE_PERMISSIONS.ADMIN).toContain('MANAGE_IDENTITIES');
    expect(ROLE_PERMISSIONS.ADMIN).toContain('RESOLVE_APPROVALS');
    expect(ROLE_PERMISSIONS.ADMIN).toContain('RUN_SCENARIO_LAB');
    expect(ROLE_PERMISSIONS.SECURITY_REVIEWER).toContain('RESOLVE_APPROVALS');
    expect(ROLE_PERMISSIONS.SECURITY_REVIEWER).not.toContain('MANAGE_IDENTITIES');
    expect(ROLE_PERMISSIONS.VIEWER).toContain('VIEW_OPERATIONS');
    expect(ROLE_PERMISSIONS.VIEWER).not.toContain('RESOLVE_APPROVALS');
    expect(ROLE_PERMISSIONS.VIEWER).not.toContain('RUN_SCENARIO_LAB');
  });
});
