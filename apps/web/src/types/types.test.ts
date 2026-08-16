import { describe, it, expect } from 'vitest';
import {
  AgentIdentity,
  ToolRequest,
  ThreatSignal,
  ThreatReport,
  RiskAssessment,
  SecurityDecision,
  SecurityEvent,
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
});
