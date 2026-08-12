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
});
