// Phase 0 Baseline Types
export interface HealthStatus {
  status: string;
  service: string;
}

export interface BaseSystemConfig {
  appName: string;
  environment: string;
  apiHost: string;
  apiPort: number;
}

// Phase 1 Security Domain Enums
export type ToolCategory =
  | 'FILESYSTEM'
  | 'BROWSER'
  | 'NETWORK'
  | 'COMMUNICATION'
  | 'CODE_EXECUTION'
  | 'DATABASE'
  | 'SYSTEM'
  | 'OTHER';

export type ActionType =
  | 'READ'
  | 'WRITE'
  | 'DELETE'
  | 'EXECUTE'
  | 'SEND'
  | 'UPLOAD'
  | 'DOWNLOAD'
  | 'SEARCH'
  | 'NAVIGATE'
  | 'QUERY'
  | 'MODIFY'
  | 'OTHER';

export type ThreatType =
  | 'PROMPT_INJECTION'
  | 'CREDENTIAL_ACCESS'
  | 'SENSITIVE_DATA_ACCESS'
  | 'DATA_EXFILTRATION'
  | 'DANGEROUS_ACTION'
  | 'MALICIOUS_DESTINATION'
  | 'PRIVILEGE_ESCALATION'
  | 'SUSPICIOUS_BEHAVIOR'
  | 'UNKNOWN';

export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type SecurityDecisionType = 'ALLOW' | 'BLOCK' | 'REQUIRE_APPROVAL';

export type EventType =
  | 'REQUESTED'
  | 'ANALYZED'
  | 'ALLOWED'
  | 'BLOCKED'
  | 'APPROVAL_REQUIRED'
  | 'EXECUTED'
  | 'FAILED';

// Phase 1 Security Domain Interfaces
export interface AgentIdentity {
  agent_id: string;
  name: string;
  version?: string;
  provider?: string;
  session_id?: string | null;
  metadata?: Record<string, unknown>;
}

export interface ToolRequest {
  request_id: string;
  agent: AgentIdentity;
  tool_name: string;
  tool_category: ToolCategory;
  action: ActionType;
  parameters: Record<string, unknown>;
  target: string;
  destination?: string | null;
  timestamp: string; // ISO 8601 UTC string
  session_id?: string | null;
  metadata?: Record<string, unknown>;
}

export interface SecurityContext {
  session_id: string;
  user_id?: string | null;
  agent_id: string;
  environment?: string;
  trust_level?: string;
  previous_decisions?: string[];
  metadata?: Record<string, unknown>;
}

export interface ThreatSignal {
  signal_id: string;
  threat_type: ThreatType;
  severity: Severity;
  title: string;
  description: string;
  evidence?: Record<string, unknown>;
  confidence: number; // Normalized 0.0 to 1.0
  source?: string;
  metadata?: Record<string, unknown>;
}

export interface ThreatReport {
  report_id: string;
  request_id: string;
  signals: ThreatSignal[];
  overall_severity: Severity;
  summary: string;
  analyzed_at: string; // ISO 8601 UTC string
  metadata?: Record<string, unknown>;
}

export interface RiskAssessment {
  assessment_id: string;
  request_id: string;
  risk_score: number; // Bounded 0.0 to 100.0
  severity: Severity;
  contributing_signals?: string[];
  rationale?: string;
  assessed_at: string; // ISO 8601 UTC string
  metadata?: Record<string, unknown>;
}

export interface SecurityDecision {
  decision_id: string;
  request_id: string;
  decision: SecurityDecisionType;
  risk_assessment_id?: string | null;
  reason: string;
  decided_at: string; // ISO 8601 UTC string
  policy_id?: string | null;
  metadata?: Record<string, unknown>;
}

export interface SecurityEvent {
  event_id: string;
  request_id: string;
  event_type: EventType;
  timestamp: string; // ISO 8601 UTC string
  actor: string;
  details?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}
