// Phase 0 Baseline Types
export interface HealthStatus {
  status: string;
  service: string;
  environment?: string;
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
  | 'APPROVAL_APPROVED'
  | 'APPROVAL_REJECTED'
  | 'APPROVAL_EXPIRED'
  | 'APPROVAL_CANCELLED'
  | 'EXECUTED'
  | 'FAILED'
  | 'DENIED'
  | 'AUTHENTICATION_SUCCESS'
  | 'AUTHENTICATION_FAILURE'
  | 'SESSION_CREATED'
  | 'SESSION_REVOKED'
  | 'AUTHORIZATION_ALLOWED'
  | 'AUTHORIZATION_DENIED'
  | 'ROLE_CHANGE'
  | 'IDENTITY_DISABLED'
  | 'APPROVAL_AUTHORIZED'
  | 'APPROVAL_AUTHORIZATION_DENIED';

export type ApprovalStatus = 'PENDING' | 'CLAIMED' | 'APPROVED' | 'REJECTED' | 'EXPIRED' | 'CANCELLED';
export type ApprovalDecision = 'APPROVE' | 'REJECT';

export type RuntimeExecutionStatus =
  | 'PENDING'
  | 'AUTHORIZED'
  | 'COMPLETED'
  | 'FAILED'
  | 'TIMED_OUT'
  | 'DENIED';

export type ComponentStatus = 'HEALTHY' | 'DEGRADED' | 'FAILED' | 'UNKNOWN';
export type ConnectionStatus = 'CONNECTING' | 'HEALTHY' | 'DISCONNECTED';

export type ApiErrorClassification =
  | 'NETWORK_ERROR'
  | 'AUTH_REQUIRED'
  | 'FORBIDDEN'
  | 'SUCCESS'
  | 'UNEXPECTED_SERVER_ERROR';

export type TabType =
  | 'overview'
  | 'threats'
  | 'decisions'
  | 'approvals'
  | 'executions'
  | 'audit'
  | 'diagnostics'
  | 'laboratory'
  | string;


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

// Phase 10 Operations Console Contracts
export interface ComponentHealth {
  name: string;
  status: ComponentStatus;
  details: string;
  checked_at: string;
  metadata?: Record<string, unknown>;
}

export interface OverallSystemHealth {
  status: ComponentStatus;
  components: ComponentHealth[];
  checked_at: string;
  version: string;
  summary: string;
}

export interface SecurityMetrics {
  total_requests: number;
  allowed: number;
  require_approval: number;
  blocked: number;
  authorized: number;
  denied_execution: number;
  successful_execution: number;
  failed_execution: number;
  timed_out_execution: number;
  detected_threats: number;
  critical_threats: number;
  high_threats: number;
  audit_events: number;
  runtime_requests: number;
  runtime_failures: number;
  calculated_at: string;
  metadata?: Record<string, unknown>;
}

export interface ThreatActivityItem {
  threat_id: string;
  threat_type: ThreatType;
  severity: Severity;
  detector: string;
  request_id: string;
  title: string;
  description: string;
  confidence: number;
  timestamp: string;
  metadata?: Record<string, unknown>;
}

export interface SecurityDecisionItem {
  decision_id: string;
  request_id: string;
  decision: SecurityDecisionType;
  risk_score: number;
  severity: Severity;
  policy_id: string;
  reason: string;
  threat_count: number;
  timestamp: string;
  metadata?: Record<string, unknown>;
}

export interface ExecutionActivityItem {
  execution_id: string;
  request_id: string;
  tool_name: string;
  tool_category: ToolCategory;
  action: ActionType;
  status: RuntimeExecutionStatus;
  success: boolean;
  duration_ms: number;
  error?: string | null;
  timestamp: string;
  metadata?: Record<string, unknown>;
}

export interface OperationsOverview {
  overall_health: OverallSystemHealth;
  metrics: SecurityMetrics;
  recent_threats: ThreatActivityItem[];
  recent_decisions: SecurityDecisionItem[];
  recent_executions: ExecutionActivityItem[];
  retrieved_at: string;
}

// Phase 11 Approval Domain Interfaces
export interface ReviewerIdentity {
  reviewer_id: string;
  reviewer_name?: string | null;
  role?: string | null;
  metadata?: Record<string, unknown>;
}

export interface ApprovalResolution {
  approval_id: string;
  request_id: string;
  reviewer: ReviewerIdentity;
  decision: ApprovalDecision;
  reason: string;
  resolved_at: string;
  metadata?: Record<string, unknown>;
}

export interface ApprovalRequest {
  approval_id: string;
  request_id: string;
  agent: AgentIdentity;
  tool_name: string;
  tool_category: ToolCategory;
  action: ActionType;
  target: string;
  parameters: Record<string, unknown>;
  destination?: string | null;
  request_fingerprint: string;
  risk_score: number;
  severity: Severity;
  threat_summary: string;
  created_at: string;
  expires_at: string;
  status: ApprovalStatus;
  resolution?: ApprovalResolution | null;
  metadata?: Record<string, unknown>;
}

// Phase 12 Scenario / Attack Laboratory Interfaces
export enum ScenarioCategory {
  BASELINE = 'BASELINE',
  APPROVAL_LIFECYCLE = 'APPROVAL_LIFECYCLE',
  ANTI_TAMPER = 'ANTI_TAMPER',
  FAILURE_ABUSE = 'FAILURE_ABUSE',
}

export interface ScenarioDefinition {
  scenario_id: string;
  name: string;
  description: string;
  category: ScenarioCategory;
  expected_decision: SecurityDecisionType;
  expected_status: string;
  expected_executed: boolean;
  requires_approval: boolean;
  metadata?: Record<string, unknown>;
}

export interface ScenarioRunRequest {
  scenario_id: string;
  request_id?: string | null;
}

export interface ScenarioResult {
  scenario_id: string;
  scenario_name: string;
  category: ScenarioCategory;
  request_id: string;
  expected_decision: SecurityDecisionType;
  actual_decision: SecurityDecisionType;
  expected_status: string;
  actual_status: string;
  expected_executed: boolean;
  actual_executed: boolean;
  expected_approval_status?: ApprovalStatus | null;
  actual_approval_status?: ApprovalStatus | null;
  approval_id?: string | null;
  passed: boolean;
  message: string;
  metadata?: Record<string, unknown>;
}

// Phase 14 Identity, Authentication & RBAC Contracts
export const Role = {
  VIEWER: 'VIEWER',
  OPERATOR: 'OPERATOR',
  SECURITY_REVIEWER: 'SECURITY_REVIEWER',
  ADMIN: 'ADMIN',
} as const;
export type Role = (typeof Role)[keyof typeof Role];

export const Permission = {
  VIEW_OPERATIONS: 'VIEW_OPERATIONS',
  VIEW_THREATS: 'VIEW_THREATS',
  VIEW_DECISIONS: 'VIEW_DECISIONS',
  VIEW_AUDIT: 'VIEW_AUDIT',
  VIEW_APPROVALS: 'VIEW_APPROVALS',
  RESOLVE_APPROVALS: 'RESOLVE_APPROVALS',
  CANCEL_APPROVAL: 'CANCEL_APPROVAL',
  RUN_SCENARIO_LAB: 'RUN_SCENARIO_LAB',
  MANAGE_IDENTITIES: 'MANAGE_IDENTITIES',
  MANAGE_ROLES: 'MANAGE_ROLES',
  MANAGE_SECURITY_CONFIGURATION: 'MANAGE_SECURITY_CONFIGURATION',
  MANAGE_TOOLS: 'MANAGE_TOOLS',
  MANAGE_POLICIES: 'MANAGE_POLICIES',
} as const;
export type Permission = (typeof Permission)[keyof typeof Permission];

export const ROLE_PERMISSIONS: Record<Role, Permission[]> = {
  VIEWER: [
    'VIEW_OPERATIONS',
    'VIEW_THREATS',
    'VIEW_DECISIONS',
    'VIEW_AUDIT',
    'VIEW_APPROVALS',
  ],
  OPERATOR: [
    'VIEW_OPERATIONS',
    'VIEW_THREATS',
    'VIEW_DECISIONS',
    'VIEW_AUDIT',
    'VIEW_APPROVALS',
    'CANCEL_APPROVAL',
    'RUN_SCENARIO_LAB',
  ],
  SECURITY_REVIEWER: [
    'VIEW_OPERATIONS',
    'VIEW_THREATS',
    'VIEW_DECISIONS',
    'VIEW_AUDIT',
    'VIEW_APPROVALS',
    'RESOLVE_APPROVALS',
    'CANCEL_APPROVAL',
    'RUN_SCENARIO_LAB',
  ],
  ADMIN: [
    'VIEW_OPERATIONS',
    'VIEW_THREATS',
    'VIEW_DECISIONS',
    'VIEW_AUDIT',
    'VIEW_APPROVALS',
    'RESOLVE_APPROVALS',
    'CANCEL_APPROVAL',
    'RUN_SCENARIO_LAB',
    'MANAGE_IDENTITIES',
    'MANAGE_ROLES',
    'MANAGE_SECURITY_CONFIGURATION',
    'MANAGE_TOOLS',
    'MANAGE_POLICIES',
  ],
};

export interface UserIdentity {
  user_id: string;
  username: string;
  email?: string | null;
  display_name: string;
  roles: Role[];
  is_active: boolean;
  created_at: string;
  updated_at: string;
  metadata?: Record<string, unknown>;
}

export interface LoginRequest {
  username: string;
  password: string;
  ttl_seconds?: number;
}

export interface LoginResponse {
  session_id: string;
  user_id: string;
  username: string;
  display_name: string;
  roles: Role[];
  issued_at: string;
  expires_at: string;
}

export interface LogoutResponse {
  message: string;
  revoked: boolean;
}

export interface AuthorizeCheckRequest {
  permission: string;
  resource?: string | null;
}

export interface AuthorizationDecision {
  decision_id: string;
  user_id?: string | null;
  username?: string | null;
  permission: string;
  resource?: string | null;
  allowed: boolean;
  reason: string;
  timestamp: string;
}
