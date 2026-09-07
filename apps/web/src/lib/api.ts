import {
  HealthStatus,
  OperationsOverview,
  OverallSystemHealth,
  SecurityMetrics,
  ThreatActivityItem,
  SecurityDecisionItem,
  ExecutionActivityItem,
  SecurityEvent,
  ApprovalRequest,
  ScenarioDefinition,
  ScenarioResult,
  UserIdentity,
  LoginRequest,
  LoginResponse,
  LogoutResponse,
  AuthorizeCheckRequest,
  AuthorizationDecision,
  ApiErrorClassification,
} from '../types';

/**
 * Resolves the authoritative backend API base URL with the following precedence:
 * 1. Explicit VITE_API_BASE_URL environment variable override (if defined and non-empty).
 * 2. Dynamically derived from the current browser window.location:
 *    `${protocol}//${hostname}:8000`
 *    Examples:
 *      http://localhost:5173    -> http://localhost:8000
 *      http://127.0.0.1:5173    -> http://127.0.0.1:8000
 *      http://172.25.1.97:5173  -> http://172.25.1.97:8000
 *      http://192.168.1.20:5173 -> http://192.168.1.20:8000
 * 3. Fallback to 'http://localhost:8000' if window or location is not available.
 */
export function getApiBaseUrl(): string {
  const rawEnv = (import.meta.env.VITE_API_BASE_URL as string | undefined)?.trim();
  if (rawEnv && rawEnv !== 'undefined' && rawEnv !== 'null' && rawEnv.length > 0) {
    return rawEnv.replace(/\/+$/, '');
  }

  if (typeof window !== 'undefined' && window.location) {
    const rawProtocol = window.location.protocol || 'http:';
    const protocol = rawProtocol.endsWith(':') ? rawProtocol : `${rawProtocol}:`;
    const rawHostname = window.location.hostname;
    if (rawHostname && rawHostname.trim().length > 0) {
      const hostname = rawHostname.trim();
      const cleanHostname = hostname.includes(':') && !hostname.startsWith('[')
        ? `[${hostname}]`
        : hostname;
      return `${protocol}//${cleanHostname}:8000`;
    }
  }

  return 'http://localhost:8000';
}

export const API_BASE_URL = getApiBaseUrl();

// In-memory token storage (memory only; never written to localStorage to prevent session harvesting)
let memoryToken: string | null = null;
let memoryCsrfToken: string | null = null;

// Listeners for 401 Unauthorized / session revocation
type UnauthorizedListener = () => void;
const unauthorizedListeners: Set<UnauthorizedListener> = new Set();

export function onUnauthorized(listener: UnauthorizedListener): () => void {
  unauthorizedListeners.add(listener);
  return () => unauthorizedListeners.delete(listener);
}

function notifyUnauthorized(): void {
  unauthorizedListeners.forEach((listener) => {
    try {
      listener();
    } catch {
      // Ignore listener errors
    }
  });
}

export function getCsrfToken(): string | null {
  if (typeof document !== 'undefined' && document.cookie) {
    const match = document.cookie.match(/(?:^|;\s*)csrf_token=([^;]+)/);
    if (match) {
      return decodeURIComponent(match[1]);
    }
  }
  return memoryCsrfToken;
}

export function setCsrfToken(token: string | null): void {
  memoryCsrfToken = token;
}

export function getStoredToken(): string | null {
  return memoryToken;
}

export function setStoredToken(token: string | null): void {
  memoryToken = token;
  // Intentionally memory-only. Never write to localStorage (P2 Security Hardening).
}

export function clearStoredToken(): void {
  memoryToken = null;
  memoryCsrfToken = null;
}

/**
 * Authoritative API error class carrying HTTP status code, classification, and server details.
 */
export class ApiError extends Error {
  public status: number;
  public classification: ApiErrorClassification;
  public details?: any;
  public correlationId?: string;

  constructor(status: number, message: string, details?: any, correlationId?: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.details = details;
    this.correlationId = correlationId || (typeof details === 'object' && details !== null ? details.correlation_id : undefined);

    if (status === 401) {
      this.classification = 'AUTH_REQUIRED';
    } else if (status === 403) {
      this.classification = 'FORBIDDEN';
    } else if (status >= 500) {
      this.classification = 'UNEXPECTED_SERVER_ERROR';
    } else if (status === 0) {
      this.classification = 'NETWORK_ERROR';
    } else {
      this.classification = 'UNEXPECTED_SERVER_ERROR';
    }
  }
}

/**
 * Deterministically classifies any error into standard AgentShield API error categories:
 * - NETWORK_ERROR: Backend unreachable, connection refused, DNS failure, offline
 * - AUTH_REQUIRED: HTTP 401 unauthenticated / session token required
 * - FORBIDDEN: HTTP 403 authenticated caller lacks required role/permission
 * - UNEXPECTED_SERVER_ERROR: HTTP 500+ or unexpected error
 */
export function classifyError(error: unknown): ApiErrorClassification {
  if (error instanceof ApiError) {
    return error.classification;
  }
  if (typeof error === 'object' && error !== null) {
    const status = (error as { status?: unknown }).status;
    if (status === 401) return 'AUTH_REQUIRED';
    if (status === 403) return 'FORBIDDEN';
    if (status === 0) return 'NETWORK_ERROR';
    if (status === 200) return 'SUCCESS';
    if (typeof status === 'number' && status >= 500) return 'UNEXPECTED_SERVER_ERROR';
  }
  if (error instanceof Error) {
    const msg = error.message.toLowerCase();
    if (
      msg.includes('failed to fetch') ||
      msg.includes('network error') ||
      msg.includes('networkerror') ||
      msg.includes('connection refused') ||
      msg.includes('econnrefused') ||
      msg.includes('abort') ||
      error.name === 'TypeError'
    ) {
      return 'NETWORK_ERROR';
    }
    if (msg.includes('401') || msg.includes('unauthorized') || msg.includes('not authenticated')) {
      return 'AUTH_REQUIRED';
    }
    if (msg.includes('403') || msg.includes('forbidden') || msg.includes('permission denied')) {
      return 'FORBIDDEN';
    }
    if (msg.includes('500') || msg.includes('internal server error')) {
      return 'UNEXPECTED_SERVER_ERROR';
    }
  }
  return 'NETWORK_ERROR';
}

/**
 * Centralized fetch helper enforcing credentials and authentication headers.
 * Attaches Authorization: Bearer <token> and X-Session-ID headers without logging secrets.
 */
export async function authFetch(url: string, options: RequestInit = {}): Promise<Response> {
  const resolvedUrl = url.startsWith('http://') || url.startsWith('https://')
    ? url
    : `${getApiBaseUrl()}${url.startsWith('/') ? '' : '/'}${url}`;

  const headers = new Headers(options.headers || {});
  const token = getStoredToken();

  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
    headers.set('X-Session-ID', token);
  }

  const method = (options.method || 'GET').toUpperCase();
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    const csrfToken = getCsrfToken();
    if (csrfToken && !headers.has('X-CSRF-Token')) {
      headers.set('X-CSRF-Token', csrfToken);
    }
  }

  const mergedOptions: RequestInit = {
    ...options,
    headers,
    credentials: 'include',
  };

  try {
    const response = await fetch(resolvedUrl, mergedOptions);

    if (response.status === 401) {
      // Only notify if we actually had a stored token that was revoked/expired
      const hadToken = Boolean(getStoredToken());
      clearStoredToken();
      if (hadToken) {
        notifyUnauthorized();
      }
    }

    return response;
  } catch (err: any) {
    if (err instanceof ApiError) throw err;
    throw new ApiError(0, err?.message || 'Network connection failed', err);
  }
}

// ----------------------------------------------------------------------------
// Phase 14 Authentication & Identity API Methods
// ----------------------------------------------------------------------------

export async function login(credentials: LoginRequest): Promise<LoginResponse> {
  const response = await fetch(`${getApiBaseUrl()}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify(credentials),
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ detail: response.statusText }));
    throw new Error(errorData.detail || `Authentication failed: ${response.statusText}`);
  }

  const data: LoginResponse = await response.json();
  if (data.session_id) {
    setStoredToken(data.session_id);
  }
  const csrfHeader = response.headers?.get ? response.headers.get('X-CSRF-Token') : null;
  if (csrfHeader) {
    setCsrfToken(csrfHeader);
  } else if ((data as any).csrf_token) {
    setCsrfToken((data as any).csrf_token);
  }
  return data;
}

export async function logout(): Promise<LogoutResponse> {
  try {
    const response = await authFetch(`${getApiBaseUrl()}/api/v1/auth/logout`, {
      method: 'POST',
    });
    clearStoredToken();
    if (response.ok) {
      return await response.json();
    }
    return { message: 'Logged out locally', revoked: true };
  } catch {
    clearStoredToken();
    return { message: 'Logged out locally', revoked: true };
  }
}

export async function fetchCurrentUser(): Promise<UserIdentity> {
  const response = await authFetch(`${getApiBaseUrl()}/api/v1/auth/me`);
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ detail: response.statusText }));
    throw new ApiError(response.status, errorData.detail || `Failed to fetch current user profile: ${response.statusText}`, errorData);
  }
  return await response.json();
}

export async function checkAuthorization(req: AuthorizeCheckRequest): Promise<AuthorizationDecision> {
  const response = await authFetch(`${getApiBaseUrl()}/api/v1/auth/authorize`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(req),
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ detail: response.statusText }));
    throw new ApiError(response.status, errorData.detail || `Authorization check failed: ${response.statusText}`, errorData);
  }
  return await response.json();
}

// ----------------------------------------------------------------------------
// Operations Console API Methods
// ----------------------------------------------------------------------------

export async function fetchHealthStatus(): Promise<HealthStatus> {
  try {
    const response = await fetch(`${getApiBaseUrl()}/health`, {
      headers: { 'Accept': 'application/json' },
    });
    if (!response.ok) {
      throw new ApiError(response.status, `Health check failed with status: ${response.status}`);
    }
    return await response.json();
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(0, error instanceof Error ? error.message : 'Backend connection failed');
  }
}

export async function fetchOperationsOverview(): Promise<OperationsOverview> {
  const response = await authFetch(`${getApiBaseUrl()}/api/v1/security/operations/overview`);
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ detail: response.statusText }));
    throw new ApiError(response.status, errorData.detail || `Failed to fetch operations overview: ${response.statusText}`, errorData);
  }
  return await response.json();
}

export async function fetchSystemHealth(): Promise<OverallSystemHealth> {
  const response = await authFetch(`${getApiBaseUrl()}/api/v1/security/operations/health`);
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ detail: response.statusText }));
    throw new ApiError(response.status, errorData.detail || `Failed to fetch system health: ${response.statusText}`, errorData);
  }
  return await response.json();
}

export async function fetchSecurityMetrics(): Promise<SecurityMetrics> {
  const response = await authFetch(`${getApiBaseUrl()}/api/v1/security/operations/metrics`);
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ detail: response.statusText }));
    throw new ApiError(response.status, errorData.detail || `Failed to fetch security metrics: ${response.statusText}`, errorData);
  }
  return await response.json();
}

export async function fetchThreats(
  limit: number = 50,
  severity?: string,
  threatType?: string
): Promise<ThreatActivityItem[]> {
  const params = new URLSearchParams({ limit: limit.toString() });
  if (severity) params.append('severity', severity);
  if (threatType) params.append('threat_type', threatType);

  const response = await authFetch(`${getApiBaseUrl()}/api/v1/security/operations/threats?${params.toString()}`);
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ detail: response.statusText }));
    throw new ApiError(response.status, errorData.detail || `Failed to fetch threats: ${response.statusText}`, errorData);
  }
  return await response.json();
}

export async function fetchDecisions(
  limit: number = 50,
  decision?: string
): Promise<SecurityDecisionItem[]> {
  const params = new URLSearchParams({ limit: limit.toString() });
  if (decision) params.append('decision', decision);

  const response = await authFetch(`${getApiBaseUrl()}/api/v1/security/operations/decisions?${params.toString()}`);
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ detail: response.statusText }));
    throw new ApiError(response.status, errorData.detail || `Failed to fetch decisions: ${response.statusText}`, errorData);
  }
  return await response.json();
}

export async function fetchExecutions(
  limit: number = 50,
  status?: string
): Promise<ExecutionActivityItem[]> {
  const params = new URLSearchParams({ limit: limit.toString() });
  if (status) params.append('status', status);

  const response = await authFetch(`${getApiBaseUrl()}/api/v1/security/operations/executions?${params.toString()}`);
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ detail: response.statusText }));
    throw new ApiError(response.status, errorData.detail || `Failed to fetch executions: ${response.statusText}`, errorData);
  }
  return await response.json();
}

export async function fetchAuditEvents(
  limit: number = 100,
  requestId?: string
): Promise<SecurityEvent[]> {
  const params = new URLSearchParams({ limit: limit.toString() });
  if (requestId) params.append('request_id', requestId);

  const response = await authFetch(`${getApiBaseUrl()}/api/v1/security/operations/audit?${params.toString()}`);
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ detail: response.statusText }));
    throw new ApiError(response.status, errorData.detail || `Failed to fetch audit events: ${response.statusText}`, errorData);
  }
  return await response.json();
}

// ----------------------------------------------------------------------------
// Phase 11 & Phase 14 Approval Workflow API Endpoints
// ----------------------------------------------------------------------------

export async function fetchApprovals(
  status?: string,
  limit: number = 50
): Promise<ApprovalRequest[]> {
  const params = new URLSearchParams({ limit: limit.toString() });
  if (status) params.append('status', status);

  const response = await authFetch(`${getApiBaseUrl()}/api/v1/security/approvals?${params.toString()}`);
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ detail: response.statusText }));
    throw new ApiError(response.status, errorData.detail || `Failed to fetch approvals: ${response.statusText}`, errorData);
  }
  return await response.json();
}

export async function fetchApproval(approvalId: string): Promise<ApprovalRequest> {
  const response = await authFetch(`${getApiBaseUrl()}/api/v1/security/approvals/${approvalId}`);
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ detail: response.statusText }));
    throw new ApiError(response.status, errorData.detail || `Failed to fetch approval details: ${response.statusText}`, errorData);
  }
  return await response.json();
}

export async function approveApproval(
  approvalId: string,
  reviewerId: string,
  reviewerName: string,
  role: string,
  reason: string
): Promise<ApprovalRequest> {
  const response = await authFetch(`${getApiBaseUrl()}/api/v1/security/approvals/${approvalId}/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      reviewer_id: reviewerId,
      reviewer_name: reviewerName,
      role: role,
      reason: reason,
    }),
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ detail: response.statusText }));
    throw new ApiError(response.status, errorData.detail || `Failed to approve request: ${response.statusText}`, errorData);
  }
  return await response.json();
}

export async function rejectApproval(
  approvalId: string,
  reviewerId: string,
  reviewerName: string,
  role: string,
  reason: string
): Promise<ApprovalRequest> {
  const response = await authFetch(`${getApiBaseUrl()}/api/v1/security/approvals/${approvalId}/reject`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      reviewer_id: reviewerId,
      reviewer_name: reviewerName,
      role: role,
      reason: reason,
    }),
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ detail: response.statusText }));
    throw new ApiError(response.status, errorData.detail || `Failed to reject request: ${response.statusText}`, errorData);
  }
  return await response.json();
}

export async function cancelApproval(
  approvalId: string,
  reason: string = 'Cancelled by requester'
): Promise<ApprovalRequest> {
  const response = await authFetch(`${getApiBaseUrl()}/api/v1/security/approvals/${approvalId}/cancel`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reason }),
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ detail: response.statusText }));
    throw new ApiError(response.status, errorData.detail || `Failed to cancel request: ${response.statusText}`, errorData);
  }
  return await response.json();
}

// ----------------------------------------------------------------------------
// Phase 12 Scenario / Attack Laboratory API Endpoints
// ----------------------------------------------------------------------------

export async function fetchLaboratoryScenarios(
  category?: string
): Promise<ScenarioDefinition[]> {
  const params = new URLSearchParams();
  if (category) params.append('category', category);

  const response = await authFetch(`${getApiBaseUrl()}/api/v1/dev/laboratory/scenarios?${params.toString()}`);
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ detail: response.statusText }));
    throw new ApiError(response.status, errorData.detail || `Failed to fetch laboratory scenarios: ${response.statusText}`, errorData);
  }
  return await response.json();
}

export async function runLaboratoryScenario(
  scenarioId: string,
  requestId?: string | null
): Promise<ScenarioResult> {
  const response = await authFetch(`${getApiBaseUrl()}/api/v1/dev/laboratory/run`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      scenario_id: scenarioId,
      request_id: requestId || undefined,
    }),
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ detail: response.statusText }));
    throw new ApiError(response.status, errorData.detail || `Failed to execute scenario: ${response.statusText}`, errorData);
  }
  return await response.json();
}

export async function fetchOperationalTelemetry(): Promise<any> {
  const response = await authFetch(`${getApiBaseUrl()}/api/v1/security/operations/telemetry`);
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ detail: response.statusText }));
    const correlationId = response.headers.get('X-Correlation-ID') || response.headers.get('x-correlation-id') || undefined;
    throw new ApiError(response.status, errorData.detail || `Failed to fetch operational telemetry: ${response.statusText}`, errorData, correlationId);
  }
  return await response.json();
}

// ----------------------------------------------------------------------------
// Stage 13 & 14: IAM, Policy Governance, and Gateway Client Methods
// ----------------------------------------------------------------------------

export async function fetchIdentities(limit = 100): Promise<UserIdentity[]> {
  const response = await authFetch(`${getApiBaseUrl()}/api/v1/auth/identities?limit=${limit}`);
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ detail: response.statusText }));
    throw new ApiError(response.status, errorData.detail || 'Failed to fetch user identities', errorData);
  }
  return await response.json();
}

export async function createIdentity(data: {
  username: string;
  password: string;
  display_name: string;
  roles: string[];
  email?: string;
  is_active?: boolean;
}): Promise<UserIdentity> {
  const response = await authFetch(`${getApiBaseUrl()}/api/v1/auth/identities`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ detail: response.statusText }));
    throw new ApiError(response.status, errorData.detail || 'Failed to create user identity', errorData);
  }
  return await response.json();
}

export async function disableIdentity(userId: string): Promise<UserIdentity> {
  const response = await authFetch(`${getApiBaseUrl()}/api/v1/auth/identities/${encodeURIComponent(userId)}/disable`, {
    method: 'POST',
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ detail: response.statusText }));
    throw new ApiError(response.status, errorData.detail || 'Failed to disable user identity', errorData);
  }
  return await response.json();
}

export async function updateIdentityRoles(userId: string, roles: string[]): Promise<UserIdentity> {
  const response = await authFetch(`${getApiBaseUrl()}/api/v1/auth/identities/${encodeURIComponent(userId)}/roles`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ roles }),
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ detail: response.statusText }));
    throw new ApiError(response.status, errorData.detail || 'Failed to update roles', errorData);
  }
  return await response.json();
}

export async function fetchPolicies(isEnabled?: boolean): Promise<any[]> {
  const url = isEnabled !== undefined
    ? `${getApiBaseUrl()}/api/v1/policies?is_enabled=${isEnabled}`
    : `${getApiBaseUrl()}/api/v1/policies`;
  const response = await authFetch(url);
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ detail: response.statusText }));
    throw new ApiError(response.status, errorData.detail || 'Failed to fetch policies', errorData);
  }
  return await response.json();
}

export async function createPolicy(policy: {
  policy_id: string;
  name: string;
  description: string;
  rule_type: string;
  priority: number;
  conditions?: Record<string, any>;
  action: string;
  is_enabled?: boolean;
}): Promise<any> {
  const response = await authFetch(`${getApiBaseUrl()}/api/v1/policies`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(policy),
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ detail: response.statusText }));
    throw new ApiError(response.status, errorData.detail || 'Failed to create policy', errorData);
  }
  return await response.json();
}

export async function deletePolicy(policyId: string): Promise<any> {
  const response = await authFetch(`${getApiBaseUrl()}/api/v1/policies/${encodeURIComponent(policyId)}`, {
    method: 'DELETE',
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ detail: response.statusText }));
    throw new ApiError(response.status, errorData.detail || 'Failed to disable policy', errorData);
  }
  return await response.json();
}

export async function fetchRegisteredTools(): Promise<any[]> {
  const response = await authFetch(`${getApiBaseUrl()}/api/v1/tools`);
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ detail: response.statusText }));
    throw new ApiError(response.status, errorData.detail || 'Failed to fetch registered tools', errorData);
  }
  return await response.json();
}

export async function fetchRegisteredAgents(): Promise<any[]> {
  const response = await authFetch(`${getApiBaseUrl()}/api/v1/agents`);
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ detail: response.statusText }));
    throw new ApiError(response.status, errorData.detail || 'Failed to fetch registered agents', errorData);
  }
  return await response.json();
}

export async function ingestAgentAction(action: {
  agent_id: string;
  action_type?: string;
  target: string;
  parameters?: Record<string, any>;
  context?: Record<string, any>;
  idempotency_key?: string;
}): Promise<any> {
  const response = await authFetch(`${getApiBaseUrl()}/api/v1/gateway/actions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(action),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok && response.status !== 202 && response.status !== 403) {
    throw new ApiError(response.status, data.detail || 'Gateway action failed', data);
  }
  return data;
}
