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

const TOKEN_STORAGE_KEY = 'agentshield_session_token';

// In-memory fallback if localStorage is unavailable
let memoryToken: string | null = null;

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

export function getStoredToken(): string | null {
  try {
    return localStorage.getItem(TOKEN_STORAGE_KEY) || memoryToken;
  } catch {
    return memoryToken;
  }
}

export function setStoredToken(token: string | null): void {
  memoryToken = token;
  try {
    if (token) {
      localStorage.setItem(TOKEN_STORAGE_KEY, token);
    } else {
      localStorage.removeItem(TOKEN_STORAGE_KEY);
    }
  } catch {
    // Ignore storage quota/access errors
  }
}

export function clearStoredToken(): void {
  setStoredToken(null);
}

/**
 * Authoritative API error class carrying HTTP status code, classification, and server details.
 */
export class ApiError extends Error {
  public status: number;
  public classification: ApiErrorClassification;
  public details?: any;

  constructor(status: number, message: string, details?: any) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.details = details;

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
