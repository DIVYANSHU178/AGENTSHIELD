import {
  HealthStatus,
  OperationsOverview,
  OverallSystemHealth,
  SecurityMetrics,
  ThreatActivityItem,
  SecurityDecisionItem,
  ExecutionActivityItem,
  SecurityEvent,
} from '../types';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

export async function fetchHealthStatus(): Promise<HealthStatus> {
  try {
    const response = await fetch(`${API_BASE_URL}/health`);
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    return await response.json();
  } catch (error) {
    console.error('Failed to fetch health status:', error);
    throw error;
  }
}

export async function fetchOperationsOverview(): Promise<OperationsOverview> {
  const response = await fetch(`${API_BASE_URL}/api/v1/security/operations/overview`);
  if (!response.ok) {
    throw new Error(`Failed to fetch operations overview: ${response.statusText}`);
  }
  return await response.json();
}

export async function fetchSystemHealth(): Promise<OverallSystemHealth> {
  const response = await fetch(`${API_BASE_URL}/api/v1/security/operations/health`);
  if (!response.ok) {
    throw new Error(`Failed to fetch system health: ${response.statusText}`);
  }
  return await response.json();
}

export async function fetchSecurityMetrics(): Promise<SecurityMetrics> {
  const response = await fetch(`${API_BASE_URL}/api/v1/security/operations/metrics`);
  if (!response.ok) {
    throw new Error(`Failed to fetch security metrics: ${response.statusText}`);
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

  const response = await fetch(`${API_BASE_URL}/api/v1/security/operations/threats?${params.toString()}`);
  if (!response.ok) {
    throw new Error(`Failed to fetch threats: ${response.statusText}`);
  }
  return await response.json();
}

export async function fetchDecisions(
  limit: number = 50,
  decision?: string
): Promise<SecurityDecisionItem[]> {
  const params = new URLSearchParams({ limit: limit.toString() });
  if (decision) params.append('decision', decision);

  const response = await fetch(`${API_BASE_URL}/api/v1/security/operations/decisions?${params.toString()}`);
  if (!response.ok) {
    throw new Error(`Failed to fetch decisions: ${response.statusText}`);
  }
  return await response.json();
}

export async function fetchExecutions(
  limit: number = 50,
  status?: string
): Promise<ExecutionActivityItem[]> {
  const params = new URLSearchParams({ limit: limit.toString() });
  if (status) params.append('status', status);

  const response = await fetch(`${API_BASE_URL}/api/v1/security/operations/executions?${params.toString()}`);
  if (!response.ok) {
    throw new Error(`Failed to fetch executions: ${response.statusText}`);
  }
  return await response.json();
}

export async function fetchAuditEvents(
  limit: number = 100,
  requestId?: string
): Promise<SecurityEvent[]> {
  const params = new URLSearchParams({ limit: limit.toString() });
  if (requestId) params.append('request_id', requestId);

  const response = await fetch(`${API_BASE_URL}/api/v1/security/operations/audit?${params.toString()}`);
  if (!response.ok) {
    throw new Error(`Failed to fetch audit events: ${response.statusText}`);
  }
  return await response.json();
}
