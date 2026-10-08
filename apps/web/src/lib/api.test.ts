import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  getApiBaseUrl,
  authFetch,
  login,
  fetchOperationsOverview,
  setStoredToken,
  clearStoredToken,
  getStoredToken,
  onUnauthorized,
  ApiError,
  classifyError,
  fetchHealthStatus,
} from './api';

describe('API URL Robustness & Origin Derivation', () => {
  const originalLocation = window.location;
  const originalEnv = import.meta.env.VITE_API_BASE_URL;

  beforeEach(() => {
    clearStoredToken();
    vi.restoreAllMocks();
    // Reset VITE_API_BASE_URL to undefined by default for derivation tests
    (import.meta.env as any).VITE_API_BASE_URL = undefined;
  });

  afterEach(() => {
    // Restore window.location
    Object.defineProperty(window, 'location', {
      value: originalLocation,
      writable: true,
      configurable: true,
    });
    // Restore env
    (import.meta.env as any).VITE_API_BASE_URL = originalEnv;
    clearStoredToken();
  });

  function mockLocation(protocol: string, hostname: string, port = '5173') {
    Object.defineProperty(window, 'location', {
      value: {
        protocol,
        hostname,
        port,
        host: `${hostname}:${port}`,
        origin: `${protocol}//${hostname}:${port}`,
        href: `${protocol}//${hostname}:${port}/`,
        pathname: '/',
        search: '',
        hash: '',
        assign: vi.fn(),
        replace: vi.fn(),
        reload: vi.fn(),
      },
      writable: true,
      configurable: true,
    });
  }

  it('derives backend origin from localhost:5173 -> http://localhost:8001', () => {
    mockLocation('http:', 'localhost', '5173');
    expect(getApiBaseUrl()).toBe('http://localhost:8001');
  });

  it('derives backend origin from 127.0.0.1:5173 -> http://127.0.0.1:8001', () => {
    mockLocation('http:', '127.0.0.1', '5173');
    expect(getApiBaseUrl()).toBe('http://127.0.0.1:8001');
  });

  it('derives backend origin from arbitrary LAN IP 172.25.1.97 -> http://172.25.1.97:8001', () => {
    mockLocation('http:', '172.25.1.97', '5173');
    expect(getApiBaseUrl()).toBe('http://172.25.1.97:8001');
  });

  it('derives backend origin from arbitrary LAN IP 192.168.1.20 -> http://192.168.1.20:8001', () => {
    mockLocation('http:', '192.168.1.20', '5173');
    expect(getApiBaseUrl()).toBe('http://192.168.1.20:8001');
  });

  it('derives backend origin from 10.0.0.5 with https -> https://10.0.0.5:8001', () => {
    mockLocation('https:', '10.0.0.5', '5173');
    expect(getApiBaseUrl()).toBe('https://10.0.0.5:8001');
  });

  it('preserves explicit VITE_API_BASE_URL as an override', () => {
    mockLocation('http:', '192.168.1.20', '5173');
    (import.meta.env as any).VITE_API_BASE_URL = 'http://custom-api.internal:9000';

    expect(getApiBaseUrl()).toBe('http://custom-api.internal:9000');
  });

  it('trims trailing slashes from explicit VITE_API_BASE_URL override', () => {
    mockLocation('http:', 'localhost', '5173');
    (import.meta.env as any).VITE_API_BASE_URL = 'http://override-server:8000///';

    expect(getApiBaseUrl()).toBe('http://override-server:8000');
  });

  it('falls back to location derivation when VITE_API_BASE_URL is empty or whitespace', () => {
    mockLocation('http:', '192.168.1.55', '5173');
    (import.meta.env as any).VITE_API_BASE_URL = '   ';

    expect(getApiBaseUrl()).toBe('http://192.168.1.55:8001');
  });

  it('API requests dynamically use the derived origin from current browser location', async () => {
    mockLocation('http:', '192.168.1.105', '5173');

    let calledUrl = '';
    global.fetch = vi.fn().mockImplementation((url: string) => {
      calledUrl = url;
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ status: 'ok' }),
      });
    });

    await fetchOperationsOverview();

    expect(calledUrl).toBe('http://192.168.1.105:8001/api/v1/security/operations/overview');
  });

  it('login API request dynamically uses derived origin', async () => {
    mockLocation('http:', '10.20.30.40', '5173');

    let calledUrl = '';
    global.fetch = vi.fn().mockImplementation((url: string) => {
      calledUrl = url;
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () =>
          Promise.resolve({
            session_id: 'sess-dynamic-origin-test',
            user_id: 'u-1',
            username: 'lead',
            roles: ['SECURITY_REVIEWER'],
            expires_at: new Date().toISOString(),
          }),
      });
    });

    await login({ username: 'lead', password: 'ValidPassword123!' });

    expect(calledUrl).toBe('http://10.20.30.40:8001/api/v1/auth/login');
    expect(getStoredToken()).toBe('sess-dynamic-origin-test');
  });

  it('authFetch attaches Authorization: Bearer, X-Session-ID, and credentials: include', async () => {
    mockLocation('http:', '192.168.1.20', '5173');
    setStoredToken('test-bearer-token-xyz');

    let capturedHeaders: Headers | undefined;
    let capturedCredentials: RequestCredentials | undefined;

    global.fetch = vi.fn().mockImplementation((_url: string, init?: RequestInit) => {
      capturedHeaders = new Headers(init?.headers);
      capturedCredentials = init?.credentials;
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve({}),
      });
    });

    await authFetch('/api/v1/security/operations/health');

    expect(capturedHeaders?.get('Authorization')).toBe('Bearer test-bearer-token-xyz');
    expect(capturedHeaders?.get('X-Session-ID')).toBe('test-bearer-token-xyz');
    expect(capturedCredentials).toBe('include');
  });

  it('authFetch automatically cleans up session on 401 response', async () => {
    mockLocation('http:', 'localhost', '5173');
    setStoredToken('expired-session-token');

    let unauthorizedTriggered = false;
    const unsubscribe = onUnauthorized(() => {
      unauthorizedTriggered = true;
    });

    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      statusText: 'Unauthorized',
    });

    await authFetch('/api/v1/security/operations/health');

    expect(getStoredToken()).toBeNull();
    expect(unauthorizedTriggered).toBe(true);

    unsubscribe();
  });
});

describe('API Error Classification & Semantic Invariants', () => {
  beforeEach(() => {
    clearStoredToken();
    vi.restoreAllMocks();
  });

  afterEach(() => {
    clearStoredToken();
  });

  it('instantiates ApiError with correct classification based on status code', () => {
    const err401 = new ApiError(401, 'Unauthorized');
    expect(err401.status).toBe(401);
    expect(err401.classification).toBe('AUTH_REQUIRED');

    const err403 = new ApiError(403, 'Forbidden');
    expect(err403.status).toBe(403);
    expect(err403.classification).toBe('FORBIDDEN');

    const err500 = new ApiError(500, 'Server Error');
    expect(err500.status).toBe(500);
    expect(err500.classification).toBe('UNEXPECTED_SERVER_ERROR');

    const err0 = new ApiError(0, 'Network Down');
    expect(err0.status).toBe(0);
    expect(err0.classification).toBe('NETWORK_ERROR');
  });

  it('classifyError deterministically classifies various error types', () => {
    expect(classifyError(new ApiError(401, 'Unauthorized'))).toBe('AUTH_REQUIRED');
    expect(classifyError(new ApiError(403, 'Forbidden'))).toBe('FORBIDDEN');
    expect(classifyError(new ApiError(0, 'Failed to connect'))).toBe('NETWORK_ERROR');
    expect(classifyError(new ApiError(503, 'Service unavailable'))).toBe('UNEXPECTED_SERVER_ERROR');

    // Object status inspection
    expect(classifyError({ status: 401 })).toBe('AUTH_REQUIRED');
    expect(classifyError({ status: 403 })).toBe('FORBIDDEN');
    expect(classifyError({ status: 0 })).toBe('NETWORK_ERROR');
    expect(classifyError({ status: 200 })).toBe('SUCCESS');
    expect(classifyError({ status: 500 })).toBe('UNEXPECTED_SERVER_ERROR');

    // Standard Error messages
    expect(classifyError(new TypeError('Failed to fetch'))).toBe('NETWORK_ERROR');
    expect(classifyError(new Error('Network error: connection refused'))).toBe('NETWORK_ERROR');
    expect(classifyError(new Error('connect ECONNREFUSED 127.0.0.1:8000'))).toBe('NETWORK_ERROR');
    expect(classifyError(new Error('Request aborted'))).toBe('NETWORK_ERROR');
    expect(classifyError(new Error('HTTP 401 Unauthorized'))).toBe('AUTH_REQUIRED');
    expect(classifyError(new Error('HTTP 403 Forbidden'))).toBe('FORBIDDEN');
    expect(classifyError(new Error('500 Internal Server Error'))).toBe('UNEXPECTED_SERVER_ERROR');
  });

  it('authFetch does NOT trigger notifyUnauthorized when unauthenticated on initial load (no token was stored)', async () => {
    clearStoredToken();

    let unauthorizedTriggered = false;
    const unsubscribe = onUnauthorized(() => {
      unauthorizedTriggered = true;
    });

    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      statusText: 'Unauthorized',
    });

    await authFetch('/api/v1/security/operations/overview');

    expect(unauthorizedTriggered).toBe(false);
    unsubscribe();
  });

  it('fetchOperationsOverview throws ApiError with AUTH_REQUIRED on HTTP 401', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      statusText: 'Unauthorized',
      json: () => Promise.resolve({ detail: 'Authentication required' }),
    });

    await expect(fetchOperationsOverview()).rejects.toThrow(ApiError);
    try {
      await fetchOperationsOverview();
    } catch (err: any) {
      expect(err).toBeInstanceOf(ApiError);
      expect(err.status).toBe(401);
      expect(err.classification).toBe('AUTH_REQUIRED');
    }
  });

  it('fetchHealthStatus succeeds on 200 and throws ApiError(0) on network failure', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: () => Promise.resolve({ status: 'ok', service: 'agentshield' }),
    });

    const result = await fetchHealthStatus();
    expect(result.status).toBe('ok');

    global.fetch = vi.fn().mockRejectedValue(new TypeError('Failed to fetch'));
    await expect(fetchHealthStatus()).rejects.toThrow(ApiError);
    try {
      await fetchHealthStatus();
    } catch (err: any) {
      expect(err.status).toBe(0);
      expect(err.classification).toBe('NETWORK_ERROR');
    }
  });

  it('Phase 16: ApiError preserves correlationId from response headers or error payload', async () => {
    const errPayload = { detail: 'Internal server error', correlation_id: 'req-test-corr-123' };
    const err1 = new ApiError(500, 'Server Error', errPayload);
    expect(err1.correlationId).toBe('req-test-corr-123');

    const err2 = new ApiError(403, 'Forbidden', { detail: 'Denied' }, 'req-custom-header-id');
    expect(err2.correlationId).toBe('req-custom-header-id');
  });

  it('Phase 16: fetchOperationalTelemetry retrieves telemetry snapshot from backend', async () => {
    const { fetchOperationalTelemetry } = await import('./api');
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'X-Correlation-ID': 'req-telemetry-001' }),
      json: () => Promise.resolve({
        uptime_seconds: 120.5,
        http_requests_total: [],
        auth_events_total: [],
      }),
    });

    const telemetry = await fetchOperationalTelemetry();
    expect(telemetry.uptime_seconds).toBe(120.5);
    expect(Array.isArray(telemetry.http_requests_total)).toBe(true);
  });
});
