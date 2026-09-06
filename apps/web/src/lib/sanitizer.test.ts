import { describe, it, expect } from 'vitest';
import { sanitizeTelemetryData } from './sanitizer';

describe('sanitizeTelemetryData Security Leakage Prevention', () => {
  it('passes through safe primitives and objects', () => {
    const input = {
      action: 'EXECUTE',
      tool: 'calculator.compute',
      duration_ms: 45.2,
      success: true,
      safe_array: ['item1', 'item2'],
    };
    const output = sanitizeTelemetryData(input);
    expect(output).toEqual(input);
  });

  it('redacts sensitive keys including password, token, bearer, credential, secret', () => {
    const input = {
      tool: 'auth_helper',
      api_token: 'secret_abc_123',
      user_password: 'super_secret_password',
      client_secret: 'sec-987654',
      bearer_auth: 'some-value',
      session_id: 'sess-xyz',
      nested: {
        db_password: 'admin',
        credentials: {
          key: 'val',
        },
      },
    };
    const output = sanitizeTelemetryData(input) as Record<string, any>;
    expect(output.tool).toBe('auth_helper');
    expect(output.api_token).toBe('[REDACTED_SECURITY_DATA]');
    expect(output.user_password).toBe('[REDACTED_SECURITY_DATA]');
    expect(output.client_secret).toBe('[REDACTED_SECURITY_DATA]');
    expect(output.bearer_auth).toBe('[REDACTED_SECURITY_DATA]');
    expect(output.session_id).toBe('[REDACTED_SECURITY_DATA]');
    expect(output.nested.db_password).toBe('[REDACTED_SECURITY_DATA]');
    expect(output.nested.credentials).toBe('[REDACTED_SECURITY_DATA]');
  });

  it('redacts sensitive values such as Bearer tokens, DB paths, and 256-bit keys', () => {
    const input = {
      auth_header: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummy.sig',
      win_db: 'C:\\Users\\admin\\secrets\\agentshield.db',
      lin_db: '/var/lib/data/agentshield.sqlite',
      hex_key: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    };
    const output = sanitizeTelemetryData(input) as Record<string, any>;
    expect(output.auth_header).toBe('[REDACTED_SECURITY_DATA]'); // Matches both key and value
    expect(output.win_db).toBe('[REDACTED_SECRET]');
    expect(output.lin_db).toBe('[REDACTED_SECRET]');
    expect(output.hex_key).toBe('[REDACTED_SECRET]');
  });

  it('redacts connection strings with embedded credentials even when key is neutral', () => {
    const input = {
      service_endpoint: 'postgresql://dbadmin:superSecretPass@db.internal:5432/agentshield',
      redis_endpoint: 'redis://:auth_pass_999@redis.internal:6379/0',
    };
    const output = sanitizeTelemetryData(input) as Record<string, any>;
    expect(output.service_endpoint).toBe('[REDACTED_SECRET]');
    expect(output.redis_endpoint).toBe('[REDACTED_SECRET]');
  });
});
