/**
 * Security Redaction & Leakage Prevention Utility
 * Phase 14J-C6 Operational UX Hardening
 *
 * Ensures technical telemetry, evidence objects, and metadata rendered in UI
 * drawers or cards never expose sensitive tokens, passwords, database paths,
 * or raw internal credentials.
 */

const SENSITIVE_KEY_PATTERNS = [
  /password/i,
  /token/i,
  /bearer/i,
  /auth/i,
  /secret/i,
  /credential/i,
  /session_id/i,
  /private_key/i,
  /api_key/i,
  /db_pass/i,
  /database_url/i,
  /connection_string/i,
];

const SENSITIVE_VALUE_PATTERNS = [
  /^Bearer\s+[A-Za-z0-9\-_.]+/i,
  /^eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$/, // JWT pattern
  /[A-Fa-f0-9]{64}/, // 256-bit raw hex keys
  /[a-zA-Z]:\\[^:\n\r]+(\.db|\.sqlite|\.sqlite3)/i, // Windows DB paths
  /\/var\/[^:\n\r]+(\.db|\.sqlite|\.sqlite3)/i, // Linux DB paths
  /[a-zA-Z0-9_+.-]+:\/\/[^:\s]*:[^@\s]+@[^\s]+/i, // Connection URLs with embedded credentials
];

/**
 * Recursively sanitize an object or primitive before rendering in the security console UI.
 */
export function sanitizeTelemetryData(data: unknown, depth = 0): unknown {
  if (depth > 6) {
    return '[TRUNCATED_DEPTH]';
  }

  if (data === null || data === undefined) {
    return data;
  }

  if (typeof data === 'string') {
    for (const pattern of SENSITIVE_VALUE_PATTERNS) {
      if (pattern.test(data)) {
        return '[REDACTED_SECRET]';
      }
    }
    return data;
  }

  if (typeof data === 'number' || typeof data === 'boolean') {
    return data;
  }

  if (Array.isArray(data)) {
    return data.map((item) => sanitizeTelemetryData(item, depth + 1));
  }

  if (typeof data === 'object') {
    const sanitizedObj: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(data as Record<string, unknown>)) {
      const isSensitiveKey = SENSITIVE_KEY_PATTERNS.some((pat) => pat.test(key));
      if (isSensitiveKey) {
        sanitizedObj[key] = '[REDACTED_SECURITY_DATA]';
      } else {
        sanitizedObj[key] = sanitizeTelemetryData(value, depth + 1);
      }
    }
    return sanitizedObj;
  }

  return String(data);
}
