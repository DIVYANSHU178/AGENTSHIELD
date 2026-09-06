# AgentShield Security Configuration & Secret Management Guide

**Phase 15 — Secrets & Configuration Hardening**

This document establishes the official configuration and secret management boundary for AgentShield.

---

## 1. Primary Security Principles

1. **Zero Hardcoded Secrets**: Production secrets must never be hardcoded in source code or committed to git.
2. **Fail-Closed in Production**: If a required secret or secure configuration is missing in production, the application must immediately fail closed during startup rather than falling back to an insecure default.
3. **No Secret Leakage**: Secrets must never appear in frontend bundles, DOM elements, API responses, exception messages, client stack traces, or audit log records.
4. **Environment Separation**: Development and QA environments may utilize deterministic test seeds; production environments strictly disallow automatic default credential seeding and permissive private-network CORS rules.

---

## 2. Secret Classification Matrix

| Category | Description | Source / Location | Storage | Redaction / Protection | Production Requirement |
|---|---|---|---|---|---|
| **A. Authentication Secrets** | User login passwords | Client request payload | Never stored in plaintext; PBKDF2-HMAC-SHA256 hashed | `sanitize_audit_payload`, `[REDACTED_SECURITY_DATA]` | Strong passwords enforced |
| **B. Session Secrets** | 32-byte URL-safe session tokens | `AuthenticationService.authenticate()` | Server-side SQLite `sessions` table | Redacted in audit events, masked in logs | Cryptographically secure entropy (`secrets.token_urlsafe(32)`) |
| **C. Signing Keys** | HMAC-SHA256 capability authorization keys | `AGENTSHIELD_AUTHORIZATION_SECRET` | Process memory only | `[REDACTED_SECRET_KEY]` | **Mandatory** ($\ge 32$ characters) |
| **D. Security Secret Key** | Application secret key | `SECRET_KEY` | Process memory only | `[REDACTED_SECRET_KEY]` | **Mandatory** ($\ge 32$ characters, no dev default) |
| **E. Database Credentials** | Connection URLs & credentials | `DATABASE_URL` | Process memory | `mask_connection_url` (`:****@`) | Isolated connection string |
| **F. Model / API Keys** | Upstream AI tool API keys | Tool request parameters | Evaluated in-memory | Sanitized from telemetry and audit | Secure injection per execution |
| **G. Development Credentials** | Seeded QA/dev accounts (`admin`, `security_lead`) | `_bootstrap_default_identities` | SQLite `users` table (hashed) | Disabled in production | `ALLOW_DEFAULT_CREDENTIALS=false` |
| **H. Non-Secret Config** | Host, port, environment, allowed origins | `Settings` | Memory | Safe to expose in health diagnostics | Fully validated via Pydantic |

---

## 3. Environment Variables Reference

### Backend (`apps/api`)

| Variable | Type | Required in Prod? | Default (Dev) | Description |
|---|---|---|---|---|
| `ENVIRONMENT` / `AGENTSHIELD_ENV` | `str` | Yes | `"development"` | Active runtime mode (`development`, `qa`, `testing`, `production`). |
| `DEBUG` | `bool` | No | `false` | Debug mode. Strictly rejected if `true` in production. |
| `API_HOST` | `str` | No | `"127.0.0.1"` | Bind host IP for Uvicorn server. |
| `API_PORT` | `int` | No | `8000` | Bind port for Uvicorn server. |
| `DATABASE_URL` | `str` | Yes | `"sqlite:///./agentshield.db"` | SQLAlchemy database URL. Masked in diagnostics. |
| `AGENTSHIELD_AUTHORIZATION_SECRET` | `str` | **YES** | Dev fallback (dev only) | Secret key for signing execution capability tokens. Min 32 chars in prod. |
| `SECRET_KEY` | `str` | **YES** | Dev fallback (dev only) | Application security key. Min 32 chars in prod. |
| `ALLOW_DEFAULT_CREDENTIALS` | `bool` | No | `false` | Allows default identities to seed. Rejected if `true` in prod. |
| `CORS_ALLOWED_ORIGINS` | `str` | No | Localhost origins | Comma-separated list of allowed origins. |
| `CORS_ALLOW_ORIGIN_REGEX` | `str` | No | Local LAN regex (dev only) | Regex for allowed origins. Inactive in prod unless set. |

### Frontend (`apps/web`)

| Variable | Type | Required in Prod? | Default | Description |
|---|---|---|---|---|
| `VITE_API_BASE_URL` | `str` | No | Derived from `window.location` | Base URL of the AgentShield API Gateway. |
| `VITE_ENVIRONMENT` | `str` | No | Derived from build mode | Environment badge label override. |

*WARNING: Never prefix server secrets with `VITE_`. Any variable starting with `VITE_` is baked into client bundles at build time.*

---

## 4. Production Hardening Checklist

- [x] Set `ENVIRONMENT=production` in the deployment environment.
- [x] Generate and inject `AGENTSHIELD_AUTHORIZATION_SECRET` with at least 32 cryptographically random characters (`openssl rand -hex 32`).
- [x] Generate and inject `SECRET_KEY` with at least 32 cryptographically random characters.
- [x] Configure production `DATABASE_URL` with secure credentials.
- [x] Verify `ALLOW_DEFAULT_CREDENTIALS` is `false` or unset.
- [x] Verify `DEBUG` is `false`.
- [x] Restrict `CORS_ALLOWED_ORIGINS` to the exact HTTPS domain hosting the frontend console.
