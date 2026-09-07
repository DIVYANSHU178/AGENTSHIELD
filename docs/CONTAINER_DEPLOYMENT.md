# AgentShield: Container Deployment & Operations Guide (Phase 18)

## 1. Overview & Architecture

AgentShield Phase 18 provides a production-grade, hardened container architecture designed for zero-trust operational environments. The architecture separates the backend API engine from the frontend static web presentation layer using multi-stage, non-root, minimal runtime images.

```
+-------------------------------------------------------------------------------+
|                           agentshield-network                                 |
|                                                                               |
|   +--------------------------+           +--------------------------------+   |
|   |   Frontend Container     |           |       Backend Container        |   |
|   |   (nginx:1.27-alpine-slim|           |   (python:3.11-slim-bookworm)  |   |
|   |   UID: 101 (nginx)       |           |   UID: 10001 (agentshield)     |   |
|   |   Port: 8080             |           |   Port: 8000                   |   |
|   |                          |           |                                |   |
|   |   - Serves React SPA     |  /api/*   |   - Uvicorn / FastAPI Core     |   |
|   |   - Reverse proxies API  +---------->|   - Phase 14 Auth / RBAC       |   |
|   |   - Hardened headers     |  /health  |   - Phase 15 Secrets Redaction |   |
|   +------------+-------------+           |   - Phase 16 Observability     |   |
|                |                         |   - Phase 17 Hardening Bounds  |   |
|                v                         +---------------+----------------+   |
|          Host Port :3000                                 |                    |
+----------------------------------------------------------|--------------------+
                                                           v
                                                  Volume: /app/data
                                                  (chmod 700, UID 10001)
```

---

## 2. Image Specifications

### Backend Image (`apps/api/Dockerfile`)
- **Base Image**: `python:3.11-slim-bookworm` (pinned, deterministic, Debian slim).
- **Multi-Stage Build**:
  - `builder` stage compiles dependencies into `/install`.
  - `runtime` stage contains zero build tools (`gcc`, `make` excluded) and zero test tooling (`pytest`, `httpx` excluded).
- **Non-Root User**: `agentshield:agentshield` (`UID 10001`, `GID 10001`).
- **Internal Port**: `8000`.
- **Healthcheck**: Python native HTTP probe against `http://127.0.0.1:8000/health/live`.

### Frontend Image (`apps/web/Dockerfile`)
- **Base Image**: Multi-stage `node:20-alpine` (builder) $\to$ `nginx:1.27-alpine-slim` (runtime).
- **Static Assets**: React 18 SPA compiled via Vite and served from `/usr/share/nginx/html`.
- **Zero-Secret Guarantee**: Excludes `node_modules`, `.env`, source maps, and developer credentials.
- **Non-Root User**: `nginx:nginx` (`UID 101`, `GID 101`).
- **Internal Port**: `8080`.
- **Healthcheck**: `wget -q -O /dev/null http://127.0.0.1:8080/ || exit 1`.

---

## 3. Environment Variables & Secret Injection

Configuration adheres strictly to the Phase 15 hierarchy. **Secrets are never embedded into Dockerfiles, image layers, or build arguments.**

| Variable | Required in Prod | Default (Dev) | Description |
| :--- | :---: | :--- | :--- |
| `ENVIRONMENT` | Yes | `development` | Runtime environment (`production`, `development`, `qa`). |
| `DEBUG` | Yes (must be `false`) | `false` | Debug mode. **Fails closed if `true` in production.** |
| `ALLOW_DEFAULT_CREDENTIALS` | Yes (must be `false`) | `true` (dev) | Seeds default dev users. **Fails closed if `true` in production.** |
| `AGENTSHIELD_AUTHORIZATION_SECRET` | **MANDATORY** | Fallback in dev | High-entropy signing secret ($\ge 32$ characters). |
| `SECRET_KEY` | **MANDATORY** | Fallback in dev | Cryptographic HMAC secret ($\ge 32$ characters). |
| `DATABASE_URL` | **MANDATORY** | `sqlite:////app/data/agentshield.db` | Production DB URI. **Rejects default `./agentshield.db` in production.** |
| `API_HOST` | No | `0.0.0.0` | Bind host inside container. |
| `API_PORT` | No | `8000` | Bind port inside container. |
| `CORS_ALLOWED_ORIGINS` | No | `http://localhost:3000,...` | Allowed CORS origins for the API. |

---

## 4. Local Development & Integration

To launch the local development stack:

```bash
docker compose up --build -d
```

Verify service status:
```bash
docker compose ps
```

Access the services:
- **Frontend Web UI**: `http://localhost:3000`
- **Backend API**: `http://localhost:8000`
- **Liveness Probe**: `http://localhost:8000/health/live`
- **Readiness Probe**: `http://localhost:8000/health/ready`

Stop the stack:
```bash
docker compose down
```

---

## 5. Production Deployment

### Prerequisites
1. Provide a secure, external PostgreSQL database (or dedicated isolated persistent volume).
2. Generate cryptographically strong secrets ($\ge 32$ characters).
3. Populate an environment file or inject secrets via orchestrator (Kubernetes Secrets / HashiCorp Vault).

### Example Production Command

```bash
export ENVIRONMENT=production
export DEBUG=false
export ALLOW_DEFAULT_CREDENTIALS=false
export AGENTSHIELD_AUTHORIZATION_SECRET="4d89a7f39b4e1837c2a10582d90f2381ab49c631e80927da084e72fb8134ad65"
export SECRET_KEY="9f83a2b1049581c7e6d5a3b2c1e0f984a7b6c5d4e3f2a10987654321fedcba09"
export DATABASE_URL="postgresql://agentshield_prod:SuperSecurePass123!@db.internal:5432/agentshield"

docker compose -f docker-compose.prod.yml up --build -d
```

### Fail-Closed Validation
If any required secret or production database configuration is missing, the backend container immediately halts and exits with exit code 1:
```
CRITICAL SECURITY CONFIGURATION ERROR: AGENTSHIELD_AUTHORIZATION_SECRET environment variable is missing in production mode.
```

---

## 6. Security Hardening & Container Invariants

1. **Non-Root Execution**:
   - Backend runs as `UID 10001:10001`.
   - Frontend runs as `UID 101:101`.
2. **Capability Dropping**:
   - Production compose drops `ALL` Linux capabilities (`cap_drop: [ALL]`).
   - Enables `no-new-privileges:true` to prevent privilege escalation via `setuid` binaries.
3. **Read-Only Compatibility & Ephemeral Tmpfs**:
   - Runtime mounts `/tmp` as a `tmpfs` volume (`rw,noexec,nosuid,size=64m`).
   - Only `/app/data` is writable by the application for persistent state.
4. **Network Isolation**:
   - Containers communicate across private bridge network `agentshield-network`.
   - In production compose, backend binds only to `127.0.0.1:8000` or relies purely on internal frontend proxy routing.
5. **Image Layer Hygiene**:
   - Build contexts exclude `.git`, `.env*`, `*.db`, `node_modules`, and `.venv`.
   - Zero credentials or tokens exist in image layer histories or metadata.
