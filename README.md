# AgentShield

> **The Authoritative Runtime Security Firewall for Autonomous AI Agents**

AgentShield is an inline, zero-trust execution firewall and governance platform for autonomous AI agents. Operating between AI models and underlying operating systems, cloud APIs, and tool execution environments, AgentShield deterministically intercepts, normalizes, inspects, and enforces security policies on every action an AI agent attempts to perform.

---

## Architecture & System Overview

Autonomous AI agents given tool execution privileges (such as shell commands, filesystem operations, HTTP clients, and database queries) represent a major attack surface. Adversarial prompts, indirect prompt injection, jailbreaks, and confused-deputy bugs can cause agents to leak secrets, execute destructive commands, or exfiltrate sensitive data.

AgentShield guarantees that **an AI agent never directly executes a tool**. Every action must traverse AgentShield's deterministic security boundary before execution.

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                             AUTONOMOUS AI AGENT                                  │
│                 (OpenAI / Anthropic / LangChain / CrewAI / Custom)               │
└────────────────────────────────────────┬─────────────────────────────────────────┘
                                         │ Action Request (Tool Call / Payload)
                                         ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                         AGENTSHIELD INGESTION GATEWAY                            │
│  - Multi-Format Adapters (OpenAI tool calls, Anthropic tool use, LangChain)      │
│  - Agent Identity & Key Authentication (AgentRegistry)                           │
│  - Rate Limiting & Token Bucket Throttling                                       │
└────────────────────────────────────────┬─────────────────────────────────────────┘
                                         │ Standardized ToolRequest
                                         ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                   DETERMINISTIC THREAT & RISK ENGINE                             │
│  - Threat Normalization (Multi-pass URL decode, Zero-width strip, Leetspeak)     │
│  - Specialized Detectors (Prompt Injection, Sensitive Data, SSRF, Cmd Injection) │
│  - Risk Scoring & Severity Aggregation (Bounded 0.0 - 100.0)                     │
└────────────────────────────────────────┬─────────────────────────────────────────┘
                                         │ Evaluated Request + Threat Report
                                         ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                      FAIL-CLOSED POLICY ENGINE                                   │
│  - Priority-Ordered Evaluation (Priority 0 Default-Deny Catch-All)               │
│  - RBAC Scope & Resource Permission Validation                                   │
│  - Deterministic Decision: ALLOW | REQUIRE_APPROVAL | BLOCK                      │
└───────────────────┬────────────────────┬────────────────────┬────────────────────┘
                    │                    │                    │
     [ALLOW]        │   [REQUIRE_APPV]   │       [BLOCK]      │
                    ▼                    ▼                    ▼
┌───────────────────────┐ ┌────────────────────────┐ ┌────────────────────────┐
│  SUBPROCESS SANDBOX   │ │   APPROVAL PIPELINE    │ │   SECURITY DENIAL      │
│ - Stripped Clean Env  │ │ - Cryptographic Hash   │ │ - Immediate Block      │
│ - AST-Safe Calculator │ │ - Reviewer RBAC Gate   │ │ - Audit Log Event      │
│ - Path-Confined FS    │ │ - Execution on Appv    │ │ - Zero Side Effects    │
│ - SSRF-Defended HTTP  │ │ - Durable Persistence  │ │                        │
│ - Restricted Commands │ └────────────────────────┘ └────────────────────────┘
└───────────────────────┘
```

---

## Core Capabilities & Subsystems

### 1. Autonomous Agent Ingestion Gateway (AGCP v1)
- **Standard Protocol**: Canonical `AgentActionRequest` and `AgentActionResponse` structures.
- **Multi-Format Adapters**:
  - `OpenAIToolCallAdapter`: Ingests OpenAI function and tool call schemas.
  - `AnthropicToolUseAdapter`: Ingests Anthropic tool use JSON structures.
  - `LangChainToolAdapter`: Ingests LangChain tool invocation models.
- **Agent Registry**: Cryptographic agent keys (`agk_...`), lifecycle status (ACTIVE, SUSPENDED, REVOKED), and per-agent tool allowlists.
- **Autonomous Runtime Loop**: Reference execution loop with deterministic step execution and automated halt on denial.

### 2. Multi-Pass Threat Normalization Engine
- **Unicode & Zero-Width Stripping**: Strips zero-width spaces (`\u200b`), zero-width joiners (`\u200c`, `\u200d`), and invisible formatting characters.
- **Multi-Pass URL Decoding**: Recursively decodes up to 3 passes of percent-encoding to catch double-encoded traversal (`%252e%252e%252f`) and hidden delimiters.
- **Leetspeak Translation**: Translates character substitution evasion techniques (`1gn0r3` $\to$ `ignore`, `pr3v10us` $\to$ `previous`).
- **Null-Byte Injection Defenses**: Immediately blocks poisoned paths containing embedded `\x00` bytes.

### 3. Fail-Closed Policy Engine
- **Priority 0 Catch-All Default Deny**: If no explicit policy matches an incoming request, the request is blocked (`policy.default.deny`).
- **Dynamic Policy Persistence**: Manage security policies dynamically through the API, Web UI, or Admin CLI with priority-ordered evaluation.
- **Deterministic Evaluation**: Operates completely deterministically without calling secondary LLMs for security judgments.

### 4. Human-in-the-Loop Approval-Execution Pipeline
- **Cryptographic Fingerprint Binding**: Each approval request is permanently bound to an SHA-256 fingerprint of the original `ToolRequest` parameters.
- **Authoritative Lifecycle State Machine**: Enforces `PENDING` $\to$ `APPROVED` | `REJECTED` | `CANCELLED` | `EXPIRED` transitions.
- **Real Execution on Approval**: Upon authorized human approval, AgentShield automatically executes the underlying real tool in an isolated sandbox and records the output in `execution_result`.
- **RBAC-Protected Approvals**: Only users with the `SECURITY_REVIEWER`, `OPERATOR`, or `ADMIN` roles can approve or reject requests.

### 5. Process-Level Sandbox Isolation & Real Tools
- **Subprocess Isolation (`ExecutionIsolation`)**: Executes tool logic in clean OS child processes with strict timeout limits and stripped environment variables (`DATABASE_URL`, `SECRET_KEY`, `JWT_SECRET` are scrubbed).
- **`RealCalculatorTool`**: AST-based arithmetic and mathematical parser that strictly denies arbitrary code execution and `eval()`.
- **`RealFileSystemTool`**: Sandboxed filesystem reader, writer, and directory inspector with strict root confinement, size limits (1 MB), and path traversal prevention.
- **`RealHttpTool`**: SSRF-defended HTTP client blocking loopback addresses (`127.0.0.1`), cloud metadata IPs (`169.254.169.254`, `metadata.google.internal`), private CIDR ranges, and numeric decimal/hex IP representations.
- **`RealCommandTool`**: Command executor restricting execution to strict allowlisted system utilities (`echo`, `date`, `whoami`, `cat`, `ls`) with shell injection metacharacter detection.

### 6. Administrative CLI (`agentshield-admin`)
- Headless system administration and governance tool (`python -m app.cli`).
- Command groups: `users`, `agents`, `policies`, `audit`, `system`, and `seed-demo`.
- Enables automated deployment, bootstrapping, and CI/CD secret management without requiring browser interaction.

### 7. Enterprise IAM & Authentication
- **Dual Session Authentication**: Supports both secure `HttpOnly` session cookies and standard `Authorization: Bearer` headers.
- **Role-Based Access Control (RBAC)**: Fine-grained permissions for `ADMIN`, `OPERATOR`, `SECURITY_REVIEWER`, `AUDITOR`, and `VIEWER`.
- **Brute-Force Protection**: IP-based and username-based sliding window rate limiters.

### 8. Observability, Metrics & Telemetry
- **Live Metrics**: Real-time evaluation counters, decision distributions, approval latency, and error tracking via `/api/v1/metrics/live`.
- **Correlation & Tracing**: Every request is stamped with a unique `X-Correlation-ID` and compliant W3C `traceparent` headers.
- **Immutable Audit Trail**: Append-only log repository tracking all actions, evaluations, and security decisions.

---

## Tech Stack

| Layer | Technologies |
| :--- | :--- |
| **Backend** | Python 3.11+, FastAPI, Pydantic V2, SQLAlchemy 2.0, SQLite / PostgreSQL, Pytest |
| **Frontend** | React 18, TypeScript, Vite, Tailwind CSS, Lucide React, Zustand, Vitest |
| **Sandbox** | OS Subprocess Isolation, AST Parsing, Python `ipaddress` & `socket` verification |
| **Container** | Docker Multi-Stage (Debian slim, Alpine slim), Nginx reverse proxy, Non-root users |
| **Security** | Automated secret scanning, CI/CD merge gates, Dependabot, CodeQL |

---

## Repository Structure

```
AgentShield/
├── apps/
│   ├── api/                    # FastAPI Backend Engine
│   │   ├── app/
│   │   │   ├── agent/          # Ingestion Gateway, Registry, Adapters & Runtime Loop
│   │   │   ├── api/            # REST API Routers (V1 Endpoints)
│   │   │   ├── database/       # SQLAlchemy Sessions & Database Config
│   │   │   ├── models/         # ORM Models (Users, Policies, Approvals, Audit)
│   │   │   ├── security/       # Core Security Domain, Detectors, Policies, Sandbox
│   │   │   └── cli.py          # Administrative CLI Tool
│   │   └── tests/              # Exhaustive Backend Test Suite (Pytest)
│   └── web/                    # React + Vite + TypeScript Frontend
│       ├── src/
│       │   ├── components/     # UI Components (Dashboard, Approvals, IAM, Policies)
│       │   ├── types/          # Authoritative TypeScript Contracts
│       │   └── context/        # Auth & Security Contexts
│       └── ...
├── docs/                       # Architecture, Container & Security Documentation
├── scripts/                    # Independent Verification, Scans & CI Utilities
├── docker-compose.yml          # Local & Production Container Orchestration
└── README.md                   # System Architecture & Documentation
```

---

## Quickstart & Local Operations

### 1. Running the Administrative CLI
```bash
cd apps/api
python -m app.cli system info
python -m app.cli users list
python -m app.cli agents list
```

### 2. Running Backend Tests
```bash
cd apps/api
pytest -v
```

### 3. Running Frontend Tests & Production Build
```bash
cd apps/web
npm run test:run
npm run build
```

### 4. Running Independent Verification Suite
```bash
python scripts/verify_phase20.py
```

### 5. Running Automated Secret Scan
```bash
python scripts/scan_secrets.py
```

### 6. Container Stack Execution
```bash
docker compose up --build -d
docker compose ps
```

---

## License & Security Policy

AgentShield is engineered for mission-critical AI security environments. To report security vulnerabilities or review threat models, refer to [docs/architecture.md](docs/architecture.md) and [docs/CI_SECURITY.md](docs/CI_SECURITY.md).
