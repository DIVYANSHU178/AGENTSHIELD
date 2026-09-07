# AgentShield — Architecture & System Design

## 1. What AgentShield Is
AgentShield is a deterministic, high-throughput runtime security firewall and governance platform for autonomous AI agents. It acts as an inline boundary between AI agents and external tool execution environments (operating systems, filesystems, network endpoints, databases, and APIs).

---

## 2. The Core Problem
Autonomous AI agents are increasingly granted tool execution capabilities. If an agent is targeted by indirect prompt injection, adversarial jailbreaks, or untrusted user content, it may attempt dangerous operations such as:
- Exfiltrating API credentials or system environment variables.
- Reading or overwriting sensitive files (`/etc/shadow`, `.env`, SSH keys).
- Executing arbitrary shell commands or downloading remote binaries.
- Making SSRF calls to internal services or cloud metadata endpoints (`169.254.169.254`).

---

## 3. Core Architectural Principles

1. **Inline Security Invariant**:
   > **The AI agent must never directly execute a tool. Every tool request must pass through AgentShield's security boundary before execution.**

2. **Deterministic Security**:
   > **A security system designed to prevent LLM exploitation must not rely on another LLM to make security determinations.**
   AgentShield's security core operates deterministically using static pattern analysis, structural validation, path sensitivity policies, and rule-based risk scoring.

3. **Fail-Closed Default**:
   > **If an agent action does not match an explicit allow policy, or if any unhandled error occurs, the request must fail closed and be blocked.**

---

## 4. Architectural Dataflow & Execution Pipeline

```
USER / ENVIRONMENT
  │
  ▼
AUTONOMOUS AI AGENT
  │ (Attempts action: OpenAI tool_call, Anthropic tool_use, or LangChain action)
  ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                       AGENTSHIELD SECURITY GATEWAY                          │
│                                                                             │
│ 1. Ingestion Gateway (AGCP v1)                                              │
│    - Format Adapter: OpenAI / Anthropic / LangChain → AgentActionRequest    │
│    - Agent Authentication: AgentRegistry API key hash verification         │
│    - Token Bucket Rate Limiting                                             │
│                                                                             │
│ 2. Normalization Engine                                                     │
│    - Zero-width character stripping (\u200b, \u200c, etc.)                  │
│    - Multi-pass recursive URL percent decoding (%252e%252e%252f)            │
│    - Unicode NFKC normalization                                             │
│    - Leetspeak translation                                                  │
│                                                                             │
│ 3. Specialized Threat Detectors                                             │
│    - Prompt Injection Detector (Direct & Indirect)                          │
│    - Sensitive Data / Credential Leak Detector (Secrets, Tokens, Keys)      │
│    - SSRF & IP Evasion Detector (Cloud metadata, loopback, decimal IPs)     │
│    - Destructive Command & Shell Injection Detector                         │
│                                                                             │
│ 4. Risk Assessment Engine                                                   │
│    - Signal aggregation & severity weight computation (0.0 to 100.0)        │
│                                                                             │
│ 5. Priority-Ordered Policy Engine                                           │
│    - Rule match evaluation (ALLOW, REQUIRE_APPROVAL, BLOCK)                 │
│    - Priority 0 Default-Deny catch-all rule                                 │
└───────────────────────────────────────┬─────────────────────────────────────┘
                                        │
                 ┌──────────────────────┼──────────────────────┐
                 │                      │                      │
                 ▼                      ▼                      ▼
           [   ALLOW   ]      [ REQUIRE_APPROVAL ]       [    BLOCK    ]
                 │                      │                      │
                 ▼                      ▼                      ▼
┌──────────────────────────────┐ ┌──────────────────┐ ┌────────────────┐
│   EXECUTION ISOLATION        │ │ APPROVAL ENGINE  │ │ DENIAL AUDIT   │
│ - OS Subprocess Isolation    │ │ - SHA-256 Hash   │ │ - Immediate    │
│ - Scrubbed Environment       │ │ - Reviewer Gate  │ │   Block        │
│ - Restricted Tool Handler:   │ │ - Exec on Appv   │ │ - Audit Trail  │
│   * RealCalculatorTool       │ └─────────┬────────┘ └────────────────┘
│   * RealFileSystemTool       │           │
│   * RealHttpTool             │           │ (When approved by Reviewer)
│   * RealCommandTool          │           │
│ - Strict Execution Limits    │◀──────────┘
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│       AUDIT & METRICS        │
│ - Structured Event Logged    │
│ - Correlation ID & Tracing   │
│ - Live Metrics Updated       │
└──────────────────────────────┘
```

---

## 5. Subsystem Details

### 5.1 Ingestion Gateway & Multi-Format Adapters
AgentShield's Ingestion Gateway (`app.agent`) normalizes heterogeneous agent payloads into a standardized `AgentActionRequest`.
- **OpenAI Adapter**: Ingests tool calls from chat completion responses.
- **Anthropic Adapter**: Ingests tool use blocks from Claude API responses.
- **LangChain Adapter**: Ingests agent tool invocation dictionaries.
- **Agent Registry**: Enforces per-agent identity, allowlisted tools, rate limits, and cryptographic API keys (`agk_...`).

### 5.2 Deterministic Detectors & Normalization
Incoming payloads are sanitized before detector analysis:
- Invisible and zero-width characters are stripped.
- Percent-encoding is decoded recursively up to 3 passes to uncover buried path traversals.
- Canonical leetspeak mappings resolve character-substitution evasions.
Specialized detectors evaluate the normalized input and produce structured `ThreatSignal` objects.

### 5.3 Risk & Policy Engine
- `RiskAssessmentEngine`: Combines signals using weighted threat severity algorithms to generate a normalized score between `0.0` and `100.0`.
- `PolicyEngine`: Evaluates registered policies in descending priority order. If no rule matches, the Priority 0 `policy.default.deny` rule blocks the action.

### 5.4 Approval-Execution Pipeline
When an action requires human verification:
1. An immutable `ApprovalRequest` is created and assigned a cryptographic SHA-256 fingerprint.
2. The request is persisted in the database with status `PENDING`.
3. An authorized human reviewer (`SECURITY_REVIEWER`, `OPERATOR`, `ADMIN`) reviews the request.
4. Upon approval, AgentShield automatically executes the approved tool in an isolated sandbox and attaches the output to `execution_result`.

### 5.5 Process-Level Sandbox Isolation & Real Tools
Tools are executed via `ExecutionIsolation` in separate child OS subprocesses:
- **Clean Environment**: Secrets (`JWT_SECRET`, `DATABASE_URL`, `SECRET_KEY`) are stripped from the child environment.
- **Real Calculator Tool**: Evaluates mathematical expressions using AST node traversal, completely disallowing `eval()` or code execution.
- **Real Filesystem Tool**: Restricts file reading and writing to an isolated sandbox directory (`SANDBOX_ROOT_DIR`). Enforces strict path traversal prevention, file size limits (1 MB), and null-byte rejection.
- **Real HTTP Tool**: Validates requested URLs against an SSRF blocklist, including private CIDR blocks, loopback addresses (`127.0.0.1`), decimal IP representations, and cloud metadata endpoints (`169.254.169.254`).
- **Real Command Tool**: Restricts terminal command execution to an allowlisted set of utilities (`echo`, `date`, `cat`, etc.) without shell invocation (`shell=False`).

### 5.6 Frontend / Backend Architecture
- **Backend (`apps/api`)**: The authoritative security engine, policy evaluator, and execution sandbox.
- **Frontend (`apps/web`)**: A zero-trust dashboard providing security visibility, real-time metrics, live approval queues, policy management, and user governance. The frontend never makes security determinations independently.

---

## 6. Future Ecosystem Integrations
Future releases will add native middleware adapters for:
- LangChain AgentExecutor middleware
- CrewAI custom security callbacks
- AutoGen safe execution hooks
- Model Context Protocol (MCP) server proxy gateway
