# AgentShield — Architecture & System Design

## 1. What AgentShield Is
AgentShield is a runtime security layer for autonomous AI agents. It acts as an inline security boundary between AI agents and external tool execution environments.

## 2. Core Problem
Autonomous AI agents are increasingly granted tool execution capabilities (file system access, terminal shell commands, HTTP requests, browser automation). If an agent is targeted by prompt injection, jailbreaks, or malicious instructions, it may attempt dangerous operations such as credential exfiltration, destructive command execution, or unauthorized network calls.

## 3. Core Architectural Principle
> **The AI agent must never directly execute a tool. Every tool request must pass through AgentShield's security boundary before execution.**

## 4. Security Boundary Workflow
```
USER
  ↓
AI AGENT
  ↓
TOOL REQUEST
  ↓
┌──────────────────────────────┐
│          AGENTSHIELD         │
│                              │
│ Input Inspection             │
│ Threat Detection             │
│ Sensitive Data Detection     │
│ Risk Engine                  │
│ Policy Engine                │
│ Audit Engine                 │
└──────────────┬───────────────┘
               │
     ┌─────────┼─────────┐
     ↓         ↓         ↓
   ALLOW    REVIEW     BLOCK
     ↓         ↓         ↓
   TOOL      USER      AUDIT
```

When an agent requests a tool execution, AgentShield evaluates the request across three possible outcomes:
- **ALLOW**: Tool executes within controlled sandbox constraints.
- **REVIEW**: Request requires explicit human-in-the-loop confirmation.
- **BLOCK**: Request is denied and logged in the audit trail.

## 5. Frontend / Backend Relationship
- **Backend (`apps/api`)**: Built with FastAPI, Pydantic, and SQLAlchemy/SQLite. The backend is the **authoritative source** for all security decisions, policy enforcement, and audit logs.
- **Frontend (`apps/web`)**: Built with React, TypeScript, Vite, and Tailwind CSS. The frontend is a UI layer that displays real-time security state, decision logs, and user review interfaces. It never makes security determinations independently.

## 6. Future AI Provider Strategy
AgentShield is designed to protect agents running on diverse intelligence models (local Ollama models, cloud APIs like OpenAI/Gemini). The AI agent provider layer is modular and completely decoupled from AgentShield's security core.

## 7. Why Deterministic Security Must Not Depend on an LLM
A security system designed to prevent LLM exploitation must not rely on another LLM to make security decisions. LLMs are non-deterministic, vulnerable to adversarial bypass, prompt injection, and latency spikes. AgentShield's security core operates deterministically using static pattern analysis, structural validation, path sensitivity policies, and rule-based risk scoring.

## 8. Planned Modular Architecture
AgentShield follows a modular monolith architecture:
- `app/agent`: Agent integration adapters.
- `app/security`: Core security engine, threat detectors, policy rules, risk models.
- `app/tools`: Safe tool execution abstractions.
- `app/database`: SQLite database models and audit repositories.
- `app/api`: FastAPI endpoints.

---

## 9. Security Domain Contracts (Phase 1)

Phase 1 establishes the canonical data vocabulary and contracts that flow through the security boundary:

```
AgentIdentity
     ↓
ToolRequest ──(inspect)──> ThreatSignal[] ──(aggregate)──> ThreatReport
     │                                                           │
     └──────────────────────────────┬────────────────────────────┘
                                    ↓
                              RiskAssessment
                                    ↓
                             SecurityDecision (ALLOW / BLOCK / REQUIRE_APPROVAL)
                                    ↓
                              SecurityEvent (Audit Trail)
```

- **`AgentIdentity`**: Identifies the AI agent requesting action execution (agent ID, name, version, provider, session metadata).
- **`ToolRequest`**: Represents the structured request initiated by an agent (tool name, tool category, action type, parameters, target resource, destination).
- **`ThreatSignal`**: Captures an individual threat indicator emitted by an inspection detector (threat type, severity, title, evidence, normalized confidence `0.0`-`1.0`).
- **`ThreatReport`**: Aggregates all threat signals generated for a correlated `ToolRequest` along with an overall severity and summary.
- **`RiskAssessment`**: Represents a calculated risk score (bounded `0.0`-`100.0`) and severity evaluation based on contributing signals.
- **`SecurityDecision`**: The final authoritative determination (`ALLOW`, `BLOCK`, or `REQUIRE_APPROVAL`) with human-readable rationale and policy identifier.
- **`SecurityEvent`**: Immutable lifecycle audit record capturing stage events (`REQUESTED`, `ANALYZED`, `ALLOWED`, `BLOCKED`, `APPROVAL_REQUIRED`, `EXECUTED`, `FAILED`).
