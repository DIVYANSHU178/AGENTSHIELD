# AgentShield

> **The Security Layer for Autonomous AI Agents**

AgentShield is an inline runtime security layer for autonomous AI agents. It intercepts every tool execution request from AI agents before execution, ensuring that dangerous operations (credential theft, destructive commands, data exfiltration) are deterministically evaluated, blocked, or flagged for human review.

---

## ⚠️ Current Project Status: Phase 1 — Security Domain Core & Canonical Contracts

**Note:** This repository is currently at **Phase 1 (Security Domain Core)**. The formal data contracts, serializable models (`ToolRequest`, `ThreatSignal`, `ThreatReport`, `RiskAssessment`, `SecurityDecision`, `SecurityEvent`), and frontend TypeScript interfaces have been established.

**Detection algorithms, risk scoring engines, policy evaluation rules, and tool gateways are NOT implemented in Phase 1** and will be built in Phase 2+.

---

## Core Architectural Principle

> **The AI agent must never directly execute a tool. Every tool request must pass through AgentShield's security boundary before execution.**

```
USER → AI AGENT → TOOL REQUEST → [ AGENTSHIELD ] → ALLOW / REVIEW / BLOCK → TOOL / USER / AUDIT
```

AgentShield's security core operates **deterministically** without depending on an LLM for security decisions.

---

## Tech Stack

- **Frontend**: React, TypeScript, Vite, Tailwind CSS, Framer Motion, Lucide React, Zustand, Vitest.
- **Backend**: Python 3.11+, FastAPI, Pydantic V2, SQLAlchemy 2.0, SQLite, Pytest.
- **Testing**: Pytest (Backend), Vitest & Testing Library (Frontend).

---

## Repository Structure

```
AgentShield/
├── apps/
│   ├── web/            # React + Vite + TypeScript Frontend Application & Contracts
│   └── api/            # FastAPI + Pydantic V2 + SQLAlchemy Backend & Security Models
├── sandbox/
│   ├── public/         # Public harmless sample files
│   └── sensitive/      # Placeholder sensitive file targets
├── scenarios/          # Security testing scenario specifications
├── docs/               # Architecture and development documentation
├── .env.example
├── .gitignore
└── README.md
```

---

## Local Quickstart & Commands

### Backend (`apps/api`)
```bash
cd apps/api
python -m venv .venv
.venv\Scripts\Activate.ps1   # On Windows
pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
pytest                       # Run backend tests (27 unit tests)
```

### Frontend (`apps/web`)
```bash
cd apps/web
npm install
npm run dev                  # Start Vite development server
npm run build                # TypeScript check and Vite build
npm run test                 # Run Vitest test runner
```
