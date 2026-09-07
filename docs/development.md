# AgentShield — Development Guide

## Local Development Prerequisites
- Python 3.11+
- Node.js 18+ and npm 10+

## Backend Setup (`apps/api`)

1. Navigate to the backend directory:
   ```bash
   cd apps/api
   ```

2. Create and activate virtual environment:
   ```bash
   python -m venv .venv
   # Windows PowerShell
   .venv\Scripts\Activate.ps1
   # Linux/macOS
   source .venv/bin/activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run FastAPI development server:
   ```bash
   uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
   ```

5. Run backend tests:
   ```bash
   pytest
   ```

## Frontend Setup (`apps/web`)

1. Navigate to the frontend directory:
   ```bash
   cd apps/web
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Run Vite development server:
   ```bash
   npm run dev
   ```

4. Run TypeScript type checks & production build:
   ```bash
   npm run build
   ```

5. Run Vitest test runner:
   ```bash
   npm run test
   ```

---

## Administrative CLI (`agentshield-admin`)

Manage users, agents, policies, and system diagnostics:
```bash
cd apps/api
python -m app.cli system info
python -m app.cli users list
python -m app.cli agents list
python -m app.cli policies list
```

---

## Security Verification & Scans

1. **Independent Verification Suite**:
   ```bash
   python scripts/verify_phase20.py
   ```

2. **Automated Secret Scanner**:
   ```bash
   python scripts/scan_secrets.py
   ```
