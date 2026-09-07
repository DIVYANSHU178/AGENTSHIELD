# AgentShield CI/CD & Automated Security Policy

## 1. Overview & Architecture

AgentShield treats the Continuous Integration and Continuous Delivery (CI/CD) pipeline as an authoritative component of the application security boundary. No code may merge to `master` without passing automated validation across all security domains established in Phases 14 through 18.

### Pipeline Workflows (`.github/workflows/`)

1. **`ci.yml` (Core Build, Test & Regression Pipeline)**:
   - **Triggers**: Pull requests targeting `master`, pushes to `master`.
   - **Permissions**: `contents: read` (strict least-privilege).
   - **Jobs**:
     - `backend`: Installs dependencies, runs `pytest` (unit & integration), executes Phase 14–17 and Phase 19 verification scripts.
     - `frontend`: Executes `npm ci`, Vitest suite (`npm test -- --run`), production compilation (`tsc && vite build`), and scans production bundle assets for leaked secrets.
     - `container`: Builds Docker API and Web images, inspects image metadata (non-root `10001:10001` and `101:101`), executes native container health checks, and runs `scripts/verify_phase18.py`.

2. **`security.yml` (Security Audits & Supply-Chain Hardening)**:
   - **Triggers**: Pull requests targeting `master`, pushes to `master`, and scheduled weekly scan (`cron: '0 2 * * 1'`).
   - **Permissions**: `contents: read`.
   - **Jobs**:
     - `secret-scan`: Executes `scripts/scan_secrets.py` recursively across source code, workflows, Dockerfiles, and compose manifests.
     - `dependency-audit`: Executes `scripts/audit_dependencies.py` to audit Python and Node packages against documented vulnerability policies.
     - `static-security`: Generates machine-readable `endpoint_inventory.json` via `scripts/extract_endpoint_inventory.py`, verifies zero secrets in inventory, and runs `scripts/check_static_security.py` (CORS, AST checks, Dockerfile invariants, and RBAC coverage).

---

## 2. Supply-Chain Security & Action Pinning

All GitHub Actions in `.github/workflows/` are strictly pinned to full commit SHAs with inline version comments:

```yaml
- name: Checkout Repository
  uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2

- name: Set up Python 3.11
  uses: actions/setup-python@42375524e23c412d93fb67b49958b491fce71c38 # v5.4.0

- name: Set up Node.js 20
  uses: actions/setup-node@1d0ff469b7ec7b3cb9d8673fde0c81c44821de2a # v4.2.0
```

### Prohibitions
- **NO floating branch references**: `@main`, `@master`, `@latest` are forbidden by static policy.
- **NO unverified remote script execution**: `curl | sh` and `wget | bash` are blocked.
- **NO write permissions for PR jobs**: Default permissions are `contents: read`.

---

## 3. Fork & Untrusted Pull Request Safety

1. **Zero Secret Requirement**: CI runs completely self-contained. No real API keys, production database passwords, or signing secrets are required or injected into GitHub Actions runners.
2. **No `pull_request_target`**: Workflows use standard `pull_request` triggers to guarantee that untrusted pull requests from forks cannot access write tokens or GitHub repository secrets.
3. **No Automatic Deployment**: CI workflows are strictly non-deploying test and verification gates.

---

## 4. Vulnerability & Dependency Policy

The automated dependency auditor (`scripts/audit_dependencies.py`) enforces:

- **CRITICAL Vulnerabilities**: Immediate build failure / merge block.
- **HIGH Vulnerabilities**: Immediate build failure / merge block unless explicitly documented in the Scoped Exceptions registry.
- **Production Dependencies (`--omit=dev`)**: **Zero** CRITICAL or HIGH vulnerabilities permitted under any circumstance.
- **Documented Exceptions Format**: Blanket ignores are prohibited. Exceptions must define:
  - Advisory / CVE Identifier
  - Package Name & Ecosystem
  - Scope (`devDependencies`)
  - Architectural / Non-Applicability Justification
  - Expiration / Review Date

---

## 5. Artifact Security & Retention Policy

CI workflows strictly prohibit archiving or uploading:
- Environment configuration files (`.env`, `.env.*`)
- Database files (`*.db`, `*.sqlite`, `*.sqlite3`)
- Private keys, certificates, or tokens
- Raw unredacted debug traces containing credential material

Permitted artifacts are limited to sanitized test reports, machine-readable endpoint inventories, and build metadata.

---

## 6. Recommended Branch Protection Configuration

To enforce these automated CI gates, the following branch protection rules must be configured for the `master` branch in the GitHub repository settings:

1. **Require a pull request before merging**:
   - Require at least 1 approving review from code owners.
   - Dismiss stale pull request approvals when new commits are pushed.
2. **Require status checks to pass before merging**:
   - `Backend Tests & Phase Verifications`
   - `Frontend Tests, Typecheck & Bundle Verification`
   - `Container Build & Runtime Security Verification`
   - `Source & Manifest Secret Scanning`
   - `Dependency Vulnerability Audit`
   - `Static Security Policy & Endpoint RBAC Verification`
3. **Require branches to be up to date before merging**: Enforce strict linear history.
4. **Block direct pushes**: Direct pushes to `master` must be restricted to repository administrators or completely disabled.
5. **Disable force pushes and branch deletions**: Prevent history rewriting or accidental deletion.

---

## 7. Local Reproduction Commands

To replicate all CI gates locally prior to pushing:

```bash
# 1. Backend Pytest & Phase Verifications
pytest -q apps/api/tests
python scripts/verify_phase14_acceptance.py
python apps/api/scripts/demo_phase14.py
python scripts/verify_phase15.py
python scripts/verify_phase15_acceptance.py
python scripts/verify_phase16.py
python scripts/verify_phase17.py
python scripts/verify_phase18.py
python scripts/verify_phase19.py

# 2. Frontend Tests & Production Build
cd apps/web
npm ci
npm test -- --run
npm run build
cd ../..

# 3. Security Audits & Scans
python scripts/scan_secrets.py --include-dist
python scripts/audit_dependencies.py
python scripts/extract_endpoint_inventory.py
python scripts/check_static_security.py
```
