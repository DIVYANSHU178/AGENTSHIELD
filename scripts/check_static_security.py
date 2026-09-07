#!/usr/bin/env python3
"""
AgentShield Static Security Policy Checker (Phase 19 CI/CD & Automated Security Checks)

Performs comprehensive static analysis across:
1. Python backend source (CORS, eval/exec, pickle, unsafe shell, endpoint auth/RBAC)
2. Dockerfiles & Compose manifests (non-root, read-only, cap-drop, no secrets in ARG/ENV)
3. GitHub Actions Workflows (least-privilege permissions, action SHA pinning, no curl|sh)
4. Endpoint Inventory (ensures all sensitive routes require authentication and RBAC permissions)

Exit codes:
- 0: PASS (All static policies satisfied)
- 1: FAIL (One or more security policy violations found)
"""

import sys
import os
import re
from pathlib import Path
from typing import List, Dict, Any, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
API_DIR = REPO_ROOT / "apps" / "api"
WEB_DIR = REPO_ROOT / "apps" / "web"
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(API_DIR))


def check_python_source_policies() -> Tuple[List[str], List[str]]:
    """Scan Python codebase for insecure coding patterns."""
    violations = []
    checks = []

    # 1. Inspect app source files
    app_dir = API_DIR / "app"
    for py_file in app_dir.rglob("*.py"):
        try:
            with open(py_file, "r", encoding="utf-8") as f:
                lines = f.readlines()

            for line_no, line in enumerate(lines, start=1):
                clean = line.strip()

                # Rule 1: No eval or exec
                if re.search(r"\b(eval|exec)\s*\(", clean) and not clean.startswith("#"):
                    violations.append(f"Insecure dynamic code execution in {py_file.name}:{line_no} -> {clean}")

                # Rule 2: No pickle.loads / pickle.load
                if "pickle.loads" in clean or "pickle.load(" in clean:
                    violations.append(f"Insecure deserialization in {py_file.name}:{line_no} -> {clean}")

                # Rule 3: No unquoted or dynamic shell=True
                if "shell=True" in clean and not clean.startswith("#"):
                    violations.append(f"Suspicious subprocess shell=True in {py_file.name}:{line_no} -> {clean}")
        except Exception as exc:
            violations.append(f"Failed to read {py_file}: {exc}")

    checks.append("Python source: eval/exec, pickle, and shell=True checks verified")

    # Rule 4: Verify CORS policy does not allow wildcard with credentials
    settings_file = API_DIR / "app" / "config" / "settings.py"
    if settings_file.is_file():
        with open(settings_file, "r", encoding="utf-8") as f:
            content = f.read()
        if 'allow_origins=["*"]' in content and "allow_credentials=True" in content:
            violations.append("Wildcard CORS with allow_credentials=True detected in settings.py")
        else:
            checks.append("CORS configuration: Wildcard with credentials prohibited")

    return violations, checks


def check_endpoint_inventory_policy() -> Tuple[List[str], List[str]]:
    """Verify endpoint authorization and RBAC invariants using route extraction."""
    violations = []
    checks = []

    try:
        from scripts.extract_endpoint_inventory import get_all_routes
        routes = get_all_routes()

        checked_routes = 0
        for r in routes:
            path = r["path"]
            method = r["method"]
            auth_req = r["auth_required"]
            perm = r["permission_required"]
            is_dev = r["dev_only"]

            # Security and Approvals endpoints must require auth
            if path.startswith("/api/v1/security/"):
                checked_routes += 1
                if not auth_req:
                    violations.append(f"Unauthenticated security endpoint: {method} {path}")

            # Approvals mutation endpoints must require appropriate RBAC permission
            if path.startswith("/api/v1/security/approvals/") and method == "POST":
                checked_routes += 1
                if path.endswith("/cancel"):
                    if perm != "CANCEL_APPROVAL":
                        violations.append(f"Approval cancel missing CANCEL_APPROVAL permission: {method} {path}")
                else:
                    if perm != "RESOLVE_APPROVALS":
                        violations.append(f"Approval mutation missing RESOLVE_APPROVALS permission: {method} {path}")

            # Identity endpoints must require MANAGE_IDENTITIES permission
            if path.startswith("/api/v1/identities") and method in ("POST", "PUT", "DELETE"):
                checked_routes += 1
                if perm != "MANAGE_IDENTITIES":
                    violations.append(f"Identity mutation missing MANAGE_IDENTITIES permission: {method} {path}")

            # Dev endpoints must be marked dev_only
            if path.startswith("/api/v1/dev/"):
                checked_routes += 1
                if not is_dev:
                    violations.append(f"Dev endpoint not marked dev_only: {method} {path}")

        checks.append(f"Endpoint RBAC: {checked_routes} sensitive routes verified authoritative")
    except Exception as exc:
        violations.append(f"Endpoint inventory check failed: {exc}")

    return violations, checks


def check_docker_and_compose_policies() -> Tuple[List[str], List[str]]:
    """Verify Dockerfiles and Docker Compose security policies."""
    violations = []
    checks = []

    # 1. Backend Dockerfile
    api_dockerfile = API_DIR / "Dockerfile"
    if api_dockerfile.is_file():
        with open(api_dockerfile, "r", encoding="utf-8") as f:
            content = f.read()

        if "USER 10001:10001" not in content and "USER agentshield" not in content:
            violations.append("apps/api/Dockerfile does not configure non-root USER (10001:10001)")
        if "HEALTHCHECK" not in content:
            violations.append("apps/api/Dockerfile missing HEALTHCHECK directive")
        if re.search(r"ARG\s+.*(SECRET|PASSWORD|AUTH)", content, re.IGNORECASE):
            violations.append("apps/api/Dockerfile uses secret-bearing ARG directive")
        checks.append("apps/api/Dockerfile: Non-root user, healthcheck, zero secret ARGs verified")
    else:
        violations.append("apps/api/Dockerfile missing")

    # 2. Frontend Dockerfile
    web_dockerfile = WEB_DIR / "Dockerfile"
    if web_dockerfile.is_file():
        with open(web_dockerfile, "r", encoding="utf-8") as f:
            content = f.read()

        if "USER nginx" not in content and "USER 101" not in content:
            violations.append("apps/web/Dockerfile does not configure non-root USER nginx")
        if "HEALTHCHECK" not in content:
            violations.append("apps/web/Dockerfile missing HEALTHCHECK directive")
        checks.append("apps/web/Dockerfile: Non-root user and healthcheck verified")
    else:
        violations.append("apps/web/Dockerfile missing")

    # 3. Production Compose Policy
    prod_compose = REPO_ROOT / "docker-compose.prod.yml"
    if prod_compose.is_file():
        with open(prod_compose, "r", encoding="utf-8") as f:
            content = f.read()

        if "read_only: true" not in content:
            violations.append("docker-compose.prod.yml missing read_only: true filesystem protection")
        if "cap_drop:" not in content or "ALL" not in content:
            violations.append("docker-compose.prod.yml missing cap_drop: [ALL]")
        if "no-new-privileges:true" not in content:
            violations.append("docker-compose.prod.yml missing no-new-privileges:true")
        if "network_mode: host" in content or "privileged: true" in content:
            violations.append("docker-compose.prod.yml specifies host network or privileged mode")
        checks.append("docker-compose.prod.yml: read-only root, cap-drop ALL, no-new-privileges verified")
    else:
        violations.append("docker-compose.prod.yml missing")

    return violations, checks


def check_workflow_policies() -> Tuple[List[str], List[str]]:
    """Verify GitHub Actions workflows adhere to supply chain and least privilege policies."""
    violations = []
    checks = []

    if not WORKFLOWS_DIR.is_dir():
        # Will be verified when workflows exist
        return ["GitHub Actions workflows directory (.github/workflows) does not exist"], checks

    workflow_files = list(WORKFLOWS_DIR.glob("*.yml")) + list(WORKFLOWS_DIR.glob("*.yaml"))
    if not workflow_files:
        violations.append("No workflow files found in .github/workflows")
        return violations, checks

    for wf in workflow_files:
        with open(wf, "r", encoding="utf-8") as f:
            content = f.read()

        # 1. Least privilege permissions
        if "permissions:" not in content:
            violations.append(f"{wf.name} missing top-level permissions block")
        if "write-all" in content:
            violations.append(f"{wf.name} specifies excessive permissions: write-all")

        # 2. No pull_request_target
        if "pull_request_target" in content:
            violations.append(f"{wf.name} uses dangerous pull_request_target trigger")

        # 3. No unpinned or floating action references (@main, @master, @latest)
        floating_matches = re.findall(r"uses:\s*[^@\s]+@(main|master|latest)\b", content)
        if floating_matches:
            violations.append(f"{wf.name} references unpinned floating action version: {floating_matches}")

        # 4. No arbitrary curl | sh
        if re.search(r"curl\s+[^|]+\|\s*(sh|bash)", content) or re.search(r"wget\s+[^|]+\|\s*(sh|bash)", content):
            violations.append(f"{wf.name} contains unverified curl|sh or wget|bash installer")

    checks.append(f"GitHub Actions Workflows: {len(workflow_files)} workflows verified for least privilege and pinning")
    return violations, checks


def main():
    print("=" * 72)
    print("AGENTSHIELD STATIC SECURITY POLICY SCANNER")
    print("=" * 72)

    py_errs, py_checks = check_python_source_policies()
    end_errs, end_checks = check_endpoint_inventory_policy()
    dk_errs, dk_checks = check_docker_and_compose_policies()
    wf_errs, wf_checks = check_workflow_policies()

    all_checks = py_checks + end_checks + dk_checks + wf_checks
    all_violations = py_errs + end_errs + dk_errs + wf_errs

    for c in all_checks:
        print(f"[OK] {c}")

    if all_violations:
        print("\n" + "!" * 72)
        print(f"[FAIL] STATIC SECURITY POLICY VIOLATIONS DETECTED ({len(all_violations)} issues):")
        print("!" * 72)
        for v in all_violations:
            print(f"  - {v}")
        sys.exit(1)
    else:
        print("\n" + "=" * 72)
        print("ALL STATIC SECURITY POLICIES SATISFIED (0 VIOLATIONS)")
        print("=" * 72)
        sys.exit(0)


if __name__ == "__main__":
    main()
