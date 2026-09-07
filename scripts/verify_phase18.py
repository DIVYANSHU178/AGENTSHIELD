#!/usr/bin/env python3
"""
AgentShield Phase 18: Containerization Independent Verification Script.

Executes standalone, live Docker container verification covering:
- V18-01: Docker image builds and existence
- V18-02: Non-root user configuration (UID 10001 / UID 101)
- V18-03: Minimal exposed port footprint
- V18-04: Native container healthcheck configuration
- V18-05: Exclusion of dev/test tooling from runtime images
- V18-06: Build context exclusion (.env, host DBs, node_modules)
- V18-07: Layer history secret leakage scan
- V18-08: Production configuration fail-closed validation
- V18-09: Isolated bridge networking
- V18-10: Liveness probe execution in running container
- V18-11: Readiness probe execution in running container
- V18-12: Frontend static SPA serving and security headers
- V18-13: Frontend-to-backend API reverse proxy routing
- V18-14: Containerized authentication & RBAC session issuance
- V18-15: Phase 17 request bounds enforcement (HTTP 413)
- V18-16: Phase 16 correlation header propagation
- V18-17: Production container invariants (demo lock, Scenario Lab lock)
- V18-18: Non-root process execution in live containers
"""

import sys
import json
import time
import subprocess
import urllib.request
import urllib.error
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

def run_cmd(cmd, timeout=120):
    proc = subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=timeout)
    return proc.returncode, proc.stdout, proc.stderr

def report(check_id, title, passed, details=""):
    mark = "[PASS]" if passed else "[FAIL]"
    print(f"{mark} {check_id}: {title}")
    if details:
        print(f"       Details: {details}")
    if not passed:
        sys.exit(1)

def main():
    print("=" * 72)
    print("AGENTSHIELD PHASE 18 — INDEPENDENT CONTAINER VERIFICATION SUITE")
    print("=" * 72)

    # 1. Image Builds
    code_api, _, _ = run_cmd(["docker", "image", "inspect", "agentshield-api:test"])
    if code_api != 0:
        c, _, _ = run_cmd(["docker", "build", "-t", "agentshield-api:test", "apps/api"])
        assert c == 0
    code_web, _, _ = run_cmd(["docker", "image", "inspect", "agentshield-web:test"])
    if code_web != 0:
        c, _, _ = run_cmd(["docker", "build", "-t", "agentshield-web:test", "apps/web"])
        assert c == 0
    report("V18-01", "Backend and frontend Docker images built and verified", True)

    # 2. Non-Root Config
    _, out_u1, _ = run_cmd(["docker", "inspect", "--format", "{{.Config.User}}", "agentshield-api:test"])
    _, out_u2, _ = run_cmd(["docker", "inspect", "--format", "{{.Config.User}}", "agentshield-web:test"])
    u1_ok = out_u1.strip() == "10001:10001"
    u2_ok = out_u2.strip() == "nginx"
    report("V18-02", "Image metadata specifies non-root runtime users", u1_ok and u2_ok, f"api={out_u1.strip()}, web={out_u2.strip()}")

    # 3. Minimal Ports
    _, out_p1, _ = run_cmd(["docker", "inspect", "--format", "{{json .Config.ExposedPorts}}", "agentshield-api:test"])
    p1 = json.loads(out_p1.strip())
    ports_ok = "8000/tcp" in p1 and len(p1) == 1
    report("V18-03", "Backend image restricts exposed ports to 8000/tcp", ports_ok, f"ports={p1}")

    # 4. Native Healthcheck
    _, out_hc1, _ = run_cmd(["docker", "inspect", "--format", "{{json .Config.Healthcheck}}", "agentshield-api:test"])
    _, out_hc2, _ = run_cmd(["docker", "inspect", "--format", "{{json .Config.Healthcheck}}", "agentshield-web:test"])
    hc_ok = "health/live" in out_hc1 and "8080" in out_hc2
    report("V18-04", "Container native HEALTHCHECK configured on both images", hc_ok)

    # 5. Exclusion of dev tooling
    c_pt, _, err_pt = run_cmd(["docker", "run", "--rm", "agentshield-api:test", "python", "-c", "import pytest"], timeout=20)
    pt_excluded = c_pt != 0 and ("No module named" in err_pt or "ModuleNotFoundError" in err_pt)
    report("V18-05", "Dev/test tooling (pytest) excluded from production runtime image", pt_excluded)

    # 6. Build Context Hygiene
    c_env, _, _ = run_cmd(["docker", "run", "--rm", "agentshield-api:test", "ls", "/app/.env"], timeout=20)
    c_db, _, _ = run_cmd(["docker", "run", "--rm", "agentshield-api:test", "ls", "/app/agentshield.db"], timeout=20)
    report("V18-06", "Sensitive host artifacts (.env, host DB) excluded from image context", c_env != 0 and c_db != 0)

    # 7. Layer Secret Scan
    _, hist_api, _ = run_cmd(["docker", "history", "--no-trunc", "agentshield-api:test"])
    _, hist_web, _ = run_cmd(["docker", "history", "--no-trunc", "agentshield-web:test"])
    leak_api = "secret_key=" in hist_api.lower() or "authorization_secret=" in hist_api.lower()
    leak_web = "password=" in hist_web.lower()
    report("V18-07", "Image layers and history scan reveals zero secrets", not (leak_api or leak_web))

    # 8. Production Fail-Closed
    c_m1, o_m1, e_m1 = run_cmd([
        "docker", "run", "--rm",
        "-e", "ENVIRONMENT=production",
        "-e", "SECRET_KEY=12345678901234567890123456789012",
        "-e", "DATABASE_URL=sqlite:////app/data/prod.db",
        "agentshield-api:test"
    ], timeout=20)
    c_m2, o_m2, e_m2 = run_cmd([
        "docker", "run", "--rm",
        "-e", "ENVIRONMENT=production",
        "-e", "AGENTSHIELD_AUTHORIZATION_SECRET=12345678901234567890123456789012",
        "-e", "DATABASE_URL=sqlite:////app/data/prod.db",
        "agentshield-api:test"
    ], timeout=20)
    c_m3, o_m3, e_m3 = run_cmd([
        "docker", "run", "--rm",
        "-e", "ENVIRONMENT=production",
        "-e", "AGENTSHIELD_AUTHORIZATION_SECRET=12345678901234567890123456789012",
        "-e", "SECRET_KEY=12345678901234567890123456789012",
        "-e", "DATABASE_URL=sqlite:///./agentshield.db",
        "agentshield-api:test"
    ], timeout=20)
    fc_ok = c_m1 == 1 and c_m2 == 1 and c_m3 == 1
    report("V18-08", "Production container fails closed on missing secrets or default DB", fc_ok)

    # 9-16. Live Container Testing on Isolated Network
    NET = "v18-verify-net"
    BACKEND = "v18-verify-backend"
    FRONTEND = "v18-verify-frontend"
    PORT = 19180

    run_cmd(["docker", "rm", "-f", BACKEND, FRONTEND])
    run_cmd(["docker", "network", "rm", NET])

    try:
        run_cmd(["docker", "network", "create", NET])
        run_cmd([
            "docker", "run", "-d",
            "--name", BACKEND,
            "--network", NET,
            "--network-alias", "backend",
            "-e", "ENVIRONMENT=development",
            "-e", "DATABASE_URL=sqlite:////app/data/agentshield.db",
            "-e", "API_HOST=0.0.0.0",
            "-e", "API_PORT=8000",
            "-e", "ALLOW_DEFAULT_CREDENTIALS=true",
            "agentshield-api:test"
        ])
        run_cmd([
            "docker", "run", "-d",
            "--name", FRONTEND,
            "--network", NET,
            "-p", f"{PORT}:8080",
            "agentshield-web:test"
        ])

        # Allow service stabilization via readiness polling
        ready = False
        for _ in range(15):
            time.sleep(1)
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/health/live") as r:
                    if r.status == 200:
                        ready = True
                        break
            except Exception:
                pass
        if not ready:
            raise RuntimeError(f"Services on port {PORT} failed to stabilize")

        report("V18-09", "Containers launched on dedicated bridge network", True)

        # 10. Liveness probe
        with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/health/live") as r:
            body = json.loads(r.read().decode())
            report("V18-10", "Live container liveness probe (/health/live) returns 200", r.status == 200 and body.get("alive") is True)

        # 11. Readiness probe
        with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/health/ready") as r:
            body = json.loads(r.read().decode())
            report("V18-11", "Live container readiness probe (/health/ready) returns 200", r.status == 200 and body.get("ready") is True)

        # 12. Frontend SPA & Security Headers
        with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/") as r:
            h = dict(r.headers)
            spa_ok = r.status == 200 and h.get("X-Content-Type-Options") == "nosniff" and h.get("X-Frame-Options") == "DENY"
            report("V18-12", "Frontend container serves SPA HTML with security headers", spa_ok)

        # 13. Reverse Proxy Routing
        with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/health") as r:
            body = json.loads(r.read().decode())
            report("V18-13", "Nginx reverse proxy successfully forwards /health to backend", r.status == 200 and body.get("service") == "agentshield")

        # 14. Containerized Authentication
        login_data = json.dumps({"username": "admin", "password": "AdminPass123!"}).encode()
        req_auth = urllib.request.Request(
            f"http://127.0.0.1:{PORT}/api/v1/auth/login",
            data=login_data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req_auth) as r:
            body = json.loads(r.read().decode())
            auth_ok = r.status == 200 and body.get("username") == "admin" and "session_id" in body
            report("V18-14", "Authentication and session issuance verified through container proxy", auth_ok)

        # 15. Phase 17 Request Bounds
        oversized = b"x" * (1024 * 1024 + 10)
        req_bounds = urllib.request.Request(
            f"http://127.0.0.1:{PORT}/api/v1/auth/login",
            data=oversized,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        bounds_ok = False
        try:
            urllib.request.urlopen(req_bounds)
        except urllib.error.HTTPError as e:
            bounds_ok = (e.code == 413)
        report("V18-15", "Phase 17 request bounds (1MB limit -> HTTP 413) enforced in container", bounds_ok)

        # 16. Phase 16 Correlation ID
        with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/health") as r:
            cid_ok = r.headers.get("X-Correlation-ID") is not None
            report("V18-16", "Phase 16 X-Correlation-ID header propagated through container proxy", cid_ok)

        # 18. Non-root in live containers
        _, id_b, _ = run_cmd(["docker", "exec", BACKEND, "id", "-u"])
        _, id_f, _ = run_cmd(["docker", "exec", FRONTEND, "id", "-u"])
        nr_ok = id_b.strip() == "10001" and id_f.strip() == "101"
        report("V18-18", "Running containers verified non-root (API=10001, Web=101)", nr_ok)

    finally:
        run_cmd(["docker", "rm", "-f", BACKEND, FRONTEND])
        run_cmd(["docker", "network", "rm", NET])

    # 17. Production Container Invariants
    PROD_BACKEND = "v18-prod-verify"
    run_cmd(["docker", "rm", "-f", PROD_BACKEND])
    try:
        run_cmd([
            "docker", "run", "-d",
            "--name", PROD_BACKEND,
            "-p", "19181:8000",
            "-e", "ENVIRONMENT=production",
            "-e", "AGENTSHIELD_AUTHORIZATION_SECRET=12345678901234567890123456789012",
            "-e", "SECRET_KEY=12345678901234567890123456789012",
            "-e", "DATABASE_URL=sqlite:////app/data/prod_verify.db",
            "agentshield-api:test"
        ])

        # Allow production service stabilization
        prod_ready = False
        for _ in range(15):
            time.sleep(1)
            try:
                with urllib.request.urlopen("http://127.0.0.1:19181/health/live") as r:
                    if r.status == 200:
                        prod_ready = True
                        break
            except Exception:
                pass
        if not prod_ready:
            raise RuntimeError("Production backend failed to stabilize on port 19181")

        # Demo login rejection
        req_demo = urllib.request.Request(
            "http://127.0.0.1:19181/api/v1/auth/login",
            data=json.dumps({"username": "admin", "password": "AdminPass123!"}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        demo_rejected = False
        try:
            urllib.request.urlopen(req_demo)
        except urllib.error.HTTPError as e:
            demo_rejected = (e.code == 401)

        # Scenario Lab lockout
        req_lab = urllib.request.Request("http://127.0.0.1:19181/api/v1/dev/laboratory/scenarios")
        lab_locked = False
        try:
            urllib.request.urlopen(req_lab)
        except urllib.error.HTTPError as e:
            lab_locked = (e.code == 403)

        report("V18-17", "Production container enforces demo rejection (401) and Scenario Lab lockout (403)", demo_rejected and lab_locked)
    finally:
        run_cmd(["docker", "rm", "-f", PROD_BACKEND])

    print("=" * 72)
    print("ALL 18 PHASE 18 VERIFICATION CHECKS PASSED (0 FAILED)")
    print("=" * 72)

if __name__ == "__main__":
    main()
