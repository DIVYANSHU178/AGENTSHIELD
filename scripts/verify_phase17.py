"""
Independent Standalone Verification Script for AgentShield Phase 17: API and Service Hardening.

Executes comprehensive validation of:
- V17-01: Hardening module architecture and exports
- V17-02: Request payload bounds (HTTP 413)
- V17-03: Header count and byte size limits (HTTP 431)
- V17-04: Content-Type enforcement on mutating requests (HTTP 415)
- V17-05: Path traversal and null byte prevention (HTTP 400)
- V17-06: Security headers (nosniff, DENY, strict-origin)
- V17-07: Strict Cache-Control (no-store) on sensitive endpoints
- V17-08: Failed login brute-force rate limiting (HTTP 429)
- V17-09: Sensitive operation rate limiting (HTTP 429)
- V17-10: Approval router RBAC enforcement (VIEW_APPROVALS, RESOLVE_APPROVALS, CANCEL_APPROVAL)
- V17-11: approval_id path parameter validation (HTTP 422)
- V17-12: Input parameter length bounds (HTTP 422)
- V17-13: Validation error sanitization and correlation attribution
- V17-14: Production lockout invariants preserved
"""

import sys
import os
import uuid
from unittest.mock import patch

# Ensure apps/api is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "apps", "api")))

from fastapi.testclient import TestClient
from app.main import app
from app.config import settings
from app.core.hardening import (
    SecurityHeadersMiddleware,
    RequestBoundsMiddleware,
    rate_limiter,
)
from app.security.identity.models import UserIdentity, Role, Permission
from app.security.identity.dependencies import get_current_user_optional


def run_checks():
    client = TestClient(app, raise_server_exceptions=False)
    passed = 0
    total = 14

    print("=" * 70)
    print("AGENTSHIELD PHASE 17 — INDEPENDENT VERIFICATION SUITE")
    print("=" * 70)

    # V17-01: Module Architecture and Exports
    try:
        from app.core import hardening
        assert hasattr(hardening, "SecurityHeadersMiddleware")
        assert hasattr(hardening, "RequestBoundsMiddleware")
        assert hasattr(hardening, "rate_limiter")
        assert hasattr(hardening, "check_login_rate_limit")
        assert hasattr(hardening, "validation_exception_handler")
        print("[PASS] V17-01: Hardening module architecture and exports verified.")
        passed += 1
    except Exception as exc:
        print(f"[FAIL] V17-01: Module architecture error: {exc}")

    # V17-02: Request Payload Bounds (HTTP 413)
    try:
        # Header Content-Length check
        res1 = client.post(
            "/api/v1/auth/login",
            content=b"{}",
            headers={"Content-Type": "application/json", "Content-Length": str(2 * 1024 * 1024)},
        )
        assert res1.status_code == 413

        # Stream body check
        huge = b'{"username":"' + (b"x" * (1024 * 1024 + 50)) + b'"}'
        res2 = client.post("/api/v1/auth/login", content=huge, headers={"Content-Type": "application/json"})
        assert res2.status_code == 413
        print("[PASS] V17-02: Request payload bounds (1MB limit -> HTTP 413) verified.")
        passed += 1
    except Exception as exc:
        print(f"[FAIL] V17-02: Payload bounds failure: {exc}")

    # V17-03: Header Limits (HTTP 431)
    try:
        # > 50 headers
        h_count = {f"X-H-{i}": f"v-{i}" for i in range(55)}
        res_count = client.get("/health", headers=h_count)
        assert res_count.status_code == 431

        # > 16 KB headers
        h_size = {"X-Big": "Z" * 17000}
        res_size = client.get("/health", headers=h_size)
        assert res_size.status_code == 431
        print("[PASS] V17-03: Header limits (50 count / 16KB size -> HTTP 431) verified.")
        passed += 1
    except Exception as exc:
        print(f"[FAIL] V17-03: Header limits failure: {exc}")

    # V17-04: Content-Type Enforcement (HTTP 415)
    try:
        # Non-empty body with text/plain
        res_txt = client.post(
            "/api/v1/auth/login",
            content=b"user=admin",
            headers={"Content-Type": "text/plain"},
        )
        assert res_txt.status_code == 415

        # Non-empty body with missing Content-Type
        res_none = client.post("/api/v1/auth/login", content=b'{"user":"admin"}', headers={})
        assert res_none.status_code == 415

        # Empty body POST permitted without Content-Type
        res_empty = client.post("/api/v1/auth/logout")
        assert res_empty.status_code == 200
        print("[PASS] V17-04: Content-Type enforcement (HTTP 415) on mutating requests verified.")
        passed += 1
    except Exception as exc:
        print(f"[FAIL] V17-04: Content-Type enforcement failure: {exc}")

    # V17-05: Path Traversal & Null Byte Prevention (HTTP 400)
    try:
        assert client.get("/api/v1/%2e%2e/health").status_code == 400
        assert client.get("/health?q=../etc/passwd").status_code == 400
        assert client.get("/health?q=%2e%2e/passwd").status_code == 400
        assert client.get("/health%00evil").status_code == 400
        assert client.get("/health?evil=%00").status_code == 400
        print("[PASS] V17-05: Path traversal and null byte prevention (HTTP 400) verified.")
        passed += 1
    except Exception as exc:
        print(f"[FAIL] V17-05: Traversal/null byte failure: {exc}")

    # V17-06: Security Headers Presence
    try:
        res = client.get("/health")
        assert res.headers.get("X-Content-Type-Options") == "nosniff"
        assert res.headers.get("X-Frame-Options") == "DENY"
        assert res.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
        print("[PASS] V17-06: Security headers (nosniff, DENY, strict-origin) verified.")
        passed += 1
    except Exception as exc:
        print(f"[FAIL] V17-06: Security headers failure: {exc}")

    # V17-07: Strict Cache-Control on Sensitive Endpoints
    try:
        res = client.get("/api/v1/auth/me")
        cc = res.headers.get("Cache-Control", "")
        assert "no-store" in cc
        assert "no-cache" in cc
        assert res.headers.get("Pragma") == "no-cache"
        assert res.headers.get("Expires") == "0"
        print("[PASS] V17-07: Strict Cache-Control: no-store on sensitive endpoints verified.")
        passed += 1
    except Exception as exc:
        print(f"[FAIL] V17-07: Cache-Control failure: {exc}")

    # V17-08: Failed Login Brute-Force Rate Limiting (HTTP 429)
    try:
        rate_limiter.reset_for_testing()
        ip_headers = {"X-Forwarded-For": "198.51.100.77"}
        for i in range(10):
            r = client.post("/api/v1/auth/login", json={"username": f"test_bf_{i}", "password": "wrong"}, headers=ip_headers)
            assert r.status_code == 401
        # 11th attempt
        r_blk = client.post("/api/v1/auth/login", json={"username": "test_bf_11", "password": "wrong"}, headers=ip_headers)
        assert r_blk.status_code == 429
        assert "Retry-After" in r_blk.headers
        print("[PASS] V17-08: Login brute-force rate limiting (10 fails -> HTTP 429) verified.")
        passed += 1
    except Exception as exc:
        print(f"[FAIL] V17-08: Login rate limiting failure: {exc}")

    # V17-09: Sensitive Operation Rate Limiting (HTTP 429)
    try:
        rate_limiter.reset_for_testing()
        sim_headers = {"X-Forwarded-For": "203.0.113.44"}
        for i in range(30):
            allowed, _, _ = rate_limiter.record_hit("sensitive:203.0.113.44", 30, 60.0)
            assert allowed is True
        # 31st request via client
        r_sens = client.post(
            "/api/v1/security/approvals/app-dummy-12345/approve",
            json={"reviewer_id": "rev-1", "reason": "test"},
            headers=sim_headers,
        )
        assert r_sens.status_code == 429
        assert "Retry-After" in r_sens.headers
        print("[PASS] V17-09: Sensitive operation rate limiting (30/60s -> HTTP 429) verified.")
        passed += 1
    except Exception as exc:
        print(f"[FAIL] V17-09: Sensitive operation rate limit failure: {exc}")

    # V17-10: Approval Router RBAC
    try:
        with patch.object(settings, "ENVIRONMENT", "production"):
            # Unauthenticated GET /approvals in production -> 401
            assert client.get("/api/v1/security/approvals").status_code == 401

        # Unauthorized viewer resolving approval -> 403
        viewer = UserIdentity(user_id="u-v", username="v", display_name="V", roles=[Role.VIEWER])
        app.dependency_overrides[get_current_user_optional] = lambda: viewer
        try:
            r_v = client.post(
                "/api/v1/security/approvals/app-dummy-12345/approve",
                json={"reviewer_id": "u-v", "reason": "test"},
            )
            assert r_v.status_code == 403
        finally:
            app.dependency_overrides.pop(get_current_user_optional, None)
        print("[PASS] V17-10: Approval router RBAC dependencies and permissions verified.")
        passed += 1
    except Exception as exc:
        print(f"[FAIL] V17-10: Approval RBAC failure: {exc}")

    # V17-11: approval_id Path Parameter Validation (HTTP 422)
    try:
        assert client.get("/api/v1/security/approvals/short").status_code == 422
        assert client.get("/api/v1/security/approvals/evil<script>").status_code == 422
        assert client.get(f"/api/v1/security/approvals/{'a'*100}").status_code == 422
        print("[PASS] V17-11: approval_id regex and length validation (HTTP 422) verified.")
        passed += 1
    except Exception as exc:
        print(f"[FAIL] V17-11: approval_id validation failure: {exc}")

    # V17-12: Input Model Parameter Length Bounding (HTTP 422)
    try:
        assert client.post("/api/v1/auth/login", json={"username": "u" * 129, "password": "pwd"}).status_code == 422
        assert client.post("/api/v1/auth/login", json={"username": "u", "password": "p" * 257}).status_code == 422
        assert client.post("/api/v1/dev/laboratory/run", json={"scenario_id": "s" * 65}).status_code == 422
        assert client.post("/api/v1/security/approvals/app-dummy-12345/approve", json={"reviewer_id": "r" * 65, "reason": "ok"}).status_code == 422
        assert client.post("/api/v1/security/approvals/app-dummy-12345/approve", json={"reviewer_id": "r", "reason": "x" * 1001}).status_code == 422
        print("[PASS] V17-12: Input model parameter bounding (HTTP 422) verified.")
        passed += 1
    except Exception as exc:
        print(f"[FAIL] V17-12: Parameter bounding failure: {exc}")

    # V17-13: Validation Error Sanitization & Correlation
    try:
        res_val = client.post("/api/v1/auth/login", json={"username": "valid", "password": ""})
        assert res_val.status_code == 422
        assert "X-Correlation-ID" in res_val.headers
        body = res_val.json()
        assert "correlation_id" in body
        assert "detail" in body
        print("[PASS] V17-13: Validation error sanitization and correlation attribution verified.")
        passed += 1
    except Exception as exc:
        print(f"[FAIL] V17-13: Validation error sanitization failure: {exc}")

    # V17-14: Production Lockout Invariants Preserved
    try:
        with patch.object(settings, "ENVIRONMENT", "production"):
            assert client.get("/api/v1/dev/laboratory/scenarios").status_code == 403
            assert client.post("/api/v1/dev/laboratory/run", json={"scenario_id": "ALLOW_CLEAN"}).status_code == 403
            assert client.post("/api/v1/dev/test-requests", json={"scenario": "ALLOW"}).status_code == 403
        print("[PASS] V17-14: Production dev/laboratory lockout invariants preserved.")
        passed += 1
    except Exception as exc:
        print(f"[FAIL] V17-14: Production lockout invariant failure: {exc}")

    print("=" * 70)
    print(f"VERIFICATION SUMMARY: {passed}/{total} CHECKS PASSED")
    print("=" * 70)

    return passed == total


if __name__ == "__main__":
    success = run_checks()
    sys.exit(0 if success else 1)
