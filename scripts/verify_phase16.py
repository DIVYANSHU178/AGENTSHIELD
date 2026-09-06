#!/usr/bin/env python3
"""
AgentShield Phase 16: Observability Subsystem Verification Suite.

Validates all 12 core Phase 16 observability properties:
1. Correlation ID Generation, Validation & Sanitization
2. Correlation ID Propagation & Response Header (X-Correlation-ID)
3. Structured JSON Logging & Development Console Formatter
4. Automated Secret Redaction in Log Stream & Arguments
5. Log Injection Prevention (CRLF, Quotes, Control Characters)
6. Bounded Low-Cardinality Route Normalization & Metrics Registry
7. HTTP Request & Security Domain Telemetry Accounting
8. Liveness Probe (/health/live) Responsiveness
9. Readiness Probe (/health/ready) Dependency Checking & Fail-Closed Behavior
10. Error Observability & 500 Sanitization with Correlation Tracking
11. Telemetry Endpoint (/api/v1/security/operations/telemetry) RBAC Protection
12. Adversarial Non-Leakage & Resilience
"""

import io
import json
import logging
import os
import re
import sys
from pathlib import Path
from unittest.mock import patch

# Setup paths
ROOT_DIR = Path(__file__).resolve().parent.parent
API_DIR = ROOT_DIR / "apps" / "api"
sys.path.insert(0, str(API_DIR))

from fastapi.testclient import TestClient
from app.main import app
from app.config.settings import settings
from app.core.observability import (
    get_correlation_id,
    set_correlation_id,
    reset_correlation_id,
    generate_correlation_id,
    validate_and_sanitize_correlation_id,
    metrics_registry,
    normalize_route,
    get_status_family,
    StructuredJsonFormatter,
    DevelopmentConsoleFormatter,
    RedactingFilter,
    check_liveness,
    check_readiness,
)
from app.security.identity.models import UserIdentity, Role, Permission
from app.security.identity.dependencies import get_current_user_optional


def run_verification() -> bool:
    print("=" * 80)
    print("AGENTSHIELD PHASE 16: OBSERVABILITY SUBSYSTEM VERIFICATION")
    print("=" * 80)

    results = []
    client = TestClient(app, raise_server_exceptions=False)

    def check(title: str, condition: bool, details: str = ""):
        status = "PASS" if condition else "FAIL"
        results.append((title, condition, details))
        mark = "OK" if condition else "FAIL"
        print(f"[{mark:4s}] {title}: {status}")
        if details and not condition:
            print(f"    Reason: {details}")

    # ----------------------------------------------------------------------
    # 1. Correlation ID Generation, Validation & Sanitization
    # ----------------------------------------------------------------------
    try:
        cid = generate_correlation_id()
        valid_cid = validate_and_sanitize_correlation_id("client-req-abc-12345")
        short_cid = validate_and_sanitize_correlation_id("short")  # < 8 chars -> replaced
        injected = validate_and_sanitize_correlation_id("id\r\nInjected-Header: evil")
        oversized = validate_and_sanitize_correlation_id("a" * 120)

        c1 = (
            len(cid) == 40
            and cid.startswith("req-")
            and valid_cid == "client-req-abc-12345"
            and len(short_cid) == 40
            and short_cid.startswith("req-")
            and len(injected) == 40
            and len(oversized) == 40
        )
        check("1. Correlation ID Generation & Sanitization", c1)
    except Exception as e:
        check("1. Correlation ID Generation & Sanitization", False, str(e))

    # ----------------------------------------------------------------------
    # 2. Correlation ID Propagation & Response Header
    # ----------------------------------------------------------------------
    try:
        custom_id = "external-client-trace-999"
        res = client.get("/health", headers={"X-Correlation-ID": custom_id})
        resp_cid = res.headers.get("X-Correlation-ID")
        res_auto = client.get("/health")
        auto_cid = res_auto.headers.get("X-Correlation-ID")

        c2 = (
            res.status_code == 200
            and resp_cid == custom_id
            and auto_cid is not None
            and len(auto_cid) == 40
            and auto_cid.startswith("req-")
        )
        check("2. Correlation Propagation & Response Header", c2)
    except Exception as e:
        check("2. Correlation Propagation & Response Header", False, str(e))

    # ----------------------------------------------------------------------
    # 3. Structured JSON Logging & Console Formatter
    # ----------------------------------------------------------------------
    try:
        formatter = StructuredJsonFormatter()
        logger = logging.getLogger("test_structured")
        record = logger.makeRecord(
            "test_structured",
            logging.INFO,
            "test_file.py",
            42,
            "Service operation executed successfully",
            (),
            None,
            extra={"correlation_id": "test-corr-1234", "event": "TEST_OP", "outcome": "SUCCESS"},
        )
        output = formatter.format(record)
        data = json.loads(output)

        c3 = (
            data.get("level") == "INFO"
            and data.get("correlation_id") == "test-corr-1234"
            and data.get("event") == "TEST_OP"
            and data.get("outcome") == "SUCCESS"
            and "timestamp" in data
            and "\n" not in output
        )
        check("3. Structured JSON Logging & Schema", c3)
    except Exception as e:
        check("3. Structured JSON Logging & Schema", False, str(e))

    # ----------------------------------------------------------------------
    # 4. Automated Secret Redaction in Log Stream
    # ----------------------------------------------------------------------
    try:
        filt = RedactingFilter()
        rec1 = logging.LogRecord("test", logging.INFO, "", 0, "User password: SecretPassword123!", (), None)
        filt.filter(rec1)
        rec2 = logging.LogRecord(
            "test",
            logging.INFO,
            "",
            0,
            "Bearer token received: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.dummy",
            (),
            None,
        )
        filt.filter(rec2)
        rec3 = logging.LogRecord(
            "test",
            logging.INFO,
            "",
            0,
            "Connecting to postgresql://dbuser:SuperSecretDBPass@localhost:5432/agentshield",
            (),
            None,
        )
        filt.filter(rec3)

        c4 = (
            "SecretPassword123!" not in rec1.msg
            and "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in rec2.msg
            and "SuperSecretDBPass" not in rec3.msg
        )
        check("4. Automated Secret Redaction in Logs", c4)
    except Exception as e:
        check("4. Automated Secret Redaction in Logs", False, str(e))

    # ----------------------------------------------------------------------
    # 5. Log Injection Prevention
    # ----------------------------------------------------------------------
    try:
        filt = RedactingFilter()
        rec = logging.LogRecord(
            "test",
            logging.INFO,
            "",
            0,
            "Login failed for user: admin\r\n[2026-09-06] [ERROR] INJECTED LOG ENTRY",
            (),
            None,
        )
        formatter = StructuredJsonFormatter()
        formatted = formatter.format(rec)

        # Must be strict single-line JSON without raw newline characters in string
        lines = formatted.strip().split("\n")
        parsed = json.loads(formatted)

        c5 = len(lines) == 1 and "INJECTED LOG ENTRY" in parsed["message"]
        check("5. Log Injection Prevention (CRLF Escaping)", c5)
    except Exception as e:
        check("5. Log Injection Prevention (CRLF Escaping)", False, str(e))

    # ----------------------------------------------------------------------
    # 6. Low-Cardinality Route Normalization
    # ----------------------------------------------------------------------
    try:
        r1 = normalize_route("/api/v1/security/approval/requests/550e8400-e29b-41d4-a716-446655440000/approve")
        r2 = normalize_route("/api/v1/auth/users/usr-12345678/profile")
        r3 = normalize_route("/api/v1/security/operations/telemetry?token=secret123&user=attacker")
        r4 = normalize_route("/health/live")

        c6 = (
            r1 == "/api/v1/security/approval"
            and r2 == "/api/v1/auth"
            and r3 == "/api/v1/security/operations/telemetry"
            and r4 == "/health/live"
        )
        check("6. Bounded Low-Cardinality Route Normalization", c6)
    except Exception as e:
        check("6. Bounded Low-Cardinality Route Normalization", False, str(e))

    # ----------------------------------------------------------------------
    # 7. Metrics Registry & Telemetry Accounting
    # ----------------------------------------------------------------------
    try:
        metrics_registry.reset_for_testing()
        metrics_registry.record_http_request("GET", "/health", 200, 0.012)
        metrics_registry.record_auth_event("AUTHENTICATION_SUCCESS", "SUCCESS")
        metrics_registry.record_security_decision("ALLOW", "CLEAN")
        metrics_registry.record_approval_transition("APPROVED")
        metrics_registry.record_threat_detection("PROMPT_INJECTION")
        metrics_registry.record_execution("COMPLETED")
        metrics_registry.record_database_error("query_timeout")

        snap = metrics_registry.get_telemetry_snapshot()

        c7 = (
            any(r["method"] == "GET" and r["route_group"] == "/health" and r["status_family"] == "2xx" and r["count"] == 1 for r in snap["http_requests_total"])
            and any(r["event_type"] == "AUTHENTICATION_SUCCESS" and r["outcome"] == "SUCCESS" and r["count"] == 1 for r in snap["auth_events_total"])
            and any(r["decision"] == "ALLOW" and r["severity"] == "CLEAN" and r["count"] == 1 for r in snap["security_decisions_total"])
            and snap["approval_transitions_total"].get("APPROVED") == 1
            and snap["threats_detected_total"].get("PROMPT_INJECTION") == 1
            and snap["executions_total"].get("COMPLETED") == 1
            and snap["database_errors_total"].get("query_timeout") == 1
        )
        check("7. Metrics Registry & Domain Telemetry Accounting", c7)
    except Exception as e:
        check("7. Metrics Registry & Domain Telemetry Accounting", False, str(e))

    # ----------------------------------------------------------------------
    # 8. Liveness Probe (/health/live)
    # ----------------------------------------------------------------------
    try:
        res = client.get("/health/live")
        data = res.json()
        c8 = (
            res.status_code == 200
            and data.get("alive") is True
            and data.get("status") == "ok"
            and "X-Correlation-ID" in res.headers
        )
        check("8. Liveness Probe (/health/live) Responsiveness", c8)
    except Exception as e:
        check("8. Liveness Probe (/health/live) Responsiveness", False, str(e))

    # ----------------------------------------------------------------------
    # 9. Readiness Probe (/health/ready) & Degraded Fail-Closed
    # ----------------------------------------------------------------------
    try:
        res_ok = client.get("/health/ready")
        data_ok = res_ok.json()

        # Test simulated degraded state
        with patch("app.core.observability.health.get_db", side_effect=RuntimeError("DB disconnected")):
            res_degraded = client.get("/health/ready")
            data_degraded = res_degraded.json()

        c9 = (
            res_ok.status_code == 200
            and data_ok.get("ready") is True
            and data_ok.get("dependencies", {}).get("database") == "healthy"
            and res_degraded.status_code == 503
            and data_degraded.get("ready") is False
            and data_degraded.get("dependencies", {}).get("database") == "unreachable"
        )
        check("9. Readiness Probe (/health/ready) & Fail-Closed 503", c9)
    except Exception as e:
        check("9. Readiness Probe (/health/ready) & Fail-Closed 503", False, str(e))

    # ----------------------------------------------------------------------
    # 10. Error Observability & 500 Sanitization
    # ----------------------------------------------------------------------
    try:
        # 404
        r404 = client.get("/api/v1/nonexistent-route-for-observability")
        c10_404 = r404.status_code == 404 and "X-Correlation-ID" in r404.headers

        # 500 in production mode
        with patch.object(settings, "ENVIRONMENT", "production"):
            with patch("app.core.observability.health.check_liveness", side_effect=Exception("Database password was: secret123!")):
                r500 = client.get("/health/live")
                data500 = r500.json()
                c10_500 = (
                    r500.status_code == 500
                    and "secret123!" not in r500.text
                    and data500.get("error") == "An unexpected error occurred."
                    and "correlation_id" in data500
                    and "X-Correlation-ID" in r500.headers
                )

        check("10. Error Observability & 500 Response Sanitization", c10_404 and c10_500)
    except Exception as e:
        check("10. Error Observability & 500 Response Sanitization", False, str(e))

    # ----------------------------------------------------------------------
    # 11. Telemetry Endpoint RBAC Protection
    # ----------------------------------------------------------------------
    try:
        # 1. Unauthenticated in production -> 401
        with patch.object(settings, "ENVIRONMENT", "production"):
            r_unauth = client.get("/api/v1/security/operations/telemetry")
            c11_unauth = r_unauth.status_code == 401

        # 2. Invalid token -> 401
        r_bad_token = client.get(
            "/api/v1/security/operations/telemetry",
            headers={"Authorization": "Bearer invalid-token-12345"},
        )
        c11_bad_token = r_bad_token.status_code == 401

        # 3. Viewer without VIEW_OPERATIONS -> 403
        restricted_user = UserIdentity(
            user_id="usr-restricted",
            username="restricted",
            display_name="Restricted User",
            roles=[],
        )
        app.dependency_overrides[get_current_user_optional] = lambda: restricted_user
        try:
            r_forbidden = client.get("/api/v1/security/operations/telemetry")
            c11_forbidden = r_forbidden.status_code == 403
        finally:
            app.dependency_overrides.pop(get_current_user_optional, None)

        # 4. Operator with VIEW_OPERATIONS -> 200
        ops_user = UserIdentity(
            user_id="usr-ops",
            username="ops_user",
            display_name="Operations User",
            roles=[Role.OPERATOR],
        )
        app.dependency_overrides[get_current_user_optional] = lambda: ops_user
        try:
            r_allowed = client.get("/api/v1/security/operations/telemetry")
            c11_allowed = r_allowed.status_code == 200 and "uptime_seconds" in r_allowed.json()
        finally:
            app.dependency_overrides.pop(get_current_user_optional, None)

        c11 = c11_unauth and c11_bad_token and c11_forbidden and c11_allowed
        check("11. Telemetry Endpoint RBAC Protection", c11)
    except Exception as e:
        check("11. Telemetry Endpoint RBAC Protection", False, str(e))

    # ----------------------------------------------------------------------
    # 12. Adversarial Non-Leakage & Resilience
    # ----------------------------------------------------------------------
    try:
        # Attack with malicious headers and payloads
        attack_cid = '{"evil": true}\r\nSet-Cookie: session=hijacked\r\n'
        res_attack = client.get("/health", headers={"X-Correlation-ID": attack_cid})
        returned_cid = res_attack.headers.get("X-Correlation-ID")

        # Returned CID must be sanitized (req-<uuid4>), not containing attacker payload
        c12_cid_safe = (
            returned_cid is not None
            and "evil" not in returned_cid
            and "\r" not in returned_cid
            and "\n" not in returned_cid
            and len(returned_cid) == 40
            and returned_cid.startswith("req-")
        )

        # Verify no secret keywords in telemetry output
        snap = client.get(
            "/api/v1/security/operations/telemetry",
            headers={"Authorization": "Bearer invalid-token"},
        )
        # Even if 401, error detail does not contain secrets
        c12_no_secrets = "SuperSecret" not in snap.text and "password" not in snap.text.lower()

        c12 = c12_cid_safe and c12_no_secrets
        check("12. Adversarial Non-Leakage & Resilience", c12)
    except Exception as e:
        check("12. Adversarial Non-Leakage & Resilience", False, str(e))

    print("=" * 80)
    total = len(results)
    passed = sum(1 for _, c, _ in results if c)
    failed = total - passed
    print(f"RESULTS: {passed}/{total} CHECKS PASSED ({failed} FAILED)")
    print("=" * 80)

    return failed == 0


if __name__ == "__main__":
    success = run_verification()
    sys.exit(0 if success else 1)
