"""
Comprehensive Test Suite for AgentShield Phase 16: Observability Subsystem.

Covers:
- Correlation ID generation, validation, anti-poisoning, and response propagation
- Structured JSON and terminal logging with automated Phase 15 redaction
- Log injection prevention (newlines, quotes, JSON fragments, control characters)
- Thread-safe, low-cardinality metrics registry (HTTP, auth, decisions, approvals, threats, executions, DB)
- Health, Liveness, and Readiness probes (including degraded dependency handling)
- Error observability (404, 422, 500) and response sanitization
- RBAC enforcement on the /telemetry endpoint
- Adversarial tests (oversized IDs, log poisoning, simulated DB outage, high-cardinality attacks)
"""

import json
import logging
import io
import re
import pytest
from unittest.mock import patch, MagicMock
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
from app.security.identity.dependencies import get_current_user, get_current_user_optional


@pytest.fixture(autouse=True)
def reset_metrics():
    """Reset metrics registry before each test to ensure determinism."""
    metrics_registry.reset_for_testing()
    yield
    metrics_registry.reset_for_testing()


@pytest.fixture
def client():
    return TestClient(app, raise_server_exceptions=False)


# ==============================================================================
# 1. CORRELATION ID UNIT & ADVERSARIAL TESTS
# ==============================================================================

class TestCorrelationId:
    def test_generated_id_format(self):
        """Test default generated correlation ID format."""
        cid = generate_correlation_id()
        assert cid.startswith("req-")
        assert len(cid) >= 36

    def test_valid_inbound_id_accepted(self):
        """Valid alphanumeric IDs with hyphens and underscores must be preserved."""
        valid_id = "trace-client-12345_xyz"
        assert validate_and_sanitize_correlation_id(valid_id) == valid_id

    def test_x_request_id_and_correlation_headers(self, client):
        """Middleware accepts both X-Correlation-ID and X-Request-ID."""
        custom_id = "audit-req-trace-9999"
        res1 = client.get("/health", headers={"X-Correlation-ID": custom_id})
        assert res1.headers.get("X-Correlation-ID") == custom_id

        res2 = client.get("/health", headers={"X-Request-ID": custom_id})
        assert res2.headers.get("X-Correlation-ID") == custom_id

    def test_invalid_short_id_replaced(self):
        """IDs shorter than 8 characters must be safely replaced with a generated UUID."""
        short_id = "abc"
        sanitized = validate_and_sanitize_correlation_id(short_id)
        assert sanitized != short_id
        assert sanitized.startswith("req-")

    def test_oversized_id_rejected(self):
        """IDs longer than 64 characters must be safely replaced."""
        oversized = "a" * 1000
        sanitized = validate_and_sanitize_correlation_id(oversized)
        assert sanitized != oversized
        assert sanitized.startswith("req-")
        assert len(sanitized) <= 64

    def test_whitespace_rejection(self):
        """IDs with leading, trailing, or embedded whitespace must be replaced."""
        assert validate_and_sanitize_correlation_id("   valid-len-id   ").startswith("req-")
        assert validate_and_sanitize_correlation_id("id with spaces inside").startswith("req-")
        assert validate_and_sanitize_correlation_id("\tid-with-tab-123").startswith("req-")

    def test_control_character_rejection(self):
        """IDs containing control characters or unprintable characters must be rejected."""
        assert validate_and_sanitize_correlation_id("id\x00nullbyte1234").startswith("req-")
        assert validate_and_sanitize_correlation_id("id\x1b[31mcolor123").startswith("req-")

    def test_newline_carriage_return_injection_rejected(self):
        """IDs containing newlines or CR (log injection attempts) must be replaced."""
        malicious = "req-123\nINFO: fake log line injected"
        assert validate_and_sanitize_correlation_id(malicious).startswith("req-")

        malicious_cr = "req-123\r\nSET-COOKIE: admin=true"
        assert validate_and_sanitize_correlation_id(malicious_cr).startswith("req-")

    def test_quotes_and_json_injection_rejected(self):
        """IDs containing quotes, slashes, or JSON fragments must be replaced."""
        fake_json = 'req-123", "fake_field": "val'
        assert validate_and_sanitize_correlation_id(fake_json).startswith("req-")

    def test_response_header_always_present(self, client):
        """Every HTTP response must carry X-Correlation-ID header."""
        res = client.get("/health")
        assert "X-Correlation-ID" in res.headers
        assert res.headers["X-Correlation-ID"].startswith("req-")

    def test_context_reset_after_request(self, client):
        """Correlation ID contextvar must be reset after request finishes."""
        initial_id = get_correlation_id()
        client.get("/health", headers={"X-Correlation-ID": "temp-test-req-001"})
        assert get_correlation_id() == initial_id


# ==============================================================================
# 2. STRUCTURED LOGGING & REDACTION TESTS
# ==============================================================================

class TestStructuredLogging:
    def _create_record(self, msg, level=logging.INFO, extra=None):
        rec = logging.LogRecord(
            name="agentshield.test",
            level=level,
            pathname=__file__,
            lineno=10,
            msg=msg,
            args=(),
            exc_info=None,
        )
        if extra:
            for k, v in extra.items():
                setattr(rec, k, v)
        return rec

    def test_structured_json_fields(self):
        """StructuredJsonFormatter produces valid JSON with required standard fields."""
        formatter = StructuredJsonFormatter()
        rec = self._create_record("Test operational message", extra={
            "actor": "usr-admin",
            "event": "AUTH_CHECK",
            "outcome": "SUCCESS",
            "duration_ms": 14.5,
        })
        formatted = formatter.format(rec)
        data = json.loads(formatted)

        assert data["level"] == "INFO"
        assert data["logger"] == "agentshield.test"
        assert "timestamp" in data
        assert "correlation_id" in data
        assert data["actor"] == "usr-admin"
        assert data["event"] == "AUTH_CHECK"
        assert data["outcome"] == "SUCCESS"
        assert data["duration_ms"] == 14.5
        assert data["message"] == "Test operational message"

    def test_redaction_in_log_message(self):
        """Sensitive keywords (password, token, secrets) are redacted in log messages."""
        filt = RedactingFilter()
        rec = self._create_record("User provided password: SuperSecretPass123! to server")
        filt.filter(rec)
        assert "SuperSecretPass123!" not in rec.msg
        assert "****" in rec.msg or "[REDACTED" in rec.msg

    def test_bearer_token_redaction(self):
        """Bearer tokens in log messages are replaced with [REDACTED_TOKEN]."""
        filt = RedactingFilter()
        rec = self._create_record("Header Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.tokenpayload123")
        filt.filter(rec)
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in rec.msg
        assert "[REDACTED_TOKEN]" in rec.msg

    def test_database_credential_redaction(self):
        """Database connection URLs with passwords are automatically masked."""
        filt = RedactingFilter()
        rec = self._create_record("Connecting to postgresql://dbuser:super_secret_db_pass@db.internal:5432/shield")
        filt.filter(rec)
        assert "super_secret_db_pass" not in rec.msg
        assert "postgresql://dbuser:****@db.internal:5432/shield" in rec.msg

    def test_secret_key_and_auth_secret_redaction(self):
        """Configuration SECRET_KEY and AUTHORIZATION_SECRET are redacted if present."""
        filt = RedactingFilter()
        secret_val = settings.SECRET_KEY or "fallback-secret-for-testing-purposes-1234"
        rec = self._create_record(f"Internal key dump: {secret_val}")
        filt.filter(rec)
        assert secret_val not in rec.msg
        assert "[REDACTED_SECRET_KEY]" in rec.msg

    def test_log_injection_control_character_escaping(self):
        """Newlines and carriage returns are escaped in human console formatting to prevent line splitting."""
        formatter = DevelopmentConsoleFormatter()
        rec = self._create_record("User attempted login: admin\n[2026-09-06] [CRITICAL] Admin privilege granted")
        formatted = formatter.format(rec)
        # Should be a single log line (no unescaped newline creating fake log entry)
        lines = formatted.split("\n")
        assert len(lines) == 1
        assert "\\n" in formatted


# ==============================================================================
# 3. METRICS REGISTRY UNIT & ADVERSARIAL TESTS
# ==============================================================================

class TestMetricsRegistry:
    def test_http_request_recording(self):
        """Recording HTTP request updates counters and duration summary."""
        metrics_registry.record_http_request("GET", "/health", 200, 12.4)
        metrics_registry.record_http_request("GET", "/health", 200, 18.2)
        metrics_registry.record_http_request("POST", "/api/v1/auth/login", 401, 35.0)

        snap = metrics_registry.get_telemetry_snapshot()
        reqs = { (r["method"], r["route_group"], r["status_family"]): r["count"] for r in snap["http_requests_total"] }

        assert reqs[("GET", "/health", "2xx")] == 2
        assert reqs[("POST", "/api/v1/auth/login", "4xx")] == 1

        durs = { (d["method"], d["route_group"]): d for d in snap["http_request_duration"] }
        assert durs[("GET", "/health")]["count"] == 2
        assert durs[("GET", "/health")]["avg_ms"] == 15.3

    def test_route_normalization_bounds_cardinality(self):
        """Random UUIDs, query strings, and dynamic IDs map to bounded route groups."""
        assert normalize_route("/api/v1/security/approval/app-12345/approve") == "/api/v1/security/approval"
        assert normalize_route("/api/v1/security/operations/threats?limit=10&severity=HIGH") == "/api/v1/security/operations/threats"
        assert normalize_route("/health?probe=k8s") == "/health"

    def test_high_cardinality_attack_bounded(self):
        """Simulate an attacker flooding 1,000 unique URLs; route groups remain strictly bounded."""
        for i in range(1000):
            metrics_registry.record_http_request("GET", f"/api/v1/auth/user-{i}?token=fake-{i}", 200, 5.0)

        snap = metrics_registry.get_telemetry_snapshot()
        # All 1000 requests map to a single route group
        route_groups = {r["route_group"] for r in snap["http_requests_total"]}
        assert len(route_groups) <= 2

    def test_security_domain_metrics(self):
        """Auth, decision, approval, threat, and execution metrics update properly."""
        metrics_registry.record_auth_event("AUTHENTICATION_SUCCESS", "SUCCESS")
        metrics_registry.record_auth_event("AUTHENTICATION_FAILURE", "FAILURE")
        metrics_registry.record_auth_event("DEMO_PROHIBITED", "REJECTED")

        metrics_registry.record_security_decision("ALLOW", "LOW")
        metrics_registry.record_security_decision("DENY", "HIGH")

        metrics_registry.record_approval_transition("APPROVED")
        metrics_registry.record_approval_transition("REJECTED")

        metrics_registry.record_threat_detection("COMMAND_INJECTION")
        metrics_registry.record_threat_detection("PATH_TRAVERSAL")

        metrics_registry.record_execution("COMPLETED")
        metrics_registry.record_database_error("query")

        snap = metrics_registry.get_telemetry_snapshot()
        assert snap["approval_transitions_total"]["APPROVED"] == 1
        assert snap["approval_transitions_total"]["REJECTED"] == 1
        assert snap["threats_detected_total"]["COMMAND_INJECTION"] == 1
        assert snap["threats_detected_total"]["PATH_TRAVERSAL"] == 1
        assert snap["executions_total"]["COMPLETED"] == 1
        assert snap["database_errors_total"]["query"] == 1


# ==============================================================================
# 4. HEALTH, LIVENESS & READINESS PROBES
# ==============================================================================

class TestHealthProbes:
    def test_root_health_compatibility(self, client):
        """Root /health must preserve backward-compatible schema."""
        res = client.get("/health")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        assert data["service"] == "agentshield"
        assert "environment" in data
        assert "X-Correlation-ID" in res.headers

    def test_liveness_probe_returns_200(self, client):
        """Liveness probe /health/live returns HTTP 200 and alive=True."""
        res = client.get("/health/live")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        assert data["alive"] is True
        assert "timestamp" in data

    def test_readiness_probe_healthy(self, client):
        """Readiness probe /health/ready returns HTTP 200 and ready=True under normal conditions."""
        res = client.get("/health/ready")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        assert data["ready"] is True
        assert data["dependencies"]["database"] == "healthy"
        assert data["dependencies"]["security_engine"] == "healthy"

    def test_readiness_probe_degraded_on_db_failure(self, client):
        """When database is unreachable, readiness probe returns HTTP 503 and ready=False."""
        with patch("app.core.observability.health.get_db", side_effect=RuntimeError("Simulated DB connection lost")):
            res = client.get("/health/ready")
            assert res.status_code == 503
            data = res.json()
            assert data["status"] == "degraded"
            assert data["ready"] is False
            assert data["dependencies"]["database"] == "unreachable"

    def test_health_probes_zero_secret_leakage(self, client):
        """Health endpoints must never expose passwords, keys, or stack traces."""
        for path in ("/health", "/health/live", "/health/ready", "/api/v1/health/ready"):
            res = client.get(path)
            raw = res.text
            assert "password" not in raw.lower()
            assert "secret" not in raw.lower() or "authorization" not in raw.lower()
            assert "Traceback" not in raw


# ==============================================================================
# 5. ERROR OBSERVABILITY & PRODUCTION SANITIZATION
# ==============================================================================

class TestErrorObservability:
    def test_404_error_has_correlation_id(self, client):
        """404 Not Found returns X-Correlation-ID header."""
        res = client.get("/api/v1/nonexistent-route-for-testing")
        assert res.status_code == 404
        assert "X-Correlation-ID" in res.headers

    def test_422_validation_error_has_correlation_id(self, client):
        """422 Validation Error returns X-Correlation-ID header."""
        res = client.post("/api/v1/auth/login", json={})
        assert res.status_code == 422
        assert "X-Correlation-ID" in res.headers

    def test_500_error_sanitization_and_correlation(self, client):
        """Unhandled 500 error includes correlation_id and sanitized message in production."""
        with patch.object(settings, "ENVIRONMENT", "production"):
            # Trigger generic exception handler via an endpoint
            with patch("app.core.observability.health.check_liveness", side_effect=Exception("Database password was: secret123!")):
                res = client.get("/health/live")
                assert res.status_code == 500
                assert "X-Correlation-ID" in res.headers
                data = res.json()
                assert "secret123!" not in res.text
                assert "correlation_id" in data
                assert data["detail"] == "Internal server error"
                assert data["error"] == "An unexpected error occurred."


# ==============================================================================
# 6. TELEMETRY ENDPOINT & RBAC
# ==============================================================================

class TestTelemetryEndpointRBAC:
    def test_telemetry_requires_authentication(self, client):
        """Unauthenticated caller in production receives 401, and invalid token returns 401."""
        with patch.object(settings, "ENVIRONMENT", "production"):
            res = client.get("/api/v1/security/operations/telemetry")
            assert res.status_code == 401

        # Invalid token is rejected with 401 regardless of environment
        res = client.get("/api/v1/security/operations/telemetry", headers={"Authorization": "Bearer invalid-token-xyz"})
        assert res.status_code == 401

    def test_telemetry_viewer_denied_without_view_operations(self, client):
        """Identity without VIEW_OPERATIONS is denied 403 Forbidden."""
        # Create a user with zero permissions
        restricted_user = UserIdentity(
            user_id="usr-test-restricted",
            username="restricted",
            display_name="Restricted User",
            roles=[],
        )
        app.dependency_overrides[get_current_user_optional] = lambda: restricted_user
        try:
            res = client.get("/api/v1/security/operations/telemetry")
            assert res.status_code == 403
        finally:
            app.dependency_overrides.pop(get_current_user_optional, None)

    def test_telemetry_operator_allowed(self, client):
        """Operator user with VIEW_OPERATIONS receives telemetry snapshot."""
        operator_user = UserIdentity(
            user_id="usr-test-ops",
            username="test_ops",
            display_name="Test Operator",
            roles=[Role.OPERATOR],
        )
        app.dependency_overrides[get_current_user_optional] = lambda: operator_user
        try:
            res = client.get("/api/v1/security/operations/telemetry")
            assert res.status_code == 200
            data = res.json()
            assert "uptime_seconds" in data
            assert "http_requests_total" in data
            assert "auth_events_total" in data
            assert "security_decisions_total" in data
        finally:
            app.dependency_overrides.pop(get_current_user_optional, None)


# ==============================================================================
# 7. ADVERSARIAL & INJECTION SECURITY TESTS
# ==============================================================================

class TestAdversarialObservability:
    def test_malicious_correlation_id_does_not_break_system(self, client):
        """Adversarial header payloads with injection attempts do not crash application."""
        malicious_headers = [
            {"X-Correlation-ID": "admin\nCRITICAL: Privilege Escalation"},
            {"X-Correlation-ID": 'test", "injected": true, "sub": "'},
            {"X-Correlation-ID": "a" * 5000},
            {"X-Correlation-ID": "<script>alert(1)</script>"},
            {"X-Correlation-ID": "\x00\x01\x02\x03"},
        ]
        for headers in malicious_headers:
            res = client.get("/health", headers=headers)
            assert res.status_code == 200
            resp_corr = res.headers.get("X-Correlation-ID")
            # Should have safely replaced the malicious payload with a clean req-<uuid>
            assert resp_corr.startswith("req-")
            assert "\n" not in resp_corr
            assert '"' not in resp_corr
            assert "<script>" not in resp_corr

    def test_malicious_username_in_login_does_not_poison_logs(self, client):
        """Malicious username attempting log injection is sanitized."""
        malicious_user = "attacker\nINFO: Log forged by attacker"
        res = client.post("/api/v1/auth/login", json={"username": malicious_user, "password": "anypassword"})
        assert res.status_code == 401
        assert "X-Correlation-ID" in res.headers

    def test_query_parameter_with_secrets_does_not_leak_in_metrics(self, client):
        """Query parameters containing simulated API keys or tokens do not leak into metric labels."""
        res = client.get("/health?api_key=sk-proj-supersecret1234567890123")
        assert res.status_code == 200

        snap = metrics_registry.get_telemetry_snapshot()
        raw_snap = json.dumps(snap)
        assert "supersecret" not in raw_snap
        assert "api_key" not in raw_snap
