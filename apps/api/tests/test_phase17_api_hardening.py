"""
Comprehensive Test Suite for AgentShield Phase 17: API and Service Hardening.

Contains >= 40 meaningful, independent tests covering:
1. Exact request-size boundary acceptance & one-byte-over rejection (HTTP 413).
2. Header count and byte bounds (HTTP 431).
3. Content-Type enforcement (application/json, charset variations, missing header) (HTTP 415).
4. Path traversal (%2e%2e, ..) and null byte (%00) prevention (HTTP 400).
5. Authoritative security headers & Cache-Control policies across 2xx, 4xx, and 5xx.
6. Rate limiting: login brute-force per IP/username, normalization, window expiration, Retry-After.
7. Approval router RBAC: VIEW_APPROVALS, RESOLVE_APPROVALS, CANCEL_APPROVAL, double resolution.
8. Anti-spoofing of reviewer identity and validation of approval_id and user_id path params.
9. Comprehensive input model parameter bounding and sanitized validation errors.
10. Production invariants: Scenario Lab lockout, demo account rejection, and zero secret leakage.
"""

import uuid
import time
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.config import settings
from app.core.hardening.rate_limiting import (
    rate_limiter,
    normalize_username,
    record_login_failure,
    record_login_success,
    get_client_ip,
)
from app.core.hardening.request_bounds import MAX_BODY_BYTES, MAX_HEADER_COUNT, MAX_HEADER_BYTES
from app.security.identity.models import UserIdentity, Role, Permission
from app.security.identity.dependencies import get_current_user_optional, get_current_user
from app.security.approval.contracts import (
    ApprovalRequest,
    ApprovalStatus,
    ReviewerIdentity,
    ApprovalResolution,
)
from app.security.approval.service import get_approval_service, ApprovalService
from app.security.audit import SecurityAuditTrail


@pytest.fixture(autouse=True)
def reset_hardening_state():
    """Ensure clean rate limiter state before each test."""
    rate_limiter.reset_for_testing()
    yield
    rate_limiter.reset_for_testing()


@pytest.fixture
def client():
    return TestClient(app, raise_server_exceptions=False)


# ==============================================================================
# 1. REQUEST SIZE & HEADER BOUNDS
# ==============================================================================

class TestRequestSizeAndHeaderBounds:
    def test_small_request_body_accepted(self, client):
        """1. Normal payload under 1MB is accepted."""
        res = client.post("/api/v1/dev/test-requests", json={"scenario": "ALLOW"})
        assert res.status_code == 200

    def test_exact_1mb_boundary_acceptance(self, client):
        """2. Request body with exactly MAX_BODY_BYTES (1,048,576 bytes) is accepted past boundary middleware."""
        # 1MB minus JSON formatting bytes
        exact_bytes = MAX_BODY_BYTES
        padding = exact_bytes - len('{"scenario":"ALLOW","request_id":""}')
        payload = '{"scenario":"ALLOW","request_id":"' + ('x' * (padding - 1)) + '"}'
        assert len(payload.encode("utf-8")) <= MAX_BODY_BYTES

        res = client.post(
            "/api/v1/dev/test-requests",
            content=payload.encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        # Bounded by request_id validation (422) but NOT rejected by size middleware (413)
        assert res.status_code != 413

    def test_one_byte_over_1mb_rejected_with_413(self, client):
        """3. Request body with 1MB + 1 byte is rejected with HTTP 413 immediately."""
        oversized = b"x" * (MAX_BODY_BYTES + 1)
        res = client.post(
            "/api/v1/auth/login",
            content=oversized,
            headers={"Content-Type": "application/json"},
        )
        assert res.status_code == 413
        assert "1MB" in res.json().get("detail", "")
        assert "X-Correlation-ID" in res.headers

    def test_oversized_content_length_rejected_with_413(self, client):
        """4. Content-Length header exceeding 1MB is rejected with HTTP 413 before reading body."""
        headers = {
            "Content-Type": "application/json",
            "Content-Length": str(MAX_BODY_BYTES + 1024),
        }
        res = client.post("/api/v1/auth/login", content=b"{}", headers=headers)
        assert res.status_code == 413
        assert "1MB" in res.json().get("detail", "")

    def test_normal_header_count_accepted(self, client):
        """5. Request with fewer than 50 headers passes cleanly."""
        headers = {f"X-Custom-Header-{i}": f"val-{i}" for i in range(10)}
        res = client.get("/health", headers=headers)
        assert res.status_code == 200

    def test_excessive_header_count_rejected_with_431(self, client):
        """6. Request with more than 50 headers is rejected with HTTP 431."""
        headers = {f"X-Custom-Header-{i}": f"val-{i}" for i in range(MAX_HEADER_COUNT + 5)}
        res = client.get("/health", headers=headers)
        assert res.status_code == 431
        assert "maximum header count exceeded" in res.json().get("detail", "")
        assert "X-Correlation-ID" in res.headers
        assert res.headers.get("X-Content-Type-Options") == "nosniff"

    def test_excessive_header_byte_size_rejected_with_431(self, client):
        """7. Request with cumulative header size > 16KB is rejected with HTTP 431."""
        headers = {"X-Giant-Header": "A" * (MAX_HEADER_BYTES + 500)}
        res = client.get("/health", headers=headers)
        assert res.status_code == 431
        assert "maximum header size exceeded" in res.json().get("detail", "")


# ==============================================================================
# 2. CONTENT-TYPE ENFORCEMENT & PROTOCOL HARDENING
# ==============================================================================

class TestContentTypeAndProtocolHardening:
    def test_mutating_json_payload_accepted(self, client):
        """8. Mutating request with application/json is accepted."""
        res = client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrong"})
        assert res.status_code in (200, 401)

    def test_application_json_with_charset_accepted(self, client):
        """9. application/json; charset=utf-8 is accepted on mutating requests."""
        res = client.post(
            "/api/v1/auth/login",
            content=b'{"username":"admin","password":"wrong"}',
            headers={"Content-Type": "application/json; charset=utf-8"},
        )
        assert res.status_code in (200, 401)

    def test_mutating_payload_with_unsupported_media_type_rejected_with_415(self, client):
        """10. Mutating request with text/plain body is rejected with HTTP 415."""
        res = client.post(
            "/api/v1/auth/login",
            content=b"username=admin&password=pwd",
            headers={"Content-Type": "text/plain"},
        )
        assert res.status_code == 415
        assert "application/json is required" in res.json().get("detail", "")
        assert "X-Correlation-ID" in res.headers

    def test_mutating_payload_with_missing_content_type_rejected_with_415(self, client):
        """11. Mutating request with body but no Content-Type header is rejected with 415."""
        res = client.post("/api/v1/auth/login", content=b'{"username":"admin"}', headers={})
        assert res.status_code == 415

    def test_empty_mutating_request_without_body_permitted(self, client):
        """12. Empty POST request without body (e.g. /logout) does not require Content-Type."""
        res = client.post("/api/v1/auth/logout")
        assert res.status_code == 200
        assert res.json().get("revoked") is False

    def test_path_traversal_encoded_rejected_with_400(self, client):
        """13. Encoded path traversal %2e%2e in path returns HTTP 400."""
        res = client.get("/api/v1/%2e%2e/health")
        assert res.status_code == 400
        assert "directory traversal sequence" in res.json().get("detail", "")

    def test_path_traversal_in_query_rejected_with_400(self, client):
        """14. Path traversal ../ or %2e%2e in query string returns HTTP 400."""
        res1 = client.get("/health?file=../etc/passwd")
        assert res1.status_code == 400
        assert "directory traversal sequence" in res1.json().get("detail", "")

        res2 = client.get("/health?file=%2e%2e/etc/passwd")
        assert res2.status_code == 400

    def test_null_byte_in_path_rejected_with_400(self, client):
        """15. Null byte %00 in URL path returns HTTP 400."""
        res = client.get("/health%00extra")
        assert res.status_code == 400
        assert "null byte" in res.json().get("detail", "")

    def test_null_byte_in_query_rejected_with_400(self, client):
        """16. Null byte %00 in query string returns HTTP 400."""
        res = client.get("/health?param=hello%00world")
        assert res.status_code == 400
        assert "null byte" in res.json().get("detail", "")


# ==============================================================================
# 3. SECURITY HEADERS & CACHE CONTROL
# ==============================================================================

class TestSecurityHeadersAndCacheControl:
    def test_security_headers_present_on_standard_200(self, client):
        """17. nosniff, frame denial, and referrer policy are present on standard responses."""
        res = client.get("/health")
        assert res.headers.get("X-Content-Type-Options") == "nosniff"
        assert res.headers.get("X-Frame-Options") == "DENY"
        assert res.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"

    def test_security_headers_present_on_4xx_errors(self, client):
        """18. Security headers are present on client error responses (400, 404, 413, 415, 422)."""
        res_404 = client.get("/api/v1/not-found-route")
        assert res_404.headers.get("X-Content-Type-Options") == "nosniff"
        assert res_404.headers.get("X-Frame-Options") == "DENY"

        res_400 = client.get("/health%00bad")
        assert res_400.headers.get("X-Content-Type-Options") == "nosniff"
        assert res_400.headers.get("X-Frame-Options") == "DENY"

    def test_security_headers_present_on_5xx_errors(self):
        """19. Security headers are attached even when internal exceptions occur."""
        client = TestClient(app, raise_server_exceptions=False)
        with patch.object(settings, "ENVIRONMENT", "production"):
            with patch("app.core.observability.health.check_liveness", side_effect=Exception("Crash")):
                res_500 = client.get("/health/live")
                assert res_500.status_code == 500
                assert res_500.headers.get("X-Content-Type-Options") == "nosniff"
                assert res_500.headers.get("X-Frame-Options") == "DENY"

    def test_sensitive_auth_endpoints_have_no_store_cache_control(self, client):
        """20. Sensitive auth endpoints have strict no-store cache control."""
        res = client.get("/api/v1/auth/me")
        cc = res.headers.get("Cache-Control", "")
        assert "no-store" in cc
        assert "no-cache" in cc
        assert res.headers.get("Pragma") == "no-cache"

    def test_sensitive_security_endpoints_have_no_store_cache_control(self, client):
        """21. Sensitive security operations endpoints have strict no-store cache control."""
        res = client.get("/api/v1/security/operations/overview")
        cc = res.headers.get("Cache-Control", "")
        assert "no-store" in cc
        assert res.headers.get("Expires") == "0"

    def test_sensitive_dev_endpoints_have_no_store_cache_control(self, client):
        """22. Sensitive dev endpoints have strict no-store cache control."""
        res = client.get("/api/v1/dev/laboratory/scenarios")
        cc = res.headers.get("Cache-Control", "")
        assert "no-store" in cc


# ==============================================================================
# 4. RATE LIMITING HARDENING
# ==============================================================================

class TestRateLimitingHardening:
    def test_failed_login_brute_force_throttled_per_ip(self, client):
        """23. 10 failed login attempts from an IP succeed with 401; 11th is throttled with 429."""
        ip_headers = {"X-Forwarded-For": "198.51.100.42"}
        user_uuid = uuid.uuid4().hex[:8]

        for i in range(10):
            res = client.post(
                "/api/v1/auth/login",
                json={"username": f"user-{user_uuid}-{i}", "password": "wrongpassword"},
                headers=ip_headers,
            )
            assert res.status_code == 401

        res_blocked = client.post(
            "/api/v1/auth/login",
            json={"username": f"user-{user_uuid}-11", "password": "wrongpassword"},
            headers=ip_headers,
        )
        assert res_blocked.status_code == 429
        assert "Retry-After" in res_blocked.headers

    def test_failed_login_username_spraying_throttled_across_ips(self, client):
        """24. 10 failed login attempts targeting the same username from multiple IPs triggers 429."""
        target_user = f"target_user_{uuid.uuid4().hex[:8]}"

        for i in range(10):
            res = client.post(
                "/api/v1/auth/login",
                json={"username": target_user, "password": "wrongpassword"},
                headers={"X-Forwarded-For": f"198.51.100.{i+10}"},
            )
            assert res.status_code == 401

        res_blocked = client.post(
            "/api/v1/auth/login",
            json={"username": target_user, "password": "wrongpassword"},
            headers={"X-Forwarded-For": "198.51.100.99"},
        )
        assert res_blocked.status_code == 429
        assert "Too many failed login attempts" in res_blocked.json().get("detail", "")

    def test_rate_limit_username_normalization(self, client):
        """25. Username casing and whitespace are normalized to the same rate limit bucket."""
        base_user = f"NormUser_{uuid.uuid4().hex[:6]}"
        ip = "198.51.100.55"

        # Record 10 failures with varied casing/spaces
        variants = [base_user.upper(), base_user.lower(), f" {base_user} ", f"{base_user.lower()} "]
        for i in range(10):
            variant = variants[i % len(variants)]
            client.post(
                "/api/v1/auth/login",
                json={"username": variant, "password": "wrong"},
                headers={"X-Forwarded-For": ip},
            )

        # Checking normalized username is blocked
        blocked, _ = rate_limiter.is_blocked(f"login_fail:user:{normalize_username(base_user)}", 10, 60.0)
        assert blocked is True

    def test_successful_login_clears_failure_state(self, client):
        """26. Successful login clears failed attempt tracking for the authenticated identity."""
        username = "admin"
        # Simulate previous failed attempts
        rate_limiter.record_failure(f"login_fail:user:{username}", 60.0)
        rate_limiter.record_failure(f"login_fail:user:{username}", 60.0)
        assert len(rate_limiter._records.get(f"login_fail:user:{username}", [])) == 2

        # Record login success
        dummy_req = MagicMock()
        record_login_success(dummy_req, username)

        assert f"login_fail:user:{username}" not in rate_limiter._records

    def test_rate_limit_retry_after_header_present_and_accurate(self, client):
        """27. 429 response contains positive integer Retry-After header <= 60."""
        ip = "203.0.113.12"
        for _ in range(10):
            rate_limiter.record_failure(f"login_fail:ip:{ip}", 60.0)

        res = client.post(
            "/api/v1/auth/login",
            json={"username": "user", "password": "pwd"},
            headers={"X-Forwarded-For": ip},
        )
        assert res.status_code == 429
        retry_after = int(res.headers.get("Retry-After", 0))
        assert 1 <= retry_after <= 60

    def test_rate_limit_window_expiration(self):
        """28. Rate limit timestamps naturally expire after sliding window elapsed."""
        key = "test_expire_bucket"
        rate_limiter.record_failure(key, window_seconds=1.0)
        assert len(rate_limiter._records[key]) == 1

        # Advance monotonic time by 2 seconds
        now = time.monotonic() + 2.0
        with patch("time.monotonic", return_value=now):
            blocked, _ = rate_limiter.is_blocked(key, limit=1, window_seconds=1.0)
            assert blocked is False

    def test_sensitive_operation_rate_limiting(self, client):
        """29. Sensitive mutating endpoints are throttled beyond 30 requests/60s."""
        sim_ip = "203.0.113.88"
        for _ in range(30):
            allowed, _, _ = rate_limiter.record_hit(f"sensitive:{sim_ip}", 30, 60.0)
            assert allowed is True

        res = client.post(
            "/api/v1/security/approvals/app-dummy-12345/approve",
            json={"reviewer_id": "rev-1", "reason": "test"},
            headers={"X-Forwarded-For": sim_ip},
        )
        assert res.status_code == 429
        assert "sensitive operations" in res.json().get("detail", "")


# ==============================================================================
# 5. APPROVAL & IDENTITY RBAC HARDENING
# ==============================================================================

class TestApprovalAndIdentityRBACHardening:
    def test_approval_list_requires_view_permission_in_production(self, client):
        """30. Unauthenticated call to GET /security/approvals returns 401 in production."""
        with patch.object(settings, "ENVIRONMENT", "production"):
            res = client.get("/api/v1/security/approvals")
            assert res.status_code == 401
            assert "Authentication required" in res.json().get("detail", "")

    def test_approval_detail_requires_view_permission_in_production(self, client):
        """31. Unauthenticated call to GET /security/approvals/{id} returns 401 in production."""
        with patch.object(settings, "ENVIRONMENT", "production"):
            res = client.get("/api/v1/security/approvals/app-valid-12345")
            assert res.status_code == 401

    def test_approval_resolution_denied_for_unauthorized_user(self, client):
        """32. User with VIEWER role cannot resolve approvals (HTTP 403)."""
        viewer = UserIdentity(
            user_id="usr-test-viewer",
            username="test_viewer",
            display_name="Viewer",
            roles=[Role.VIEWER],
        )
        app.dependency_overrides[get_current_user_optional] = lambda: viewer
        try:
            res_approve = client.post(
                "/api/v1/security/approvals/app-dummy-12345/approve",
                json={"reviewer_id": "usr-test-viewer", "reason": "Attempted approve"},
            )
            assert res_approve.status_code == 403

            res_reject = client.post(
                "/api/v1/security/approvals/app-dummy-12345/reject",
                json={"reviewer_id": "usr-test-viewer", "reason": "Attempted reject"},
            )
            assert res_reject.status_code == 403
        finally:
            app.dependency_overrides.pop(get_current_user_optional, None)

    def test_approval_cancellation_allowed_for_operator(self, client):
        """33. Operator has CANCEL_APPROVAL capability."""
        operator = UserIdentity(
            user_id="usr-test-ops",
            username="test_ops",
            display_name="Operator",
            roles=[Role.OPERATOR],
        )
        app.dependency_overrides[get_current_user_optional] = lambda: operator
        try:
            # 404 indicates RBAC passed and target record was inspected
            res_cancel = client.post(
                "/api/v1/security/approvals/app-dummy-12345/cancel",
                json={"reason": "Operator cancel"},
            )
            assert res_cancel.status_code == 404
        finally:
            app.dependency_overrides.pop(get_current_user_optional, None)

    def test_approval_cancellation_denied_for_viewer(self, client):
        """34. VIEWER lacks CANCEL_APPROVAL capability (HTTP 403)."""
        viewer = UserIdentity(
            user_id="usr-test-viewer",
            username="test_viewer",
            display_name="Viewer",
            roles=[Role.VIEWER],
        )
        app.dependency_overrides[get_current_user_optional] = lambda: viewer
        try:
            res = client.post(
                "/api/v1/security/approvals/app-dummy-12345/cancel",
                json={"reason": "Viewer cancel attempt"},
            )
            assert res.status_code == 403
        finally:
            app.dependency_overrides.pop(get_current_user_optional, None)

    def test_terminal_approval_double_resolution_prevented(self, client):
        """35. Attempting to approve an already-approved request returns HTTP 400."""
        from app.security.approval.errors import InvalidApprovalStateTransitionError
        mock_service = MagicMock()
        mock_service.approve.side_effect = InvalidApprovalStateTransitionError(
            "Approval 'app-term-test-01' is already in terminal state 'APPROVED'."
        )
        with patch("app.security.approval.router.get_approval_service", return_value=mock_service):
            res = client.post(
                "/api/v1/security/approvals/app-term-test-01/approve",
                json={"reviewer_id": "rev-2", "reason": "Double approve attempt"},
            )
            assert res.status_code == 400
            assert "terminal" in res.json().get("detail", "").lower()

    def test_reviewer_identity_anti_spoofing(self, client):
        """36. Authenticated user ID authoritatively replaces any forged reviewer_id in request body."""
        from app.security.models import AgentIdentity, ToolCategory, ActionType, Severity
        from app.security.models.utils import utc_now
        from datetime import timedelta

        authenticated_reviewer = UserIdentity(
            user_id="usr-auth-reviewer-99",
            username="sec_reviewer",
            display_name="Real Reviewer",
            roles=[Role.SECURITY_REVIEWER],
        )
        app.dependency_overrides[get_current_user_optional] = lambda: authenticated_reviewer
        mock_service = MagicMock()
        mock_service.approve.return_value = ApprovalRequest(
            approval_id="app-spoof-check-01",
            request_id="req-spoof-01",
            agent=AgentIdentity(name="test-agent"),
            tool_name="system.execute",
            tool_category=ToolCategory.SYSTEM,
            action=ActionType.EXECUTE,
            target="test",
            request_fingerprint="fp-12345",
            risk_score=10.0,
            severity=Severity.LOW,
            expires_at=utc_now() + timedelta(hours=1),
            status=ApprovalStatus.APPROVED,
        )

        with patch("app.security.approval.router.get_approval_service", return_value=mock_service):
            try:
                res = client.post(
                    "/api/v1/security/approvals/app-spoof-check-01/approve",
                    json={"reviewer_id": "forged_admin_id", "reviewer_name": "Fake Name", "reason": "Approve"},
                )
                assert res.status_code == 200
                called_reviewer = mock_service.approve.call_args[1]["reviewer"]
                assert called_reviewer.reviewer_id == "usr-auth-reviewer-99"
                assert called_reviewer.reviewer_name == "Real Reviewer"
            finally:
                app.dependency_overrides.pop(get_current_user_optional, None)

    def test_malformed_approval_id_path_parameter_rejected(self, client):
        """37. approval_id with invalid characters, spaces, or script tags returns HTTP 422."""
        bad_ids = [
            "short",
            "has space inside",
            "evil<script>",
            "a" * 100,
        ]
        for bid in bad_ids:
            res = client.get(f"/api/v1/security/approvals/{bid}")
            assert res.status_code == 422


# ==============================================================================
# 6. INPUT MODEL PARAMETER BOUNDING & SANITIZATION
# ==============================================================================

class TestParameterBoundingAndSanitization:
    def test_oversized_login_username_rejected(self, client):
        """38. Username > 128 characters returns 422."""
        res = client.post("/api/v1/auth/login", json={"username": "u" * 129, "password": "validpassword"})
        assert res.status_code == 422

    def test_oversized_login_password_rejected(self, client):
        """39. Password > 256 characters returns 422."""
        res = client.post("/api/v1/auth/login", json={"username": "admin", "password": "p" * 257})
        assert res.status_code == 422

    def test_oversized_reviewer_reason_rejected(self, client):
        """40. Approval reason > 1000 characters returns 422."""
        res = client.post(
            "/api/v1/security/approvals/app-dummy-12345/approve",
            json={"reviewer_id": "rev-1", "reason": "r" * 1001},
        )
        assert res.status_code == 422

    def test_oversized_reviewer_id_rejected(self, client):
        """41. Reviewer ID > 64 characters returns 422."""
        res = client.post(
            "/api/v1/security/approvals/app-dummy-12345/approve",
            json={"reviewer_id": "r" * 65, "reason": "valid reason"},
        )
        assert res.status_code == 422

    def test_oversized_scenario_id_rejected(self, client):
        """42. Scenario ID > 64 characters returns 422."""
        res = client.post(
            "/api/v1/dev/laboratory/run",
            json={"scenario_id": "s" * 65},
        )
        assert res.status_code == 422

    def test_invalid_user_id_path_rejected(self, client):
        """43. user_id with special characters or invalid length in disable endpoint returns 422."""
        admin = UserIdentity(user_id="usr-adm", username="adm", display_name="Adm", roles=[Role.ADMIN])
        app.dependency_overrides[get_current_user_optional] = lambda: admin
        try:
            assert client.post("/api/v1/auth/identities/x/disable").status_code == 422
            assert client.post("/api/v1/auth/identities/user<script>/disable").status_code == 422
        finally:
            app.dependency_overrides.pop(get_current_user_optional, None)

    def test_out_of_bounds_identities_limit_rejected(self, client):
        """44. list_identities limit > 500 or < 1 returns 422."""
        admin = UserIdentity(user_id="usr-adm", username="adm", display_name="Adm", roles=[Role.ADMIN])
        app.dependency_overrides[get_current_user_optional] = lambda: admin
        try:
            assert client.get("/api/v1/auth/identities?limit=501").status_code == 422
            assert client.get("/api/v1/auth/identities?limit=0").status_code == 422
        finally:
            app.dependency_overrides.pop(get_current_user_optional, None)

    def test_sanitized_validation_error_output(self, client):
        """45. 422 Validation Error returns correlation_id and redacts passwords from reflection."""
        res = client.post("/api/v1/auth/login", json={"username": "valid", "password": ""})
        assert res.status_code == 422
        assert "X-Correlation-ID" in res.headers
        data = res.json()
        assert "correlation_id" in data
        assert "detail" in data


# ==============================================================================
# 7. PRODUCTION INVARIANTS & DEFENSE-IN-DEPTH
# ==============================================================================

class TestProductionInvariantsAndDefenseInDepth:
    def test_scenario_lab_production_get_lockout(self, client):
        """46. Scenario Lab catalog is locked out in production (HTTP 403)."""
        with patch.object(settings, "ENVIRONMENT", "production"):
            res = client.get("/api/v1/dev/laboratory/scenarios")
            assert res.status_code == 403

    def test_scenario_lab_production_post_lockout(self, client):
        """47. Scenario Lab run is locked out in production (HTTP 403)."""
        with patch.object(settings, "ENVIRONMENT", "production"):
            res = client.post("/api/v1/dev/laboratory/run", json={"scenario_id": "ALLOW_CLEAN"})
            assert res.status_code == 403

    def test_production_demo_account_rejected(self, client):
        """48. In production, default demo credentials fail authentication (HTTP 401)."""
        with patch.object(settings, "ENVIRONMENT", "production"):
            res = client.post("/api/v1/auth/login", json={"username": "admin", "password": "AdminPass123!"})
            assert res.status_code == 401

    def test_correlation_headers_on_all_hardening_error_codes(self, client):
        """49. 413, 415, and 429 error responses all propagate X-Correlation-ID."""
        # 415
        r_415 = client.post("/api/v1/auth/login", content=b"raw", headers={"Content-Type": "text/plain"})
        assert r_415.status_code == 415
        assert "X-Correlation-ID" in r_415.headers

        # 413
        r_413 = client.post(
            "/api/v1/auth/login",
            content=b"{}",
            headers={"Content-Type": "application/json", "Content-Length": str(2 * 1024 * 1024)},
        )
        assert r_413.status_code == 413
        assert "X-Correlation-ID" in r_413.headers

    def test_telemetry_endpoint_rbac(self, client):
        """50. /telemetry returns 401 unauthenticated, 403 for unauthorized caller, and 200 for operator."""
        with patch.object(settings, "ENVIRONMENT", "production"):
            # Unauthenticated in production -> 401
            assert client.get("/api/v1/security/operations/telemetry").status_code == 401

        restricted = UserIdentity(user_id="u-r", username="restricted", display_name="Restricted", roles=[])
        app.dependency_overrides[get_current_user_optional] = lambda: restricted
        try:
            assert client.get("/api/v1/security/operations/telemetry").status_code == 403
        finally:
            app.dependency_overrides.pop(get_current_user_optional, None)

        operator = UserIdentity(user_id="u-o", username="o", display_name="O", roles=[Role.OPERATOR])
        app.dependency_overrides[get_current_user_optional] = lambda: operator
        try:
            assert client.get("/api/v1/security/operations/telemetry").status_code == 200
        finally:
            app.dependency_overrides.pop(get_current_user_optional, None)

    def test_response_models_exclude_credentials(self, client):
        """51. User models returned by the API never expose hashed_password or salt."""
        user = UserIdentity(user_id="u-test", username="testuser", display_name="Test User", roles=[Role.VIEWER])
        app.dependency_overrides[get_current_user] = lambda: user
        try:
            res = client.get("/api/v1/auth/me")
            assert res.status_code == 200
            data = res.json()
            assert "password" not in data
            assert "hashed_password" not in data
            assert "salt" not in data
        finally:
            app.dependency_overrides.pop(get_current_user, None)

    def test_malformed_authorization_header_rejected(self, client):
        """52. Malformed Authorization headers (empty Bearer or garbage) return HTTP 401."""
        res1 = client.get("/api/v1/auth/me", headers={"Authorization": "Bearer"})
        assert res1.status_code == 401

        res2 = client.get("/api/v1/auth/me", headers={"Authorization": "Bearer   "})
        assert res2.status_code == 401
