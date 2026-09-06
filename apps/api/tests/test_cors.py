"""
Tests for AgentShield CORS (Cross-Origin Resource Sharing) Configuration.

Validates:
- Explicit allowed origins including LAN frontend (http://172.25.1.97:5173)
- Preservation of localhost/127.0.0.1 origins
- Absence of wildcard allow_origins ("*")
- Credential support (access-control-allow-credentials: true)
- Preflight OPTIONS requests for authenticated endpoints with Authorization / X-Session-ID headers
- Rejection of untrusted / malicious origins
- Environment-configurable origin parsing
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.config.settings import Settings


@pytest.fixture
def client():
    return TestClient(app)


def test_cors_get_request_from_lan_origin(client):
    """Verify that requests from LAN origin receive correct Access-Control headers."""
    headers = {"Origin": "http://172.25.1.97:5173"}
    resp = client.get("/api/v1/security/operations/health", headers=headers)
    assert resp.status_code == 200
    assert resp.headers.get("access-control-allow-origin") == "http://172.25.1.97:5173"
    assert resp.headers.get("access-control-allow-credentials") == "true"


def test_cors_get_request_from_localhost_origins(client):
    """Verify standard localhost origins continue to be permitted."""
    for origin in ["http://localhost:5173", "http://127.0.0.1:5173"]:
        headers = {"Origin": origin}
        resp = client.get("/api/v1/security/operations/overview", headers=headers)
        assert resp.status_code == 200
        assert resp.headers.get("access-control-allow-origin") == origin
        assert resp.headers.get("access-control-allow-credentials") == "true"


def test_cors_preflight_options_for_authenticated_request(client):
    """Verify browser preflight OPTIONS request for protected endpoints with auth headers."""
    headers = {
        "Origin": "http://172.25.1.97:5173",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "authorization, content-type, x-session-id",
    }
    resp = client.options("/api/v1/auth/login", headers=headers)
    assert resp.status_code == 200
    assert resp.headers.get("access-control-allow-origin") == "http://172.25.1.97:5173"
    assert resp.headers.get("access-control-allow-credentials") == "true"
    allowed_headers = resp.headers.get("access-control-allow-headers", "").lower()
    assert "authorization" in allowed_headers
    assert "x-session-id" in allowed_headers


def test_cors_preflight_and_get_for_all_operational_endpoints(client):
    """Verify CORS headers for GET and preflight OPTIONS across all requested operational endpoints."""
    endpoints = [
        "/api/v1/security/operations/health",
        "/api/v1/security/operations/overview",
        "/api/v1/security/operations/threats",
        "/api/v1/security/operations/decisions",
        "/api/v1/security/operations/executions",
        "/api/v1/security/operations/audit",
        "/api/v1/security/approvals",
    ]
    lan_origin = "http://172.25.1.97:5173"

    for ep in endpoints:
        # 1. Preflight OPTIONS
        preflight_headers = {
            "Origin": lan_origin,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization,x-session-id",
        }
        resp_options = client.options(ep, headers=preflight_headers)
        assert resp_options.status_code == 200, f"OPTIONS failed on {ep}: {resp_options.status_code}"
        assert resp_options.headers.get("access-control-allow-origin") == lan_origin, f"CORS origin missing on OPTIONS {ep}"
        assert resp_options.headers.get("access-control-allow-credentials") == "true", f"CORS credentials missing on OPTIONS {ep}"
        allowed_methods = resp_options.headers.get("access-control-allow-methods", "")
        assert "GET" in allowed_methods, f"GET method not allowed on OPTIONS {ep}"
        allowed_headers = resp_options.headers.get("access-control-allow-headers", "").lower()
        assert "authorization" in allowed_headers, f"authorization header not allowed on OPTIONS {ep}"
        assert "x-session-id" in allowed_headers, f"x-session-id header not allowed on OPTIONS {ep}"

        # 2. Simple GET
        get_headers = {"Origin": lan_origin}
        resp_get = client.get(ep, headers=get_headers)
        assert resp_get.headers.get("access-control-allow-origin") == lan_origin, f"CORS origin missing on GET {ep}"
        assert resp_get.headers.get("access-control-allow-credentials") == "true", f"CORS credentials missing on GET {ep}"


def test_cors_rejects_unauthorized_origin(client):
    """Verify untrusted origin does NOT receive access-control-allow-origin header."""
    for bad_origin in [
        "http://evil-attacker-site.com",
        "http://evil-attacker-site.com:5173",
        "http://1.1.1.1:5173",
        "http://8.8.8.8:8000",
    ]:
        headers = {"Origin": bad_origin}
        resp = client.get("/api/v1/security/operations/health", headers=headers)
        assert resp.status_code == 200
        assert "access-control-allow-origin" not in resp.headers


def test_cors_dynamic_lan_private_subnets(client):
    """Verify arbitrary RFC 1918 LAN origins are accepted via CORS regex without hardcoding."""
    lan_origins = [
        "http://192.168.1.20:5173",
        "http://192.168.0.100:3000",
        "http://10.0.0.15:5173",
        "http://172.16.0.5:5173",
        "http://172.31.255.254:5173",
    ]
    for origin in lan_origins:
        # Preflight OPTIONS
        preflight_headers = {
            "Origin": origin,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization,x-session-id",
        }
        resp_options = client.options("/api/v1/security/operations/overview", headers=preflight_headers)
        assert resp_options.status_code == 200, f"OPTIONS failed for {origin}"
        assert resp_options.headers.get("access-control-allow-origin") == origin
        assert resp_options.headers.get("access-control-allow-credentials") == "true"

        # Simple GET
        resp_get = client.get("/api/v1/security/operations/health", headers={"Origin": origin})
        assert resp_get.status_code == 200, f"GET failed for {origin}"
        assert resp_get.headers.get("access-control-allow-origin") == origin
        assert resp_get.headers.get("access-control-allow-credentials") == "true"


def test_cors_settings_parsing_and_deduplication():
    """Verify Settings.get_cors_origins parses comma-separated lists and normalizes slashes."""
    custom_settings = Settings(
        CORS_ALLOWED_ORIGINS="http://192.168.1.100:5173/ , http://lan-host:3000 , http://localhost:5173"
    )
    origins = custom_settings.get_cors_origins()
    assert "http://192.168.1.100:5173" in origins
    assert "http://lan-host:3000" in origins
    assert "http://localhost:5173" in origins
    # No trailing slashes
    assert not any(o.endswith("/") for o in origins)
    # Never wildcard
    assert "*" not in origins


def test_cors_settings_origin_regex():
    """Verify default CORS origin regex matches localhost and private RFC 1918 subnets."""
    settings = Settings()
    regex = settings.get_cors_origin_regex()
    assert regex is not None
    import re
    compiled = re.compile(regex)
    # Matching cases
    assert compiled.match("http://localhost:5173")
    assert compiled.match("http://127.0.0.1:5173")
    assert compiled.match("http://192.168.1.20:5173")
    assert compiled.match("http://10.0.0.1:3000")
    assert compiled.match("http://172.25.1.97:5173")
    assert compiled.match("https://192.168.1.20")
    # Non-matching cases
    assert not compiled.match("http://evil-attacker-site.com")
    assert not compiled.match("http://evil-attacker-site.com:5173")
    assert not compiled.match("http://8.8.8.8:5173")
    assert not compiled.match("http://172.32.0.1:5173")  # Outside 172.16.0.0/12
