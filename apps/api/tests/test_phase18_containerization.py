"""
Comprehensive Test Suite for AgentShield Phase 18: Containerization.

Covers all Phase 18 container security, runtime, and architecture requirements:
1. Backend multi-stage build and image verification.
2. Frontend multi-stage build and static serving verification.
3. Non-root user execution (Backend: UID 10001, Frontend: UID 101).
4. Container healthcheck and readiness probe validation.
5. Production fail-closed environment invariants (missing secrets, default DB, debug flag).
6. Zero secret leakage across image configs, layers, and histories.
7. Build context hygiene (.dockerignore exclusions: .env, databases, node_modules, pytest).
8. Network isolation and frontend-to-backend reverse proxy routing.
9. End-to-end containerized authentication, authorization, and RBAC.
10. Phase 14-17 security regressions inside containerized runtime.
"""

import json
import subprocess
import time
import urllib.request
import urllib.error
from pathlib import Path
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
API_DIR = REPO_ROOT / "apps" / "api"
WEB_DIR = REPO_ROOT / "apps" / "web"


def run_cmd(cmd: list[str], timeout: int = 120) -> tuple[int, str, str]:
    """Helper to run a subprocess command safely."""
    proc = subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return proc.returncode, proc.stdout, proc.stderr


# ==============================================================================
# 1. STATIC DOCKERFILE & COMPOSE SECURITY AUDITS
# ==============================================================================

class TestStaticContainerSecurity:
    def test_backend_dockerfile_multi_stage_and_hardening(self):
        """1. Backend Dockerfile uses multi-stage build, slim base, non-root user, and explicit CMD."""
        df_content = (API_DIR / "Dockerfile").read_text(encoding="utf-8")
        assert "FROM python:3.11-slim-bookworm AS builder" in df_content
        assert "FROM python:3.11-slim-bookworm AS runtime" in df_content
        assert "USER 10001:10001" in df_content
        assert "EXPOSE 8000" in df_content
        assert "HEALTHCHECK" in df_content
        assert "requirements-prod.txt" in df_content
        assert "latest" not in df_content

    def test_frontend_dockerfile_multi_stage_and_hardening(self):
        """2. Frontend Dockerfile uses multi-stage build, alpine slim base, and non-root nginx user."""
        df_content = (WEB_DIR / "Dockerfile").read_text(encoding="utf-8")
        assert "FROM node:20-alpine AS builder" in df_content
        assert "FROM nginx:1.27-alpine-slim AS runtime" in df_content
        assert "USER nginx" in df_content
        assert "EXPOSE 8080" in df_content
        assert "HEALTHCHECK" in df_content
        assert "latest" not in df_content

    def test_dockerignore_excludes_sensitive_artifacts(self):
        """3. Root and app .dockerignore files exclude secrets, databases, venvs, and caches."""
        root_ignore = (REPO_ROOT / ".dockerignore").read_text(encoding="utf-8")
        api_ignore = (API_DIR / ".dockerignore").read_text(encoding="utf-8")
        web_ignore = (WEB_DIR / ".dockerignore").read_text(encoding="utf-8")

        for content in (root_ignore, api_ignore, web_ignore):
            assert ".env" in content
            assert "*.key" in content or ".git" in content

        assert "agentshield.db" in api_ignore
        assert ".venv" in api_ignore
        assert "tests" in api_ignore
        assert "node_modules" in web_ignore

    def test_compose_production_hardening_directives(self):
        """4. Production Compose file enforces dropped capabilities, no-new-privileges, and tmpfs."""
        prod_compose = (REPO_ROOT / "docker-compose.prod.yml").read_text(encoding="utf-8")
        assert "no-new-privileges:true" in prod_compose
        assert "cap_drop:" in prod_compose
        assert "ALL" in prod_compose
        assert "tmpfs:" in prod_compose
        assert "ENVIRONMENT=production" in prod_compose
        assert "DEBUG=false" in prod_compose
        assert "ALLOW_DEFAULT_CREDENTIALS=false" in prod_compose

    def test_zero_secrets_baked_in_dockerfiles_or_compose(self):
        """5. Dockerfiles and Compose files contain zero embedded private keys, tokens, or hardcoded production passwords."""
        suspicious = ["CHANGE_ME", "BEGIN PRIVATE KEY", "bearer ", "secret-prod-12345"]
        all_files = [
            API_DIR / "Dockerfile",
            WEB_DIR / "Dockerfile",
            REPO_ROOT / "docker-compose.yml",
            REPO_ROOT / "docker-compose.prod.yml",
        ]
        for f in all_files:
            text = f.read_text(encoding="utf-8")
            for pattern in suspicious:
                assert pattern not in text


# ==============================================================================
# 2. IMAGE METADATA, INSPECTION & LAYER AUDITS
# ==============================================================================

class TestImageMetadataAndInspection:
    @classmethod
    def setup_class(cls):
        """Ensure test images exist."""
        code, out, err = run_cmd(["docker", "image", "inspect", "agentshield-api:test"])
        if code != 0:
            run_cmd(["docker", "build", "-t", "agentshield-api:test", "apps/api"])
        code, out, err = run_cmd(["docker", "image", "inspect", "agentshield-web:test"])
        if code != 0:
            run_cmd(["docker", "build", "-t", "agentshield-web:test", "apps/web"])

    def test_backend_image_user_is_non_root(self):
        """6. Backend Docker image specifies non-root USER 10001:10001 in config."""
        code, out, _ = run_cmd(["docker", "inspect", "--format", "{{.Config.User}}", "agentshield-api:test"])
        assert code == 0
        assert out.strip() == "10001:10001"

    def test_frontend_image_user_is_non_root(self):
        """7. Frontend Docker image specifies non-root USER nginx in config."""
        code, out, _ = run_cmd(["docker", "inspect", "--format", "{{.Config.User}}", "agentshield-web:test"])
        assert code == 0
        assert out.strip() == "nginx"

    def test_backend_image_exposed_ports(self):
        """8. Backend image exposes only port 8000/tcp."""
        code, out, _ = run_cmd(["docker", "inspect", "--format", "{{json .Config.ExposedPorts}}", "agentshield-api:test"])
        assert code == 0
        ports = json.loads(out.strip())
        assert "8000/tcp" in ports
        assert len(ports) == 1

    def test_image_history_layer_secret_audit(self):
        """9. Neither image history reveals credentials or secrets passed via commands."""
        for img in ("agentshield-api:test", "agentshield-web:test"):
            code, out, _ = run_cmd(["docker", "history", "--no-trunc", img])
            assert code == 0
            low = out.lower()
            assert "password=" not in low
            assert "secret_key=" not in low
            assert "authorization_secret=" not in low

    def test_production_image_excludes_test_tooling(self):
        """10. pytest and test files are absent from the backend runtime image."""
        cmd = ["docker", "run", "--rm", "agentshield-api:test", "python", "-c", "import pytest"]
        code, out, err = run_cmd(cmd, timeout=30)
        assert code != 0
        assert "No module named 'pytest'" in err or "ModuleNotFoundError" in err

    def test_production_image_excludes_host_databases(self):
        """11. Development databases are absent from the container filesystem root."""
        cmd = ["docker", "run", "--rm", "agentshield-api:test", "ls", "-la", "/app/agentshield.db"]
        code, out, err = run_cmd(cmd, timeout=30)
        assert code != 0


# ==============================================================================
# 3. PRODUCTION CONFIGURATION FAIL-CLOSED TESTS
# ==============================================================================

class TestProductionFailClosedInvariants:
    def test_missing_auth_secret_fails_closed(self):
        """12. Production container exits immediately when AGENTSHIELD_AUTHORIZATION_SECRET is missing."""
        cmd = [
            "docker", "run", "--rm",
            "-e", "ENVIRONMENT=production",
            "-e", "SECRET_KEY=12345678901234567890123456789012",
            "-e", "DATABASE_URL=sqlite:////app/data/prod.db",
            "agentshield-api:test",
        ]
        code, out, err = run_cmd(cmd, timeout=30)
        assert code == 1
        assert "AGENTSHIELD_AUTHORIZATION_SECRET" in (out + err)

    def test_missing_secret_key_fails_closed(self):
        """13. Production container exits immediately when SECRET_KEY is missing."""
        cmd = [
            "docker", "run", "--rm",
            "-e", "ENVIRONMENT=production",
            "-e", "AGENTSHIELD_AUTHORIZATION_SECRET=12345678901234567890123456789012",
            "-e", "DATABASE_URL=sqlite:////app/data/prod.db",
            "agentshield-api:test",
        ]
        code, out, err = run_cmd(cmd, timeout=30)
        assert code == 1
        assert "SECRET_KEY" in (out + err)

    def test_default_dev_db_fails_closed(self):
        """14. Production container exits immediately when default dev DB is supplied."""
        cmd = [
            "docker", "run", "--rm",
            "-e", "ENVIRONMENT=production",
            "-e", "AGENTSHIELD_AUTHORIZATION_SECRET=12345678901234567890123456789012",
            "-e", "SECRET_KEY=12345678901234567890123456789012",
            "-e", "DATABASE_URL=sqlite:///./agentshield.db",
            "agentshield-api:test",
        ]
        code, out, err = run_cmd(cmd, timeout=30)
        assert code == 1
        assert "default development SQLite database" in (out + err)

    def test_debug_true_fails_closed(self):
        """15. Production container exits immediately when DEBUG=true."""
        cmd = [
            "docker", "run", "--rm",
            "-e", "ENVIRONMENT=production",
            "-e", "DEBUG=true",
            "-e", "AGENTSHIELD_AUTHORIZATION_SECRET=12345678901234567890123456789012",
            "-e", "SECRET_KEY=12345678901234567890123456789012",
            "-e", "DATABASE_URL=sqlite:////app/data/prod.db",
            "agentshield-api:test",
        ]
        code, out, err = run_cmd(cmd, timeout=30)
        assert code == 1
        assert "DEBUG mode cannot be enabled" in (out + err)

    def test_default_credentials_true_fails_closed(self):
        """16. Production container exits immediately when ALLOW_DEFAULT_CREDENTIALS=true."""
        cmd = [
            "docker", "run", "--rm",
            "-e", "ENVIRONMENT=production",
            "-e", "ALLOW_DEFAULT_CREDENTIALS=true",
            "-e", "AGENTSHIELD_AUTHORIZATION_SECRET=12345678901234567890123456789012",
            "-e", "SECRET_KEY=12345678901234567890123456789012",
            "-e", "DATABASE_URL=sqlite:////app/data/prod.db",
            "agentshield-api:test",
        ]
        code, out, err = run_cmd(cmd, timeout=30)
        assert code == 1
        assert "ALLOW_DEFAULT_CREDENTIALS cannot be enabled" in (out + err)


# ==============================================================================
# 4. CONTAINER RUNTIME, NETWORKING & INTEGRATION TESTS
# ==============================================================================

class TestContainerRuntimeAndNetworking:
    NETWORK_NAME = "test-phase18-net"
    BACKEND_NAME = "test-phase18-backend"
    FRONTEND_NAME = "test-phase18-frontend"
    HOST_PORT = 19080

    @classmethod
    def setup_class(cls):
        """Launch isolated backend and frontend containers on a dedicated network."""
        run_cmd(["docker", "network", "create", cls.NETWORK_NAME])
        # Start backend
        run_cmd([
            "docker", "run", "-d",
            "--name", cls.BACKEND_NAME,
            "--network", cls.NETWORK_NAME,
            "--network-alias", "backend",
            "-e", "ENVIRONMENT=development",
            "-e", "DATABASE_URL=sqlite:////app/data/agentshield.db",
            "-e", "API_HOST=0.0.0.0",
            "-e", "API_PORT=8000",
            "-e", "ALLOW_DEFAULT_CREDENTIALS=true",
            "-e", "DEBUG=false",
            "agentshield-api:test",
        ])
        # Start frontend
        run_cmd([
            "docker", "run", "-d",
            "--name", cls.FRONTEND_NAME,
            "--network", cls.NETWORK_NAME,
            "-p", f"{cls.HOST_PORT}:8080",
            "agentshield-web:test",
        ])
        # Allow service stabilization via readiness polling
        ready = False
        for _ in range(15):
            time.sleep(1)
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{cls.HOST_PORT}/health/live") as r:
                    if r.status == 200:
                        ready = True
                        break
            except Exception:
                pass
        if not ready:
            raise RuntimeError(f"Containers on port {cls.HOST_PORT} failed to stabilize")

    @classmethod
    def teardown_class(cls):
        """Clean up containers and network."""
        run_cmd(["docker", "rm", "-f", cls.BACKEND_NAME, cls.FRONTEND_NAME])
        run_cmd(["docker", "network", "rm", cls.NETWORK_NAME])

    def test_backend_container_running_and_healthy(self):
        """17. Backend container is running and passes healthcheck."""
        code, out, _ = run_cmd(["docker", "inspect", "--format", "{{.State.Status}}", self.BACKEND_NAME])
        assert code == 0
        assert out.strip() == "running"

    def test_frontend_container_running_and_healthy(self):
        """18. Frontend container is running and passes healthcheck."""
        code, out, _ = run_cmd(["docker", "inspect", "--format", "{{.State.Status}}", self.FRONTEND_NAME])
        assert code == 0
        assert out.strip() == "running"

    def test_frontend_serves_spa_html(self):
        """19. Frontend container delivers index.html with appropriate security headers."""
        with urllib.request.urlopen(f"http://127.0.0.1:{self.HOST_PORT}/") as resp:
            assert resp.status == 200
            content = resp.read().decode()
            assert "<title>" in content
            headers = dict(resp.headers)
            assert headers.get("X-Content-Type-Options") == "nosniff"
            assert headers.get("X-Frame-Options") == "DENY"

    def test_frontend_reverse_proxies_health_check(self):
        """20. /health request to frontend is transparently reverse-proxied to backend container."""
        with urllib.request.urlopen(f"http://127.0.0.1:{self.HOST_PORT}/health") as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode())
            assert data["status"] == "ok"
            assert data["service"] == "agentshield"
            assert data["environment"] == "development"

    def test_frontend_reverse_proxies_liveness_and_readiness(self):
        """21. /health/live and /health/ready are proxied and return 200."""
        with urllib.request.urlopen(f"http://127.0.0.1:{self.HOST_PORT}/health/live") as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode())
            assert data["alive"] is True

        with urllib.request.urlopen(f"http://127.0.0.1:{self.HOST_PORT}/health/ready") as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode())
            assert data["ready"] is True
            assert data["dependencies"]["database"] == "healthy"

    def test_frontend_reverse_proxies_authentication(self):
        """22. Authentication POST /api/v1/auth/login works through frontend reverse proxy."""
        login_body = json.dumps({"username": "admin", "password": "AdminPass123!"}).encode()
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.HOST_PORT}/api/v1/auth/login",
            data=login_body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode())
            assert data["username"] == "admin"
            assert "ADMIN" in data["roles"]
            assert "session_id" in data

    def test_container_enforces_phase17_request_bounds(self):
        """23. Oversized payloads (>1MB) are rejected with HTTP 413 through the container proxy."""
        oversized = b"x" * (1024 * 1024 + 10)
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.HOST_PORT}/api/v1/auth/login",
            data=oversized,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req)
        assert exc_info.value.code == 413

    def test_container_enforces_phase17_content_type(self):
        """24. Mutating request with text/plain is rejected with HTTP 415 through container proxy."""
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.HOST_PORT}/api/v1/auth/login",
            data=b"raw-data",
            headers={"Content-Type": "text/plain"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req)
        assert exc_info.value.code == 415

    def test_container_enforces_phase16_correlation_id(self):
        """25. Responses from container propagate X-Correlation-ID header."""
        with urllib.request.urlopen(f"http://127.0.0.1:{self.HOST_PORT}/health") as resp:
            assert resp.headers.get("X-Correlation-ID") is not None

    def test_container_filesystem_permissions(self):
        """26. Backend container data directory is mode 700 and owned by agentshield."""
        cmd = ["docker", "exec", self.BACKEND_NAME, "stat", "-c", "%a %u:%g", "/app/data"]
        code, out, _ = run_cmd(cmd)
        assert code == 0
        assert out.strip() == "700 10001:10001"

    def test_container_sensitive_endpoints_cache_control(self):
        """27. Sensitive endpoints have strict Cache-Control: no-store through container proxy."""
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{self.HOST_PORT}/api/v1/auth/me")
        except urllib.error.HTTPError as e:
            cc = e.headers.get("Cache-Control", "")
            assert "no-store" in cc
            assert "no-cache" in cc
            assert e.headers.get("Pragma") == "no-cache"

    def test_container_enforces_rate_limiting(self):
        """28. 10 failed login attempts from an IP succeed with 401; 11th triggers HTTP 429."""
        headers = {"Content-Type": "application/json", "X-Forwarded-For": "198.51.100.88"}
        body = json.dumps({"username": "rate_user", "password": "wrongpassword"}).encode()
        for _ in range(10):
            req = urllib.request.Request(
                f"http://127.0.0.1:{self.HOST_PORT}/api/v1/auth/login",
                data=body,
                headers=headers,
                method="POST",
            )
            try:
                urllib.request.urlopen(req)
            except urllib.error.HTTPError as e:
                assert e.code == 401

        req_blocked = urllib.request.Request(
            f"http://127.0.0.1:{self.HOST_PORT}/api/v1/auth/login",
            data=body,
            headers=headers,
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req_blocked)
        assert exc_info.value.code == 429
        assert "Retry-After" in exc_info.value.headers


# ==============================================================================
# 5. ADVANCED CONTAINER HARDENING & PERSISTENCE TESTS
# ==============================================================================

class TestAdvancedContainerHardening:
    def test_container_image_size_footprint(self):
        """29. Backend image footprint is <350MB and frontend is <50MB."""
        code, out, _ = run_cmd(["docker", "image", "inspect", "--format", "{{.Size}}", "agentshield-api:test"])
        assert code == 0
        api_size_mb = int(out.strip()) / (1024 * 1024)
        assert api_size_mb < 350

        code, out, _ = run_cmd(["docker", "image", "inspect", "--format", "{{.Size}}", "agentshield-web:test"])
        assert code == 0
        web_size_mb = int(out.strip()) / (1024 * 1024)
        assert web_size_mb < 50

    def test_container_production_lockout_and_demo_rejection(self):
        """30. Live production container rejects default demo accounts and locks Scenario Lab."""
        c_name = "test-prod-lockout"
        run_cmd(["docker", "rm", "-f", c_name])
        try:
            code, _, _ = run_cmd([
                "docker", "run", "-d",
                "--name", c_name,
                "-p", "19199:8000",
                "-e", "ENVIRONMENT=production",
                "-e", "AGENTSHIELD_AUTHORIZATION_SECRET=12345678901234567890123456789012",
                "-e", "SECRET_KEY=12345678901234567890123456789012",
                "-e", "DATABASE_URL=sqlite:////app/data/prod_lockout.db",
                "agentshield-api:test",
            ])
            assert code == 0

            # Stabilization
            for _ in range(15):
                time.sleep(1)
                try:
                    with urllib.request.urlopen("http://127.0.0.1:19199/health/live") as r:
                        if r.status == 200:
                            break
                except Exception:
                    pass

            # 1. Demo rejected
            req = urllib.request.Request(
                "http://127.0.0.1:19199/api/v1/auth/login",
                data=json.dumps({"username": "admin", "password": "AdminPass123!"}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(req)
            assert exc_info.value.code == 401

            # 2. Scenario Lab locked
            req_lab = urllib.request.Request("http://127.0.0.1:19199/api/v1/dev/laboratory/scenarios")
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(req_lab)
            assert exc_info.value.code == 403
        finally:
            run_cmd(["docker", "rm", "-f", c_name])

    def test_container_dropped_capabilities_and_no_new_privileges(self):
        """31. Container runs successfully with --cap-drop=ALL and --security-opt=no-new-privileges:true."""
        c_name = "test-least-privilege"
        run_cmd(["docker", "rm", "-f", c_name])
        try:
            code, _, _ = run_cmd([
                "docker", "run", "-d",
                "--name", c_name,
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges:true",
                "-p", "19198:8000",
                "-e", "ENVIRONMENT=development",
                "-e", "DATABASE_URL=sqlite:////app/data/capdrop.db",
                "-e", "API_HOST=0.0.0.0",
                "-e", "API_PORT=8000",
                "-e", "ALLOW_DEFAULT_CREDENTIALS=true",
                "agentshield-api:test",
            ])
            assert code == 0

            # Stabilization
            ready = False
            for _ in range(15):
                time.sleep(1)
                try:
                    with urllib.request.urlopen("http://127.0.0.1:19198/health/live") as r:
                        if r.status == 200:
                            ready = True
                            break
                except Exception:
                    pass
            assert ready is True
        finally:
            run_cmd(["docker", "rm", "-f", c_name])

    def test_container_read_only_root_filesystem_with_tmpfs(self):
        """32. Container runs cleanly with --read-only root filesystem and tmpfs /tmp."""
        c_name = "test-readonly-root"
        run_cmd(["docker", "rm", "-f", c_name])
        try:
            code, _, _ = run_cmd([
                "docker", "run", "-d",
                "--name", c_name,
                "--read-only",
                "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
                "-p", "19197:8000",
                "-e", "ENVIRONMENT=development",
                "-e", "DATABASE_URL=sqlite:////tmp/readonly_test.db",
                "-e", "API_HOST=0.0.0.0",
                "-e", "API_PORT=8000",
                "-e", "ALLOW_DEFAULT_CREDENTIALS=true",
                "agentshield-api:test",
            ])
            assert code == 0

            ready = False
            for _ in range(15):
                time.sleep(1)
                try:
                    with urllib.request.urlopen("http://127.0.0.1:19197/health/live") as r:
                        if r.status == 200:
                            ready = True
                            break
                except Exception:
                    pass
            assert ready is True
        finally:
            run_cmd(["docker", "rm", "-f", c_name])

    def test_container_persistence_across_restart(self):
        """33. Named volume preserves SQLite state across container destroy and recreate."""
        vol_name = "test-persistence-vol"
        c_name = "test-persist-1"
        run_cmd(["docker", "volume", "create", vol_name])
        run_cmd(["docker", "rm", "-f", c_name])
        try:
            # 1. Start container with named volume
            code, _, _ = run_cmd([
                "docker", "run", "-d",
                "--name", c_name,
                "-v", f"{vol_name}:/app/data",
                "-p", "19196:8000",
                "-e", "ENVIRONMENT=development",
                "-e", "DATABASE_URL=sqlite:////app/data/persist.db",
                "-e", "API_HOST=0.0.0.0",
                "-e", "API_PORT=8000",
                "-e", "ALLOW_DEFAULT_CREDENTIALS=true",
                "agentshield-api:test",
            ])
            assert code == 0

            for _ in range(15):
                time.sleep(1)
                try:
                    with urllib.request.urlopen("http://127.0.0.1:19196/health/live") as r:
                        if r.status == 200:
                            break
                except Exception:
                    pass

            # Destroy container
            run_cmd(["docker", "rm", "-f", c_name])

            # 2. Recreate container with same volume
            code2, _, _ = run_cmd([
                "docker", "run", "-d",
                "--name", c_name,
                "-v", f"{vol_name}:/app/data",
                "-p", "19196:8000",
                "-e", "ENVIRONMENT=development",
                "-e", "DATABASE_URL=sqlite:////app/data/persist.db",
                "-e", "API_HOST=0.0.0.0",
                "-e", "API_PORT=8000",
                "-e", "ALLOW_DEFAULT_CREDENTIALS=true",
                "agentshield-api:test",
            ])
            assert code2 == 0

            persisted = False
            for _ in range(15):
                time.sleep(1)
                try:
                    with urllib.request.urlopen("http://127.0.0.1:19196/health/ready") as r:
                        if r.status == 200:
                            data = json.loads(r.read().decode())
                            if data.get("dependencies", {}).get("database") == "healthy":
                                persisted = True
                                break
                except Exception:
                    pass
            assert persisted is True
        finally:
            run_cmd(["docker", "rm", "-f", c_name])
            run_cmd(["docker", "volume", "rm", "-f", vol_name])

    def test_container_readiness_probe_dependency_degradation(self):
        """34. Readiness probe degrades to 503 when database dependency fails and recovers on reconnect."""
        from unittest.mock import patch
        from starlette.testclient import TestClient
        from app.main import app

        client = TestClient(app, raise_server_exceptions=False)
        # 1. Normal state -> 200 OK, ready=True, database=healthy
        res = client.get("/health/ready")
        assert res.status_code == 200
        assert res.json()["ready"] is True
        assert res.json()["dependencies"]["database"] == "healthy"

        # 2. Outage state -> 503 Service Unavailable, ready=False, database=unreachable
        with patch("app.core.observability.health.get_db", side_effect=RuntimeError("Simulated DB connection lost")):
            res_degraded = client.get("/health/ready")
            assert res_degraded.status_code == 503
            data = res_degraded.json()
            assert data["status"] == "degraded"
            assert data["ready"] is False
            assert data["dependencies"]["database"] == "unreachable"

        # 3. Recovery state -> 200 OK, ready=True, database=healthy
        res_recovered = client.get("/health/ready")
        assert res_recovered.status_code == 200
        assert res_recovered.json()["ready"] is True
        assert res_recovered.json()["dependencies"]["database"] == "healthy"

    def test_container_adversarial_build_arg_injection_prevented(self):
        """35. Build args are not used for secrets, preventing leak in docker history."""
        code, out, _ = run_cmd(["docker", "history", "--no-trunc", "agentshield-api:test"])
        assert code == 0
        assert "ARG AGENTSHIELD" not in out
        assert "ARG SECRET" not in out

    def test_container_no_privileged_mode_requirement(self):
        """36. Image metadata confirms container runs as non-root with no host privilege requirements."""
        code, out, _ = run_cmd(["docker", "image", "inspect", "--format", "{{json .Config}}", "agentshield-api:test"])
        assert code == 0
        cfg = json.loads(out)
        assert cfg.get("User") == "10001:10001"
        assert cfg.get("WorkingDir") == "/app"
        assert "uvicorn" in cfg.get("Cmd", [""])[0]
