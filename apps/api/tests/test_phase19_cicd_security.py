"""
AgentShield Phase 19 — CI/CD & Automated Security Test Suite

Comprehensive automated verification covering:
1. GitHub Actions workflow structure, triggers, permissions, and supply chain pinning
2. Pipeline jobs (Backend, Frontend, Container, Security Audits)
3. Secret scanning engine and failure-gate enforcement
4. Dependency auditing and scoped vulnerability exception handling
5. Static security analysis (CORS, AST checks, Dockerfile invariants, and RBAC coverage)
6. Artifact hygiene, fork PR safety, and branch protection readiness
"""

import sys
import os
import re
import yaml
import tempfile
import subprocess
from pathlib import Path
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
API_DIR = REPO_ROOT / "apps" / "api"
WEB_DIR = REPO_ROOT / "apps" / "web"
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(API_DIR))

from scripts.scan_secrets import scan_file_content, scan_directory, scan_bundle_assets
from scripts.audit_dependencies import audit_frontend, audit_backend, DOCUMENTED_EXCEPTIONS
from scripts.check_static_security import (
    check_python_source_policies,
    check_endpoint_inventory_policy,
    check_docker_and_compose_policies,
    check_workflow_policies,
)
from scripts.extract_endpoint_inventory import get_all_routes


@pytest.fixture(scope="module")
def ci_workflow():
    wf_path = WORKFLOWS_DIR / "ci.yml"
    assert wf_path.is_file(), "ci.yml must exist"
    with open(wf_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f), wf_path.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def security_workflow():
    wf_path = WORKFLOWS_DIR / "security.yml"
    assert wf_path.is_file(), "security.yml must exist"
    with open(wf_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f), wf_path.read_text(encoding="utf-8")


# ==============================================================================
# 1. WORKFLOW STRUCTURE & TRIGGER TESTS
# ==============================================================================

class TestWorkflowStructureAndTriggers:
    def test_ci_workflow_file_exists(self):
        """1. .github/workflows/ci.yml exists."""
        assert (WORKFLOWS_DIR / "ci.yml").is_file()

    def test_security_workflow_file_exists(self):
        """2. .github/workflows/security.yml exists."""
        assert (WORKFLOWS_DIR / "security.yml").is_file()

    def test_ci_workflow_valid_yaml(self, ci_workflow):
        """3. ci.yml parses as valid YAML structure."""
        data, _ = ci_workflow
        assert isinstance(data, dict)
        assert data.get("name") == "AgentShield CI"

    def test_security_workflow_valid_yaml(self, security_workflow):
        """4. security.yml parses as valid YAML structure."""
        data, _ = security_workflow
        assert isinstance(data, dict)
        assert data.get("name") == "AgentShield Security Audits"

    def test_ci_master_push_trigger(self, ci_workflow):
        """5. ci.yml triggers on pushes to master branch."""
        data, _ = ci_workflow
        on_block = data.get("on") or data.get(True) or {}
        assert "master" in on_block.get("push", {}).get("branches", [])

    def test_ci_master_pr_trigger(self, ci_workflow):
        """6. ci.yml triggers on pull requests targeting master."""
        data, _ = ci_workflow
        on_block = data.get("on") or data.get(True) or {}
        assert "master" in on_block.get("pull_request", {}).get("branches", [])

    def test_security_master_push_trigger(self, security_workflow):
        """7. security.yml triggers on pushes to master branch."""
        data, _ = security_workflow
        on_block = data.get("on") or data.get(True) or {}
        assert "master" in on_block.get("push", {}).get("branches", [])

    def test_security_master_pr_trigger(self, security_workflow):
        """8. security.yml triggers on pull requests targeting master."""
        data, _ = security_workflow
        on_block = data.get("on") or data.get(True) or {}
        assert "master" in on_block.get("pull_request", {}).get("branches", [])

    def test_security_weekly_schedule_trigger(self, security_workflow):
        """9. security.yml specifies a weekly scheduled cron trigger."""
        data, _ = security_workflow
        on_block = data.get("on") or data.get(True) or {}
        schedules = on_block.get("schedule", [])
        assert len(schedules) >= 1
        cron = schedules[0].get("cron")
        assert "0 2 * * 1" in cron


# ==============================================================================
# 2. PERMISSIONS & SUPPLY-CHAIN SECURITY TESTS
# ==============================================================================

class TestPermissionsAndSupplyChain:
    def test_ci_global_permissions_least_privilege(self, ci_workflow):
        """10. ci.yml defines top-level permissions restricted to contents: read."""
        data, _ = ci_workflow
        perms = data.get("permissions", {})
        assert perms.get("contents") == "read"
        assert len(perms) == 1

    def test_security_global_permissions_least_privilege(self, security_workflow):
        """11. security.yml defines top-level permissions restricted to contents: read."""
        data, _ = security_workflow
        perms = data.get("permissions", {})
        assert perms.get("contents") == "read"
        assert len(perms) == 1

    def test_workflows_forbid_write_all_permissions(self, ci_workflow, security_workflow):
        """12. Workflows strictly forbid write-all permissions."""
        _, ci_raw = ci_workflow
        _, sec_raw = security_workflow
        assert "write-all" not in ci_raw
        assert "write-all" not in sec_raw

    def test_workflows_forbid_pull_request_target(self, ci_workflow, security_workflow):
        """13. Workflows strictly forbid dangerous pull_request_target triggers."""
        _, ci_raw = ci_workflow
        _, sec_raw = security_workflow
        assert "pull_request_target" not in ci_raw
        assert "pull_request_target" not in sec_raw

    def test_actions_are_sha_pinned(self, ci_workflow, security_workflow):
        """14. All third-party action invocations are pinned to 40-character commit SHAs."""
        _, ci_raw = ci_workflow
        _, sec_raw = security_workflow
        combined = ci_raw + "\n" + sec_raw
        action_refs = re.findall(r"uses:\s*([^@\s]+)@([^\s#]+)", combined)
        assert len(action_refs) >= 5
        sha_regex = re.compile(r"^[0-9a-f]{40}$")
        for name, ref in action_refs:
            assert sha_regex.match(ref), f"Action {name}@{ref} must be pinned to 40-char SHA"

    def test_no_floating_action_versions(self, ci_workflow, security_workflow):
        """15. No actions reference unpinned floating branch tags (@main, @master, @latest)."""
        _, ci_raw = ci_workflow
        _, sec_raw = security_workflow
        combined = ci_raw + "\n" + sec_raw
        floating = re.findall(r"uses:\s*[^@\s]+@(main|master|latest)\b", combined)
        assert len(floating) == 0, f"Discovered floating action references: {floating}"

    def test_no_arbitrary_curl_pipe_sh(self, ci_workflow, security_workflow):
        """16. Workflows do not execute unverified curl|sh or wget|bash installers."""
        _, ci_raw = ci_workflow
        _, sec_raw = security_workflow
        combined = ci_raw + "\n" + sec_raw
        assert not re.search(r"curl\s+[^|]+\|\s*(sh|bash)", combined)
        assert not re.search(r"wget\s+[^|]+\|\s*(sh|bash)", combined)


# ==============================================================================
# 3. PIPELINE JOBS & PHASE REGRESSION INTEGRATION
# ==============================================================================

class TestPipelineJobsAndRegressionWiring:
    def test_ci_backend_job_configured(self, ci_workflow):
        """17. ci.yml includes backend job running on ubuntu-latest."""
        data, _ = ci_workflow
        jobs = data.get("jobs", {})
        assert "backend" in jobs
        assert jobs["backend"].get("runs-on") == "ubuntu-latest"

    def test_ci_frontend_job_configured(self, ci_workflow):
        """18. ci.yml includes frontend job running on ubuntu-latest."""
        data, _ = ci_workflow
        jobs = data.get("jobs", {})
        assert "frontend" in jobs
        assert jobs["frontend"].get("runs-on") == "ubuntu-latest"

    def test_ci_container_job_configured(self, ci_workflow):
        """19. ci.yml includes container job running on ubuntu-latest."""
        data, _ = ci_workflow
        jobs = data.get("jobs", {})
        assert "container" in jobs
        assert jobs["container"].get("runs-on") == "ubuntu-latest"

    def test_security_secret_scan_job_configured(self, security_workflow):
        """20. security.yml includes secret-scan job."""
        data, _ = security_workflow
        jobs = data.get("jobs", {})
        assert "secret-scan" in jobs

    def test_security_dependency_audit_job_configured(self, security_workflow):
        """21. security.yml includes dependency-audit job."""
        data, _ = security_workflow
        jobs = data.get("jobs", {})
        assert "dependency-audit" in jobs

    def test_security_static_security_job_configured(self, security_workflow):
        """22. security.yml includes static-security job."""
        data, _ = security_workflow
        jobs = data.get("jobs", {})
        assert "static-security" in jobs

    def test_backend_job_runs_pytest(self, ci_workflow):
        """23. Backend job executes pytest across test suite."""
        _, raw = ci_workflow
        assert "pytest -q apps/api/tests" in raw

    def test_backend_job_runs_phase14_acceptance(self, ci_workflow):
        """24. Backend job executes Phase 14 acceptance verification."""
        _, raw = ci_workflow
        assert "scripts/verify_phase14_acceptance.py" in raw

    def test_backend_job_runs_phase15_acceptance(self, ci_workflow):
        """25. Backend job executes Phase 15 acceptance verification."""
        _, raw = ci_workflow
        assert "scripts/verify_phase15_acceptance.py" in raw

    def test_backend_job_runs_phase16_observability(self, ci_workflow):
        """26. Backend job executes Phase 16 observability verification."""
        _, raw = ci_workflow
        assert "scripts/verify_phase16.py" in raw

    def test_backend_job_runs_phase17_hardening(self, ci_workflow):
        """27. Backend job executes Phase 17 hardening verification."""
        _, raw = ci_workflow
        assert "scripts/verify_phase17.py" in raw

    def test_backend_job_runs_phase19_security(self, ci_workflow):
        """28. Backend job executes Phase 19 independent security verification."""
        _, raw = ci_workflow
        assert "scripts/verify_phase19.py" in raw

    def test_frontend_job_runs_npm_test(self, ci_workflow):
        """29. Frontend job runs npm test -- --run."""
        _, raw = ci_workflow
        assert "npm test -- --run" in raw

    def test_frontend_job_runs_production_build(self, ci_workflow):
        """30. Frontend job runs production build (tsc && vite build)."""
        _, raw = ci_workflow
        assert "npm run build" in raw

    def test_frontend_job_runs_bundle_secret_scan(self, ci_workflow):
        """31. Frontend job runs bundle secret scanner on dist assets."""
        _, raw = ci_workflow
        assert "scan_secrets.py --include-dist" in raw

    def test_container_job_builds_api_and_web(self, ci_workflow):
        """32. Container job builds both API and Web Docker images."""
        _, raw = ci_workflow
        assert "docker build -t agentshield-api:test apps/api" in raw
        assert "docker build -t agentshield-web:test apps/web" in raw

    def test_container_job_runs_phase18_independent_verification(self, ci_workflow):
        """33. Container job executes scripts/verify_phase18.py."""
        _, raw = ci_workflow
        assert "scripts/verify_phase18.py" in raw


# ==============================================================================
# 4. AUTOMATED SECRET SCANNER & FAILURE GATES
# ==============================================================================

class TestSecretScannerAndFailureGates:
    def test_secret_scanner_clean_on_repository(self):
        """34. Automated secret scanner confirms zero leaks on repository."""
        findings = scan_directory(REPO_ROOT)
        assert len(findings) == 0

    def test_secret_scanner_detects_rsa_private_key_fixture(self):
        """35. Secret scanner detects unencrypted RSA private key block."""
        with tempfile.NamedTemporaryFile("w", suffix=".key", delete=False) as tf:
            tf.write("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n")
            path = Path(tf.name)
        try:
            findings = scan_file_content(path)
            assert any(f["rule_id"] == "SEC-01-PRIVATE-KEY" for f in findings)
        finally:
            os.remove(path)

    def test_secret_scanner_detects_ec_private_key_fixture(self):
        """36. Secret scanner detects unencrypted EC private key block."""
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as tf:
            tf.write("-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEI...\n-----END EC PRIVATE KEY-----\n")
            path = Path(tf.name)
        try:
            findings = scan_file_content(path)
            assert any(f["rule_id"] == "SEC-01-PRIVATE-KEY" for f in findings)
        finally:
            os.remove(path)

    def test_secret_scanner_detects_aws_key_fixture(self):
        """37. Secret scanner detects high-entropy AWS access key format."""
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as tf:
            tf.write('AWS_KEY = "AKIA1234567890ABCDEF"\n')
            path = Path(tf.name)
        try:
            findings = scan_file_content(path)
            assert any(f["rule_id"] == "SEC-02-AWS-KEY" for f in findings)
        finally:
            os.remove(path)

    def test_secret_scanner_detects_api_token_fixture(self):
        """38. Secret scanner detects provider API keys (OpenAI / GitHub format)."""
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as tf:
            tf.write('OPENAI_KEY = "sk-live998877665544332211aabbccddeeff"\n')
            path = Path(tf.name)
        try:
            findings = scan_file_content(path)
            assert any(f["rule_id"] == "SEC-03-API-TOKEN" for f in findings)
        finally:
            os.remove(path)

    def test_secret_scanner_detects_credential_bearing_database_url(self):
        """39. Secret scanner detects connection strings with embedded passwords."""
        with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False) as tf:
            tf.write('DATABASE_URL=postgresql://dbuser:MyRealSecretPass999@db.prod.internal:5432/app\n')
            path = Path(tf.name)
        try:
            findings = scan_file_content(path)
            assert any(f["rule_id"] == "SEC-04-CONN-STRING-CREDS" for f in findings)
        finally:
            os.remove(path)

    def test_secret_scanner_allows_safe_placeholders(self):
        """40. Secret scanner ignores documented synthetic placeholders and templates."""
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as tf:
            tf.write('DATABASE_URL=postgresql://user:placeholder@host:5432/db\n')
            tf.write('API_KEY=sk-proj-TEST-SECRET-DO-NOT-LEAK\n')
            tf.write('AWS_KEY=AKIAIOSFODNN7EXAMPLE\n')
            path = Path(tf.name)
        try:
            findings = scan_file_content(path)
            assert len(findings) == 0
        finally:
            os.remove(path)

    def test_secret_scanner_never_prints_matched_secret_value(self):
        """41. Secret scanner output never echoes matched raw secret material."""
        secret_token = "sk-live0000000000000000000000000000"
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as tf:
            tf.write(f'TOKEN = "{secret_token}"\n')
            path = Path(tf.name)
        try:
            res = subprocess.run(
                [sys.executable, str(REPO_ROOT / "scripts" / "scan_secrets.py"), "--target", str(path)],
                capture_output=True,
                text=True
            )
            assert res.returncode != 0
            assert secret_token not in res.stdout
            assert secret_token not in res.stderr
        finally:
            os.remove(path)

    def test_secret_scanner_flags_accidental_env_files(self):
        """42. Secret scanner detects accidental committed .env secret files."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / ".env.production"
            path.write_text("SECRET_KEY=12345678901234567890123456789012\n", encoding="utf-8")
            findings = scan_file_content(path)
            assert any(f["rule_id"] == "SEC-05-ACCIDENTAL-ENV" for f in findings)

    def test_bundle_scanner_detects_demo_credentials_in_bundle(self):
        """43. Bundle scanner detects leaked demo credentials in production JS assets."""
        with tempfile.TemporaryDirectory() as td:
            assets_dir = Path(td) / "assets"
            assets_dir.mkdir(parents=True)
            js_file = assets_dir / "app.js"
            js_file.write_text('const cred = "AdminPass123!";', encoding="utf-8")
            findings = scan_bundle_assets(Path(td))
            assert len(findings) >= 1
            assert findings[0]["rule_id"] == "SEC-06-BUNDLE-LEAK"


# ==============================================================================
# 5. DEPENDENCY AUDITING & VULNERABILITY POLICY
# ==============================================================================

class TestDependencyAuditingPolicy:
    def test_dependency_auditor_clean_production_dependencies(self):
        """44. Dependency auditor confirms zero high/critical vulns in production dependencies."""
        passed, errors, warnings = audit_frontend()
        assert passed is True
        assert len(errors) == 0

    def test_dependency_auditor_verifies_documented_exceptions(self):
        """45. All documented vulnerability exceptions define package, reason, and review date."""
        assert len(DOCUMENTED_EXCEPTIONS) >= 2
        for adv_id, exc in DOCUMENTED_EXCEPTIONS.items():
            assert "package" in exc
            assert "reason" in exc
            assert "review_date" in exc
            assert "scope" in exc
            assert exc["scope"] == "devDependencies"

    def test_backend_dependency_requirements_baseline(self):
        """46. Backend dependency specification satisfies baseline requirements."""
        passed, errors, _ = audit_backend()
        assert passed is True
        assert len(errors) == 0


# ==============================================================================
# 6. STATIC SECURITY ANALYSIS & ENDPOINT INVENTORY
# ==============================================================================

class TestStaticSecurityAndEndpointInventory:
    def test_static_policy_verifies_python_source_integrity(self):
        """47. Static analysis confirms zero eval, exec, or pickle in backend source."""
        violations, checks = check_python_source_policies()
        assert len(violations) == 0
        assert len(checks) >= 2

    def test_static_policy_verifies_cors_wildcard_protection(self):
        """48. CORS policy forbids allow_origins=['*'] with allow_credentials=True."""
        settings_path = API_DIR / "app" / "config" / "settings.py"
        content = settings_path.read_text(encoding="utf-8")
        assert not ('allow_origins=["*"]' in content and "allow_credentials=True" in content)

    def test_static_policy_verifies_dockerfile_non_root_user(self):
        """49. Dockerfiles configure non-root runtime users."""
        violations, checks = check_docker_and_compose_policies()
        assert len(violations) == 0
        assert any("Non-root user" in c for c in checks)

    def test_static_policy_verifies_dockerfile_healthcheck(self):
        """50. Dockerfiles define explicit HEALTHCHECK directives."""
        violations, checks = check_docker_and_compose_policies()
        assert len(violations) == 0
        assert any("healthcheck" in c.lower() for c in checks)

    def test_static_policy_verifies_production_compose_hardening(self):
        """51. Production Compose enforces read_only root, cap-drop ALL, and no-new-privileges."""
        violations, checks = check_docker_and_compose_policies()
        assert len(violations) == 0
        assert any("read-only root, cap-drop ALL" in c for c in checks)

    def test_static_policy_detects_unpinned_action_fixture(self):
        """52. Static policy failure gate: detects and rejects floating action version (@master)."""
        with tempfile.TemporaryDirectory() as td:
            bad_wf = Path(td) / "bad.yml"
            bad_wf.write_text("name: Bad\npermissions:\n  contents: read\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@master\n", encoding="utf-8")
            import scripts.check_static_security
            orig_dir = scripts.check_static_security.WORKFLOWS_DIR
            scripts.check_static_security.WORKFLOWS_DIR = Path(td)
            try:
                violations, _ = check_workflow_policies()
                assert any("unpinned floating action" in v for v in violations)
            finally:
                scripts.check_static_security.WORKFLOWS_DIR = orig_dir

    def test_static_policy_detects_excessive_write_permissions_fixture(self):
        """53. Static policy failure gate: detects and rejects excessive permissions (write-all)."""
        with tempfile.TemporaryDirectory() as td:
            bad_wf = Path(td) / "bad.yml"
            bad_wf.write_text("name: Bad\npermissions: write-all\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n", encoding="utf-8")
            import scripts.check_static_security
            orig_dir = scripts.check_static_security.WORKFLOWS_DIR
            scripts.check_static_security.WORKFLOWS_DIR = Path(td)
            try:
                violations, _ = check_workflow_policies()
                assert any("excessive permissions: write-all" in v for v in violations)
            finally:
                scripts.check_static_security.WORKFLOWS_DIR = orig_dir

    def test_endpoint_inventory_generation_succeeds(self):
        """54. Endpoint inventory extracts registered application routes."""
        routes = get_all_routes()
        assert len(routes) >= 20

    def test_endpoint_inventory_all_security_routes_authenticated(self):
        """55. 100% of sensitive security and authorization routes require authentication."""
        routes = get_all_routes()
        sec_routes = [r for r in routes if r["path"].startswith("/api/v1/security/")]
        assert len(sec_routes) >= 10
        assert all(r["auth_required"] for r in sec_routes)

    def test_endpoint_inventory_approval_mutation_requires_permission(self):
        """56. Approval mutation endpoints require RESOLVE_APPROVALS or CANCEL_APPROVAL permission."""
        routes = get_all_routes()
        mutation_routes = [r for r in routes if r["path"].startswith("/api/v1/security/approvals/") and r["method"] == "POST"]
        assert len(mutation_routes) >= 2
        for r in mutation_routes:
            assert r["permission_required"] in ("RESOLVE_APPROVALS", "CANCEL_APPROVAL")


# ==============================================================================
# 7. ARTIFACT HYGIENE & BRANCH PROTECTION READINESS
# ==============================================================================

class TestArtifactHygieneAndBranchProtection:
    def test_git_tracked_files_contain_no_env_or_db(self):
        """57. Git-tracked files contain zero .env secrets or SQLite database files."""
        res = subprocess.run(["git", "ls-files"], cwd=str(REPO_ROOT), capture_output=True, text=True)
        files = res.stdout.splitlines()
        bad_files = [f for f in files if f.endswith(".env") or f.endswith(".db") or f.endswith(".sqlite")]
        assert len(bad_files) == 0, f"Discovered untracked secrets in git index: {bad_files}"

    def test_ci_documentation_recommends_strict_branch_protection(self):
        """58. docs/CI_SECURITY.md documents strict branch protection requirements."""
        doc_path = REPO_ROOT / "docs" / "CI_SECURITY.md"
        assert doc_path.is_file()
        content = doc_path.read_text(encoding="utf-8")
        assert "Recommended Branch Protection Configuration" in content
        assert "Require a pull request before merging" in content
        assert "Require status checks to pass before merging" in content
        assert "Block direct pushes" in content

    def test_ci_pipeline_requires_zero_external_secrets(self, ci_workflow, security_workflow):
        """59. Workflows require zero external secrets (secrets.XYZ) for pull request execution."""
        _, ci_raw = ci_workflow
        _, sec_raw = security_workflow
        combined = ci_raw + "\n" + sec_raw
        secret_refs = re.findall(r"\${{\s*secrets\.[A-Za-z0-9_]+\s*}}", combined)
        assert len(secret_refs) == 0, f"Discovered external secret dependencies: {secret_refs}"

    def test_supply_chain_python_and_node_versions_declared(self, ci_workflow):
        """60. Workflows explicitly declare production Python 3.11 and Node 20 versions."""
        _, raw = ci_workflow
        assert 'python-version: "3.11"' in raw
        assert 'node-version: "20"' in raw
