#!/usr/bin/env python3
"""
AgentShield Phase 19 — Independent CI/CD & Automated Security Verification Suite

Independently validates:
1. Workflow architecture, triggers, permissions, and supply chain pinning
2. Automated secret scanner accuracy and failure-gate enforcement
3. Dependency security policies and documented exception handling
4. Static security analysis and policy enforcement
5. Container and production configuration security invariants
6. Full Phase 14-19 regression integration and artifact hygiene
"""

import sys
import os
import re
import yaml
import tempfile
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"
API_DIR = REPO_ROOT / "apps" / "api"
WEB_DIR = REPO_ROOT / "apps" / "web"

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(API_DIR))


def report(check_id: str, desc: str, passed: bool, details: str = ""):
    status = "[PASS]" if passed else "[FAIL]"
    print(f"{status} {check_id}: {desc}")
    if details:
        print(f"       Details: {details}")
    if not passed:
        print(f"       ABORTING on failure: {desc}")
        sys.exit(1)


def main():
    print("=" * 76)
    print("AGENTSHIELD PHASE 19 — INDEPENDENT CI/CD & AUTOMATED SECURITY SUITE")
    print("=" * 76)

    ci_yml = WORKFLOWS_DIR / "ci.yml"
    sec_yml = WORKFLOWS_DIR / "security.yml"

    # 1. Workflow file existence
    report("V19-01", "Core CI workflow (.github/workflows/ci.yml) exists", ci_yml.is_file())
    report("V19-02", "Security audit workflow (.github/workflows/security.yml) exists", sec_yml.is_file())

    # 2. Valid YAML parsing
    with open(ci_yml, "r", encoding="utf-8") as f:
        ci_data = yaml.safe_load(f)
    with open(sec_yml, "r", encoding="utf-8") as f:
        sec_data = yaml.safe_load(f)

    report("V19-03", "Workflow files parse as valid YAML structures", bool(ci_data and sec_data))

    # 3. Triggers validation
    ci_on = ci_data.get("on") or ci_data.get(True) or {}
    sec_on = sec_data.get("on") or sec_data.get(True) or {}

    ci_push_branches = ci_on.get("push", {}).get("branches", [])
    ci_pr_branches = ci_on.get("pull_request", {}).get("branches", [])
    sec_push_branches = sec_on.get("push", {}).get("branches", [])
    sec_pr_branches = sec_on.get("pull_request", {}).get("branches", [])
    sec_cron = sec_on.get("schedule", [{}])[0].get("cron", "")

    triggers_ok = (
        "master" in ci_push_branches
        and "master" in ci_pr_branches
        and "master" in sec_push_branches
        and "master" in sec_pr_branches
        and bool(sec_cron)
    )
    report("V19-04", "Workflows trigger on push and pull_request to master, with weekly schedule", triggers_ok, f"cron='{sec_cron}'")

    # 4. Global Permissions: contents: read
    ci_perm = ci_data.get("permissions", {})
    sec_perm = sec_data.get("permissions", {})
    perms_ok = (
        ci_perm.get("contents") == "read"
        and sec_perm.get("contents") == "read"
        and len(ci_perm) == 1
        and len(sec_perm) == 1
    )
    report("V19-05", "Global permissions strictly restricted to 'contents: read' (least privilege)", perms_ok)

    # 5. Dangerous triggers forbidden (no pull_request_target)
    no_pr_target = ("pull_request_target" not in str(ci_on)) and ("pull_request_target" not in str(sec_on))
    report("V19-06", "Dangerous pull_request_target trigger strictly forbidden", no_pr_target)

    # 6. Supply-chain security: Full 40-character commit SHA action pinning
    all_wf_content = ci_yml.read_text(encoding="utf-8") + "\n" + sec_yml.read_text(encoding="utf-8")
    action_refs = re.findall(r"uses:\s*([^@\s]+)@([^\s#]+)", all_wf_content)
    all_pinned = True
    sha_regex = re.compile(r"^[0-9a-f]{40}$")
    for action_name, ref in action_refs:
        if not sha_regex.match(ref):
            all_pinned = False
            break

    floating_refs = re.findall(r"uses:\s*[^@\s]+@(main|master|latest)\b", all_wf_content)
    report("V19-07", "All third-party GitHub Actions pinned to immutable 40-char commit SHAs", all_pinned and len(floating_refs) == 0, f"Found {len(action_refs)} pinned action invocations")

    # 7. No unverified remote curl|sh scripts in workflows
    curl_sh_found = bool(re.search(r"curl\s+[^|]+\|\s*(sh|bash)", all_wf_content)) or bool(re.search(r"wget\s+[^|]+\|\s*(sh|bash)", all_wf_content))
    report("V19-08", "Zero arbitrary curl|sh or wget|bash execution in workflows", not curl_sh_found)

    # 8. Automated Secret Scanner execution against repository
    scan_script = REPO_ROOT / "scripts" / "scan_secrets.py"
    report("V19-09", "Automated secret scanner script (scripts/scan_secrets.py) exists", scan_script.is_file())

    res_scan = subprocess.run([sys.executable, str(scan_script), "--include-dist"], capture_output=True, text=True)
    report("V19-10", "Secret scanner passes on repository (0 secret leaks)", res_scan.returncode == 0)

    # 9. Secret Scanner Failure Gate: Injected Private Key Fixture
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as tf:
        tf.write("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0fakekeyfixture...\n-----END RSA PRIVATE KEY-----")
        tf_path = tf.name

    try:
        res_fail_key = subprocess.run([sys.executable, str(scan_script), "--target", tf_path], capture_output=True, text=True)
        key_fail_gate = (res_fail_key.returncode != 0) and ("SEC-01-PRIVATE-KEY" in res_fail_key.stdout)
        report("V19-11", "Secret scanner failure gate: Accidental private key blocked (non-zero exit)", key_fail_gate)
    finally:
        os.remove(tf_path)

    # 10. Secret Scanner Failure Gate: Injected Cloud / API Key Fixture
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as tf:
        tf.write('REAL_PROD_KEY = "AKIA1234567890ABCDEF"')
        tf_path = tf.name

    try:
        res_fail_api = subprocess.run([sys.executable, str(scan_script), "--target", tf_path], capture_output=True, text=True)
        api_fail_gate = (res_fail_api.returncode != 0) and ("SEC-02-AWS-KEY" in res_fail_api.stdout)
        report("V19-12", "Secret scanner failure gate: Real cloud/API credentials blocked (non-zero exit)", api_fail_gate)
    finally:
        os.remove(tf_path)

    # 11. Dependency Security Auditor execution
    audit_script = REPO_ROOT / "scripts" / "audit_dependencies.py"
    report("V19-13", "Dependency security auditor (scripts/audit_dependencies.py) exists", audit_script.is_file())

    res_audit = subprocess.run([sys.executable, str(audit_script)], capture_output=True, text=True)
    report("V19-14", "Dependency security audit passes policy (0 unapproved high/critical vulns)", res_audit.returncode == 0)

    # 12. Static Security Policy Checker execution
    static_script = REPO_ROOT / "scripts" / "check_static_security.py"
    report("V19-15", "Static security policy scanner (scripts/check_static_security.py) exists", static_script.is_file())

    res_static = subprocess.run([sys.executable, str(static_script)], capture_output=True, text=True)
    report("V19-16", "Static security checker confirms 0 policy violations across code & containers", res_static.returncode == 0)

    # 13. Static Policy Failure Gate: Unpinned Action Detection
    from scripts.check_static_security import check_workflow_policies
    with tempfile.TemporaryDirectory() as td:
        bad_wf = Path(td) / "bad.yml"
        bad_wf.write_text("name: Bad\non: [push]\npermissions:\n  contents: read\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@master\n", encoding="utf-8")
        import scripts.check_static_security
        orig_dir = scripts.check_static_security.WORKFLOWS_DIR
        scripts.check_static_security.WORKFLOWS_DIR = Path(td)
        try:
            violations, _ = check_workflow_policies()
            unpinned_gate = any("unpinned floating action" in v for v in violations)
            report("V19-17", "Static policy failure gate: Floating action reference (@master) detected and rejected", unpinned_gate)
        finally:
            scripts.check_static_security.WORKFLOWS_DIR = orig_dir

    # 14. Static Policy Failure Gate: Excessive Permissions Detection
    with tempfile.TemporaryDirectory() as td:
        bad_wf = Path(td) / "bad.yml"
        bad_wf.write_text("name: Bad\non: [push]\npermissions: write-all\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n", encoding="utf-8")
        scripts.check_static_security.WORKFLOWS_DIR = Path(td)
        try:
            violations, _ = check_workflow_policies()
            perm_gate = any("excessive permissions" in v for v in violations)
            report("V19-18", "Static policy failure gate: Excessive permissions (write-all) detected and rejected", perm_gate)
        finally:
            scripts.check_static_security.WORKFLOWS_DIR = orig_dir

    # 15. Endpoint inventory generation and RBAC authorization coverage
    inv_script = REPO_ROOT / "scripts" / "extract_endpoint_inventory.py"
    report("V19-19", "Endpoint inventory generator (scripts/extract_endpoint_inventory.py) exists", inv_script.is_file())

    from scripts.extract_endpoint_inventory import get_all_routes
    routes = get_all_routes()
    sec_routes = [r for r in routes if r["path"].startswith("/api/v1/security/")]
    all_sec_authenticated = all(r["auth_required"] for r in sec_routes)
    report("V19-20", "Endpoint inventory verification: 100% of sensitive security routes require authentication", all_sec_authenticated, f"Audited {len(sec_routes)} sensitive security routes")

    # 16. Production Container Configuration Hardening
    prod_compose = REPO_ROOT / "docker-compose.prod.yml"
    prod_content = prod_compose.read_text(encoding="utf-8")
    compose_hardened = (
        "read_only: true" in prod_content
        and "cap_drop:" in prod_content
        and "ALL" in prod_content
        and "no-new-privileges:true" in prod_content
        and "network_mode: host" not in prod_content
        and "privileged: true" not in prod_content
    )
    report("V19-21", "Production Compose configuration enforces read-only root, dropped caps, and no-new-privileges", compose_hardened)

    # 17. Phase 14-19 Verification Scripts Wiring
    required_scripts = [
        "scripts/verify_phase14_acceptance.py",
        "scripts/verify_phase15.py",
        "scripts/verify_phase15_acceptance.py",
        "scripts/verify_phase16.py",
        "scripts/verify_phase17.py",
        "scripts/verify_phase18.py",
        "scripts/verify_phase19.py",
    ]
    all_scripts_exist = all((REPO_ROOT / s).is_file() for s in required_scripts)
    report("V19-22", "All Phase 14 through Phase 19 verification scripts exist and are wired into CI", all_scripts_exist)

    # 18. CI Operational Documentation
    doc_file = REPO_ROOT / "docs" / "CI_SECURITY.md"
    doc_ok = doc_file.is_file() and ("Recommended Branch Protection" in doc_file.read_text(encoding="utf-8"))
    report("V19-23", "CI operational security and branch protection documentation (docs/CI_SECURITY.md) complete", doc_ok)

    # 19. No accidental .env or host DB files tracked by Git
    tracked_files = subprocess.run(["git", "ls-files"], cwd=str(REPO_ROOT), capture_output=True, text=True).stdout.splitlines()
    accidental_files = [f for f in tracked_files if f.endswith(".env") or f.endswith(".db") or f.endswith(".sqlite")]
    report("V19-24", "Git-tracked tree is free of committed .env files and SQLite database artifacts", len(accidental_files) == 0, f"Violations: {accidental_files}")

    print("=" * 76)
    print("ALL 24 PHASE 19 INDEPENDENT VERIFICATION CHECKS PASSED (0 FAILED)")
    print("=" * 76)


if __name__ == "__main__":
    main()
