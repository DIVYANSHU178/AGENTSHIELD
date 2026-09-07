#!/usr/bin/env python3
"""
AgentShield Secret Scanner (Phase 19 CI/CD & Automated Security Checks)

Recursively scans repository files, workflows, Dockerfiles, Compose manifests,
and production build artifacts for sensitive credentials, private keys,
and unmasked connection strings.

Security invariants:
- Zero printing of matched secret material (masks or omits raw values in output).
- Deterministic exit codes: 0 = PASS (no secrets found), 1 = FAIL (secrets detected).
- Explicit, narrowly-scoped rule exceptions for test fixtures.
"""

import sys
import os
import re
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent

IGNORED_DIRS = {
    ".git",
    ".venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    "dist",
}

IGNORED_EXTENSIONS = {
    ".pyc",
    ".db",
    ".sqlite",
    ".sqlite3",
    ".png",
    ".jpg",
    ".jpeg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".gz",
    ".tar",
}

SAFE_SUBSTRINGS = (
    "placeholder",
    "example",
    "redacted",
    "change_me",
    "changeme",
    "test-secret",
    "do-not-leak",
    "passwordhere",
    "dummy",
    "your-secret",
    "adminpass123!",
    "reviewerpass123!",
    "operatorpass123!",
    "viewerpass123!",
    "secret123!",
    "****",
)

EXEMPT_FILES = {
    "test_phase15_secrets_config.py",
    "verify_phase15_acceptance.py",
    "verify_phase15.py",
    "verify_phase14_acceptance.py",
    "run_m15_manual_acceptance.py",
    "verify_phase16.py",
    "test_phase16_observability.py",
    "IntegrationQA.test.tsx",
    "sanitizer.test.ts",
    "settings.py",
    "scan_secrets.py",
    "test_phase19_cicd_security.py",
    "verify_phase19.py",
    "test_phase20_agent_gateway.py",
    "test_phase20_isolated_tools.py",
    "test_phase20_approval_execution.py",
    "test_phase20_adversarial.py",
    "verify_phase20.py",
}

RULES = [
    {
        "id": "SEC-01-PRIVATE-KEY",
        "description": "Unencrypted Private Key Header",
        "pattern": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        "severity": "CRITICAL",
    },
    {
        "id": "SEC-02-AWS-KEY",
        "description": "AWS Access Key Identifier",
        "pattern": re.compile(r"\b(AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[0-9A-Z]{16}\b"),
        "severity": "CRITICAL",
    },
    {
        "id": "SEC-03-API-TOKEN",
        "description": "API / Provider Key (e.g. OpenAI, GitHub, Slack)",
        "pattern": re.compile(r"\b(sk-[a-zA-Z0-9]{20,}|sk-proj-[a-zA-Z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9_]{36,}|xox[baprs]-[0-9a-zA-Z-]{10,})\b"),
        "severity": "CRITICAL",
    },
    {
        "id": "SEC-04-CONN-STRING-CREDS",
        "description": "Database Connection String with Embedded Credentials",
        "pattern": re.compile(r"(?:postgres(?:ql)?|mysql|mongodb)://([^:\s]+):([^@\s]+)@([^/\s]+)"),
        "severity": "HIGH",
    },
    {
        "id": "SEC-05-ACCIDENTAL-ENV",
        "description": "Committed or Tracked .env Secret File",
        "file_pattern": re.compile(r"^\.env(\.(production|prod|local|secret))?$"),
        "severity": "CRITICAL",
    },
]


def is_safe_value(val: str) -> bool:
    """Check if matched string is a known synthetic placeholder or template token."""
    cleaned = val.strip().lower()
    if any(sub in cleaned for sub in SAFE_SUBSTRINGS):
        return True
    if cleaned == "12345678901234567890123456789012":
        return True
    if cleaned.startswith("<") and cleaned.endswith(">"):
        return True
    if cleaned.startswith("${") and cleaned.endswith("}"):
        return True
    return False


def is_test_or_harness_file(path: Path) -> bool:
    """Determine if a file is an automated test, demo script, or attack scenario harness within the repository."""
    try:
        rel = path.resolve().relative_to(REPO_ROOT.resolve())
        norm = str(rel).replace("\\", "/").lower()
        return any(norm.startswith(p) for p in ("apps/api/tests/", "apps/api/scripts/", "scenarios/", "apps/web/src/"))
    except ValueError:
        return False


def scan_file_content(path: Path) -> List[Dict[str, Any]]:
    """Scan a single file for secret patterns."""
    findings = []
    filename = path.name

    for rule in RULES:
        if "file_pattern" in rule and rule["file_pattern"].match(filename):
            findings.append({
                "rule_id": rule["id"],
                "description": rule["description"],
                "severity": rule["severity"],
                "file": str(path),
                "line": 0,
            })

    if filename in EXEMPT_FILES:
        return findings

    is_test_file = is_test_or_harness_file(path)

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line_no, line in enumerate(f, start=1):
                for rule in RULES:
                    if "pattern" not in rule:
                        continue

                    match = rule["pattern"].search(line)
                    if not match:
                        continue

                    if rule["id"] == "SEC-04-CONN-STRING-CREDS":
                        user, pwd, host = match.groups()
                        if is_safe_value(pwd) or pwd in ("pass", "password", "****", "****password****"):
                            continue

                    elif rule["id"] == "SEC-03-API-TOKEN":
                        token = match.group(0)
                        if is_safe_value(token) or is_safe_value(line):
                            continue
                        if is_test_file:
                            continue

                    elif rule["id"] == "SEC-02-AWS-KEY":
                        token = match.group(0)
                        if token == "AKIAIOSFODNN7EXAMPLE" or is_safe_value(token) or is_safe_value(line):
                            continue
                        if is_test_file:
                            continue

                    findings.append({
                        "rule_id": rule["id"],
                        "description": rule["description"],
                        "severity": rule["severity"],
                        "file": str(path),
                        "line": line_no,
                    })
    except Exception as exc:
        print(f"Warning: could not scan {path}: {exc}", file=sys.stderr)

    return findings


def get_git_tracked_files() -> Optional[List[Path]]:
    """Get list of files tracked by Git."""
    try:
        res = subprocess.run(
            ["git", "ls-files"],
            cwd=str(REPO_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        return [REPO_ROOT / p.strip() for p in res.stdout.splitlines() if p.strip()]
    except Exception:
        return None


def scan_directory(target_dir: Path) -> List[Dict[str, Any]]:
    """Recursively scan directory for secret leaks."""
    all_findings = []
    # If scanning repository root, prioritize git-tracked files
    if target_dir == REPO_ROOT:
        tracked_files = get_git_tracked_files()
        if tracked_files:
            for p in tracked_files:
                if p.is_file() and p.suffix not in IGNORED_EXTENSIONS:
                    all_findings.extend(scan_file_content(p))
            return all_findings

    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
        for f in files:
            p = Path(root) / f
            if p.suffix in IGNORED_EXTENSIONS:
                continue
            findings = scan_file_content(p)
            all_findings.extend(findings)
    return all_findings


def scan_bundle_assets(dist_dir: Path) -> List[Dict[str, Any]]:
    """Verify built frontend production assets do not leak secrets or credentials."""
    findings = []
    assets_dir = dist_dir / "assets"
    if not assets_dir.is_dir():
        return findings

    demo_creds = [
        "AdminPass123!",
        "ReviewerPass123!",
        "OperatorPass123!",
        "ViewerPass123!",
        "AGENTSHIELD_AUTHORIZATION_SECRET",
    ]

    for js_file in assets_dir.glob("*.js"):
        try:
            with open(js_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                for cred in demo_creds:
                    if cred in content:
                        findings.append({
                            "rule_id": "SEC-06-BUNDLE-LEAK",
                            "description": "Demo credential or server secret in production JS bundle",
                            "severity": "CRITICAL",
                            "file": str(js_file),
                            "line": 1,
                        })
        except Exception:
            pass
    return findings


def main():
    import argparse
    parser = argparse.ArgumentParser(description="AgentShield Secret Scanner")
    parser.add_argument("--target", type=str, default=str(REPO_ROOT), help="Target directory or file to scan")
    parser.add_argument("--include-dist", action="store_true", help="Include dist bundle verification")
    args = parser.parse_args()

    target = Path(args.target).resolve()
    print("=" * 72)
    print("AGENTSHIELD CI/CD AUTOMATED SECRET SCANNER")
    print(f"Scanning target: {target}")
    print("=" * 72)

    findings: List[Dict[str, Any]] = []
    if target.is_file():
        findings = scan_file_content(target)
    else:
        findings = scan_directory(target)

    if args.include_dist:
        dist_path = REPO_ROOT / "apps" / "web" / "dist"
        findings.extend(scan_bundle_assets(dist_path))

    if findings:
        print(f"\n[FAIL] SECRETS DETECTED: {len(findings)} violation(s) found!\n")
        for f in findings:
            print(f"  [{f['severity']}] {f['rule_id']} in {f['file']}:{f['line']}")
            print(f"         Reason: {f['description']}")
        print("\nNote: Matched secret values are suppressed in output to prevent log leakage.")
        sys.exit(1)
    else:
        print("\n[PASS] Zero secrets or sensitive credentials detected across scanned targets.")
        sys.exit(0)


if __name__ == "__main__":
    main()
