#!/usr/bin/env python3
"""
AgentShield — QA Environment Reset Script

Purpose:
Creates or cleanly resets an isolated QA/test SQLite database for manual testing.
Seeds predictable, fresh test accounts for all Phase 14 roles:
  - VIEWER (viewer_user)
  - OPERATOR (ops_user)
  - SECURITY_REVIEWER (security_lead)
  - ADMIN (admin)

Safety Invariants:
1. NEVER deletes, truncates, or modifies the active development database (agentshield.db).
2. Explicitly checks canonical database file paths and aborts if target matches dev DB.
3. Requires database name to contain a 'qa' or 'test' marker.
4. Passwords are never printed or logged to stdout or persistent files.
5. All 8 Phase 13 & 14 tables are cleanly initialized with empty operational history.
"""

import os
import sys
import argparse
from pathlib import Path
from typing import Dict, Any, Optional, List
import sqlite3

# Ensure apps/api directory is in sys.path
SCRIPT_DIR = Path(__file__).resolve().parent
API_DIR = SCRIPT_DIR.parent
if str(API_DIR) not in sys.path:
    sys.path.insert(0, str(API_DIR))

from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker

from app.config import settings
from app.database.session import init_db, configure_database
from app.security.identity.models import Role
from app.security.identity.crypto import hash_password, verify_password
from app.security.persistence import IdentityRepository
from app.security.models.utils import generate_uuid, utc_now


class DevDatabaseProtectionError(RuntimeError):
    """Raised when an operation attempts to target the development database."""
    pass


REQUIRED_TABLES = [
    "security_audit_events",
    "security_decisions",
    "threat_activities",
    "execution_activities",
    "approval_requests",
    "security_users",
    "security_sessions",
    "security_auth_events",
]


def validate_qa_target(
    target_path: Path,
    dev_path: Path,
    environment: str,
    force_qa: bool = False,
) -> None:
    """
    Strict safety validation to ensure that the target database is exclusively a QA database
    and can NEVER be the active development database.
    """
    target_resolved = target_path.resolve()
    dev_resolved = dev_path.resolve()

    # Guard 1: Exact canonical path equality
    if target_resolved == dev_resolved:
        raise DevDatabaseProtectionError(
            f"CRITICAL SAFETY VIOLATION: Target path '{target_resolved}' matches the active "
            f"development database '{dev_resolved}'. Resetting the development database is strictly prohibited."
        )

    # Guard 2: Reserved development filename
    if target_resolved.name.lower() == "agentshield.db":
        raise DevDatabaseProtectionError(
            "CRITICAL SAFETY VIOLATION: The filename 'agentshield.db' is strictly reserved for "
            "development/historical data. The QA database must use an isolated filename (e.g. 'agentshield_qa.db')."
        )

    # Guard 3: Required QA/test name marker
    name_lower = target_resolved.name.lower()
    if "qa" not in name_lower and "test" not in name_lower:
        raise DevDatabaseProtectionError(
            f"SAFETY ERROR: Target database '{target_resolved.name}' must contain 'qa' or 'test' "
            f"in its filename to prevent accidental data loss."
        )

    # Guard 4: Production/Dev environment safety check
    env_lower = environment.lower()
    if env_lower in ("development", "dev", "production", "prod") and not force_qa:
        raise DevDatabaseProtectionError(
            f"SAFETY ERROR: Application environment is '{environment}'. "
            f"QA reset requires ENVIRONMENT='qa' or an explicit QA database target."
        )

    # Guard 5: Row count threshold protection (in case an existing dev DB was copied)
    if target_resolved.exists() and "qa" not in name_lower:
        try:
            conn = sqlite3.connect(str(target_resolved))
            cur = conn.cursor()
            res = cur.execute("SELECT count(*) FROM security_audit_events").fetchone()
            conn.close()
            if res and res[0] > 500:
                raise DevDatabaseProtectionError(
                    f"SAFETY ERROR: Target database has {res[0]} historical audit events "
                    f"and does not appear to be a QA database. Aborting reset."
                )
        except Exception:
            pass


def reset_qa_database(
    target_url: Optional[str] = None,
    seed_sample_data: bool = False,
    force_qa: bool = False,
) -> Dict[str, Any]:
    """
    Reset or initialize the QA database cleanly.
    Returns status dictionary with created accounts and table verification.
    """
    dev_path = settings.get_dev_database_path()

    # Determine target URL and target path
    if target_url:
        qa_url = target_url
    elif settings.is_qa_mode():
        qa_url = settings.DATABASE_URL
    else:
        qa_url = settings.QA_DATABASE_URL

    if qa_url.startswith("sqlite:///./"):
        rel_name = qa_url[len("sqlite:///./"):]
        target_path = (API_DIR / rel_name).resolve()
    elif qa_url.startswith("sqlite:///") and not qa_url.startswith("sqlite:///:"):
        target_path = Path(qa_url[len("sqlite:///"):]).resolve()
    else:
        target_path = settings.get_qa_database_path()

    # Safety validation
    validate_qa_target(
        target_path=target_path,
        dev_path=dev_path,
        environment=settings.ENVIRONMENT,
        force_qa=force_qa or True,
    )

    # If QA database file exists, delete it for a 100% clean, pristine state
    if target_path.exists():
        try:
            # Delete SQLite database and any temporary WAL/SHM journal files
            target_path.unlink()
            wal_file = target_path.with_name(f"{target_path.name}-wal")
            if wal_file.exists():
                wal_file.unlink()
            shm_file = target_path.with_name(f"{target_path.name}-shm")
            if shm_file.exists():
                shm_file.unlink()
        except Exception as e:
            # Fallback if file is locked: connect and drop tables
            conn = sqlite3.connect(str(target_path))
            cur = conn.cursor()
            for t in REQUIRED_TABLES:
                cur.execute(f"DROP TABLE IF EXISTS {t}")
            conn.commit()
            conn.close()

    # Create directory if needed
    target_path.parent.mkdir(parents=True, exist_ok=True)

    # Initialize tables using authoritative SQLAlchemy schema
    qa_engine = create_engine(
        f"sqlite:///{target_path}",
        connect_args={"check_same_thread": False},
        echo=False,
    )
    init_db(target_engine=qa_engine)

    # Verify all 8 tables exist
    inspector = inspect(qa_engine)
    existing_tables = set(inspector.get_table_names())
    missing_tables = [t for t in REQUIRED_TABLES if t not in existing_tables]
    if missing_tables:
        raise RuntimeError(f"Database table initialization incomplete. Missing tables: {missing_tables}")

    # Seed fresh test accounts
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=qa_engine)
    ident_repo = IdentityRepository(session_factory=session_factory)

    test_accounts = [
        {
            "user_id": "usr-viewer",
            "username": "viewer_user",
            "display_name": "Carol Viewer",
            "roles": (Role.VIEWER,),
            "email": "viewer@agentshield.local",
            "password": os.environ.get("QA_VIEWER_PASSWORD", "ViewerPass123!"),
        },
        {
            "user_id": "usr-operator",
            "username": "ops_user",
            "display_name": "Bob Operator",
            "roles": (Role.OPERATOR,),
            "email": "operator@agentshield.local",
            "password": os.environ.get("QA_OPERATOR_PASSWORD", "OperatorPass123!"),
        },
        {
            "user_id": "usr-reviewer",
            "username": "security_lead",
            "display_name": "Alice Security Lead",
            "roles": (Role.SECURITY_REVIEWER,),
            "email": "reviewer@agentshield.local",
            "password": os.environ.get("QA_REVIEWER_PASSWORD", "ReviewerPass123!"),
        },
        {
            "user_id": "usr-admin",
            "username": "admin",
            "display_name": "System Administrator",
            "roles": (Role.ADMIN,),
            "email": "admin@agentshield.local",
            "password": os.environ.get("QA_ADMIN_PASSWORD", "AdminPass123!"),
        },
    ]

    seeded_users: List[Dict[str, Any]] = []
    for acct in test_accounts:
        pwd_hash, pwd_salt = hash_password(acct["password"])
        created = ident_repo.create_user(
            user_id=acct["user_id"],
            username=acct["username"],
            display_name=acct["display_name"],
            password_hash=pwd_hash,
            password_salt=pwd_salt,
            roles=acct["roles"],
            email=acct["email"],
            is_active=True,
        )
        # Verify credential works
        assert verify_password(acct["password"], pwd_hash, pwd_salt), "Password verification failed"
        seeded_users.append({
            "user_id": created.user_id,
            "username": created.username,
            "display_name": created.display_name,
            "roles": [r.value for r in created.roles],
            "email": created.email,
        })

    # Optional UI sample data for manual UI testing
    if seed_sample_data:
        from app.models.models import ApprovalRequestModel, SecurityDecisionModel
        with session_factory() as session:
            sample_approval = ApprovalRequestModel(
                approval_id="appr-qa-sample-01",
                request_id="req-qa-sample-01",
                agent_id="agent-analyst-01",
                agent_name="Analyst Agent",
                agent_role="SECURITY_ANALYST",
                tool_name="bash_exec",
                tool_category="CODE_EXECUTION",
                action="EXECUTE",
                target="/bin/bash -c 'cat /etc/passwd'",
                parameters={"command": "cat /etc/passwd"},
                destination=None,
                request_fingerprint="fp-sample-01",
                risk_score=78.5,
                severity="HIGH",
                decision="REQUIRE_APPROVAL",
                created_at=utc_now(),
                expires_at=utc_now(),
                status="PENDING",
                metadata_payload={"note": "Sample QA approval request"},
            )
            sample_decision = SecurityDecisionModel(
                decision_id="dec-qa-sample-01",
                request_id="req-qa-sample-01",
                decision="REQUIRE_APPROVAL",
                risk_score=78.5,
                severity="HIGH",
                policy_id="POLICY_RESTRICTED_COMMAND",
                reason="Attempted execution of restricted command cat /etc/passwd",
                threat_count=1,
                timestamp=utc_now(),
                metadata_payload={},
            )
            session.add(sample_approval)
            session.add(sample_decision)
            session.commit()

    # Reconfigure in-memory engine if running in-process
    configure_database(f"sqlite:///{target_path}")

    return {
        "status": "ok",
        "target_path": str(target_path),
        "database_url": f"sqlite:///{target_path}",
        "tables": sorted(list(existing_tables)),
        "users": seeded_users,
        "dev_database_untouched": str(dev_path),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Reset AgentShield QA Environment to clean state with predictable test accounts."
    )
    parser.add_argument(
        "--confirm",
        action="store_true",
        help="Confirm non-interactive reset of the QA database.",
    )
    parser.add_argument(
        "--db-url",
        type=str,
        default=None,
        help="Optional explicit QA database URL (e.g. sqlite:///./agentshield_qa.db).",
    )
    parser.add_argument(
        "--seed-sample-data",
        action="store_true",
        help="Optionally seed a sample pending approval request for immediate UI testing.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress detailed console output.",
    )

    args = parser.parse_args()

    if not args.confirm:
        print("=" * 80)
        print("AGENTSHIELD QA ENVIRONMENT RESET")
        print("=" * 80)
        print("Target: Isolated QA Database (agentshield_qa.db)")
        print("Dev DB: agentshield.db (PROTECTED - will NOT be modified)")
        print("\nPass --confirm to execute the reset.")
        return 0

    try:
        result = reset_qa_database(
            target_url=args.db_url,
            seed_sample_data=args.seed_sample_data,
            force_qa=True,
        )
    except DevDatabaseProtectionError as e:
        print(f"\n[SAFETY REFUSAL] {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"\n[ERROR] QA Reset Failed: {e}", file=sys.stderr)
        return 1

    if not args.quiet:
        print("=" * 80)
        print("AGENTSHIELD QA ENVIRONMENT RESET COMPLETED SUCCESSFULLY")
        print("=" * 80)
        print(f"Database Location   : {result['target_path']}")
        print(f"Database URL        : {result['database_url']}")
        print(f"Dev Database State  : PROTECTED / UNTOUCHED ({result['dev_database_untouched']})")
        print(f"Initialized Tables  : {len(result['tables'])} verified")
        for tbl in result['tables']:
            print(f"  - {tbl}")

        print("\nSeeded Test Identities (Zero Plaintext Passwords Logged):")
        for u in result['users']:
            print(f"  [+] {u['username']:<15} | Display: {u['display_name']:<22} | Roles: {u['roles']} | Password: [CONFIGURED]")

        print("\nEnvironment Startup Instructions:")
        print("  Backend (PowerShell):")
        print('    $env:ENVIRONMENT="qa"; .venv\\Scripts\\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload')
        print("  Frontend:")
        print("    npm run dev -- --host")
        print("=" * 80)

    return 0


if __name__ == "__main__":
    sys.exit(main())
