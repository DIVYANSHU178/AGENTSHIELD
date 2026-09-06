#!/usr/bin/env python3
"""
AgentShield — QA Environment Reset Script (Root Wrapper)

Executes apps/api/scripts/reset_qa_environment.py from repository root.
"""

import os
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
API_DIR = ROOT_DIR / "apps" / "api"
TARGET_SCRIPT = API_DIR / "scripts" / "reset_qa_environment.py"

if str(API_DIR) not in sys.path:
    sys.path.insert(0, str(API_DIR))

if __name__ == "__main__":
    # Execute target script with original arguments
    import importlib.util
    spec = importlib.util.spec_from_file_location("reset_qa_environment", TARGET_SCRIPT)
    if spec and spec.loader:
        module = importlib.util.module_from_spec(spec)
        sys.modules["reset_qa_environment"] = module
        spec.loader.exec_module(module)
        sys.exit(module.main())
    else:
        print(f"Error: Could not load target script at {TARGET_SCRIPT}", file=sys.stderr)
        sys.exit(1)
