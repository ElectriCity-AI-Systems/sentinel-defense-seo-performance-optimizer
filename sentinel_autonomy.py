#!/usr/bin/env python3
"""Small safe wrapper for Sentinel's local operations supervisor.

This wrapper contains no independent operations logic. It maps a few stable
local commands to hard-coded `sentinel_autonomous_operations_supervisor.py`
arguments and runs them with shell disabled.
"""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path
from typing import List, Optional


PROJECT_DIR = Path("/srv/sentinel-defense")
SUPERVISOR = "sentinel_autonomous_operations_supervisor.py"

COMMANDS = {
    "status": ["python3", SUPERVISOR, "--status"],
    "preflight": ["python3", SUPERVISOR, "--preflight"],
    "run-safe-once": ["python3", SUPERVISOR, "--run-safe-once"],
    "briefing": ["python3", SUPERVISOR, "--build-owner-briefing"],
    "operation-governor-status": ["python3", "sentinel_autonomous_operation_governor.py", "--status"],
    "soak-status": ["python3", "sentinel_autonomous_soak_test.py", "--status"],
    "readiness-seal": ["python3", "sentinel_autonomous_soak_test.py", "--build-readiness-seal"],
}


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Safe local Sentinel autonomy wrapper")
    parser.add_argument("command", choices=["status", "preflight", "run-safe-once", "run-safe-batch", "briefing", "operation-governor-status", "soak-status", "soak-run", "readiness-seal"])
    parser.add_argument("count", nargs="?")
    args = parser.parse_args(argv)

    if args.command == "run-safe-batch":
        count = int(args.count or "3")
        if count > 5:
            print("blocked: max batch is 5")
            return 2
        cmd = ["python3", SUPERVISOR, "--run-safe-batch", str(count)]
    elif args.command == "soak-run":
        count = int(args.count or "3")
        if count > 5:
            print("blocked: max soak steps is 5")
            return 2
        cmd = ["python3", "sentinel_autonomous_soak_test.py", "--run-soak", str(count)]
    else:
        cmd = COMMANDS[args.command]
    proc = subprocess.run(
        cmd,
        cwd=str(PROJECT_DIR),
        check=False,
        shell=False,
    )
    return int(proc.returncode)


if __name__ == "__main__":
    raise SystemExit(main())
