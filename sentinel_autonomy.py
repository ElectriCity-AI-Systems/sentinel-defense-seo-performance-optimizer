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
    "rc-status": ["python3", "sentinel_autonomous_release_candidate.py", "--status"],
    "rc-briefing": ["python3", "sentinel_autonomous_release_candidate.py", "--build-owner-console"],
    "rc-evidence": ["python3", "sentinel_autonomous_release_candidate.py", "--build-evidence-pack"],
    "rc-runbook": ["python3", "sentinel_autonomous_release_candidate.py", "--build-runbook"],
    "public-release-status": ["python3", "sentinel_public_release_pack.py", "--status"],
    "public-summary": ["python3", "sentinel_public_release_pack.py", "--build-readme"],
    "sales-copy": ["python3", "sentinel_public_release_pack.py", "--build-sales-copy"],
    "github-release-notes": ["python3", "sentinel_public_release_pack.py", "--build-github-release-notes"],
    "distribution-status": ["python3", "sentinel_distribution_release_pack.py", "--status"],
    "release-checklist": ["python3", "sentinel_distribution_release_pack.py", "--build-repository-hygiene"],
    "changelog": ["python3", "sentinel_distribution_release_pack.py", "--build-changelog"],
    "marketplace-checklist": ["python3", "sentinel_distribution_release_pack.py", "--build-marketplace-checklists"],
    "license-status": ["python3", "sentinel_license_decision_finalizer.py", "--status"],
    "license-options": ["python3", "sentinel_license_decision_finalizer.py", "--build-license-options"],
    "release-final-status": ["python3", "sentinel_license_decision_finalizer.py", "--validate-final-release"],
    "release-draft": ["python3", "sentinel_license_decision_finalizer.py", "--build-final-github-release-draft"],
    "manual-publication-checklist": ["python3", "sentinel_license_decision_finalizer.py", "--validate-final-release"],
    "publication-handoff-status": ["python3", "sentinel_manual_publication_handoff.py", "--status"],
    "readme-candidate": ["python3", "sentinel_manual_publication_handoff.py", "--build-readme-candidate"],
    "license-candidate": ["python3", "sentinel_manual_publication_handoff.py", "--build-license-candidate"],
    "owner-go-no-go": ["python3", "sentinel_manual_publication_handoff.py", "--build-owner-go-no-go"],
    "no-action-proof": ["python3", "sentinel_manual_publication_handoff.py", "--build-no-action-proof"],
    "guarded-status": ["python3", "sentinel_guarded_autonomy.py", "--status"],
    "guarded-preflight": ["python3", "sentinel_guarded_autonomy.py", "--preflight"],
    "guarded-actions": ["python3", "sentinel_guarded_autonomy.py", "--list-actions"],
    "guarded-audit": ["python3", "sentinel_guarded_autonomy.py", "--audit-summary"],
    "guarded-pause": ["python3", "sentinel_guarded_autonomy.py", "--pause"],
    "guarded-resume": ["python3", "sentinel_guarded_autonomy.py", "--resume"],
    "guarded-emergency-stop": ["python3", "sentinel_guarded_autonomy.py", "--emergency-stop"],
    "activation-gates": ["python3", "sentinel_guarded_activation.py", "--collect-gates"],
    "health-baseline": ["python3", "sentinel_guarded_activation.py", "--build-health-baseline"],
    "tls-gate": ["python3", "sentinel_guarded_activation.py", "--evaluate-tls-gate"],
    "scheduler-verification": ["python3", "sentinel_guarded_activation.py", "--verify-scheduler-cycles"],
    "guarded-go-live-status": ["python3", "sentinel_guarded_activation.py", "--status"],
    "runtime-health": ["python3", "sentinel_guarded_runtime_activation.py", "--evaluate-health"],
    "runtime-tls": ["python3", "sentinel_guarded_runtime_activation.py", "--evaluate-tls"],
    "runtime-systemd": ["python3", "sentinel_guarded_runtime_activation.py", "--select-systemd-mode"],
    "runtime-monitoring": ["python3", "sentinel_guarded_runtime_activation.py", "--activate-monitoring"],
    "runtime-write-canary": ["python3", "sentinel_guarded_runtime_activation.py", "--probe-write-canary"],
    "runtime-level": ["python3", "sentinel_guarded_runtime_activation.py", "--status"],
}


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Safe local Sentinel autonomy wrapper")
    parser.add_argument(
        "command",
        choices=sorted([*COMMANDS, "run-safe-batch", "soak-run"]),
    )
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
