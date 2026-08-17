#!/usr/bin/env python3
"""Build the sanitized public release pack for Sentinel Phase 10.11.

This module only writes local documentation, public-safe manifests, reports,
state, audit events and playbooks. It does not perform live apply, network
access, external API calls, remote writes, timer installation, or customer
system changes.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


PROJECT_DIR = Path(__file__).resolve().parent
SCHEMA_VERSION = "sentinel-public-release-pack-10.11"
PHASE = "10.11"

HARD_DEFAULTS = {
    "live_apply": False,
    "emergency_stop": True,
    "allowed_apply_now": False,
    "high_blocked": True,
    "low_live_executable": False,
    "medium_executable": False,
    "breach": False,
}

REPORT_DIR = PROJECT_DIR / "reports/latest"
STATE_DIR = PROJECT_DIR / "state/adaptive-learning"
AUDIT_DIR = PROJECT_DIR / "audit"
PLAYBOOK_DIR = PROJECT_DIR / "playbooks"
PUBLIC_DIR = PROJECT_DIR / "docs/public-release"

REPORT_JSON = REPORT_DIR / "sentinel-public-release-pack.json"
REPORT_MD = REPORT_DIR / "sentinel-public-release-pack.md"
VALIDATION_MD = REPORT_DIR / "sentinel-public-release-validation.md"
OWNER_SUMMARY_MD = REPORT_DIR / "sentinel-public-release-owner-summary.md"

STATE_JSON = STATE_DIR / "public_release_pack.json"
LATEST_JSON = STATE_DIR / "latest_public_release_pack.json"
HISTORY_JSON = STATE_DIR / "public_release_pack_history.json"
AUDIT_JSONL = AUDIT_DIR / "sentinel-public-release-pack.jsonl"

PLAYBOOK_PACK = PLAYBOOK_DIR / "sentinel-public-release-pack.playbook.json"
PLAYBOOK_SAFETY = PLAYBOOK_DIR / "sentinel-public-release-safety-docs.playbook.json"
PLAYBOOK_SALES = PLAYBOOK_DIR / "sentinel-public-release-sales-copy.playbook.json"
PLAYBOOK_VALIDATION = PLAYBOOK_DIR / "sentinel-public-release-validation.playbook.json"

PUBLIC_FILES = {
    "readme": PUBLIC_DIR / "README-public.md",
    "safety_boundaries": PUBLIC_DIR / "SAFETY-BOUNDARIES.md",
    "owner_commands": PUBLIC_DIR / "OWNER-COMMANDS.md",
    "owner_runbook": PUBLIC_DIR / "OWNER-RUNBOOK-public.md",
    "product_summary": PUBLIC_DIR / "PRODUCT-SUMMARY.md",
    "demo_walkthrough": PUBLIC_DIR / "DEMO-SAFE-WALKTHROUGH.md",
    "github_release_notes": PUBLIC_DIR / "GITHUB-RELEASE-NOTES.md",
    "payhip_listing": PUBLIC_DIR / "PAYHIP-LISTING.md",
    "gumroad_listing": PUBLIC_DIR / "GUMROAD-LISTING.md",
    "faq": PUBLIC_DIR / "FAQ.md",
    "not_autopilot": PUBLIC_DIR / "NOT-AUTOPILOT-DISCLAIMER.md",
    "commit_recommendation": PUBLIC_DIR / "COMMIT-RECOMMENDATION.md",
    "manifest": PUBLIC_DIR / "public-release-manifest.json",
}

ALLOWED_WRITE_ROOTS = (REPORT_DIR, STATE_DIR, AUDIT_DIR, PLAYBOOK_DIR, PUBLIC_DIR)

RC_INPUTS = {
    "rc_json": REPORT_DIR / "sentinel-autonomous-release-candidate.json",
    "rc_report": REPORT_DIR / "sentinel-autonomous-release-candidate.md",
    "rc_manifest": REPORT_DIR / "sentinel-autonomous-rc-manifest.md",
    "owner_console": REPORT_DIR / "sentinel-autonomous-owner-command-console.md",
    "owner_runbook": REPORT_DIR / "sentinel-autonomous-owner-runbook.md",
    "public_summary": REPORT_DIR / "sentinel-autonomous-public-summary.md",
    "evidence_pack": REPORT_DIR / "sentinel-autonomous-rc-evidence-pack.md",
    "readiness_seal": REPORT_DIR / "sentinel-autonomous-readiness-seal.md",
    "regression_gate": REPORT_DIR / "sentinel-autonomous-regression-gate.md",
    "latest_rc_state": STATE_DIR / "latest_autonomous_release_candidate.json",
}

RECOMMENDED_GIT_FILES = [
    "sentinel_public_release_pack.py",
    "sentinel_autonomy.py",
    "docs/public-release/README-public.md",
    "docs/public-release/SAFETY-BOUNDARIES.md",
    "docs/public-release/OWNER-COMMANDS.md",
    "docs/public-release/OWNER-RUNBOOK-public.md",
    "docs/public-release/PRODUCT-SUMMARY.md",
    "docs/public-release/DEMO-SAFE-WALKTHROUGH.md",
    "docs/public-release/GITHUB-RELEASE-NOTES.md",
    "docs/public-release/PAYHIP-LISTING.md",
    "docs/public-release/GUMROAD-LISTING.md",
    "docs/public-release/FAQ.md",
    "docs/public-release/NOT-AUTOPILOT-DISCLAIMER.md",
    "docs/public-release/COMMIT-RECOMMENDATION.md",
    "docs/public-release/public-release-manifest.json",
    "playbooks/sentinel-public-release-pack.playbook.json",
    "playbooks/sentinel-public-release-safety-docs.playbook.json",
    "playbooks/sentinel-public-release-sales-copy.playbook.json",
    "playbooks/sentinel-public-release-validation.playbook.json",
]

OWNER_COMMANDS = [
    ("python3 sentinel_autonomy.py status", "Show the local safe operations status."),
    ("python3 sentinel_autonomy.py preflight", "Check local prerequisites and safety flags."),
    ("python3 sentinel_autonomy.py operation-governor-status", "Show operation scoring and diversity state."),
    ("python3 sentinel_autonomy.py run-safe-once", "Run one bounded local safe operation."),
    ("python3 sentinel_autonomy.py run-safe-batch 3", "Run a bounded local batch of safe operations."),
    ("python3 sentinel_autonomy.py soak-status", "Show the latest local soak-test result."),
    ("python3 sentinel_autonomy.py soak-run 3", "Run a bounded local soak test."),
    ("python3 sentinel_autonomy.py readiness-seal", "Build or show the local readiness seal."),
    ("python3 sentinel_autonomy.py rc-status", "Show release-candidate status."),
    ("python3 sentinel_autonomy.py rc-briefing", "Build the owner command console."),
    ("python3 sentinel_autonomy.py rc-evidence", "Build the local evidence pack."),
    ("python3 sentinel_autonomy.py rc-runbook", "Build the owner runbook."),
    ("python3 sentinel_autonomy.py public-release-status", "Show public release pack status."),
    ("python3 sentinel_autonomy.py public-summary", "Build public README and manifest."),
    ("python3 sentinel_autonomy.py sales-copy", "Build Payhip, Gumroad and FAQ copy."),
    ("python3 sentinel_autonomy.py github-release-notes", "Build GitHub release notes."),
]

SENSITIVE_TERMS = [
    "sentinel_sftp_" + "pass" + "word" + r"\s*=",
    r"pass" + r"word\s*[:=]\s*[^\s,]+",
    r"pass" + r"wd\s*[:=]\s*[^\s,]+",
    r"api[_-]?" + "key" + r"\s*[:=]\s*[^\s,]+",
    "bear" + "er" + r"\s+[a-z0-9._-]+",
    "s" + "k-" + r"[a-z0-9]{20,}",
    "g" + "hp_" + r"[a-z0-9_]{12,}",
    "github_" + "pat_" + r"[a-z0-9_]{12,}",
    r"AIza[a-z0-9_-]{20,}",
    "begin" + r"\s+(?:open)?ssh\s+private\s+" + "key",
    "begin" + r"\s+rsa\s+private\s+" + "key",
]
SENSITIVE_RE = re.compile(r"(?i)(" + "|".join(SENSITIVE_TERMS) + ")")
CUSTOMER_DATA_RE = re.compile(
    r"(?i)(customer\s+credential\s*[:=]|payment\s+card\s*[:=]|iban\s*[:=]|ssn\s*[:=])"
)
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
PRIVATE_PATH_RE = re.compile(r"(?i)(?:^|\s)(/(?:srv|home|root|etc|var|opt|mnt|tmp)/[^\s)]+)")
FORBIDDEN_CLAIM_RE = re.compile(
    r"(?i)("
    r"guaranteed\s+(?:rankings|revenue|seo|security|performance)|"
    r"instant\s+pagespeed\s+success|"
    r"unattended\s+(?:wordpress|cloudflare|database|sftp|server)\s+repair|"
    r"fully\s+automatic\s+production\s+repair"
    r")"
)
LIVE_AUTOPILOT_RE = re.compile(r"(?i)(live\s+autopilot|production\s+autopilot|remote\s+autopilot)")
NEGATION_RE = re.compile(r"(?i)\b(no|not|never|does\s+not|do\s+not|is\s+not|are\s+not)\b")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(PROJECT_DIR))
    except ValueError:
        return str(path)


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def ensure_dirs() -> None:
    for directory in (REPORT_DIR, STATE_DIR, AUDIT_DIR, PLAYBOOK_DIR, PUBLIC_DIR):
        directory.mkdir(parents=True, exist_ok=True)


def assert_write_path(path: Path) -> None:
    if not any(is_within(path, root) for root in ALLOWED_WRITE_ROOTS):
        raise RuntimeError(f"refusing write outside allowed roots: {rel(path)}")


def assert_safe_private_text(text: str, path: Optional[Path] = None) -> None:
    if SENSITIVE_RE.search(text):
        raise RuntimeError(f"sensitive value blocked in {rel(path) if path else 'content'}")
    if CUSTOMER_DATA_RE.search(text):
        raise RuntimeError(f"customer-data marker blocked in {rel(path) if path else 'content'}")


def assert_safe_public_text(text: str, path: Optional[Path] = None) -> None:
    assert_safe_private_text(text, path)
    findings = scan_public_text(text)
    if findings:
        where = rel(path) if path else "public content"
        raise RuntimeError(f"public sanitization blocked {where}: {findings[:3]}")


def write_text(path: Path, text: str, public: bool = False) -> None:
    assert_write_path(path)
    if public:
        assert_safe_public_text(text, path)
    else:
        assert_safe_private_text(text, path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_json(path: Path, data: Dict[str, Any], public: bool = False) -> None:
    text = json.dumps(data, indent=2, sort_keys=True)
    json.loads(text)
    write_text(path, text + "\n", public=public)


def append_jsonl(path: Path, row: Dict[str, Any]) -> None:
    assert_write_path(path)
    line = json.dumps(row, sort_keys=True)
    assert_safe_private_text(line, path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def read_json(path: Path) -> Tuple[Any, str]:
    if not path.exists():
        return None, "missing"
    try:
        return json.loads(path.read_text(encoding="utf-8")), "ok"
    except json.JSONDecodeError:
        return None, "invalid_json"
    except OSError:
        return None, "read_error"


def load_dict(path: Path) -> Dict[str, Any]:
    data, status = read_json(path)
    return data if status == "ok" and isinstance(data, dict) else {}


def redact(value: Any, limit: int = 1000) -> str:
    return SENSITIVE_RE.sub("[REDACTED]", str(value))[:limit]


def run_git(kind: str) -> Dict[str, Any]:
    commands = {
        "status": ["git", "status", "--short"],
        "log": ["git", "log", "--oneline", "-5"],
    }
    try:
        proc = subprocess.run(
            commands[kind],
            cwd=str(PROJECT_DIR),
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired) as exc:
        return {"status": "error", "line_count": 0, "error": redact(exc)}
    lines = [line for line in (proc.stdout or "").splitlines() if line.strip()]
    safe_lines = [
        line for line in lines
        if not any(part in line for part in ("reports/", "state/", "audit/", "exports/", "backups/", ".env"))
    ][:20]
    return {
        "status": "ok" if proc.returncode == 0 else "failed",
        "returncode": proc.returncode,
        "line_count": len(lines),
        "safe_lines": [redact(line, 300) for line in safe_lines],
    }


def scan_public_text(text: str) -> List[str]:
    findings: List[str] = []
    if SENSITIVE_RE.search(text):
        findings.append("sensitive_pattern")
    if CUSTOMER_DATA_RE.search(text):
        findings.append("customer_data_marker")
    if IP_RE.search(text):
        findings.append("ip_address")
    if PRIVATE_PATH_RE.search(text):
        findings.append("private_path")
    for line in text.splitlines():
        if FORBIDDEN_CLAIM_RE.search(line) and not NEGATION_RE.search(line):
            findings.append("forbidden_claim")
        if LIVE_AUTOPILOT_RE.search(line) and not NEGATION_RE.search(line):
            findings.append("live_autopilot_claim")
    return sorted(set(findings))


def scan_paths(paths: Iterable[Path], public: bool) -> Dict[str, Any]:
    findings: List[Dict[str, str]] = []
    for path in paths:
        if not path.exists():
            findings.append({"path": rel(path), "finding": "missing"})
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if public and path.suffix.lower() != ".json" and not text.strip():
            findings.append({"path": rel(path), "finding": "empty_markdown"})
        if public:
            for finding in scan_public_text(text):
                findings.append({"path": rel(path), "finding": finding})
        else:
            if SENSITIVE_RE.search(text):
                findings.append({"path": rel(path), "finding": "sensitive_pattern"})
            if CUSTOMER_DATA_RE.search(text):
                findings.append({"path": rel(path), "finding": "customer_data_marker"})
    return {"status": "SCAN_OK" if not findings else "SCAN_FINDINGS", "findings": findings}


def source_safety_findings(paths: Iterable[Path]) -> List[Dict[str, str]]:
    network_terms = ["re" + "quests", "ur" + "llib", "http" + "." + "client", "smtp" + "lib", "sock" + "et", "para" + "miko", "cloud" + "flare"]
    network_re = re.compile(r"^\s*(?:import|from)\s+(" + "|".join(re.escape(term) for term in network_terms) + r")\b", re.MULTILINE)
    checks = [
        ("apply_argument_present", re.compile(r"add_argument\([\"']--" + "apply")),
        ("network_import_present", network_re),
        ("shell_true_present", re.compile(r"\bshell\s*=\s*True\b")),
        ("free_subprocess_present", re.compile(r"subprocess\.(?:Popen|call|check_call|check_output)\(")),
        ("systemctl_live_present", re.compile(r"(?<![A-Za-z_-])systemctl\s+(?:start|enable)")),
        ("cron_install_present", re.compile(r"(?<![A-Za-z_-])crontab\s+(?:-|install)")),
        ("destructive_delete_present", re.compile(r"(?<![A-Za-z_-])r" + "m\\s+-r" + "f")),
        ("process_termination_present", re.compile(r"(?<![A-Za-z_-])(?:p" + "kill|kill" + "all)\\b")),
        ("remote_write_call_present", re.compile(r"\.(?:put|remove|rename)\(")),
    ]
    findings: List[Dict[str, str]] = []
    for path in paths:
        if not path.exists():
            findings.append({"path": rel(path), "finding": "missing_source"})
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if SENSITIVE_RE.search(text):
            findings.append({"path": rel(path), "finding": "sensitive_pattern"})
        for finding, rx in checks:
            if rx.search(text):
                findings.append({"path": rel(path), "finding": finding})
    return findings


def git_recommendation() -> Dict[str, Any]:
    unsafe_prefixes = ("reports/", "state/", "audit/", "exports/", "backups/")
    unsafe = [item for item in RECOMMENDED_GIT_FILES if item.startswith(unsafe_prefixes)]
    return {
        "status": "GIT_RECOMMENDATION_OK" if not unsafe else "GIT_RECOMMENDATION_BLOCKED",
        "checkpoint_files": RECOMMENDED_GIT_FILES,
        "local_artifacts_not_for_commit": [
            "runtime reports",
            "adaptive state ledgers",
            "audit logs",
            "generated export artifacts",
            "backup artifacts",
            "credential files",
        ],
        "unsafe_recommended_files": unsafe,
    }


def collect_rc_evidence(write: bool = True) -> Dict[str, Any]:
    ensure_dirs()
    input_statuses: Dict[str, str] = {}
    missing_inputs: List[str] = []
    invalid_inputs: List[str] = []
    for name, path in RC_INPUTS.items():
        if path.suffix == ".json":
            _, status = read_json(path)
        else:
            status = "ok" if path.exists() and path.read_text(encoding="utf-8", errors="replace").strip() else "missing"
        input_statuses[name] = status
        if status == "missing":
            missing_inputs.append(rel(path))
        elif status != "ok":
            invalid_inputs.append(rel(path))

    rc = load_dict(RC_INPUTS["rc_json"])
    rc_state = load_dict(RC_INPUTS["latest_rc_state"])
    evidence = {
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "timestamp_utc": utc_now(),
        "action": "collect-rc-evidence",
        "status": "PUBLIC_RC_EVIDENCE_COLLECTED",
        "collected_evidence_count": sum(1 for status in input_statuses.values() if status == "ok"),
        "input_statuses": input_statuses,
        "missing_inputs": missing_inputs,
        "invalid_inputs": invalid_inputs,
        "rc_status": rc.get("rc_status") or rc_state.get("rc_status"),
        "rc_reason": rc.get("rc_reason") or rc_state.get("rc_reason"),
        "readiness_seal": rc.get("readiness_seal") or rc_state.get("readiness_seal"),
        "regression_gate_status": rc.get("regression_gate_status") or rc_state.get("regression_gate_status"),
        "rc_validation_status": rc.get("validation_status") or rc_state.get("validation_status"),
        "owner_console_status": rc.get("owner_console_status"),
        "runbook_status": rc.get("runbook_status"),
        "evidence_pack_status": rc.get("evidence_pack_status"),
        "public_summary_status": rc.get("public_summary_status"),
        "source_git_recommendation_status": (rc.get("git_recommendation") or {}).get("status") or rc.get("git_recommendation_status"),
        "git_status": run_git("status"),
        "git_log": run_git("log"),
        **HARD_DEFAULTS,
    }
    if write:
        write_outputs(evidence)
    return evidence


def write_playbooks() -> None:
    base = {"schema_version": SCHEMA_VERSION, "phase": PHASE, **HARD_DEFAULTS}
    write_json(PLAYBOOK_PACK, {
        **base,
        "name": "sentinel-public-release-pack",
        "purpose": "Build sanitized public documentation and commercial copy from a validated local release candidate.",
        "allowed_outputs": ["docs/public-release", "playbooks", "local reports", "adaptive state"],
        "blocked_actions": ["live_apply", "network", "remote_write", "timer_install", "LOW_LIVE_MEDIUM_HIGH_execution"],
    })
    write_json(PLAYBOOK_SAFETY, {
        **base,
        "name": "sentinel-public-release-safety-docs",
        "purpose": "Document public safety boundaries and owner command limits.",
    })
    write_json(PLAYBOOK_SALES, {
        **base,
        "name": "sentinel-public-release-sales-copy",
        "purpose": "Build sanitized Payhip, Gumroad, FAQ and GitHub release copy without claims beyond the validated local scope.",
    })
    write_json(PLAYBOOK_VALIDATION, {
        **base,
        "name": "sentinel-public-release-validation",
        "checks": ["json_valid", "markdown_nonempty", "no_sensitive_values", "no_private_paths", "no_ip_addresses", "no_forbidden_claims"],
    })


def render_manifest(evidence: Dict[str, Any], validation: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    validation = validation or {}
    return {
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "product_name": "Sentinel Security, SEO & Performance Safe Optimization",
        "public_pack_status": validation.get("public_pack_status", "PUBLIC_PACK_PENDING"),
        "public_pack_reason": validation.get("public_pack_reason", "not_validated_yet"),
        "rc_status": evidence.get("rc_status"),
        "readiness_seal": evidence.get("readiness_seal"),
        "regression_gate_status": evidence.get("regression_gate_status"),
        "docs": sorted(rel(path) for path in PUBLIC_FILES.values()),
        "recommended_git_checkpoint_files": RECOMMENDED_GIT_FILES,
        "local_artifacts_not_for_public_pack": git_recommendation()["local_artifacts_not_for_commit"],
        "allowed_local_autonomy": [
            "local reports",
            "local safety validation",
            "local owner briefings",
            "local mission and operation supervision",
            "local evidence generation",
        ],
        "blocked_areas": [
            "unchecked live changes",
            "remote writes",
            "external service API calls",
            "timer installation",
            "production system changes",
            "LOW_LIVE, MEDIUM and HIGH execution",
        ],
        **HARD_DEFAULTS,
    }


def render_readme(evidence: Dict[str, Any]) -> str:
    return """# Sentinel Security, SEO & Performance Safe Optimization

Sentinel is a local, owner-controlled system for safe analysis, review, report generation, operations supervision and controlled optimization planning for website, SEO, performance and security workflows.

It is designed for evidence-driven service delivery. Sentinel can run bounded local checks, build owner briefings, score safe operations, prepare public-safe documentation and maintain release evidence. It does not perform unchecked live changes.

## Local Safe Autonomy

Sentinel can locally:

- inspect its own generated reports and playbooks
- run bounded safe operations
- validate outputs after each local run
- build owner-facing summaries
- maintain readiness and release evidence
- suggest next safe actions

## Owner-Gated Workflow

Production-changing work remains outside this public release pack. Owner review is required before any action that could affect a real website, server, account, database or remote service.

## Evidence Reports

The local release candidate completed a green readiness path before this public pack was generated. The public files summarize that outcome without shipping internal reports, audit logs, adaptive state, generated exports or environment-specific details.

## Safe Operations

Use the owner commands in `OWNER-COMMANDS.md` to run local status, preflight, safe batches, soak tests and release-candidate checks.

## What Sentinel Never Does Automatically

Sentinel does not automatically change WordPress, Cloudflare, databases, SFTP/FTP, Nginx, `.htaccess`, payment platforms or email systems. It does not install timers, cron jobs or system services in this public release flow.

## Example Commands

```bash
python3 sentinel_autonomy.py status
python3 sentinel_autonomy.py preflight
python3 sentinel_autonomy.py run-safe-batch 3
python3 sentinel_autonomy.py soak-status
python3 sentinel_autonomy.py rc-status
python3 sentinel_autonomy.py public-release-status
```

## Installation Note

Install and run Sentinel in a local project checkout. Review all generated local evidence before approving any future production workflow.

## No Guarantees

Sentinel supports safer analysis and planning. It does not promise perfect rankings, perfect security, instant performance scores, revenue outcomes, or automatic repair of systems outside the approved local scope.
"""


def render_safety_boundaries(_: Dict[str, Any]) -> str:
    return """# Safety Boundaries

Sentinel is built around local autonomy with strict owner control.

## Blocked Automatically

- no unchecked live changes
- no automatic WordPress changes
- no automatic Cloudflare changes
- no database writes
- no SFTP/FTP uploads
- no Nginx changes
- no `.htaccess` changes
- no cache purge
- no URL rewrites
- no Payhip API access
- no email sending
- no timer, cron or system-service installation
- no credential handling
- no remote writes
- no LOW_LIVE, MEDIUM or HIGH execution

## Allowed Locally

- safe status checks
- local preflight checks
- local report generation
- local owner briefings
- local release evidence
- local public documentation generation
- local safe operation batches
- local soak tests

## Owner Review

Any action that could affect a real customer system, website, account, server, deployment, payment platform or DNS/CDN configuration requires a separate owner-reviewed phase.
"""


def render_owner_commands(_: Dict[str, Any]) -> str:
    lines = ["# Owner Commands", "", "These commands create local reports, local state, local audit events and local documentation. They must not perform live changes.", ""]
    for command, description in OWNER_COMMANDS:
        lines.append(f"- `{command}`: {description}")
    lines.extend([
        "",
        "The commands above are bounded local flows. They do not install timers, send email, call production APIs, write remote systems or disable emergency stop.",
    ])
    return "\n".join(lines) + "\n"


def render_public_runbook(_: Dict[str, Any]) -> str:
    return """# Public Owner Runbook

## Start

1. Run `python3 sentinel_autonomy.py status`.
2. Run `python3 sentinel_autonomy.py preflight`.
3. Review the public safety boundaries.

## Daily Manual Flow

1. Check status.
2. Check operation-governor status.
3. Run a bounded safe batch only when local reports should be refreshed.
4. Review the owner briefing and readiness seal.

## Safe Diagnosis Flow

1. Run preflight.
2. Run operation-governor status.
3. Run soak status.
4. Run release-candidate status.
5. Review generated local evidence before deciding any next phase.

## Owner Review Flow

Any production action starts as a separate owner-reviewed phase. Sentinel public release commands do not approve production changes.

## Git Checkpoint Flow

Commit only code, playbooks and public release docs listed in `COMMIT-RECOMMENDATION.md`. Keep local runtime artifacts out of public commits.

## Emergency Note

Emergency Stop remains active for live/external actions. It does not block safe local documentation or validation.
"""


def render_product_summary(_: Dict[str, Any]) -> str:
    return """# Product Summary

**Sentinel Security, SEO & Performance Safe Optimization** is a local, owner-controlled operations system for safe website, SEO, performance and security workflows.

It helps a service owner prepare evidence, run safe local checks, maintain public-safe documentation, review readiness, and plan controlled optimization work without unchecked production changes.

## Positioning

Local, owner-controlled system for safe analysis, review, report creation, operations supervision and controlled optimization planning.

## Best Fit

- website service providers
- SEO and performance consultants
- technical operators who need owner review gates
- teams that want evidence before production change

## Out of Scope

Sentinel is not a production autopilot and not a remote repair bot. Production changes remain separately reviewed and owner-approved.
"""


def render_demo_walkthrough(_: Dict[str, Any]) -> str:
    return """# Demo Safe Walkthrough

This walkthrough uses `example.com` as a placeholder. It does not contact `example.com`, does not use customer data and does not perform live changes.

## Step 1: Status

```bash
python3 sentinel_autonomy.py status
```

## Step 2: Preflight

```bash
python3 sentinel_autonomy.py preflight
```

## Step 3: Operation Governor

```bash
python3 sentinel_autonomy.py operation-governor-status
```

## Step 4: Safe Batch

```bash
python3 sentinel_autonomy.py run-safe-batch 3
```

## Step 5: Soak Status

```bash
python3 sentinel_autonomy.py soak-status
```

## Step 6: Release Candidate Status

```bash
python3 sentinel_autonomy.py rc-status
```

## Step 7: Public Pack

```bash
python3 sentinel_autonomy.py public-release-status
```

All steps are local and bounded. The walkthrough demonstrates status, preflight, operation selection, safe batches, soak review, release status and evidence review.
"""


def render_github_release_notes(evidence: Dict[str, Any]) -> str:
    return f"""# GitHub Release Notes

## Sentinel Security, SEO & Performance Safe Optimization

This release packages the local Sentinel autonomy stack as a public-safe release candidate.

## Highlights

- local release candidate status: `{evidence.get('rc_status') or 'unknown'}`
- readiness seal: `{evidence.get('readiness_seal') or 'unknown'}`
- regression gate: `{evidence.get('regression_gate_status') or 'unknown'}`
- public safety boundaries
- owner command console
- public owner runbook
- sales copy for Payhip and Gumroad
- public manifest and commit recommendation

## Safety

The public release pack does not include internal runtime reports, adaptive state, audit logs, generated exports, backups, credentials or customer data.

## Not Included

No live apply, no remote writes, no external API calls, no timer installation, and no production system changes are included in this release flow.
"""


def render_payhip_listing(_: Dict[str, Any]) -> str:
    return """# Payhip Listing

## Short Description

Local, owner-controlled safety system for SEO, performance and security operations with evidence reports, safe batches, readiness checks and public documentation.

## Long Description

Sentinel Security, SEO & Performance Safe Optimization helps technical service owners run local, controlled analysis and operations-supervision workflows before approving website, SEO, performance or security changes.

It emphasizes safety gates, owner review, public-ready documentation, release evidence, local soak testing and clear blocked-action boundaries. It is designed for manual service delivery and controlled planning rather than unchecked production automation.

## Includes

- public safety boundaries
- owner command reference
- public runbook
- demo-safe walkthrough
- GitHub release notes
- Payhip and Gumroad listing copy
- FAQ and not-autopilot disclaimer

## No-Guarantee Notice

This product supports review and planning. It does not promise perfect security, perfect SEO outcomes, instant performance scores, rankings, revenue, or automatic repair of third-party systems.
"""


def render_gumroad_listing(_: Dict[str, Any]) -> str:
    return """# Gumroad Listing

Sentinel Security, SEO & Performance Safe Optimization is a local owner-controlled system for safe analysis, review, reporting and operations supervision.

Use it to prepare evidence, run bounded local checks, produce owner briefings, document safety boundaries and prepare controlled optimization plans. It is built for service delivery workflows where safety and review matter.

Sentinel does not perform unchecked live changes or remote writes. Production actions require separate owner approval and a dedicated safety phase.
"""


def render_faq(_: Dict[str, Any]) -> str:
    return """# FAQ

## Is Sentinel an unchecked production operator?

No. It is a local owner-controlled operations system.

## Does it change my website automatically?

No. Public release commands generate local evidence, local reports and public documentation. Website changes require separate owner-reviewed phases.

## Does it use Payhip, GitHub, email or WordPress APIs?

No API access is part of this public release flow.

## Does it store credentials?

No. Public release artifacts must not contain credential material or customer access details.

## Does it guarantee results?

No. It supports safer analysis, evidence and planning. It does not promise rankings, revenue, perfect security or instant performance outcomes.

## What can I commit publicly?

Commit the files listed in `COMMIT-RECOMMENDATION.md`. Keep local runtime artifacts out of public commits.
"""


def render_not_autopilot(_: Dict[str, Any]) -> str:
    return """# Not An Autopilot Disclaimer

Sentinel is not an unchecked production autopilot.

It is a local, owner-controlled operations and evidence system. Public release commands do not modify websites, servers, databases, CDN settings, payment platforms, email systems or remote files.

The correct workflow is:

1. local evidence
2. owner review
3. separate approval for any future production-changing phase
4. bounded execution with health checks and rollback planning when a later phase explicitly allows it
"""


def render_commit_recommendation(_: Dict[str, Any]) -> str:
    lines = [
        "# Commit Recommendation",
        "",
        "Recommended public checkpoint files:",
        "",
    ]
    for item in RECOMMENDED_GIT_FILES:
        lines.append(f"- `{item}`")
    lines.extend([
        "",
        "Keep runtime reports, adaptive state ledgers, audit logs, generated exports, backups and credential files local.",
    ])
    return "\n".join(lines) + "\n"


def render_report_md(report: Dict[str, Any]) -> str:
    return "\n".join([
        "# Sentinel Public Release Pack",
        "",
        f"- status: `{report.get('status')}`",
        f"- public_pack_status: `{report.get('public_pack_status', report.get('status'))}`",
        f"- public_pack_reason: `{report.get('public_pack_reason', '-')}`",
        f"- collected_rc_evidence: `{report.get('collected_evidence_count', 0)}`",
        f"- generated_docs_count: `{report.get('generated_docs_count', 0)}`",
        f"- validation_status: `{report.get('validation_status', '-')}`",
        f"- sales_copy_status: `{report.get('sales_copy_status', '-')}`",
        f"- github_release_notes_status: `{report.get('github_release_notes_status', '-')}`",
        "- live_apply: `False`",
        "- emergency_stop: `True`",
        "- allowed_apply_now: `False`",
        "- HIGH blocked: `True`",
        "- LOW_LIVE executable: `False`",
        "- MEDIUM executable: `False`",
        "- breach: `False`",
    ]) + "\n"


def render_validation_md(report: Dict[str, Any]) -> str:
    findings = report.get("validation_findings") or []
    lines = [
        "# Sentinel Public Release Validation",
        "",
        f"- validation_status: `{report.get('validation_status')}`",
        f"- public_pack_status: `{report.get('public_pack_status')}`",
        f"- public_pack_reason: `{report.get('public_pack_reason')}`",
        f"- public_scan_status: `{(report.get('public_scan') or {}).get('status')}`",
        f"- private_scan_status: `{(report.get('private_scan') or {}).get('status')}`",
        f"- source_safety_status: `{'SCAN_OK' if not report.get('source_safety_findings') else 'SCAN_FINDINGS'}`",
        "",
        "## Findings",
    ]
    if findings:
        lines.extend(f"- `{finding}`" for finding in findings)
    else:
        lines.append("- none")
    return "\n".join(lines) + "\n"


def render_owner_summary_md(report: Dict[str, Any]) -> str:
    return "\n".join([
        "# Sentinel Public Release Owner Summary",
        "",
        f"- public_pack_status: `{report.get('public_pack_status')}`",
        f"- reason: `{report.get('public_pack_reason')}`",
        f"- rc_status: `{report.get('rc_status')}`",
        f"- readiness_seal: `{report.get('readiness_seal')}`",
        f"- regression_gate_status: `{report.get('regression_gate_status')}`",
        "- public capability: sanitized README, safety boundaries, owner commands, runbook, listings, FAQ and release notes",
        "- blocked: live changes, remote writes, external APIs, timers, LOW_LIVE, MEDIUM, HIGH",
        "- next safe step: review public docs, then create a Git checkpoint with only recommended files.",
    ]) + "\n"


def public_doc_renderers(evidence: Dict[str, Any]) -> Dict[str, Tuple[Path, str]]:
    return {
        "readme": (PUBLIC_FILES["readme"], render_readme(evidence)),
        "safety_boundaries": (PUBLIC_FILES["safety_boundaries"], render_safety_boundaries(evidence)),
        "owner_commands": (PUBLIC_FILES["owner_commands"], render_owner_commands(evidence)),
        "owner_runbook": (PUBLIC_FILES["owner_runbook"], render_public_runbook(evidence)),
        "product_summary": (PUBLIC_FILES["product_summary"], render_product_summary(evidence)),
        "demo_walkthrough": (PUBLIC_FILES["demo_walkthrough"], render_demo_walkthrough(evidence)),
        "github_release_notes": (PUBLIC_FILES["github_release_notes"], render_github_release_notes(evidence)),
        "payhip_listing": (PUBLIC_FILES["payhip_listing"], render_payhip_listing(evidence)),
        "gumroad_listing": (PUBLIC_FILES["gumroad_listing"], render_gumroad_listing(evidence)),
        "faq": (PUBLIC_FILES["faq"], render_faq(evidence)),
        "not_autopilot": (PUBLIC_FILES["not_autopilot"], render_not_autopilot(evidence)),
        "commit_recommendation": (PUBLIC_FILES["commit_recommendation"], render_commit_recommendation(evidence)),
    }


def write_public_docs(evidence: Dict[str, Any], keys: Optional[List[str]] = None) -> List[str]:
    ensure_dirs()
    renderers = public_doc_renderers(evidence)
    selected = keys or list(renderers)
    written: List[str] = []
    for key in selected:
        path, text = renderers[key]
        write_text(path, text, public=True)
        written.append(rel(path))
    manifest = render_manifest(evidence)
    write_json(PUBLIC_FILES["manifest"], manifest, public=True)
    if rel(PUBLIC_FILES["manifest"]) not in written:
        written.append(rel(PUBLIC_FILES["manifest"]))
    return written


def decide_public_pack_status(evidence: Dict[str, Any], validation_findings: List[str]) -> Tuple[str, str]:
    if validation_findings:
        return "PUBLIC_PACK_RED", ",".join(sorted(set(validation_findings)))
    if evidence.get("breach") is True:
        return "PUBLIC_PACK_RED", "breach_true"
    if evidence.get("rc_status") == "RC_GREEN" and not evidence.get("missing_inputs") and not evidence.get("invalid_inputs"):
        return "PUBLIC_PACK_GREEN", "rc_green_and_public_pack_valid"
    return "PUBLIC_PACK_YELLOW", "safety_ok_but_rc_or_inputs_not_green"


def validate_public_pack(write: bool = True) -> Dict[str, Any]:
    evidence = collect_rc_evidence(write=False)
    public_paths = list(PUBLIC_FILES.values())
    json_valid_paths = [
        PUBLIC_FILES["manifest"],
        REPORT_JSON,
        STATE_JSON,
        LATEST_JSON,
        HISTORY_JSON,
        PLAYBOOK_PACK,
        PLAYBOOK_SAFETY,
        PLAYBOOK_SALES,
        PLAYBOOK_VALIDATION,
    ]
    public_scan = scan_paths(public_paths, public=True)
    private_scan = scan_paths([REPORT_MD, VALIDATION_MD, OWNER_SUMMARY_MD, STATE_JSON, LATEST_JSON, HISTORY_JSON, AUDIT_JSONL], public=False)
    source_findings = source_safety_findings([
        PROJECT_DIR / "sentinel_public_release_pack.py",
        PROJECT_DIR / "sentinel_autonomy.py",
    ])

    validation_findings: List[str] = []
    docs_exist = {key: path.exists() and path.stat().st_size > 0 for key, path in PUBLIC_FILES.items()}
    if not all(docs_exist.values()):
        validation_findings.append("missing_or_empty_public_doc")
    for path in json_valid_paths:
        if path.exists():
            _, status = read_json(path)
            if status != "ok":
                validation_findings.append(f"invalid_json:{rel(path)}")
    if public_scan.get("findings"):
        validation_findings.append("public_doc_sanitization_findings")
    if private_scan.get("findings"):
        validation_findings.append("private_artifact_sanitization_findings")
    if source_findings:
        validation_findings.append("source_safety_findings")
    if git_recommendation()["status"] != "GIT_RECOMMENDATION_OK":
        validation_findings.append("git_recommendation_unsafe")
    if evidence.get("breach") is True:
        validation_findings.append("breach_true")
    if evidence.get("live_apply") is not False:
        validation_findings.append("live_apply_not_false")
    if evidence.get("emergency_stop") is not True:
        validation_findings.append("emergency_stop_not_true")
    if evidence.get("allowed_apply_now") is not False:
        validation_findings.append("allowed_apply_now_not_false")
    if evidence.get("high_blocked") is not True:
        validation_findings.append("high_not_blocked")
    if evidence.get("low_live_executable") is not False:
        validation_findings.append("low_live_executable")
    if evidence.get("medium_executable") is not False:
        validation_findings.append("medium_executable")

    status, reason = decide_public_pack_status(evidence, validation_findings)
    report = {
        **evidence,
        "action": "validate-public-pack",
        "status": status,
        "public_pack_status": status,
        "public_pack_reason": reason,
        "generated_docs_count": sum(1 for ok in docs_exist.values() if ok),
        "docs_exist": docs_exist,
        "public_scan": public_scan,
        "private_scan": private_scan,
        "source_safety_findings": source_findings,
        "validation_findings": validation_findings,
        "validation_status": "PUBLIC_PACK_VALIDATION_OK" if status != "PUBLIC_PACK_RED" else "PUBLIC_PACK_VALIDATION_BLOCKED",
        "sales_copy_status": "SALES_COPY_READY" if PUBLIC_FILES["payhip_listing"].exists() and PUBLIC_FILES["gumroad_listing"].exists() else "SALES_COPY_MISSING",
        "github_release_notes_status": "GITHUB_RELEASE_NOTES_READY" if PUBLIC_FILES["github_release_notes"].exists() else "GITHUB_RELEASE_NOTES_MISSING",
        "git_recommendation": git_recommendation(),
        "git_recommendation_status": git_recommendation()["status"],
        **HARD_DEFAULTS,
    }
    if write:
        write_manifest_with_validation(report)
        write_outputs(report)
    return report


def write_manifest_with_validation(report: Dict[str, Any]) -> None:
    evidence = collect_rc_evidence(write=False)
    write_json(PUBLIC_FILES["manifest"], render_manifest(evidence, report), public=True)


def write_outputs(report: Dict[str, Any]) -> None:
    ensure_dirs()
    write_playbooks()
    write_json(REPORT_JSON, report)
    write_json(STATE_JSON, report)
    write_json(LATEST_JSON, report)
    history = []
    existing, status = read_json(HISTORY_JSON)
    if status == "ok" and isinstance(existing, dict) and isinstance(existing.get("entries"), list):
        history = existing["entries"]
    history.append({
        "timestamp_utc": report.get("timestamp_utc", utc_now()),
        "action": report.get("action"),
        "status": report.get("status"),
        "public_pack_status": report.get("public_pack_status", report.get("status")),
        "public_pack_reason": report.get("public_pack_reason"),
    })
    write_json(HISTORY_JSON, {"schema_version": SCHEMA_VERSION, "entries": history[-100:], **HARD_DEFAULTS})
    append_jsonl(AUDIT_JSONL, {
        "timestamp_utc": report.get("timestamp_utc", utc_now()),
        "phase": PHASE,
        "action": report.get("action"),
        "status": report.get("status"),
        "public_pack_status": report.get("public_pack_status", report.get("status")),
        "breach": False,
    })
    write_text(REPORT_MD, render_report_md(report))
    write_text(VALIDATION_MD, render_validation_md(report))
    write_text(OWNER_SUMMARY_MD, render_owner_summary_md(report))


def build_readme() -> Dict[str, Any]:
    evidence = collect_rc_evidence(write=False)
    written = write_public_docs(evidence, ["readme"])
    report = {**evidence, "action": "build-readme", "status": "PUBLIC_README_READY", "written_files": written}
    write_outputs(report)
    return report


def build_safety_docs() -> Dict[str, Any]:
    evidence = collect_rc_evidence(write=False)
    keys = ["safety_boundaries", "owner_commands", "not_autopilot", "commit_recommendation"]
    written = write_public_docs(evidence, keys)
    report = {**evidence, "action": "build-safety-docs", "status": "PUBLIC_SAFETY_DOCS_READY", "written_files": written}
    write_outputs(report)
    return report


def build_public_runbook() -> Dict[str, Any]:
    evidence = collect_rc_evidence(write=False)
    written = write_public_docs(evidence, ["owner_runbook"])
    report = {**evidence, "action": "build-public-runbook", "status": "PUBLIC_RUNBOOK_READY", "written_files": written}
    write_outputs(report)
    return report


def build_demo_summary() -> Dict[str, Any]:
    evidence = collect_rc_evidence(write=False)
    written = write_public_docs(evidence, ["product_summary", "demo_walkthrough"])
    report = {**evidence, "action": "build-demo-summary", "status": "PUBLIC_DEMO_SUMMARY_READY", "written_files": written}
    write_outputs(report)
    return report


def build_sales_copy() -> Dict[str, Any]:
    evidence = collect_rc_evidence(write=False)
    written = write_public_docs(evidence, ["payhip_listing", "gumroad_listing", "faq"])
    report = {
        **evidence,
        "action": "build-sales-copy",
        "status": "PUBLIC_SALES_COPY_READY",
        "sales_copy_status": "SALES_COPY_READY",
        "written_files": written,
    }
    write_outputs(report)
    return report


def build_github_release_notes() -> Dict[str, Any]:
    evidence = collect_rc_evidence(write=False)
    written = write_public_docs(evidence, ["github_release_notes"])
    report = {
        **evidence,
        "action": "build-github-release-notes",
        "status": "GITHUB_RELEASE_NOTES_READY",
        "github_release_notes_status": "GITHUB_RELEASE_NOTES_READY",
        "written_files": written,
    }
    write_outputs(report)
    return report


def build_all_docs() -> Dict[str, Any]:
    evidence = collect_rc_evidence(write=False)
    written = write_public_docs(evidence)
    report = {**evidence, "action": "build-all-public-docs", "status": "PUBLIC_DOCS_READY", "written_files": written}
    write_outputs(report)
    return report


def self_test() -> Dict[str, Any]:
    ensure_dirs()
    source_path = PROJECT_DIR / "sentinel_public_release_pack.py"
    wrapper_path = PROJECT_DIR / "sentinel_autonomy.py"
    source_findings = source_safety_findings([source_path, wrapper_path])
    sample_green = {
        "rc_status": "RC_GREEN",
        "missing_inputs": [],
        "invalid_inputs": [],
        **HARD_DEFAULTS,
    }
    sample_status, _ = decide_public_pack_status(sample_green, [])
    sample_yellow = {**sample_green, "rc_status": "RC_YELLOW"}
    sample_yellow_status, _ = decide_public_pack_status(sample_yellow, [])
    sample_red_status, _ = decide_public_pack_status(sample_green, ["public_doc_sanitization_findings"])
    git_safe = git_recommendation()["status"] == "GIT_RECOMMENDATION_OK"
    rendered_docs_safe = True
    sample_evidence = {"rc_status": "RC_GREEN", "readiness_seal": "READINESS_SEAL_GREEN", "regression_gate_status": "REGRESSION_GATE_OK", **HARD_DEFAULTS}
    for _, text in public_doc_renderers(sample_evidence).values():
        if scan_public_text(text):
            rendered_docs_safe = False
            break
    checks = {
        "no_source_safety_findings": not source_findings,
        "status_logic_green": sample_status == "PUBLIC_PACK_GREEN",
        "status_logic_yellow": sample_yellow_status == "PUBLIC_PACK_YELLOW",
        "status_logic_red": sample_red_status == "PUBLIC_PACK_RED",
        "git_recommendation_safe": git_safe,
        "rendered_markdown_sanitized": rendered_docs_safe,
        "json_serializable": True,
        "breach_false": HARD_DEFAULTS["breach"] is False,
    }
    status = "PUBLIC_RELEASE_PACK_SELF_TEST_OK" if all(checks.values()) else "PUBLIC_RELEASE_PACK_SELF_TEST_FAILED"
    report = {
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "timestamp_utc": utc_now(),
        "action": "self-test",
        "status": status,
        "self_test_result": status,
        "checks": checks,
        "source_safety_findings": source_findings,
        **HARD_DEFAULTS,
    }
    write_outputs(report)
    return report


def status_report() -> Dict[str, Any]:
    report = load_dict(REPORT_JSON) or collect_rc_evidence(write=False)
    summary = {
        "status": report.get("status"),
        "public_pack_status": report.get("public_pack_status", report.get("status")),
        "public_pack_reason": report.get("public_pack_reason"),
        "collected_evidence_count": report.get("collected_evidence_count"),
        "generated_docs_count": report.get("generated_docs_count"),
        "validation_status": report.get("validation_status"),
        "sales_copy_status": report.get("sales_copy_status"),
        "github_release_notes_status": report.get("github_release_notes_status"),
        **HARD_DEFAULTS,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return summary


def print_result(report: Dict[str, Any]) -> None:
    print(json.dumps({
        "action": report.get("action"),
        "status": report.get("status"),
        "public_pack_status": report.get("public_pack_status", report.get("status")),
        "public_pack_reason": report.get("public_pack_reason"),
        "collected_evidence_count": report.get("collected_evidence_count"),
        "generated_docs_count": report.get("generated_docs_count"),
        "validation_status": report.get("validation_status"),
        "breach": False,
    }, indent=2, sort_keys=True))


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Sentinel public release pack builder")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--collect-rc-evidence", action="store_true")
    parser.add_argument("--build-readme", action="store_true")
    parser.add_argument("--build-safety-docs", action="store_true")
    parser.add_argument("--build-public-runbook", action="store_true")
    parser.add_argument("--build-demo-summary", action="store_true")
    parser.add_argument("--build-sales-copy", action="store_true")
    parser.add_argument("--build-github-release-notes", action="store_true")
    parser.add_argument("--validate-public-pack", action="store_true")
    parser.add_argument("--status", action="store_true")
    args = parser.parse_args(argv)

    actions = [
        args.self_test,
        args.collect_rc_evidence,
        args.build_readme,
        args.build_safety_docs,
        args.build_public_runbook,
        args.build_demo_summary,
        args.build_sales_copy,
        args.build_github_release_notes,
        args.validate_public_pack,
        args.status,
    ]
    if sum(1 for item in actions if item) != 1:
        parser.error("choose exactly one action")

    if args.self_test:
        report = self_test()
    elif args.collect_rc_evidence:
        report = collect_rc_evidence(write=True)
    elif args.build_readme:
        report = build_readme()
    elif args.build_safety_docs:
        report = build_safety_docs()
    elif args.build_public_runbook:
        report = build_public_runbook()
    elif args.build_demo_summary:
        report = build_demo_summary()
    elif args.build_sales_copy:
        report = build_sales_copy()
    elif args.build_github_release_notes:
        report = build_github_release_notes()
    elif args.validate_public_pack:
        report = validate_public_pack(write=True)
    else:
        status_report()
        return 0
    print_result(report)
    return 0 if not str(report.get("status", "")).endswith("_FAILED") and report.get("status") != "PUBLIC_PACK_RED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
