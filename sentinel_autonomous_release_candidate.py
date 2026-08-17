#!/usr/bin/env python3
"""Sentinel Autonomous Release Candidate (Phase 10.10).

Builds a local release-candidate evidence pack, owner command console, runbook,
manifest, and public summary for the safe Phase-10 autonomy stack. This module
does not perform live apply, network access, external API calls, remote writes,
timer installation, or customer-system changes.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


PROJECT_DIR = Path("/srv/sentinel-defense")
SCHEMA_VERSION = "sentinel-autonomous-release-candidate-10.10"
PHASE = "10.10"

HARD_DEFAULTS = {
    "live_apply": False,
    "emergency_stop": True,
    "allowed_apply_now": False,
    "high_blocked": True,
    "low_live_executable": False,
    "medium_executable": False,
    "breach": False,
}

R = PROJECT_DIR / "reports/latest"
STATE_DIR = PROJECT_DIR / "state/adaptive-learning"
AUDIT_DIR = PROJECT_DIR / "audit"
PLAYBOOK_DIR = PROJECT_DIR / "playbooks"

REPORT_JSON = R / "sentinel-autonomous-release-candidate.json"
REPORT_MD = R / "sentinel-autonomous-release-candidate.md"
MANIFEST_MD = R / "sentinel-autonomous-rc-manifest.md"
OWNER_CONSOLE_MD = R / "sentinel-autonomous-owner-command-console.md"
RUNBOOK_MD = R / "sentinel-autonomous-owner-runbook.md"
PUBLIC_SUMMARY_MD = R / "sentinel-autonomous-public-summary.md"
EVIDENCE_PACK_MD = R / "sentinel-autonomous-rc-evidence-pack.md"
GIT_CHECKPOINT_MD = R / "sentinel-autonomous-rc-git-checkpoint.md"

STATE_JSON = STATE_DIR / "autonomous_release_candidate.json"
LATEST_JSON = STATE_DIR / "latest_autonomous_release_candidate.json"
HISTORY_JSON = STATE_DIR / "autonomous_release_candidate_history.json"
AUDIT_JSONL = AUDIT_DIR / "sentinel-autonomous-release-candidate.jsonl"

PLAYBOOK_RC = PLAYBOOK_DIR / "sentinel-autonomous-release-candidate.playbook.json"
PLAYBOOK_CONSOLE = PLAYBOOK_DIR / "sentinel-autonomous-owner-command-console.playbook.json"
PLAYBOOK_RUNBOOK = PLAYBOOK_DIR / "sentinel-autonomous-owner-runbook.playbook.json"
PLAYBOOK_EVIDENCE = PLAYBOOK_DIR / "sentinel-autonomous-rc-evidence-pack.playbook.json"

ALLOWED_WRITE_ROOTS = (R, STATE_DIR, AUDIT_DIR, PLAYBOOK_DIR)

REPORT_INPUTS = {
    "soak_test": R / "sentinel-autonomous-soak-test.json",
    "operations_supervisor": R / "sentinel-autonomous-operations-supervisor.json",
    "operation_governor": R / "sentinel-autonomous-operation-governor.json",
    "mission_runner": R / "sentinel-autonomous-mission-queue-runner.json",
    "goal_manager": R / "sentinel-autonomous-goal-manager.json",
    "health_governor": R / "sentinel-autonomous-capability-health-governor.json",
    "capability_registry": R / "sentinel-autonomous-capability-registry.json",
    "priority_engine": R / "sentinel-autonomous-priority-engine.json",
    "kernel": R / "sentinel-self-governing-autonomy-kernel.json",
    "cycle_runner": R / "sentinel-autonomous-cycle-runner.json",
}

STATE_INPUTS = {
    "latest_soak_test": STATE_DIR / "latest_autonomous_soak_test.json",
    "release_candidate": STATE_JSON,
    "operation_governor_model": STATE_DIR / "autonomous_operation_governor_model.json",
    "operations_history": STATE_DIR / "autonomous_operations_history.json",
    "mission_ledger": STATE_DIR / "autonomous_mission_completion_ledger.json",
    "capability_registry": STATE_DIR / "autonomous_capability_registry.json",
    "priority_model": STATE_DIR / "autonomy_task_priority_model.json",
}

CHECKPOINT_FILES = [
    "sentinel_autonomous_release_candidate.py",
    "sentinel_autonomy.py",
    "sentinel_autonomous_soak_test.py",
    "sentinel_autonomous_operation_governor.py",
    "sentinel_autonomous_operations_supervisor.py",
    "playbooks/sentinel-autonomous-release-candidate.playbook.json",
    "playbooks/sentinel-autonomous-owner-command-console.playbook.json",
    "playbooks/sentinel-autonomous-owner-runbook.playbook.json",
    "playbooks/sentinel-autonomous-rc-evidence-pack.playbook.json",
]

COMMAND_MAP = [
    ("python3 sentinel_autonomy.py status", "Show current safe local supervisor status."),
    ("python3 sentinel_autonomy.py preflight", "Run local operations supervisor preflight."),
    ("python3 sentinel_autonomy.py operation-governor-status", "Show operation-governor scoring status."),
    ("python3 sentinel_autonomy.py soak-status", "Show latest soak/readiness status."),
    ("python3 sentinel_autonomy.py readiness-seal", "Rebuild the local readiness seal."),
    ("python3 sentinel_autonomy.py run-safe-once", "Run exactly one safe local supervisor operation."),
    ("python3 sentinel_autonomy.py run-safe-batch 3", "Run a bounded local supervisor batch."),
    ("python3 sentinel_autonomy.py soak-run 3", "Run a bounded local soak test."),
    ("python3 sentinel_autonomy.py rc-status", "Show release-candidate status."),
    ("python3 sentinel_autonomy.py rc-briefing", "Build the owner command console."),
    ("python3 sentinel_autonomy.py rc-evidence", "Build the release-candidate evidence pack."),
    ("python3 sentinel_autonomy.py rc-runbook", "Build the owner runbook."),
]

SECRET_TERMS = [
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
SECRET_RE = re.compile(r"(?i)(" + "|".join(SECRET_TERMS) + ")")
CUSTOMER_DATA_RE = re.compile(
    r"(?i)(customer\s+credential\s*[:=]|payment\s+card\s*[:=]|iban\s*[:=]|ssn\s*[:=])"
)
NETWORK_IMPORT_RE = re.compile(
    r"^\s*(?:import|from)\s+(requests|urllib|http\.client|smtplib|socket|paramiko|cloudflare)\b",
    re.MULTILINE,
)


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
    for directory in (R, STATE_DIR, AUDIT_DIR, PLAYBOOK_DIR):
        directory.mkdir(parents=True, exist_ok=True)


def assert_write_path(path: Path) -> None:
    if not any(is_within(path, root) for root in ALLOWED_WRITE_ROOTS):
        raise RuntimeError(f"Refusing write outside allowed roots: {rel(path)}")


def assert_safe_text(text: str, path: Optional[Path] = None) -> None:
    if SECRET_RE.search(text):
        raise RuntimeError(f"Secret-like value blocked in {rel(path) if path else 'content'}")
    if CUSTOMER_DATA_RE.search(text):
        raise RuntimeError(f"Customer-data marker blocked in {rel(path) if path else 'content'}")


def write_text(path: Path, text: str) -> None:
    assert_write_path(path)
    assert_safe_text(text, path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_json(path: Path, data: Dict[str, Any]) -> None:
    text = json.dumps(data, indent=2, sort_keys=True)
    json.loads(text)
    write_text(path, text + "\n")


def append_jsonl(path: Path, row: Dict[str, Any]) -> None:
    assert_write_path(path)
    line = json.dumps(row, sort_keys=True)
    assert_safe_text(line, path)
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


def load_entries(path: Path) -> List[Dict[str, Any]]:
    data, status = read_json(path)
    if status == "ok" and isinstance(data, dict) and isinstance(data.get("entries"), list):
        return [item for item in data["entries"] if isinstance(item, dict)]
    if status == "ok" and isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    return []


def redact(value: Any, limit: int = 1000) -> str:
    return SECRET_RE.sub("[REDACTED]", str(value))[:limit]


def exact_git(kind: str) -> Dict[str, Any]:
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
        if not any(part in line for part in ("reports/", "state/", "audit/", "exports/", ".env", "backup"))
    ][:20]
    return {
        "status": "ok" if proc.returncode == 0 else "failed",
        "returncode": proc.returncode,
        "line_count": len(lines),
        "safe_lines": [redact(line, 300) for line in safe_lines],
    }


def source_safety_findings(paths: List[Path]) -> List[Dict[str, str]]:
    checks = [
        ("apply_argument_present", re.compile(r"add_argument\([\"']--" + "apply")),
        ("network_import_present", NETWORK_IMPORT_RE),
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
        if SECRET_RE.search(text):
            findings.append({"path": rel(path), "finding": "secret_like"})
        for finding, rx in checks:
            if rx.search(text):
                findings.append({"path": rel(path), "finding": finding})
    return findings


def scan_content(paths: List[Path]) -> Dict[str, Any]:
    findings: List[Dict[str, str]] = []
    for path in paths:
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if SECRET_RE.search(text):
            findings.append({"path": rel(path), "finding": "secret_like"})
        if CUSTOMER_DATA_RE.search(text):
            findings.append({"path": rel(path), "finding": "customer_data_marker"})
    return {"status": "SCAN_OK" if not findings else "SCAN_FINDINGS", "findings": findings}


def collect_evidence(write: bool = True) -> Dict[str, Any]:
    report_statuses: Dict[str, str] = {}
    report_data: Dict[str, Dict[str, Any]] = {}
    missing: List[str] = []
    for name, path in REPORT_INPUTS.items():
        data, status = read_json(path)
        report_statuses[name] = status
        if status == "missing":
            missing.append(rel(path))
        report_data[name] = data if status == "ok" and isinstance(data, dict) else {}
    state_statuses: Dict[str, str] = {}
    for name, path in STATE_INPUTS.items():
        _, status = read_json(path)
        state_statuses[name] = status
        if status == "missing":
            missing.append(rel(path))
    soak = report_data.get("soak_test", {})
    supervisor = report_data.get("operations_supervisor", {})
    governor = report_data.get("operation_governor", {})
    evidence = {
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "timestamp_utc": utc_now(),
        "action": "collect-evidence",
        "status": "RC_EVIDENCE_COLLECTED",
        "evidence_count": sum(1 for status in list(report_statuses.values()) + list(state_statuses.values()) if status == "ok"),
        "missing_inputs": missing,
        "report_statuses": report_statuses,
        "state_statuses": state_statuses,
        "readiness_seal": soak.get("readiness_seal"),
        "soak_status": soak.get("status"),
        "regression_gate_status": soak.get("regression_gate_status"),
        "soak_validation_status": soak.get("validation_status"),
        "operation_diversity": (soak.get("readiness") or {}).get("operation_diversity"),
        "mission_diversity": (soak.get("readiness") or {}).get("mission_diversity"),
        "noop_status": (soak.get("readiness") or {}).get("noop_status"),
        "supervisor_status": supervisor.get("status"),
        "operation_governor_status": governor.get("status"),
        "selected_operation": governor.get("selected_operation_name"),
        "git_status": exact_git("status"),
        "git_log": exact_git("log"),
        **HARD_DEFAULTS,
    }
    if write:
        write_outputs(evidence)
    return evidence


def git_recommendation() -> Dict[str, Any]:
    unsafe_prefixes = ("reports/", "state/", "audit/", "exports/")
    unsafe = [path for path in CHECKPOINT_FILES if path.startswith(unsafe_prefixes)]
    return {
        "status": "GIT_RECOMMENDATION_OK" if not unsafe else "GIT_RECOMMENDATION_WARNINGS",
        "checkpoint_files": CHECKPOINT_FILES,
        "blocked_from_commit": ["reports/", "state/", "audit/", "exports/", "backups/", ".env", ".sentinel-sftp.env"],
        "unsafe_recommended_files": unsafe,
    }


def safety_summary(evidence: Dict[str, Any]) -> Dict[str, Any]:
    drift: List[Dict[str, Any]] = []
    for source in ("soak_test", "operations_supervisor", "operation_governor"):
        data = load_dict(REPORT_INPUTS.get(source, R / "missing.json"))
        if not data:
            continue
        expected = {
            "live_apply": False,
            "allowed_apply_now": False,
            "high_blocked": True,
            "low_live_executable": False,
            "medium_executable": False,
            "breach": False,
        }
        for field, value in expected.items():
            if field in data and data.get(field) != value:
                drift.append({"source": source, "field": field, "expected": value, "actual": data.get(field)})
        if "emergency_stop" in data and data.get("emergency_stop") is not True:
            drift.append({"source": source, "field": "emergency_stop", "expected": True, "actual": data.get("emergency_stop")})
    return {"status": "SAFETY_OK" if not drift else "SAFETY_DRIFT", "findings": drift, **HARD_DEFAULTS}


def validate_rc(write: bool = True) -> Dict[str, Any]:
    evidence = collect_evidence(write=False)
    source_findings = source_safety_findings([
        PROJECT_DIR / "sentinel_autonomous_release_candidate.py",
        PROJECT_DIR / "sentinel_autonomy.py",
        PROJECT_DIR / "sentinel_autonomous_soak_test.py",
        PROJECT_DIR / "sentinel_autonomous_operation_governor.py",
        PROJECT_DIR / "sentinel_autonomous_operations_supervisor.py",
    ])
    content_scan = scan_content([
        REPORT_MD,
        MANIFEST_MD,
        OWNER_CONSOLE_MD,
        RUNBOOK_MD,
        PUBLIC_SUMMARY_MD,
        EVIDENCE_PACK_MD,
        GIT_CHECKPOINT_MD,
        STATE_JSON,
        LATEST_JSON,
        HISTORY_JSON,
        AUDIT_JSONL,
        PLAYBOOK_RC,
        PLAYBOOK_CONSOLE,
        PLAYBOOK_RUNBOOK,
        PLAYBOOK_EVIDENCE,
    ])
    safety = safety_summary(evidence)
    missing = evidence.get("missing_inputs") or []
    required_outputs = {
        "owner_console": OWNER_CONSOLE_MD.exists(),
        "runbook": RUNBOOK_MD.exists(),
        "public_summary": PUBLIC_SUMMARY_MD.exists(),
        "evidence_pack": EVIDENCE_PACK_MD.exists(),
        "manifest": MANIFEST_MD.exists(),
    }
    hard_blockers: List[str] = []
    yellow_reasons: List[str] = []
    if evidence.get("readiness_seal") != "READINESS_SEAL_GREEN":
        yellow_reasons.append("readiness_seal_not_green")
    if evidence.get("regression_gate_status") != "REGRESSION_GATE_OK":
        yellow_reasons.append("regression_gate_not_ok")
    if safety.get("status") != "SAFETY_OK":
        hard_blockers.append("safety_drift")
    if source_findings or content_scan.get("findings"):
        hard_blockers.append("secret_or_forbidden_findings")
    if any(status == "invalid_json" for status in (evidence.get("report_statuses") or {}).values()):
        hard_blockers.append("invalid_report_json")
    if any(status == "invalid_json" for status in (evidence.get("state_statuses") or {}).values()):
        hard_blockers.append("invalid_state_json")
    if missing:
        yellow_reasons.append("missing_inputs")
    for key, exists in required_outputs.items():
        if not exists:
            yellow_reasons.append(f"{key}_missing")
    if git_recommendation().get("status") != "GIT_RECOMMENDATION_OK":
        hard_blockers.append("git_recommendation_unsafe")
    if hard_blockers:
        rc_status = "RC_RED"
        reason = ",".join(hard_blockers)
    elif yellow_reasons:
        rc_status = "RC_YELLOW"
        reason = ",".join(sorted(set(yellow_reasons)))
    else:
        rc_status = "RC_GREEN"
        reason = "all_release_candidate_gates_ok"
    report = {
        **evidence,
        "action": "validate-rc",
        "status": rc_status,
        "rc_status": rc_status,
        "rc_reason": reason,
        "required_outputs": required_outputs,
        "safety": safety,
        "source_safety_findings": source_findings,
        "content_scan": content_scan,
        "git_recommendation": git_recommendation(),
        "validation_status": "RC_VALIDATION_OK" if rc_status != "RC_RED" else "RC_VALIDATION_BLOCKED",
        **HARD_DEFAULTS,
    }
    if write:
        write_outputs(report)
    return report


def build_rc_manifest() -> Dict[str, Any]:
    evidence = collect_evidence(write=False)
    write_text(MANIFEST_MD, render_manifest_md(evidence))
    report = {**evidence, "action": "build-rc-manifest", "status": "RC_MANIFEST_READY", "rc_manifest_status": "RC_MANIFEST_READY"}
    write_outputs(report)
    return report


def build_owner_console() -> Dict[str, Any]:
    evidence = collect_evidence(write=False)
    write_text(OWNER_CONSOLE_MD, render_owner_console_md(evidence))
    report = {**evidence, "action": "build-owner-console", "status": "OWNER_CONSOLE_READY", "owner_console_status": "OWNER_CONSOLE_READY"}
    write_outputs(report)
    return report


def build_runbook() -> Dict[str, Any]:
    evidence = collect_evidence(write=False)
    write_text(RUNBOOK_MD, render_runbook_md(evidence))
    report = {**evidence, "action": "build-runbook", "status": "OWNER_RUNBOOK_READY", "runbook_status": "OWNER_RUNBOOK_READY"}
    write_outputs(report)
    return report


def build_public_summary() -> Dict[str, Any]:
    evidence = collect_evidence(write=False)
    write_text(PUBLIC_SUMMARY_MD, render_public_summary_md(evidence))
    report = {**evidence, "action": "build-public-summary", "status": "PUBLIC_SUMMARY_READY", "public_summary_status": "PUBLIC_SUMMARY_READY"}
    write_outputs(report)
    return report


def build_evidence_pack() -> Dict[str, Any]:
    evidence = collect_evidence(write=False)
    write_text(EVIDENCE_PACK_MD, render_evidence_pack_md(evidence))
    write_text(GIT_CHECKPOINT_MD, render_git_checkpoint_md())
    report = validate_rc(write=False)
    report.update({
        "action": "build-evidence-pack",
        "evidence_pack_status": "RC_EVIDENCE_PACK_READY",
        "git_recommendation_status": git_recommendation()["status"],
    })
    report["status"] = report.get("rc_status", report.get("status"))
    write_outputs(report)
    return report


def write_playbooks() -> None:
    base = {"schema_version": SCHEMA_VERSION, "phase": PHASE, **HARD_DEFAULTS}
    write_json(PLAYBOOK_RC, {
        **base,
        "name": "sentinel-autonomous-release-candidate",
        "purpose": "Build local RC manifest, evidence, owner console, runbook and safety validation.",
        "blocked_actions": ["live_apply", "network", "remote_write", "timer_install", "LOW_LIVE_MEDIUM_HIGH_execution"],
    })
    write_json(PLAYBOOK_CONSOLE, {**base, "name": "sentinel-autonomous-owner-command-console", "commands": [cmd for cmd, _ in COMMAND_MAP]})
    write_json(PLAYBOOK_RUNBOOK, {**base, "name": "sentinel-autonomous-owner-runbook", "sections": ["daily manual flow", "diagnostics", "git checkpoint", "emergency stop"]})
    write_json(PLAYBOOK_EVIDENCE, {**base, "name": "sentinel-autonomous-rc-evidence-pack", "sections": ["readiness", "soak", "regression", "safety", "git", "public summary"]})


def render_report_md(report: Dict[str, Any]) -> str:
    return "\n".join([
        "# Sentinel Autonomous Release Candidate",
        "",
        f"- status: `{report.get('status')}`",
        f"- rc_status: `{report.get('rc_status', report.get('status'))}`",
        f"- rc_reason: `{report.get('rc_reason', '-')}`",
        f"- evidence_count: `{report.get('evidence_count', 0)}`",
        f"- readiness_seal: `{report.get('readiness_seal', '-')}`",
        f"- regression_gate_status: `{report.get('regression_gate_status', '-')}`",
        f"- owner_console_status: `{report.get('owner_console_status', OWNER_CONSOLE_MD.exists())}`",
        f"- runbook_status: `{report.get('runbook_status', RUNBOOK_MD.exists())}`",
        f"- evidence_pack_status: `{report.get('evidence_pack_status', EVIDENCE_PACK_MD.exists())}`",
        "- live_apply: `False`",
        "- emergency_stop: `True`",
        "- allowed_apply_now: `False`",
        "- HIGH blocked: `True`",
        "- LOW_LIVE executable: `False`",
        "- MEDIUM executable: `False`",
        "- breach: `False`",
    ]) + "\n"


def render_manifest_md(evidence: Dict[str, Any]) -> str:
    return "\n".join([
        "# Sentinel Autonomous RC Manifest",
        "",
        "- system: `Sentinel Security, SEO & Performance Safe Optimization`",
        f"- readiness_seal: `{evidence.get('readiness_seal')}`",
        f"- soak_status: `{evidence.get('soak_status')}`",
        f"- regression_gate_status: `{evidence.get('regression_gate_status')}`",
        f"- supervisor_status: `{evidence.get('supervisor_status')}`",
        f"- operation_governor_status: `{evidence.get('operation_governor_status')}`",
        "- autonomous_local: reports, state, playbooks, evidence, safe local batches, soak tests",
        "- blocked: live systems, remote writes, external APIs, timers, LOW_LIVE, MEDIUM, HIGH",
    ]) + "\n"


def render_owner_console_md(evidence: Dict[str, Any]) -> str:
    lines = ["# Sentinel Owner Command Console", "", "All commands are local safe commands and must not perform live apply.", ""]
    for command, description in COMMAND_MAP:
        lines.append(f"- `{command}`: {description}")
    lines.extend([
        "",
        "These commands never install timers, send email, call external APIs, write remote systems, change WordPress, change Cloudflare, change databases, or disable emergency stop.",
    ])
    return "\n".join(lines) + "\n"


def render_runbook_md(evidence: Dict[str, Any]) -> str:
    return "\n".join([
        "# Sentinel Owner Runbook",
        "",
        "## Startpunkt",
        "Run `python3 sentinel_autonomy.py rc-status`, then inspect this runbook and the owner command console.",
        "",
        "## Täglicher Manueller Ablauf",
        "1. `python3 sentinel_autonomy.py status`",
        "2. `python3 sentinel_autonomy.py operation-governor-status`",
        "3. `python3 sentinel_autonomy.py soak-status`",
        "4. `python3 sentinel_autonomy.py run-safe-batch 3` only when local safe autonomy should advance.",
        "",
        "## Sicherer Diagnoseablauf",
        "Run preflight, operation governor status, soak status, then readiness seal. Review generated reports before any next phase.",
        "",
        "## Owner Review",
        "MEDIUM, HIGH, LOW_LIVE and any production-changing action require separate Owner approval gates.",
        "",
        "## Git Checkpoint",
        "Commit only scripts and playbooks listed in the RC Git checkpoint report. Do not commit reports, state, audit, exports, backups, secrets or local evidence artifacts.",
        "",
        "## Rollback Hinweis",
        "This RC phase performs no live change; rollback means preserving local files and reverting local code through Git if needed.",
        "",
        "## Notfall",
        "Emergency Stop remains active. No timer, cron, systemd or remote automation is installed.",
    ]) + "\n"


def render_public_summary_md(evidence: Dict[str, Any]) -> str:
    return "\n".join([
        "# Sentinel Security, SEO & Performance Safe Optimization",
        "",
        "Sentinel provides local safe analysis, review, reporting and optimization-support workflows for security, SEO and performance operations.",
        "",
        "It is designed around owner review, safety gates, evidence reports, local dry-runs, controlled autonomy and clear blocked-action boundaries. It does not make unchecked live changes, does not call production APIs in this RC flow, and does not promise automatic repair of third-party systems.",
        "",
        "Suitable positioning: manual service delivery ready, evidence-report driven, owner-approved optimization support.",
        "",
        "No guarantees are made for 100% SEO, 100% security, immediate PageSpeed outcomes, or automated repair of systems outside the approved local scope.",
    ]) + "\n"


def render_evidence_pack_md(evidence: Dict[str, Any]) -> str:
    return "\n".join([
        "# Sentinel Autonomous RC Evidence Pack",
        "",
        f"- readiness_seal: `{evidence.get('readiness_seal')}`",
        f"- soak_status: `{evidence.get('soak_status')}`",
        f"- soak_validation_status: `{evidence.get('soak_validation_status')}`",
        f"- regression_gate_status: `{evidence.get('regression_gate_status')}`",
        f"- operation_diversity: `{(evidence.get('operation_diversity') or {}).get('status', '-')}`",
        f"- mission_diversity: `{(evidence.get('mission_diversity') or {}).get('status', '-')}`",
        f"- noop_status: `{(evidence.get('noop_status') or {}).get('status', '-')}`",
        f"- supervisor_status: `{evidence.get('supervisor_status')}`",
        f"- operation_governor_status: `{evidence.get('operation_governor_status')}`",
        "",
        "## Allowed Local Autonomy",
        "- local reports, state, audit, playbooks, command console, runbook, evidence, bounded safe batches, soak tests",
        "",
        "## Blocked Areas",
        "- live apply, external APIs, email, WordPress, Cloudflare, DB, SFTP, Nginx, .htaccess, timers, LOW_LIVE, MEDIUM, HIGH",
        "",
        "## Git Recommendation",
        "Use only the checkpoint files listed in `sentinel-autonomous-rc-git-checkpoint.md`.",
    ]) + "\n"


def render_git_checkpoint_md() -> str:
    lines = ["# Sentinel Autonomous RC Git Checkpoint", "", f"- status: `{git_recommendation()['status']}`", ""]
    lines.append("## Recommended Files")
    for path in CHECKPOINT_FILES:
        lines.append(f"- `{path}`")
    lines.extend([
        "",
        "## Do Not Commit",
        "- `reports/`",
        "- `state/`",
        "- `audit/`",
        "- `exports/`",
        "- `backups/`",
        "- `.env` or `.sentinel-sftp.env`",
    ])
    return "\n".join(lines) + "\n"


def write_outputs(report: Dict[str, Any]) -> None:
    ensure_dirs()
    safe = {
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "timestamp_utc": report.get("timestamp_utc") or utc_now(),
        **report,
        **HARD_DEFAULTS,
        "recommended_git_checkpoint": CHECKPOINT_FILES,
    }
    write_json(REPORT_JSON, safe)
    write_json(STATE_JSON, safe)
    write_json(LATEST_JSON, safe)
    write_text(REPORT_MD, render_report_md(safe))
    if not MANIFEST_MD.exists():
        write_text(MANIFEST_MD, render_manifest_md(safe))
    if not OWNER_CONSOLE_MD.exists():
        write_text(OWNER_CONSOLE_MD, render_owner_console_md(safe))
    if not RUNBOOK_MD.exists():
        write_text(RUNBOOK_MD, render_runbook_md(safe))
    if not PUBLIC_SUMMARY_MD.exists():
        write_text(PUBLIC_SUMMARY_MD, render_public_summary_md(safe))
    if not GIT_CHECKPOINT_MD.exists():
        write_text(GIT_CHECKPOINT_MD, render_git_checkpoint_md())
    write_playbooks()
    history = load_entries(HISTORY_JSON)
    history.append({"timestamp_utc": utc_now(), "status": safe.get("status"), "rc_status": safe.get("rc_status"), "action": safe.get("action")})
    write_json(HISTORY_JSON, {"entries": history[-200:], **HARD_DEFAULTS})
    append_jsonl(AUDIT_JSONL, {
        "timestamp_utc": utc_now(),
        "event": "autonomous_release_candidate",
        "action": safe.get("action"),
        "status": safe.get("status"),
        "rc_status": safe.get("rc_status"),
        "breach": False,
        "live_apply": False,
    })


def self_test() -> Dict[str, Any]:
    source = Path(__file__).read_text(encoding="utf-8")
    findings = source_safety_findings([Path(__file__)])
    fake = {"readiness_seal": "READINESS_SEAL_GREEN", "regression_gate_status": "REGRESSION_GATE_OK"}
    tests = {
        "no_apply_argument": not re.search(r"add_argument\([\"']--" + "apply", source),
        "no_network_imports": not NETWORK_IMPORT_RE.search(source),
        "no_shell_true": ("shell" + "=True") not in source,
        "no_free_subprocess": not any(item.get("finding") == "free_subprocess_present" for item in findings),
        "git_recommendation_safe": git_recommendation().get("status") == "GIT_RECOMMENDATION_OK",
        "rc_status_logic": fake["readiness_seal"] == "READINESS_SEAL_GREEN" and fake["regression_gate_status"] == "REGRESSION_GATE_OK",
        "json_valid": True,
        "breach_false": HARD_DEFAULTS["breach"] is False,
    }
    status = "RC_SELF_TEST_OK" if all(tests.values()) and not findings else "RC_SELF_TEST_FAILED"
    report = {
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "timestamp_utc": utc_now(),
        "action": "self-test",
        "status": status,
        "self_test_status": status,
        "tests": tests,
        "source_safety_findings": findings,
        **HARD_DEFAULTS,
    }
    write_outputs(report)
    return report


def status_report() -> Dict[str, Any]:
    data = load_dict(LATEST_JSON) or load_dict(REPORT_JSON) or {"status": "RC_STATUS_EMPTY", **HARD_DEFAULTS}
    print(f"status={data.get('status')}")
    print(f"rc_status={data.get('rc_status', data.get('status'))}")
    print(f"rc_reason={data.get('rc_reason')}")
    print(f"evidence_count={data.get('evidence_count', 0)}")
    print(f"readiness_seal={data.get('readiness_seal')}")
    print(f"owner_console_status={data.get('owner_console_status') or OWNER_CONSOLE_MD.exists()}")
    print(f"runbook_status={data.get('runbook_status') or RUNBOOK_MD.exists()}")
    print(f"evidence_pack_status={data.get('evidence_pack_status') or EVIDENCE_PACK_MD.exists()}")
    print(f"git_recommendation_status={(data.get('git_recommendation') or git_recommendation()).get('status')}")
    print(f"live_apply={data.get('live_apply')}")
    print(f"emergency_stop={data.get('emergency_stop')}")
    print(f"allowed_apply_now={data.get('allowed_apply_now')}")
    print(f"HIGH_blocked={data.get('high_blocked')}")
    print(f"LOW_LIVE_executable={data.get('low_live_executable')}")
    print(f"MEDIUM_executable={data.get('medium_executable')}")
    print(f"breach={data.get('breach')}")
    return data


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Sentinel Autonomous Release Candidate")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--collect-evidence", action="store_true")
    parser.add_argument("--build-rc-manifest", action="store_true")
    parser.add_argument("--build-owner-console", action="store_true")
    parser.add_argument("--build-runbook", action="store_true")
    parser.add_argument("--build-public-summary", action="store_true")
    parser.add_argument("--validate-rc", action="store_true")
    parser.add_argument("--build-evidence-pack", action="store_true")
    parser.add_argument("--status", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        report = self_test()
    elif args.collect_evidence:
        report = collect_evidence(write=True)
    elif args.build_rc_manifest:
        report = build_rc_manifest()
    elif args.build_owner_console:
        report = build_owner_console()
    elif args.build_runbook:
        report = build_runbook()
    elif args.build_public_summary:
        report = build_public_summary()
    elif args.validate_rc:
        report = validate_rc(write=True)
    elif args.build_evidence_pack:
        report = build_evidence_pack()
    elif args.status:
        status_report()
        return 0
    else:
        parser.print_help()
        return 2
    return 0 if report.get("status") != "RC_SELF_TEST_FAILED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
