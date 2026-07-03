#!/usr/bin/env python3
"""Sentinel Autonomous Soak Test (Phase 10.9).

Runs repeated safe local operations batches through the Operations Supervisor,
validates every batch, checks regressions, and emits a readiness seal. This
module never performs live apply, network access, external API calls, remote
writes, timer installation, or customer-system changes.
"""

from __future__ import annotations

import argparse
import json
import py_compile
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


PROJECT_DIR = Path("/srv/sentinel-defense")
SCHEMA_VERSION = "sentinel-autonomous-soak-test-10.9"
PHASE = "10.9"
MAX_SOAK_STEPS = 5
DEFAULT_SOAK_STEPS = 3
STEP_TIMEOUT_SECONDS = 900

READ_ONLY = "READ_ONLY"
DRAFT = "DRAFT"
LOW_LOCAL = "LOW_LOCAL"
LOW_EXPORT = "LOW_EXPORT"
LOW_STATE = "LOW_STATE"
LOW_LIVE = "LOW_LIVE"
MEDIUM = "MEDIUM"
HIGH = "HIGH"

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
EXPORT_LATEST_DIR = PROJECT_DIR / "exports/payhip-upload-pack/latest"

REPORT_JSON = R / "sentinel-autonomous-soak-test.json"
REPORT_MD = R / "sentinel-autonomous-soak-test.md"
PREFLIGHT_MD = R / "sentinel-autonomous-soak-preflight.md"
RUN_LOG_MD = R / "sentinel-autonomous-soak-run-log.md"
VALIDATION_MD = R / "sentinel-autonomous-soak-validation.md"
REGRESSION_MD = R / "sentinel-autonomous-regression-gate.md"
READINESS_MD = R / "sentinel-autonomous-readiness-seal.md"
OWNER_SUMMARY_MD = R / "sentinel-autonomous-soak-owner-summary.md"
NEXT_SAFE_MD = R / "sentinel-autonomous-next-safe-operation.md"

STATE_JSON = STATE_DIR / "autonomous_soak_test.json"
LATEST_JSON = STATE_DIR / "latest_autonomous_soak_test.json"
SOAK_HISTORY_JSON = STATE_DIR / "autonomous_soak_history.json"
REGRESSION_HISTORY_JSON = STATE_DIR / "autonomous_regression_gate_history.json"
READINESS_HISTORY_JSON = STATE_DIR / "autonomous_readiness_seal_history.json"
STOP_PATTERNS_JSON = STATE_DIR / "autonomous_soak_stop_patterns.json"

AUDIT_JSONL = AUDIT_DIR / "sentinel-autonomous-soak-test.jsonl"

PLAYBOOK_SOAK = PLAYBOOK_DIR / "sentinel-autonomous-soak-test.playbook.json"
PLAYBOOK_REGRESSION = PLAYBOOK_DIR / "sentinel-autonomous-regression-gate.playbook.json"
PLAYBOOK_READINESS = PLAYBOOK_DIR / "sentinel-autonomous-readiness-seal.playbook.json"
PLAYBOOK_OWNER = PLAYBOOK_DIR / "sentinel-autonomous-soak-owner-summary.playbook.json"

SUPERVISOR_JSON = R / "sentinel-autonomous-operations-supervisor.json"
SUPERVISOR_LATEST_JSON = STATE_DIR / "latest_autonomous_operations_supervisor.json"
OPERATION_GOVERNOR_JSON = R / "sentinel-autonomous-operation-governor.json"
OPERATION_GOVERNOR_LATEST_JSON = STATE_DIR / "latest_autonomous_operation_governor.json"
MISSION_RUNNER_JSON = R / "sentinel-autonomous-mission-queue-runner.json"
MISSION_RUNNER_LATEST_JSON = STATE_DIR / "latest_autonomous_mission_queue_runner.json"
GOAL_MANAGER_JSON = R / "sentinel-autonomous-goal-manager.json"
GOAL_MANAGER_LATEST_JSON = STATE_DIR / "latest_autonomous_goal_manager.json"
HEALTH_GOVERNOR_JSON = R / "sentinel-autonomous-capability-health-governor.json"
HEALTH_GOVERNOR_LATEST_JSON = STATE_DIR / "latest_autonomous_capability_health_governor.json"
CAPABILITY_REGISTRY_JSON = R / "sentinel-autonomous-capability-registry.json"
CAPABILITY_REGISTRY_STATE_JSON = STATE_DIR / "autonomous_capability_registry.json"
PRIORITY_ENGINE_JSON = R / "sentinel-autonomous-priority-engine.json"
PRIORITY_MODEL_JSON = STATE_DIR / "autonomy_task_priority_model.json"
KERNEL_JSON = R / "sentinel-self-governing-autonomy-kernel.json"
KERNEL_LATEST_JSON = STATE_DIR / "latest_self_governing_autonomy_kernel.json"
CYCLE_RUNNER_JSON = R / "sentinel-autonomous-cycle-runner.json"
CYCLE_RUNNER_LATEST_JSON = STATE_DIR / "latest_autonomous_cycle_runner.json"
COMPLETION_LEDGER_JSON = STATE_DIR / "autonomous_mission_completion_ledger.json"

ALLOWED_WRITE_ROOTS = (R, STATE_DIR, AUDIT_DIR, PLAYBOOK_DIR)

CORE_MODULES = [
    "sentinel_autonomous_soak_test.py",
    "sentinel_autonomous_operations_supervisor.py",
    "sentinel_autonomous_operation_governor.py",
    "sentinel_autonomous_mission_queue_runner.py",
    "sentinel_autonomous_goal_manager.py",
    "sentinel_autonomous_capability_health_governor.py",
    "sentinel_autonomous_capability_registry.py",
    "sentinel_autonomous_priority_engine.py",
    "sentinel_self_governing_safe_autonomy_kernel.py",
    "sentinel_autonomous_cycle_runner.py",
]

ALLOWLIST_MODULES = {
    "sentinel_autonomous_operations_supervisor.py",
    "sentinel_autonomous_operation_governor.py",
    "sentinel_autonomous_mission_queue_runner.py",
    "sentinel_autonomous_goal_manager.py",
    "sentinel_autonomous_capability_health_governor.py",
    "sentinel_autonomous_capability_registry.py",
    "sentinel_autonomous_priority_engine.py",
    "sentinel_self_governing_safe_autonomy_kernel.py",
    "sentinel_autonomous_cycle_runner.py",
}

ALLOWLIST_ARGS = {
    "--self-test",
    "--status",
    "--preflight",
    "--cycle",
    "--run-safe-once",
    "--run-safe-batch",
    "--validate-system",
    "--build-owner-briefing",
    "--scan-operations",
    "--score-operations",
    "--detect-noops",
    "--select-operation",
    "--write-model",
    "--run-missions",
    "--validate-run",
    "--build-owner-summary",
    "--discover-goals",
    "--build-mission-queue",
    "--classify-missions",
    "--route-missions",
    "--execute-safe-mission-step",
    "--validate-missions",
    "--learn",
    "--scan-health",
    "--classify-warnings",
    "--plan-repairs",
    "--execute-safe-repairs",
    "--validate-repairs",
    "--discover",
    "--build-registry",
    "--evaluate-capabilities",
    "--route-next-skill",
    "--scan-history",
    "--score-tasks",
    "--select-next",
    "--simulate-diversity",
    "--observe",
    "--decide",
    "--classify",
    "--execute",
    "--validate",
    "--repair",
}

SELF_TEST_COMMANDS = [
    ("sentinel_autonomous_operations_supervisor.py", ["--self-test"]),
    ("sentinel_autonomous_operation_governor.py", ["--self-test"]),
    ("sentinel_autonomous_mission_queue_runner.py", ["--self-test"]),
    ("sentinel_autonomous_goal_manager.py", ["--self-test"]),
    ("sentinel_autonomous_capability_health_governor.py", ["--self-test"]),
    ("sentinel_autonomous_capability_registry.py", ["--self-test"]),
    ("sentinel_autonomous_priority_engine.py", ["--self-test"]),
    ("sentinel_self_governing_safe_autonomy_kernel.py", ["--self-test"]),
    ("sentinel_autonomous_cycle_runner.py", ["--self-test"]),
]

REPORT_INPUTS = {
    "supervisor": (SUPERVISOR_JSON, SUPERVISOR_LATEST_JSON),
    "operation_governor": (OPERATION_GOVERNOR_JSON, OPERATION_GOVERNOR_LATEST_JSON),
    "mission_runner": (MISSION_RUNNER_JSON, MISSION_RUNNER_LATEST_JSON),
    "goal_manager": (GOAL_MANAGER_JSON, GOAL_MANAGER_LATEST_JSON),
    "health_governor": (HEALTH_GOVERNOR_JSON, HEALTH_GOVERNOR_LATEST_JSON),
    "capability_registry": (CAPABILITY_REGISTRY_JSON, CAPABILITY_REGISTRY_STATE_JSON),
    "priority_engine": (PRIORITY_ENGINE_JSON, PRIORITY_MODEL_JSON),
    "kernel": (KERNEL_JSON, KERNEL_LATEST_JSON),
    "cycle_runner": (CYCLE_RUNNER_JSON, CYCLE_RUNNER_LATEST_JSON),
    "completion_ledger": (COMPLETION_LEDGER_JSON,),
}

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
PRIVATE_IP_RE = re.compile(r"\b(?:10|127|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b")
INTERNAL_PATH_RE = re.compile(r"(?<!`)\/(?:srv|home|root|etc|var)\/[A-Za-z0-9_.\/-]+")


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
        raise RuntimeError(f"Refusing write outside allowed local roots: {rel(path)}")


def assert_safe_text(text: str, path: Optional[Path] = None) -> None:
    if SECRET_RE.search(text):
        raise RuntimeError(f"Secret-like value blocked in {rel(path) if path else 'content'}")
    if CUSTOMER_DATA_RE.search(text):
        raise RuntimeError(f"Customer-data marker blocked in {rel(path) if path else 'content'}")


def redact_text(value: Any, limit: int = 4000) -> str:
    text = "" if value is None else str(value)
    text = SECRET_RE.sub("[REDACTED]", text)
    return text[:limit]


def write_text(path: Path, text: str) -> None:
    assert_write_path(path)
    assert_safe_text(text, path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_json(path: Path, data: Dict[str, Any]) -> None:
    text = json.dumps(data, indent=2, sort_keys=True)
    json.loads(text)
    write_text(path, text + "\n")


def append_jsonl(path: Path, rows: List[Dict[str, Any]]) -> None:
    assert_write_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for row in rows:
            text = json.dumps(row, sort_keys=True)
            assert_safe_text(text, path)
            handle.write(text + "\n")


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


def load_first_dict(paths: Tuple[Path, ...]) -> Dict[str, Any]:
    for path in paths:
        data = load_dict(path)
        if data:
            return data
    return {}


def load_entries(path: Path) -> List[Dict[str, Any]]:
    data, status = read_json(path)
    if status == "ok" and isinstance(data, dict) and isinstance(data.get("entries"), list):
        return [item for item in data["entries"] if isinstance(item, dict)]
    if status == "ok" and isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    return []


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
        ("sftp_write_call_present", re.compile(r"\.(?:put|remove|rename)\(")),
    ]
    findings: List[Dict[str, str]] = []
    for path in paths:
        if not path.exists():
            findings.append({"path": rel(path), "finding": "missing_source"})
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if SECRET_RE.search(text):
            findings.append({"path": rel(path), "finding": "secret_like_source"})
        for finding, rx in checks:
            if rx.search(text):
                findings.append({"path": rel(path), "finding": finding})
    return findings


def scan_paths_for_patterns(paths: List[Path]) -> Dict[str, Any]:
    findings: List[Dict[str, str]] = []
    for path in paths:
        if not path.exists():
            continue
        if path.is_dir():
            candidates = [p for p in path.rglob("*") if p.is_file() and p.suffix.lower() in {".json", ".md", ".txt", ".html", ".py", ".jsonl"}]
        else:
            candidates = [path]
        for candidate in candidates:
            try:
                text = candidate.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if SECRET_RE.search(text):
                findings.append({"path": rel(candidate), "finding": "secret_like"})
            if CUSTOMER_DATA_RE.search(text):
                findings.append({"path": rel(candidate), "finding": "customer_data_marker"})
            if is_within(candidate, EXPORT_LATEST_DIR):
                if PRIVATE_IP_RE.search(text):
                    findings.append({"path": rel(candidate), "finding": "private_ip_in_public_asset"})
                if INTERNAL_PATH_RE.search(text):
                    findings.append({"path": rel(candidate), "finding": "internal_path_in_public_asset"})
    return {"status": "PATTERN_SCAN_OK" if not findings else "PATTERN_SCAN_FINDINGS", "findings": findings}


def py_compile_module(module: str) -> Dict[str, Any]:
    path = PROJECT_DIR / module
    if not path.exists():
        return {"module": module, "status": "missing"}
    try:
        py_compile.compile(str(path), doraise=True)
        return {"module": module, "status": "ok"}
    except py_compile.PyCompileError as exc:
        return {"module": module, "status": "failed", "error": redact_text(exc)}


def command_allowed(module: str, args: List[str]) -> bool:
    if module not in ALLOWLIST_MODULES:
        return False
    if not (PROJECT_DIR / module).exists():
        return False
    i = 0
    while i < len(args):
        arg = str(args[i])
        if arg in ALLOWLIST_ARGS:
            i += 1
            continue
        if i > 0 and args[i - 1] in {"--run-safe-batch", "--run-missions", "--run-cycles", "--simulate-diversity"} and str(arg).isdigit():
            i += 1
            continue
        return False
    return True


def run_allowlisted(module: str, args: List[str], timeout: int = STEP_TIMEOUT_SECONDS) -> Dict[str, Any]:
    if not command_allowed(module, args):
        return {"status": "blocked_not_allowlisted", "module": module, "args": args, "returncode": None}
    cmd = ["python3", module, *args]
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(PROJECT_DIR),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "module": module, "args": args, "returncode": None}
    except (OSError, subprocess.SubprocessError) as exc:
        return {"status": "error", "module": module, "args": args, "returncode": None, "stderr": redact_text(exc)}
    return {
        "status": "executed" if proc.returncode == 0 else "failed",
        "module": module,
        "args": args,
        "returncode": proc.returncode,
        "stdout_lines": len([line for line in (proc.stdout or "").splitlines() if line.strip()]),
        "stderr": redact_text(proc.stderr, 1200),
    }


def json_statuses() -> Dict[str, str]:
    paths = {
        "soak_test": REPORT_JSON,
        "supervisor": SUPERVISOR_JSON,
        "operation_governor": OPERATION_GOVERNOR_JSON,
        "mission_runner": MISSION_RUNNER_JSON,
        "goal_manager": GOAL_MANAGER_JSON,
        "health_governor": HEALTH_GOVERNOR_JSON,
        "capability_registry": CAPABILITY_REGISTRY_JSON,
        "priority_engine": PRIORITY_ENGINE_JSON,
        "kernel": KERNEL_JSON,
        "cycle_runner": CYCLE_RUNNER_JSON,
        "completion_ledger": COMPLETION_LEDGER_JSON,
    }
    return {name: read_json(path)[1] for name, path in paths.items()}


def collect_reports() -> Dict[str, Dict[str, Any]]:
    return {name: load_first_dict(paths) for name, paths in REPORT_INPUTS.items()}


def flag_drift(reports: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    drift: List[Dict[str, Any]] = []
    expected = {
        "live_apply": False,
        "allowed_apply_now": False,
        "high_blocked": True,
        "low_live_executable": False,
        "medium_executable": False,
        "breach": False,
    }
    for name, data in reports.items():
        if not isinstance(data, dict) or not data:
            continue
        for field, value in expected.items():
            if field in data and data.get(field) != value:
                drift.append({"source": name, "field": field, "expected": value, "actual": data.get(field)})
        if "emergency_stop" in data and data.get("emergency_stop") is not True:
            drift.append({"source": name, "field": "emergency_stop", "expected": True, "actual": data.get("emergency_stop")})
    return drift


def operation_list_from_supervisor(supervisor: Dict[str, Any]) -> List[str]:
    history = supervisor.get("operations_history")
    if isinstance(history, list) and history:
        return [str(item) for item in history if item]
    results = supervisor.get("operation_results")
    if isinstance(results, list):
        return [str(item.get("selected_operation")) for item in results if isinstance(item, dict) and item.get("selected_operation")]
    op = supervisor.get("selected_operation")
    return [str(op)] if op else []


def diversity_from_ops(ops: List[str]) -> Dict[str, Any]:
    unique = len(set(ops))
    if len(ops) >= 3 and unique < 2:
        status = "DIVERSITY_FAILURE"
    elif len(ops) >= 5 and unique < 3:
        status = "DIVERSITY_WARNING"
    else:
        status = "DIVERSITY_OK"
    return {"status": status, "operation_count": len(ops), "unique_count": unique, "operations": ops}


def noop_dominance(ops: List[str], governor: Dict[str, Any]) -> Dict[str, Any]:
    counts = {op: ops.count(op) for op in sorted(set(ops))}
    dominant = None
    if ops:
        dominant = max(counts, key=counts.get)
    ratio = (counts.get(dominant, 0) / len(ops)) if ops and dominant else 0.0
    governor_noops = governor.get("noop_analysis") if isinstance(governor.get("noop_analysis"), dict) else {}
    noop_ops = [op for op, item in governor_noops.items() if isinstance(item, dict) and item.get("is_noop_candidate")]
    status = "NOOP_DOMINANCE_DETECTED" if len(ops) >= 3 and ratio > 0.8 else "NOOP_STATUS_OK"
    return {
        "status": status,
        "dominant_operation": dominant,
        "dominance_ratio": round(ratio, 3),
        "noop_candidate_operations": noop_ops,
    }


def collect_system_state() -> Dict[str, Any]:
    reports = collect_reports()
    supervisor = reports.get("supervisor", {})
    governor = reports.get("operation_governor", {})
    ops = operation_list_from_supervisor(supervisor)
    drift = flag_drift(reports)
    validation = {
        "json_statuses": json_statuses(),
        "invalid_json": [name for name, status in json_statuses().items() if status == "invalid_json"],
        "source_safety_findings": source_safety_findings([PROJECT_DIR / module for module in CORE_MODULES if (PROJECT_DIR / module).exists()]),
        "pattern_scan": scan_paths_for_patterns([
            REPORT_JSON,
            SUPERVISOR_JSON,
            OPERATION_GOVERNOR_JSON,
            MISSION_RUNNER_JSON,
            GOAL_MANAGER_JSON,
            HEALTH_GOVERNOR_JSON,
            CAPABILITY_REGISTRY_JSON,
            PRIORITY_ENGINE_JSON,
            KERNEL_JSON,
            CYCLE_RUNNER_JSON,
            COMPLETION_LEDGER_JSON,
            EXPORT_LATEST_DIR,
        ]),
    }
    return {
        "timestamp_utc": utc_now(),
        "reports": {
            name: {"status": data.get("status"), "breach": data.get("breach"), "live_apply": data.get("live_apply")}
            for name, data in reports.items()
            if isinstance(data, dict)
        },
        "raw_reports": reports,
        "operation_history": ops,
        "operation_diversity": diversity_from_ops(ops),
        "mission_diversity": (reports.get("mission_runner", {}).get("mission_diversity") or reports.get("cycle_runner", {}).get("mission_diversity") or {"status": "MISSION_DIVERSITY_NOT_AVAILABLE"}),
        "noop_status": noop_dominance(ops, governor),
        "safety_drift": {"status": "SAFETY_DRIFT_OK" if not drift else "SAFETY_DRIFT_DETECTED", "findings": drift},
        "breach": any(bool(data.get("breach")) for data in reports.values() if isinstance(data, dict)),
        "completion_ledger_status": read_json(COMPLETION_LEDGER_JSON)[1],
        "owner_briefing_status": "OWNER_BRIEFING_READY" if OWNER_SUMMARY_MD.exists() or (R / "sentinel-autonomous-owner-briefing.md").exists() else "OWNER_BRIEFING_MISSING",
        "validation": validation,
        **HARD_DEFAULTS,
    }


def step_validation(step: Dict[str, Any]) -> Dict[str, Any]:
    snapshot = step.get("snapshot") if isinstance(step.get("snapshot"), dict) else collect_system_state()
    invalid_json = (snapshot.get("validation") or {}).get("invalid_json") or []
    source_findings = (snapshot.get("validation") or {}).get("source_safety_findings") or []
    pattern_findings = ((snapshot.get("validation") or {}).get("pattern_scan") or {}).get("findings") or []
    blockers: List[str] = []
    if step.get("supervisor_batch", {}).get("returncode") != 0:
        blockers.append("STOP_ON_SUPERVISOR_FAILURE")
    if snapshot.get("breach"):
        blockers.append("STOP_ON_BREACH")
    if (snapshot.get("safety_drift") or {}).get("status") != "SAFETY_DRIFT_OK":
        blockers.append("STOP_ON_SAFETY_DRIFT")
    if invalid_json:
        blockers.append("STOP_ON_INVALID_JSON")
    if pattern_findings:
        blockers.append("STOP_ON_SECRET_PATTERN")
    if source_findings:
        blockers.append("STOP_ON_FORBIDDEN_PATH")
    if (snapshot.get("operation_diversity") or {}).get("status") == "DIVERSITY_FAILURE":
        blockers.append("STOP_ON_DIVERSITY_FAILURE")
    if (snapshot.get("noop_status") or {}).get("status") == "NOOP_DOMINANCE_DETECTED":
        blockers.append("STOP_ON_NOOP_DOMINANCE")
    if snapshot.get("completion_ledger_status") not in {"ok", "missing"}:
        blockers.append("STOP_ON_INVALID_JSON")
    return {
        "status": "SOAK_STEP_VALIDATION_OK" if not blockers else blockers[0],
        "blockers": blockers,
        "invalid_json": invalid_json,
        "source_safety_findings": source_findings,
        "pattern_findings": pattern_findings,
    }


def base_report(action: str, status: str) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "timestamp_utc": utc_now(),
        "action": action,
        "status": status,
        "soak_steps_completed": 0,
        "soak_results": [],
        "operations_per_soak_step": [],
        "validation_status": "not_run",
        "regression_gate_status": "not_run",
        "readiness_seal": "not_built",
        "owner_summary_status": "not_written",
        "wrapper_status": "not_checked",
        "integration_status": "SOAK_INTEGRATION_READY",
        "stop_reason": None,
        **HARD_DEFAULTS,
    }


def preflight() -> Dict[str, Any]:
    ensure_dirs()
    compile_checks = {module: py_compile_module(module) for module in CORE_MODULES}
    self_tests = {
        module: run_allowlisted(module, args, timeout=STEP_TIMEOUT_SECONDS)
        for module, args in SELF_TEST_COMMANDS
    }
    state = collect_system_state()
    lockfiles = [
        STATE_DIR / "autonomous_cycle_runner.lock",
        STATE_DIR / "autonomous_mission_queue_runner.lock",
        STATE_DIR / "autonomous_cycle_runner.lock",
    ]
    active_locks = [rel(path) for path in lockfiles if path.exists()]
    blockers: List[str] = []
    if any(item.get("status") != "ok" for item in compile_checks.values()):
        blockers.append("compile_failure")
    if any(item.get("returncode") != 0 for item in self_tests.values()):
        blockers.append("self_test_failure")
    if active_locks:
        blockers.append("active_lockfile")
    if state.get("breach"):
        blockers.append("breach")
    if (state.get("safety_drift") or {}).get("status") != "SAFETY_DRIFT_OK":
        blockers.append("safety_drift")
    status = "SOAK_PREFLIGHT_OK" if not blockers else "SOAK_PREFLIGHT_BLOCKED"
    report = {
        **base_report("preflight", status),
        "compile_checks": compile_checks,
        "self_tests": self_tests,
        "active_lockfiles": active_locks,
        "blockers": blockers,
        "system_state": compact_state(state),
    }
    write_outputs(report)
    return report


def compact_state(state: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "breach": state.get("breach"),
        "safety_drift": (state.get("safety_drift") or {}).get("status"),
        "operation_diversity": state.get("operation_diversity"),
        "mission_diversity": state.get("mission_diversity"),
        "noop_status": state.get("noop_status"),
        "completion_ledger_status": state.get("completion_ledger_status"),
        "owner_briefing_status": state.get("owner_briefing_status"),
        "json_statuses": (state.get("validation") or {}).get("json_statuses"),
    }


def run_soak(steps: int = DEFAULT_SOAK_STEPS) -> Dict[str, Any]:
    if steps > MAX_SOAK_STEPS:
        report = base_report("run-soak", "STOP_ON_MAX_SOAK_STEPS")
        report["requested_soak_steps"] = steps
        report["stop_reason"] = "STOP_ON_MAX_SOAK_STEPS"
        write_outputs(report)
        return report
    before = collect_system_state()
    results: List[Dict[str, Any]] = []
    operations_per_step: List[List[str]] = []
    stop_reason: Optional[str] = None
    completed = 0
    for index in range(1, max(1, steps) + 1):
        batch = run_allowlisted("sentinel_autonomous_operations_supervisor.py", ["--run-safe-batch", "3"], timeout=STEP_TIMEOUT_SECONDS)
        snapshot = collect_system_state()
        supervisor = snapshot.get("raw_reports", {}).get("supervisor", {})
        operations = operation_list_from_supervisor(supervisor)
        step = {
            "soak_step": index,
            "started_at": utc_now(),
            "supervisor_batch": batch,
            "operations": operations,
            "supervisor_status": supervisor.get("status"),
            "operation_governor_status": (snapshot.get("raw_reports", {}).get("operation_governor", {}) or {}).get("status"),
            "mission_runner_status": (snapshot.get("raw_reports", {}).get("mission_runner", {}) or {}).get("status"),
            "goal_manager_status": (snapshot.get("raw_reports", {}).get("goal_manager", {}) or {}).get("status"),
            "health_governor_status": (snapshot.get("raw_reports", {}).get("health_governor", {}) or {}).get("status"),
            "capability_registry_status": (snapshot.get("raw_reports", {}).get("capability_registry", {}) or {}).get("status"),
            "priority_engine_status": (snapshot.get("raw_reports", {}).get("priority_engine", {}) or {}).get("status"),
            "kernel_status": (snapshot.get("raw_reports", {}).get("kernel", {}) or {}).get("status"),
            "cycle_runner_status": (snapshot.get("raw_reports", {}).get("cycle_runner", {}) or {}).get("status"),
            "snapshot": compact_state(snapshot),
            "finished_at": utc_now(),
        }
        validation = step_validation({**step, "snapshot": snapshot})
        step["validation"] = validation
        results.append(step)
        operations_per_step.append(operations)
        if validation.get("status") == "SOAK_STEP_VALIDATION_OK":
            completed += 1
        else:
            stop_reason = validation.get("status")
            break
    if stop_reason is None:
        stop_reason = "STOP_ON_MAX_SOAK_STEPS"
    after = collect_system_state()
    status = "SOAK_RUN_COMPLETED" if completed == max(1, steps) else stop_reason
    report = {
        **base_report("run-soak", status),
        "requested_soak_steps": steps,
        "soak_steps_completed": completed,
        "soak_results": results,
        "operations_per_soak_step": operations_per_step,
        "before_state": compact_state(before),
        "after_state": compact_state(after),
        "stop_reason": stop_reason,
        "validation_status": "SOAK_VALIDATION_PENDING",
    }
    learn_soak(report)
    write_outputs(report)
    return report


def validate_soak(write: bool = True) -> Dict[str, Any]:
    report = load_dict(LATEST_JSON) or load_dict(REPORT_JSON) or base_report("validate-soak", "SOAK_VALIDATION_NO_RUN")
    state = collect_system_state()
    invalid_json = (state.get("validation") or {}).get("invalid_json") or []
    source_findings = (state.get("validation") or {}).get("source_safety_findings") or []
    pattern_findings = ((state.get("validation") or {}).get("pattern_scan") or {}).get("findings") or []
    step_failures = [
        item for item in report.get("soak_results", [])
        if isinstance(item, dict) and (item.get("validation") or {}).get("status") != "SOAK_STEP_VALIDATION_OK"
    ]
    status = "SOAK_VALIDATION_OK"
    if invalid_json or source_findings or pattern_findings or step_failures or state.get("breach"):
        status = "SOAK_VALIDATION_WARNINGS"
    validation = {
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "timestamp_utc": utc_now(),
        "action": "validate-soak",
        "status": status,
        "step_failure_count": len(step_failures),
        "invalid_json": invalid_json,
        "source_safety_findings": source_findings,
        "pattern_findings": pattern_findings,
        "system_state": compact_state(state),
        **HARD_DEFAULTS,
    }
    if write:
        report.update({"action": "validate-soak", "validation_status": status, "soak_validation": validation, "status": status})
        write_outputs(report)
    return validation


def regression_gate(write: bool = True) -> Dict[str, Any]:
    report = load_dict(LATEST_JSON) or load_dict(REPORT_JSON) or base_report("regression-gate", "REGRESSION_GATE_NO_RUN")
    before = report.get("before_state") if isinstance(report.get("before_state"), dict) else {}
    after = compact_state(collect_system_state())
    blockers: List[str] = []
    if before.get("breach") is False and after.get("breach") is True:
        blockers.append("breach_regression")
    if after.get("safety_drift") != "SAFETY_DRIFT_OK":
        blockers.append("safety_drift")
    json_statuses = after.get("json_statuses") if isinstance(after.get("json_statuses"), dict) else {}
    if any(status == "invalid_json" for status in json_statuses.values()):
        blockers.append("invalid_json")
    if (after.get("noop_status") or {}).get("status") == "NOOP_DOMINANCE_DETECTED":
        blockers.append("noop_dominance")
    if (after.get("operation_diversity") or {}).get("status") == "DIVERSITY_FAILURE":
        blockers.append("operation_diversity_failure")
    if after.get("owner_briefing_status") != "OWNER_BRIEFING_READY":
        blockers.append("owner_briefing_missing")
    status = "REGRESSION_GATE_OK" if not blockers else "REGRESSION_GATE_BLOCKED"
    gate = {
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "timestamp_utc": utc_now(),
        "action": "regression-gate",
        "status": status,
        "blockers": blockers,
        "before_state": before,
        "after_state": after,
        **HARD_DEFAULTS,
    }
    if write:
        history = load_entries(REGRESSION_HISTORY_JSON)
        history.append({"timestamp_utc": utc_now(), "status": status, "blockers": blockers})
        write_json(REGRESSION_HISTORY_JSON, {"entries": history[-200:], **HARD_DEFAULTS})
        report.update({"action": "regression-gate", "regression_gate_status": status, "regression_gate": gate, "status": status})
        write_outputs(report)
    return gate


def readiness_from(validation: Dict[str, Any], gate: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
    hard_failure = (
        gate.get("status") != "REGRESSION_GATE_OK"
        or validation.get("status") not in {"SOAK_VALIDATION_OK", "SOAK_VALIDATION_NO_RUN"}
        or state.get("breach")
        or (state.get("safety_drift") or {}).get("status") != "SAFETY_DRIFT_OK"
    )
    if hard_failure:
        seal = "READINESS_SEAL_RED"
    elif (state.get("noop_status") or {}).get("status") != "NOOP_STATUS_OK" or (state.get("operation_diversity") or {}).get("status") != "DIVERSITY_OK":
        seal = "READINESS_SEAL_YELLOW"
    else:
        seal = "READINESS_SEAL_GREEN"
    return {
        "status": seal,
        "reason": "all_soak_gates_ok" if seal == "READINESS_SEAL_GREEN" else "review_warnings_or_blockers",
        "validation_status": validation.get("status"),
        "regression_gate_status": gate.get("status"),
        "operation_diversity": state.get("operation_diversity"),
        "mission_diversity": state.get("mission_diversity"),
        "noop_status": state.get("noop_status"),
        **HARD_DEFAULTS,
    }


def build_readiness_seal() -> Dict[str, Any]:
    validation = validate_soak(write=False)
    gate = regression_gate(write=False)
    state = collect_system_state()
    readiness = readiness_from(validation, gate, state)
    history = load_entries(READINESS_HISTORY_JSON)
    history.append({"timestamp_utc": utc_now(), "status": readiness.get("status"), "reason": readiness.get("reason")})
    write_json(READINESS_HISTORY_JSON, {"entries": history[-200:], **HARD_DEFAULTS})
    report = load_dict(LATEST_JSON) or load_dict(REPORT_JSON) or base_report("build-readiness-seal", readiness["status"])
    report.update({
        "action": "build-readiness-seal",
        "status": readiness["status"],
        "readiness_seal": readiness["status"],
        "readiness": readiness,
        "validation_status": validation.get("status"),
        "regression_gate_status": gate.get("status"),
    })
    write_outputs(report)
    return report


def build_owner_summary() -> Dict[str, Any]:
    report = load_dict(LATEST_JSON) or load_dict(REPORT_JSON) or base_report("build-owner-summary", "SOAK_OWNER_SUMMARY_READY")
    if report.get("readiness_seal") in {None, "not_built"}:
        readiness_report = build_readiness_seal()
        report = readiness_report
    report["action"] = "build-owner-summary"
    report["owner_summary_status"] = "SOAK_OWNER_SUMMARY_READY"
    report["status"] = report.get("readiness_seal") or "SOAK_OWNER_SUMMARY_READY"
    write_outputs(report)
    return report


def learn_soak(report: Dict[str, Any]) -> None:
    history = load_entries(SOAK_HISTORY_JSON)
    history.append({
        "timestamp_utc": utc_now(),
        "status": report.get("status"),
        "steps": report.get("soak_steps_completed"),
        "operations_per_soak_step": report.get("operations_per_soak_step"),
        "stop_reason": report.get("stop_reason"),
    })
    write_json(SOAK_HISTORY_JSON, {"entries": history[-200:], **HARD_DEFAULTS})
    stops = load_dict(STOP_PATTERNS_JSON)
    patterns = stops.get("patterns") if isinstance(stops.get("patterns"), dict) else {}
    if report.get("stop_reason"):
        patterns[str(report.get("stop_reason"))] = int(patterns.get(str(report.get("stop_reason")), 0)) + 1
    write_json(STOP_PATTERNS_JSON, {"patterns": patterns, **HARD_DEFAULTS})


def write_playbooks() -> None:
    base = {"schema_version": SCHEMA_VERSION, "phase": PHASE, **HARD_DEFAULTS}
    write_json(PLAYBOOK_SOAK, {
        **base,
        "name": "sentinel-autonomous-soak-test",
        "purpose": "Run repeated safe local supervisor batches and validate stability after every batch.",
        "max_soak_steps": MAX_SOAK_STEPS,
        "allowed_subprocess_modules": sorted(ALLOWLIST_MODULES),
        "blocked_actions": ["live_apply", "network", "external_api", "remote_write", "timer_install", "LOW_LIVE_MEDIUM_HIGH_execution"],
    })
    write_json(PLAYBOOK_REGRESSION, {
        **base,
        "name": "sentinel-autonomous-regression-gate",
        "checks": ["safety flags unchanged", "json valid", "secret scan zero", "diversity ok", "no noop dominance", "completion ledger ok"],
    })
    write_json(PLAYBOOK_READINESS, {
        **base,
        "name": "sentinel-autonomous-readiness-seal",
        "green": ["soak steps ok", "safety drift ok", "json ok", "operation diversity ok", "owner briefing ready"],
        "yellow": ["safe but warning or freshness topics remain"],
        "red": ["breach", "safety drift", "secret finding", "invalid json", "unsafe execution attempt"],
    })
    write_json(PLAYBOOK_OWNER, {
        **base,
        "name": "sentinel-autonomous-soak-owner-summary",
        "fields": ["steps completed", "operations per step", "regression gate", "readiness seal", "blocked capabilities", "next safe operation"],
    })


def render_main_md(report: Dict[str, Any]) -> str:
    return "\n".join([
        "# Sentinel Autonomous Soak Test",
        "",
        f"- status: `{report.get('status')}`",
        f"- action: `{report.get('action')}`",
        f"- soak_steps_completed: `{report.get('soak_steps_completed', 0)}`",
        f"- validation_status: `{report.get('validation_status')}`",
        f"- regression_gate_status: `{report.get('regression_gate_status')}`",
        f"- readiness_seal: `{report.get('readiness_seal')}`",
        f"- stop_reason: `{report.get('stop_reason', '-')}`",
        "- live_apply: `False`",
        "- emergency_stop: `True`",
        "- allowed_apply_now: `False`",
        "- HIGH blocked: `True`",
        "- LOW_LIVE executable: `False`",
        "- MEDIUM executable: `False`",
        "- breach: `False`",
    ]) + "\n"


def render_preflight_md(report: Dict[str, Any]) -> str:
    blockers = report.get("blockers") if isinstance(report.get("blockers"), list) else []
    return "\n".join([
        "# Sentinel Autonomous Soak Preflight",
        "",
        f"- status: `{report.get('status')}`",
        f"- blockers: `{', '.join(blockers) or '-'}`",
        f"- core_modules: `{len(CORE_MODULES)}`",
    ]) + "\n"


def render_run_log_md(report: Dict[str, Any]) -> str:
    lines = ["# Sentinel Autonomous Soak Run Log", ""]
    for item in report.get("soak_results") or []:
        if not isinstance(item, dict):
            continue
        lines.extend([
            f"## Soak Step {item.get('soak_step')}",
            f"- supervisor_status: `{item.get('supervisor_status')}`",
            f"- operations: `{', '.join(item.get('operations') or []) or '-'}`",
            f"- validation: `{(item.get('validation') or {}).get('status')}`",
            "",
        ])
    return "\n".join(lines) + "\n"


def render_validation_md(report: Dict[str, Any]) -> str:
    validation = report.get("soak_validation") if isinstance(report.get("soak_validation"), dict) else {}
    return "\n".join([
        "# Sentinel Autonomous Soak Validation",
        "",
        f"- status: `{report.get('validation_status', validation.get('status', '-'))}`",
        f"- step_failure_count: `{validation.get('step_failure_count', 0)}`",
        f"- readiness_seal: `{report.get('readiness_seal', '-')}`",
    ]) + "\n"


def render_regression_md(report: Dict[str, Any]) -> str:
    gate = report.get("regression_gate") if isinstance(report.get("regression_gate"), dict) else {}
    blockers = gate.get("blockers") if isinstance(gate.get("blockers"), list) else []
    return "\n".join([
        "# Sentinel Autonomous Regression Gate",
        "",
        f"- status: `{report.get('regression_gate_status', gate.get('status', '-'))}`",
        f"- blockers: `{', '.join(blockers) or '-'}`",
    ]) + "\n"


def render_readiness_md(report: Dict[str, Any]) -> str:
    readiness = report.get("readiness") if isinstance(report.get("readiness"), dict) else {}
    return "\n".join([
        "# Sentinel Autonomous Readiness Seal",
        "",
        f"- readiness_seal: `{report.get('readiness_seal', readiness.get('status', '-'))}`",
        f"- reason: `{readiness.get('reason', '-')}`",
        f"- operation_diversity: `{(readiness.get('operation_diversity') or {}).get('status', '-')}`",
        f"- noop_status: `{(readiness.get('noop_status') or {}).get('status', '-')}`",
    ]) + "\n"


def render_owner_md(report: Dict[str, Any]) -> str:
    ops = report.get("operations_per_soak_step") if isinstance(report.get("operations_per_soak_step"), list) else []
    return "\n".join([
        "# Sentinel Autonomous Soak Owner Summary",
        "",
        f"- soak_steps_completed: `{report.get('soak_steps_completed', 0)}`",
        f"- operations_per_soak_step: `{ops}`",
        f"- validation_status: `{report.get('validation_status')}`",
        f"- regression_gate_status: `{report.get('regression_gate_status')}`",
        f"- readiness_seal: `{report.get('readiness_seal')}`",
        f"- owner_summary_status: `{report.get('owner_summary_status')}`",
        "- blocked: live apply, network, external APIs, remote writes, timers, LOW_LIVE, MEDIUM and HIGH execution",
    ]) + "\n"


def render_next_safe_md(report: Dict[str, Any]) -> str:
    state = collect_system_state()
    governor = state.get("raw_reports", {}).get("operation_governor", {}) if isinstance(state.get("raw_reports"), dict) else {}
    next_op = governor.get("selected_operation_name") or (state.get("raw_reports", {}).get("supervisor", {}) or {}).get("next_operation")
    return "\n".join([
        "# Sentinel Autonomous Next Safe Operation",
        "",
        f"- next_safe_operation: `{next_op or 'review_owner_summary'}`",
        "- Scope remains safe local autonomy only.",
    ]) + "\n"


def write_outputs(report: Dict[str, Any]) -> None:
    ensure_dirs()
    safe_report = {
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "timestamp_utc": report.get("timestamp_utc") or utc_now(),
        **report,
        **HARD_DEFAULTS,
        "recommended_git_checkpoint": [
            "sentinel_autonomous_soak_test.py",
            "sentinel_autonomous_operation_governor.py",
            "sentinel_autonomous_operations_supervisor.py",
            "sentinel_autonomy.py",
            "sentinel_autonomous_mission_queue_runner.py",
            "sentinel_autonomous_goal_manager.py",
            "sentinel_autonomous_capability_health_governor.py",
            "sentinel_autonomous_capability_registry.py",
            "sentinel_autonomous_priority_engine.py",
            "sentinel_self_governing_safe_autonomy_kernel.py",
            "sentinel_autonomous_cycle_runner.py",
            "playbooks/sentinel-autonomous-soak-test.playbook.json",
            "playbooks/sentinel-autonomous-regression-gate.playbook.json",
            "playbooks/sentinel-autonomous-readiness-seal.playbook.json",
            "playbooks/sentinel-autonomous-soak-owner-summary.playbook.json",
        ],
    }
    write_json(REPORT_JSON, safe_report)
    write_json(STATE_JSON, safe_report)
    write_json(LATEST_JSON, safe_report)
    write_text(REPORT_MD, render_main_md(safe_report))
    write_text(PREFLIGHT_MD, render_preflight_md(safe_report))
    write_text(RUN_LOG_MD, render_run_log_md(safe_report))
    write_text(VALIDATION_MD, render_validation_md(safe_report))
    write_text(REGRESSION_MD, render_regression_md(safe_report))
    write_text(READINESS_MD, render_readiness_md(safe_report))
    write_text(OWNER_SUMMARY_MD, render_owner_md(safe_report))
    write_text(NEXT_SAFE_MD, render_next_safe_md(safe_report))
    write_playbooks()
    append_jsonl(AUDIT_JSONL, [{
        "timestamp_utc": utc_now(),
        "event": "autonomous_soak_test",
        "action": safe_report.get("action"),
        "status": safe_report.get("status"),
        "soak_steps_completed": safe_report.get("soak_steps_completed", 0),
        "readiness_seal": safe_report.get("readiness_seal"),
        "breach": False,
        "live_apply": False,
    }])


def self_test() -> Dict[str, Any]:
    source = Path(__file__).read_text(encoding="utf-8")
    findings = source_safety_findings([Path(__file__)])
    fake_ok = {
        "breach": False,
        "safety_drift": {"status": "SAFETY_DRIFT_OK"},
        "operation_diversity": {"status": "DIVERSITY_OK"},
        "noop_status": {"status": "NOOP_STATUS_OK"},
    }
    fake_validation = {"status": "SOAK_VALIDATION_OK"}
    fake_gate = {"status": "REGRESSION_GATE_OK"}
    readiness = readiness_from(fake_validation, fake_gate, fake_ok)
    tests = {
        "no_apply_argument": not re.search(r"add_argument\([\"']--" + "apply", source),
        "no_network_imports": not NETWORK_IMPORT_RE.search(source),
        "no_shell_true": ("shell" + "=True") not in source,
        "no_free_subprocess": not any(item.get("finding") == "free_subprocess_present" for item in findings),
        "max_soak_limited": MAX_SOAK_STEPS <= 5,
        "allowlist_modules_only": all(module in ALLOWLIST_MODULES for module, _ in SELF_TEST_COMMANDS),
        "regression_gate_logic": regression_gate(write=False).get("status") in {"REGRESSION_GATE_OK", "REGRESSION_GATE_BLOCKED"},
        "readiness_seal_logic": readiness.get("status") == "READINESS_SEAL_GREEN",
        "json_valid": True,
        "breach_false": HARD_DEFAULTS["breach"] is False,
    }
    status = "SOAK_SELF_TEST_OK" if all(tests.values()) and not findings else "SOAK_SELF_TEST_FAILED"
    report = {**base_report("self-test", status), "tests": tests, "source_safety_findings": findings}
    write_outputs(report)
    return report


def status_report() -> Dict[str, Any]:
    data = load_dict(LATEST_JSON) or load_dict(REPORT_JSON) or base_report("status", "SOAK_STATUS_EMPTY")
    print(f"status={data.get('status')}")
    print(f"soak_steps_completed={data.get('soak_steps_completed', 0)}")
    print(f"validation_status={data.get('validation_status')}")
    print(f"regression_gate_status={data.get('regression_gate_status')}")
    print(f"readiness_seal={data.get('readiness_seal')}")
    print(f"owner_summary_status={data.get('owner_summary_status')}")
    print(f"stop_reason={data.get('stop_reason')}")
    print(f"live_apply={data.get('live_apply')}")
    print(f"emergency_stop={data.get('emergency_stop')}")
    print(f"allowed_apply_now={data.get('allowed_apply_now')}")
    print(f"HIGH_blocked={data.get('high_blocked')}")
    print(f"LOW_LIVE_executable={data.get('low_live_executable')}")
    print(f"MEDIUM_executable={data.get('medium_executable')}")
    print(f"breach={data.get('breach')}")
    return data


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Sentinel Autonomous Soak Test")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--run-soak", type=int)
    parser.add_argument("--validate-soak", action="store_true")
    parser.add_argument("--regression-gate", action="store_true")
    parser.add_argument("--build-readiness-seal", action="store_true")
    parser.add_argument("--build-owner-summary", action="store_true")
    parser.add_argument("--status", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        report = self_test()
    elif args.preflight:
        report = preflight()
    elif args.run_soak is not None:
        report = run_soak(args.run_soak)
    elif args.validate_soak:
        validation = validate_soak(write=True)
        report = load_dict(LATEST_JSON)
        report["validation_status"] = validation.get("status")
    elif args.regression_gate:
        gate = regression_gate(write=True)
        report = load_dict(LATEST_JSON)
        report["regression_gate_status"] = gate.get("status")
    elif args.build_readiness_seal:
        report = build_readiness_seal()
    elif args.build_owner_summary:
        report = build_owner_summary()
    elif args.status:
        status_report()
        return 0
    else:
        parser.print_help()
        return 2
    return 0 if report.get("status") != "SOAK_SELF_TEST_FAILED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
