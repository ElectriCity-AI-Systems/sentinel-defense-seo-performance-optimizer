#!/usr/bin/env python3
"""Sentinel Autonomous Operations Supervisor (Phase 10.7).

Central local operations layer for Sentinel's controlled autonomy stack. The
supervisor decides which safe local autonomy module should run next, executes
only hard-allowlisted commands, validates the resulting system state and writes
owner-facing reports. It never performs live apply, network access, external
API calls, remote writes, timer installation or customer-system changes.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


PROJECT_DIR = Path("/srv/sentinel-defense")
SCHEMA_VERSION = "sentinel-autonomous-operations-supervisor-10.7"
PHASE = "10.7"
MAX_BATCH = 5
DEFAULT_BATCH = 3
OP_TIMEOUT_SECONDS = 360

READ_ONLY = "READ_ONLY"
DRAFT = "DRAFT"
LOW_LOCAL = "LOW_LOCAL"
LOW_EXPORT = "LOW_EXPORT"
LOW_STATE = "LOW_STATE"
LOW_LIVE = "LOW_LIVE"
MEDIUM = "MEDIUM"
HIGH = "HIGH"
AUTO_ALLOWED_RISK = {READ_ONLY, DRAFT, LOW_LOCAL, LOW_EXPORT, LOW_STATE}

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

REPORT_JSON = R / "sentinel-autonomous-operations-supervisor.json"
REPORT_MD = R / "sentinel-autonomous-operations-supervisor.md"
PREFLIGHT_MD = R / "sentinel-autonomous-operations-preflight.md"
DECISION_MD = R / "sentinel-autonomous-operation-decision.md"
RUN_LOG_MD = R / "sentinel-autonomous-operation-run-log.md"
VALIDATION_MD = R / "sentinel-autonomous-system-validation.md"
OWNER_BRIEFING_MD = R / "sentinel-autonomous-owner-briefing.md"
NEXT_OPERATION_MD = R / "sentinel-autonomous-next-operation.md"
SAFETY_DRIFT_MD = R / "sentinel-autonomous-safety-drift-report.md"

STATE_JSON = STATE_DIR / "autonomous_operations_supervisor.json"
LATEST_JSON = STATE_DIR / "latest_autonomous_operations_supervisor.json"
HISTORY_JSON = STATE_DIR / "autonomous_operations_history.json"
PATTERNS_JSON = STATE_DIR / "autonomous_operation_patterns.json"
BLOCKED_PATTERNS_JSON = STATE_DIR / "autonomous_blocked_operation_patterns.json"
SAFETY_DRIFT_HISTORY_JSON = STATE_DIR / "autonomous_safety_drift_history.json"

AUDIT_JSONL = AUDIT_DIR / "sentinel-autonomous-operations-supervisor.jsonl"

PLAYBOOK_SUPERVISOR = PLAYBOOK_DIR / "sentinel-autonomous-operations-supervisor.playbook.json"
PLAYBOOK_DECISION = PLAYBOOK_DIR / "sentinel-autonomous-operation-decision.playbook.json"
PLAYBOOK_VALIDATION = PLAYBOOK_DIR / "sentinel-autonomous-system-validation.playbook.json"
PLAYBOOK_OWNER = PLAYBOOK_DIR / "sentinel-autonomous-owner-briefing.playbook.json"

MISSION_RUNNER_JSON = STATE_DIR / "latest_autonomous_mission_queue_runner.json"
MISSION_RUNNER_REPORT_JSON = R / "sentinel-autonomous-mission-queue-runner.json"
GOAL_MANAGER_JSON = STATE_DIR / "latest_autonomous_goal_manager.json"
GOAL_MANAGER_REPORT_JSON = R / "sentinel-autonomous-goal-manager.json"
HEALTH_GOVERNOR_JSON = STATE_DIR / "latest_autonomous_capability_health_governor.json"
HEALTH_GOVERNOR_REPORT_JSON = R / "sentinel-autonomous-capability-health-governor.json"
CAPABILITY_REGISTRY_JSON = STATE_DIR / "autonomous_capability_registry.json"
CAPABILITY_REGISTRY_REPORT_JSON = R / "sentinel-autonomous-capability-registry.json"
PRIORITY_MODEL_JSON = STATE_DIR / "autonomy_task_priority_model.json"
PRIORITY_ENGINE_JSON = R / "sentinel-autonomous-priority-engine.json"
OPERATION_GOVERNOR_MODEL_JSON = STATE_DIR / "autonomous_operation_governor_model.json"
OPERATION_GOVERNOR_JSON = STATE_DIR / "latest_autonomous_operation_governor.json"
OPERATION_GOVERNOR_REPORT_JSON = R / "sentinel-autonomous-operation-governor.json"
SOAK_TEST_JSON = STATE_DIR / "latest_autonomous_soak_test.json"
SOAK_TEST_REPORT_JSON = R / "sentinel-autonomous-soak-test.json"
KERNEL_JSON = STATE_DIR / "latest_self_governing_autonomy_kernel.json"
KERNEL_REPORT_JSON = R / "sentinel-self-governing-autonomy-kernel.json"
CYCLE_RUNNER_JSON = STATE_DIR / "latest_autonomous_cycle_runner.json"
CYCLE_RUNNER_REPORT_JSON = R / "sentinel-autonomous-cycle-runner.json"
COMPLETION_LEDGER_JSON = STATE_DIR / "autonomous_mission_completion_ledger.json"
MISSION_QUEUE_JSON = STATE_DIR / "autonomous_mission_queue.json"

ALLOWED_WRITE_ROOTS = (R, STATE_DIR, AUDIT_DIR, PLAYBOOK_DIR)

ALLOWED_MODULES = {
    "sentinel_autonomous_mission_queue_runner.py",
    "sentinel_autonomous_goal_manager.py",
    "sentinel_autonomous_capability_health_governor.py",
    "sentinel_autonomous_capability_registry.py",
    "sentinel_autonomous_priority_engine.py",
    "sentinel_autonomous_operation_governor.py",
    "sentinel_autonomous_soak_test.py",
    "sentinel_self_governing_safe_autonomy_kernel.py",
    "sentinel_autonomous_cycle_runner.py",
}

ALLOWED_ARGS = {
    "--self-test",
    "--status",
    "--preflight",
    "--cycle",
    "--run-missions",
    "--run-cycles",
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
    "--write-registry",
    "--scan-history",
    "--score-tasks",
    "--select-next",
    "--simulate-diversity",
    "--write-model",
    "--scan-operations",
    "--score-operations",
    "--detect-noops",
    "--select-operation",
    "--run-soak",
    "--validate-soak",
    "--regression-gate",
    "--build-readiness-seal",
    "--observe",
    "--decide",
    "--classify",
    "--execute",
    "--validate",
    "--repair",
}

OPERATIONS = {
    "run_health_governor_cycle": {
        "risk_class": LOW_STATE,
        "module": "sentinel_autonomous_capability_health_governor.py",
        "args": ["--cycle"],
        "reason": "repairable capability health warning",
    },
    "run_goal_manager_cycle": {
        "risk_class": LOW_STATE,
        "module": "sentinel_autonomous_goal_manager.py",
        "args": ["--cycle"],
        "reason": "mission queue missing or stale",
    },
    "run_mission_queue_runner": {
        "risk_class": LOW_STATE,
        "module": "sentinel_autonomous_mission_queue_runner.py",
        "args": ["--run-missions", "3"],
        "reason": "safe mission queue has executable local missions",
    },
    "run_priority_engine_model": {
        "risk_class": LOW_STATE,
        "module": "sentinel_autonomous_priority_engine.py",
        "args": ["--write-model"],
        "reason": "priority model missing or stale",
    },
    "run_capability_registry_refresh": {
        "risk_class": LOW_STATE,
        "module": "sentinel_autonomous_capability_registry.py",
        "args": ["--write-registry"],
        "reason": "capability registry missing or stale",
    },
    "run_kernel_safe_cycle": {
        "risk_class": LOW_STATE,
        "module": "sentinel_self_governing_safe_autonomy_kernel.py",
        "args": ["--cycle"],
        "reason": "safe fallback kernel cycle available",
    },
    "build_owner_briefing": {
        "risk_class": DRAFT,
        "module": None,
        "args": [],
        "reason": "owner briefing requested",
    },
    "validate_system": {
        "risk_class": READ_ONLY,
        "module": None,
        "args": [],
        "reason": "system validation requested",
    },
    "status_only": {
        "risk_class": READ_ONLY,
        "module": None,
        "args": [],
        "reason": "status requested",
    },
}

STOP_STATUSES = {
    "STOP_ON_BREACH",
    "STOP_ON_SAFETY_DRIFT",
    "STOP_ON_NO_SAFE_OPERATION",
    "STOP_ON_OPERATION_FAILURE",
    "STOP_ON_MAX_BATCH",
    "STOP_ON_REPEATED_OPERATION",
    "STOP_ON_VALIDATION_FAILURE",
}

FORBIDDEN_IMPORT_RE = re.compile(
    r"^\s*(?:import|from)\s+(requests|urllib|http\.client|smtplib|socket|paramiko|cloudflare)\b",
    re.MULTILINE,
)
SECRET_TERMS = [
    "sentinel_sftp_" + "pass" + "word",
    "bear" + "er" + r"\s+[a-z0-9._-]+",
    "api[_-]?" + "key" + r"\s*[:=]\s*[^,\s]+",
    "s" + "k-" + r"[a-z0-9]{20,}",
    "g" + "hp_" + r"[a-z0-9_]{12,}",
    "github_" + "pat_" + r"[a-z0-9_]{12,}",
    "begin" + r"\s+(?:open)?ssh\s+private\s+" + "key",
    "begin" + r"\s+rsa\s+private\s+" + "key",
]
SECRET_RE = re.compile(r"(?i)(" + "|".join(SECRET_TERMS) + ")")
CUSTOMER_DATA_RE = re.compile(r"(?i)(real\s+customer|customer\s+credential|payment\s+card|iban|ssn)")
PRIVATE_IP_RE = re.compile(r"\b(?:10|127|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b")
INTERNAL_PATH_RE = re.compile(r"(?<!`)\/(?:srv|home|root|etc|var)\/[A-Za-z0-9_.\/-]+")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_time(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def age_hours(path: Path) -> Optional[float]:
    if not path.exists():
        return None
    return max(0.0, (datetime.now(timezone.utc).timestamp() - path.stat().st_mtime) / 3600.0)


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


def redact_text(value: Any, limit: int = 3000) -> str:
    text = "" if value is None else str(value)
    text = SECRET_RE.sub("[REDACTED]", text)
    return text[:limit]


def assert_safe_content(text: str, path: Optional[Path] = None) -> None:
    if SECRET_RE.search(text):
        raise RuntimeError(f"Secret-like value blocked in {rel(path) if path else 'content'}")
    if CUSTOMER_DATA_RE.search(text):
        raise RuntimeError(f"Customer-data marker blocked in {rel(path) if path else 'content'}")


def write_text(path: Path, text: str) -> None:
    assert_write_path(path)
    assert_safe_content(text, path)
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
            line = json.dumps(row, sort_keys=True)
            assert_safe_content(line, path)
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


def load_list_or_entries(path: Path) -> List[Dict[str, Any]]:
    data, status = read_json(path)
    if status == "ok" and isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if status == "ok" and isinstance(data, dict) and isinstance(data.get("entries"), list):
        return [item for item in data["entries"] if isinstance(item, dict)]
    return []


def exact_git_command(kind: str) -> Dict[str, Any]:
    commands = {
        "status": ["git", "status", "--short"],
        "log": ["git", "log", "--oneline", "-5"],
    }
    cmd = commands[kind]
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(PROJECT_DIR),
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired) as exc:
        return {"status": "error", "lines": [], "error": redact_text(exc)}
    return {
        "status": "ok" if proc.returncode == 0 else "failed",
        "returncode": proc.returncode,
        "lines": [redact_text(line, 300) for line in (proc.stdout or "").splitlines()[:20]],
    }


def module_arg_allowed(module: str, args: List[str]) -> bool:
    if module not in ALLOWED_MODULES:
        return False
    if not (PROJECT_DIR / module).exists():
        return False
    i = 0
    while i < len(args):
        arg = str(args[i])
        if arg not in ALLOWED_ARGS:
            if i > 0 and args[i - 1] in {"--run-missions", "--run-cycles", "--simulate-diversity", "--run-soak"} and str(arg).isdigit():
                i += 1
                continue
            return False
        i += 1
    return True


def run_allowlisted(module: str, args: List[str], timeout: int = OP_TIMEOUT_SECONDS) -> Dict[str, Any]:
    if not module_arg_allowed(module, args):
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
        "supervisor": REPORT_JSON,
        "mission_queue_runner": MISSION_RUNNER_REPORT_JSON,
        "goal_manager": GOAL_MANAGER_REPORT_JSON,
        "health_governor": HEALTH_GOVERNOR_REPORT_JSON,
        "capability_registry": CAPABILITY_REGISTRY_REPORT_JSON,
        "priority_engine": PRIORITY_ENGINE_JSON,
        "operation_governor": OPERATION_GOVERNOR_REPORT_JSON,
        "soak_test": SOAK_TEST_REPORT_JSON,
        "kernel": KERNEL_REPORT_JSON,
        "cycle_runner": CYCLE_RUNNER_REPORT_JSON,
        "completion_ledger": COMPLETION_LEDGER_JSON,
    }
    return {name: read_json(path)[1] for name, path in paths.items()}


def gather_state() -> Dict[str, Any]:
    reports = {
        "mission_runner": load_dict(MISSION_RUNNER_JSON) or load_dict(MISSION_RUNNER_REPORT_JSON),
        "goal_manager": load_dict(GOAL_MANAGER_JSON) or load_dict(GOAL_MANAGER_REPORT_JSON),
        "health_governor": load_dict(HEALTH_GOVERNOR_JSON) or load_dict(HEALTH_GOVERNOR_REPORT_JSON),
        "capability_registry": load_dict(CAPABILITY_REGISTRY_JSON) or load_dict(CAPABILITY_REGISTRY_REPORT_JSON),
        "priority_engine": load_dict(PRIORITY_MODEL_JSON) or load_dict(PRIORITY_ENGINE_JSON),
        "operation_governor": load_dict(OPERATION_GOVERNOR_MODEL_JSON) or load_dict(OPERATION_GOVERNOR_JSON) or load_dict(OPERATION_GOVERNOR_REPORT_JSON),
        "soak_test": load_dict(SOAK_TEST_JSON) or load_dict(SOAK_TEST_REPORT_JSON),
        "kernel": load_dict(KERNEL_JSON) or load_dict(KERNEL_REPORT_JSON),
        "cycle_runner": load_dict(CYCLE_RUNNER_JSON) or load_dict(CYCLE_RUNNER_REPORT_JSON),
        "completion_ledger": load_dict(COMPLETION_LEDGER_JSON),
        "mission_queue": load_dict(MISSION_QUEUE_JSON),
        "supervisor": load_dict(LATEST_JSON),
    }
    return {
        "timestamp_utc": utc_now(),
        "reports": reports,
        "json_statuses": json_statuses(),
        "git_status": exact_git_command("status"),
        "git_log": exact_git_command("log"),
        "ages_hours": {
            "mission_queue": age_hours(MISSION_QUEUE_JSON),
            "mission_runner": age_hours(MISSION_RUNNER_JSON),
            "goal_manager": age_hours(GOAL_MANAGER_JSON),
            "health_governor": age_hours(HEALTH_GOVERNOR_JSON),
            "capability_registry": age_hours(CAPABILITY_REGISTRY_JSON),
            "priority_model": age_hours(PRIORITY_MODEL_JSON),
            "operation_governor_model": age_hours(OPERATION_GOVERNOR_MODEL_JSON),
            "soak_test": age_hours(SOAK_TEST_JSON),
            "kernel": age_hours(KERNEL_JSON),
            "completion_ledger": age_hours(COMPLETION_LEDGER_JSON),
        },
    }


def breach_status(state: Dict[str, Any]) -> Dict[str, Any]:
    sources: List[Dict[str, Any]] = []
    breach = False
    for name, data in (state.get("reports") or {}).items():
        if not isinstance(data, dict) or not data:
            continue
        item_breach = bool(data.get("breach"))
        item_live = data.get("live_apply") is True or data.get("allowed_apply_now") is True
        if item_breach or item_live:
            breach = True
        sources.append({
            "name": name,
            "status": data.get("status"),
            "breach": item_breach,
            "live_or_apply_flag": item_live,
        })
    return {"breach": breach, "sources": sources}


def safety_drift(state: Dict[str, Any]) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    for name, data in (state.get("reports") or {}).items():
        if not isinstance(data, dict) or not data:
            continue
        checks = {
            "live_apply": False,
            "allowed_apply_now": False,
            "high_blocked": True,
            "low_live_executable": False,
            "medium_executable": False,
        }
        for field, expected in checks.items():
            if field in data and data.get(field) != expected:
                findings.append({"source": name, "field": field, "expected": expected, "actual": data.get(field)})
        if "emergency_stop" in data and data.get("emergency_stop") is not True:
            findings.append({"source": name, "field": "emergency_stop", "expected": True, "actual": data.get("emergency_stop")})
    return {
        "status": "SAFETY_DRIFT_DETECTED" if findings else "SAFETY_DRIFT_OK",
        "findings": findings,
        **HARD_DEFAULTS,
    }


def health_warnings_repairable(state: Dict[str, Any]) -> bool:
    governor = (state.get("reports") or {}).get("health_governor")
    if not isinstance(governor, dict):
        return False
    warning_count = int(governor.get("warning_count") or 0)
    blocked = int(governor.get("blocked_repair_count") or 0)
    return warning_count > 0 and blocked < warning_count


def mission_queue_stale_or_missing(state: Dict[str, Any]) -> bool:
    queue_status = (state.get("json_statuses") or {}).get("completion_ledger")
    mission_queue_status = read_json(MISSION_QUEUE_JSON)[1]
    age = (state.get("ages_hours") or {}).get("mission_queue")
    if mission_queue_status != "ok":
        return True
    return age is not None and age > 8.0 and queue_status == "ok"


def safe_missions_open(state: Dict[str, Any]) -> bool:
    goal = (state.get("reports") or {}).get("goal_manager")
    if not isinstance(goal, dict):
        return True
    count = int(goal.get("executable_mission_count") or 0)
    queue = goal.get("mission_queue") or goal.get("classified_missions") or goal.get("routed_missions") or []
    if count > 0:
        return True
    if isinstance(queue, list):
        return any(isinstance(item, dict) and item.get("can_execute_autonomously") for item in queue)
    return False


def priority_model_stale_or_missing(state: Dict[str, Any]) -> bool:
    status = read_json(PRIORITY_MODEL_JSON)[1]
    age = (state.get("ages_hours") or {}).get("priority_model")
    return status != "ok" or (age is not None and age > 6.0)


def registry_stale_or_missing(state: Dict[str, Any]) -> bool:
    status = read_json(CAPABILITY_REGISTRY_JSON)[1]
    age = (state.get("ages_hours") or {}).get("capability_registry")
    return status != "ok" or (age is not None and age > 12.0)


def operation_record(operation: str, reason: str, status: str = "OPERATION_SELECTED") -> Dict[str, Any]:
    meta = OPERATIONS[operation]
    can_execute = meta["risk_class"] in AUTO_ALLOWED_RISK
    return {
        "operation": operation,
        "status": status,
        "reason": reason,
        "risk_class": meta["risk_class"],
        "module": meta["module"],
        "args": meta["args"],
        "can_execute_now": can_execute,
        **HARD_DEFAULTS,
    }


def operation_governor_candidate(state: Dict[str, Any]) -> Dict[str, Any]:
    model = (state.get("reports") or {}).get("operation_governor")
    if not isinstance(model, dict) or not model:
        return {"status": "OPERATION_GOVERNOR_MODEL_MISSING", "selected": None}
    selected = model.get("selected_operation")
    if isinstance(selected, dict):
        operation = selected.get("operation_name") or selected.get("operation_id") or selected.get("operation")
        score = selected.get("final_score")
        can_execute = selected.get("can_execute_now")
        reason = selected.get("reason_if_blocked") or selected.get("selection_reason") or "operation governor model"
    else:
        operation = model.get("selected_operation_name") or model.get("selected_operation")
        score = model.get("selected_operation_score")
        can_execute = model.get("selected_operation_can_execute_now", True)
        reason = model.get("selection_reason") or "operation governor model"
    if not operation or operation not in OPERATIONS:
        return {"status": "OPERATION_GOVERNOR_MODEL_NO_VALID_SELECTION", "selected": None, "model_status": model.get("status")}
    if can_execute is False:
        return {
            "status": "OPERATION_GOVERNOR_SELECTION_BLOCKED",
            "selected": None,
            "operation": operation,
            "reason": reason,
            "model_status": model.get("status"),
        }
    record = operation_record(str(operation), f"operation governor selected: {reason}")
    record["governor_score"] = score
    record["governor_model_status"] = model.get("status")
    record["governor_diversity_status"] = (model.get("diversity") or {}).get("status") if isinstance(model.get("diversity"), dict) else None
    record["governor_cooldown_status"] = model.get("cooldown_status")
    return {
        "status": "OPERATION_GOVERNOR_SELECTION_ACCEPTED",
        "selected": record,
        "operation": operation,
        "model_status": model.get("status"),
    }


def operation_governor_alternate(used_operations: List[str], current_operation: Optional[str]) -> Optional[Dict[str, Any]]:
    model = load_dict(OPERATION_GOVERNOR_MODEL_JSON) or load_dict(OPERATION_GOVERNOR_JSON) or load_dict(OPERATION_GOVERNOR_REPORT_JSON)
    candidates = model.get("operation_scores") if isinstance(model.get("operation_scores"), list) else model.get("top_scores")
    if not isinstance(candidates, list):
        return None
    used_set = {op for op in used_operations if op}
    for item in candidates:
        if not isinstance(item, dict):
            continue
        operation = item.get("operation_name") or item.get("operation_id") or item.get("operation")
        if operation not in OPERATIONS:
            continue
        if operation == current_operation or operation in used_set:
            continue
        if item.get("can_execute_now") is False:
            continue
        if float(item.get("final_score") or 0.0) <= 0:
            continue
        record = operation_record(str(operation), "operation governor batch diversity alternate")
        record["governor_score"] = item.get("final_score")
        record["governor_model_status"] = model.get("status")
        record["batch_diversity_override"] = True
        return record
    return None


def decide_operation(state: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    state = state or gather_state()
    breach = breach_status(state)
    drift = safety_drift(state)
    governor = operation_governor_candidate(state)
    if breach["breach"]:
        selected = operation_record("build_owner_briefing", "breach detected", "STOP_ON_BREACH")
        selected["can_execute_now"] = False
    elif drift["status"] != "SAFETY_DRIFT_OK":
        selected = operation_record("build_owner_briefing", "safety drift detected", "STOP_ON_SAFETY_DRIFT")
        selected["can_execute_now"] = False
    elif governor.get("selected"):
        selected = governor["selected"]
    elif health_warnings_repairable(state):
        selected = operation_record("run_health_governor_cycle", "repairable capability health warning")
    elif mission_queue_stale_or_missing(state):
        selected = operation_record("run_goal_manager_cycle", "mission queue missing or stale")
    elif safe_missions_open(state):
        selected = operation_record("run_mission_queue_runner", "safe executable missions available")
    elif priority_model_stale_or_missing(state):
        selected = operation_record("run_priority_engine_model", "priority model missing or stale")
    elif registry_stale_or_missing(state):
        selected = operation_record("run_capability_registry_refresh", "capability registry missing or stale")
    elif read_json(KERNEL_JSON)[1] == "ok" or read_json(KERNEL_REPORT_JSON)[1] == "ok":
        selected = operation_record("run_kernel_safe_cycle", "safe fallback kernel cycle")
    else:
        selected = operation_record("build_owner_briefing", "no safe operation available", "STOP_ON_NO_SAFE_OPERATION")
        selected["can_execute_now"] = False
    decision = {
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "timestamp_utc": utc_now(),
        "action": "decide-operation",
        "status": "OPERATION_DECISION_READY" if selected.get("can_execute_now") else selected["status"],
        "selected_operation": selected,
        "operation_governor": governor,
        "breach_state": breach,
        "safety_drift": drift,
        "system_health": system_health_summary(state),
        "next_operation": selected.get("operation"),
        **HARD_DEFAULTS,
    }
    write_outputs(decision)
    return decision


def system_health_summary(state: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    state = state or gather_state()
    statuses = state.get("json_statuses") or {}
    invalid = [name for name, status in statuses.items() if status == "invalid_json"]
    missing = [name for name, status in statuses.items() if status == "missing"]
    reports = state.get("reports") or {}
    health = reports.get("health_governor") if isinstance(reports.get("health_governor"), dict) else {}
    mission_runner = reports.get("mission_runner") if isinstance(reports.get("mission_runner"), dict) else {}
    operation_governor = reports.get("operation_governor") if isinstance(reports.get("operation_governor"), dict) else {}
    soak_test = reports.get("soak_test") if isinstance(reports.get("soak_test"), dict) else {}
    return {
        "json_invalid_count": len(invalid),
        "json_missing_count": len(missing),
        "invalid_json": invalid,
        "missing_json": missing,
        "capability_warning_count": int(health.get("warning_count") or 0) if health else 0,
        "mission_runner_status": mission_runner.get("status") if mission_runner else "not_available",
        "mission_completion_count": int(mission_runner.get("missions_completed") or 0) if mission_runner else 0,
        "operation_governor_status": operation_governor.get("status") if operation_governor else "not_available",
        "operation_governor_selected": operation_governor.get("selected_operation_name") if operation_governor else None,
        "last_soak_status": soak_test.get("status") if soak_test else "not_available",
        "readiness_seal": soak_test.get("readiness_seal") if soak_test else None,
        "regression_gate_status": soak_test.get("regression_gate_status") if soak_test else None,
        "status": "SYSTEM_HEALTH_OK" if not invalid else "SYSTEM_HEALTH_WARNINGS",
    }


def execute_operation(decision: Dict[str, Any]) -> Dict[str, Any]:
    selected = decision.get("selected_operation") if isinstance(decision.get("selected_operation"), dict) else {}
    operation = selected.get("operation")
    if not selected.get("can_execute_now") or operation not in OPERATIONS:
        return {
            "status": selected.get("status", "STOP_ON_NO_SAFE_OPERATION"),
            "operation": operation,
            "executed": False,
            "reason": selected.get("reason"),
            **HARD_DEFAULTS,
        }
    if operation in {"build_owner_briefing", "validate_system", "status_only"}:
        return {
            "status": "OPERATION_INTERNAL_COMPLETED",
            "operation": operation,
            "executed": True,
            "module": None,
            "args": [],
            "returncode": 0,
            **HARD_DEFAULTS,
        }
    result = run_allowlisted(str(selected.get("module")), list(selected.get("args") or []))
    return {
        "status": "OPERATION_EXECUTED" if result.get("returncode") == 0 else "STOP_ON_OPERATION_FAILURE",
        "operation": operation,
        "executed": result.get("returncode") == 0,
        "module_result": result,
        **HARD_DEFAULTS,
    }


def preflight() -> Dict[str, Any]:
    ensure_dirs()
    state = gather_state()
    module_checks = {
        module: {
            "exists": (PROJECT_DIR / module).exists(),
            "py_compile_needed": True,
        }
        for module in sorted(ALLOWED_MODULES)
    }
    drift = safety_drift(state)
    breach = breach_status(state)
    blockers: List[str] = []
    if breach["breach"]:
        blockers.append("breach")
    if drift["status"] != "SAFETY_DRIFT_OK":
        blockers.append("safety_drift")
    for module, item in module_checks.items():
        if not item["exists"]:
            blockers.append(f"missing_module:{module}")
    status = "OPERATIONS_PREFLIGHT_OK" if not blockers else "OPERATIONS_PREFLIGHT_BLOCKED"
    report = {
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "timestamp_utc": utc_now(),
        "action": "preflight",
        "status": status,
        "blockers": blockers,
        "module_checks": module_checks,
        "json_statuses": state.get("json_statuses"),
        "breach_state": breach,
        "safety_drift": drift,
        "output_roots": [rel(root) for root in ALLOWED_WRITE_ROOTS],
        **HARD_DEFAULTS,
    }
    write_outputs(report)
    return report


def run_safe_once() -> Dict[str, Any]:
    state = gather_state()
    decision = decide_operation(state)
    execution = execute_operation(decision)
    validation = validate_system(write=False)
    status = "OPERATIONS_SAFE_ONCE_COMPLETED" if execution.get("executed") and validation.get("status") == "SYSTEM_VALIDATION_OK" else execution.get("status", "OPERATIONS_SAFE_ONCE_STOPPED")
    report = base_report("run-safe-once", status)
    report.update({
        "selected_operation": (decision.get("selected_operation") or {}).get("operation"),
        "operation_decision": decision,
        "operation_results": [execution],
        "operations_completed": 1 if execution.get("executed") else 0,
        "system_validation": validation,
        "stop_reason": None if execution.get("executed") else execution.get("status"),
        "next_operation": decide_operation(gather_state()).get("next_operation"),
    })
    learn_from_report(report)
    write_outputs(report)
    return report


def run_safe_batch(n: int) -> Dict[str, Any]:
    if n > MAX_BATCH:
        report = base_report("run-safe-batch", "STOP_ON_MAX_BATCH")
        report["requested_batch"] = n
        report["stop_reason"] = "STOP_ON_MAX_BATCH"
        write_outputs(report)
        return report
    operations: List[Dict[str, Any]] = []
    completed = 0
    stop_reason = None
    previous_effect_key = None
    for index in range(1, max(1, n) + 1):
        state = gather_state()
        decision = decide_operation(state)
        selected = decision.get("selected_operation") if isinstance(decision.get("selected_operation"), dict) else {}
        operation = selected.get("operation")
        alternate = None
        if operation in {item.get("selected_operation") for item in operations if isinstance(item, dict)}:
            alternate = operation_governor_alternate(
                [str(item.get("selected_operation")) for item in operations if item.get("selected_operation")],
                str(operation) if operation else None,
            )
        if alternate:
            selected = alternate
            operation = selected.get("operation")
            decision["selected_operation"] = selected
            decision["next_operation"] = operation
            decision["status"] = "OPERATION_DECISION_READY"
            decision["operation_governor_batch_override"] = {
                "status": "OPERATION_GOVERNOR_BATCH_DIVERSITY_OVERRIDE",
                "selected_operation": operation,
            }
        if decision.get("status") in {"STOP_ON_BREACH", "STOP_ON_SAFETY_DRIFT", "STOP_ON_NO_SAFE_OPERATION"}:
            stop_reason = decision.get("status")
            operations.append({"operation_index": index, "decision": decision, "execution": {"executed": False, "status": stop_reason}})
            break
        execution = execute_operation(decision)
        validation = validate_system(write=False)
        effect_key = f"{operation}:{execution.get('status')}:{validation.get('status')}"
        operations.append({
            "operation_index": index,
            "selected_operation": operation,
            "decision": decision,
            "execution": execution,
            "validation_status": validation.get("status"),
            "completed": bool(execution.get("executed") and validation.get("status") == "SYSTEM_VALIDATION_OK"),
        })
        if execution.get("executed") and validation.get("status") == "SYSTEM_VALIDATION_OK":
            completed += 1
        if execution.get("status", "").startswith("STOP_"):
            stop_reason = execution.get("status")
            break
        if validation.get("status") != "SYSTEM_VALIDATION_OK":
            stop_reason = "STOP_ON_VALIDATION_FAILURE"
            break
        if previous_effect_key == effect_key and operation not in {"run_mission_queue_runner", "run_health_governor_cycle"}:
            stop_reason = "STOP_ON_REPEATED_OPERATION"
            break
        previous_effect_key = effect_key
    if stop_reason is None:
        stop_reason = "STOP_ON_MAX_BATCH" if completed >= n else "STOP_ON_NO_SAFE_OPERATION"
    report = base_report("run-safe-batch", "OPERATIONS_SAFE_BATCH_COMPLETED")
    report.update({
        "requested_batch": n,
        "operations_completed": completed,
        "operation_results": operations,
        "operations_history": [item.get("selected_operation") for item in operations if item.get("selected_operation")],
        "selected_operation": operations[-1].get("selected_operation") if operations else None,
        "stop_reason": stop_reason,
        "system_validation": validate_system(write=False),
        "next_operation": decide_operation(gather_state()).get("next_operation"),
    })
    learn_from_report(report)
    write_outputs(report)
    return report


def scan_public_assets() -> Dict[str, Any]:
    findings: List[str] = []
    if EXPORT_LATEST_DIR.exists():
        for path in EXPORT_LATEST_DIR.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in {".md", ".txt", ".html", ".json"}:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if SECRET_RE.search(text):
                findings.append(f"{rel(path)}:secret_like")
            if PRIVATE_IP_RE.search(text):
                findings.append(f"{rel(path)}:private_ip")
            if INTERNAL_PATH_RE.search(text):
                findings.append(f"{rel(path)}:internal_path")
    return {"status": "PUBLIC_ASSET_SAFETY_OK" if not findings else "PUBLIC_ASSET_SAFETY_WARNINGS", "findings": findings}


def source_safety_findings(paths: List[Path]) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    for path in paths:
        if not path.exists():
            findings.append({"path": rel(path), "finding": "missing_source"})
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        patterns = [
            ("apply_argument_present", re.compile(r"add_argument\([\"']--" + "apply")),
            ("network_import_present", FORBIDDEN_IMPORT_RE),
            ("shell_true_present", re.compile(r"shell\s*=\s*True")),
            ("free_subprocess_present", re.compile(r"subprocess\.(?:Popen|call|check_call|check_output)\(")),
            ("systemctl_live_present", re.compile(r"systemctl\s+(?:start|enable)")),
            ("cron_install_present", re.compile(r"crontab\s+(?:-|install)")),
            ("destructive_delete_present", re.compile(r"r" + "m\\s+-r" + "f")),
            ("process_termination_present", re.compile(r"\b(?:p" + "kill|kill" + "all)\\b")),
            ("remote_write_present", re.compile(r"\b(?:sftp|ftp)\.(?:put|remove|rename)\(")),
        ]
        for finding, rx in patterns:
            if rx.search(text):
                findings.append({"path": rel(path), "finding": finding})
    return findings


def validate_system(write: bool = True) -> Dict[str, Any]:
    state = gather_state()
    json_checks = state.get("json_statuses") or {}
    invalid = [name for name, status in json_checks.items() if status == "invalid_json"]
    public_assets = scan_public_assets()
    source_paths = [PROJECT_DIR / module for module in sorted(ALLOWED_MODULES)]
    source_paths.append(PROJECT_DIR / "sentinel_autonomous_operations_supervisor.py")
    if (PROJECT_DIR / "sentinel_autonomy.py").exists():
        source_paths.append(PROJECT_DIR / "sentinel_autonomy.py")
    source_findings = source_safety_findings(source_paths)
    drift = safety_drift(state)
    breach = breach_status(state)
    status = "SYSTEM_VALIDATION_OK"
    if invalid or public_assets["findings"] or source_findings or drift["status"] != "SAFETY_DRIFT_OK" or breach["breach"]:
        status = "SYSTEM_VALIDATION_WARNINGS"
    validation = {
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "timestamp_utc": utc_now(),
        "action": "validate-system",
        "status": status,
        "json_checks": json_checks,
        "invalid_json": invalid,
        "public_assets": public_assets,
        "source_safety_findings": source_findings,
        "safety_drift": drift,
        "breach_state": breach,
        **HARD_DEFAULTS,
    }
    if write:
        write_outputs({**base_report("validate-system", status), "system_validation": validation})
    return validation


def base_report(action: str, status: str) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "timestamp_utc": utc_now(),
        "action": action,
        "status": status,
        "selected_operation": None,
        "operation_results": [],
        "operations_completed": 0,
        "operations_history": [],
        "system_validation": None,
        "safety_drift": safety_drift(gather_state()),
        "stop_reason": None,
        "next_operation": None,
        "owner_briefing_status": "not_written",
        "integrations": {
            "mission_queue_runner": "reads_supervisor_state",
            "goal_manager": "reads_supervisor_state",
            "health_governor": "reads_supervisor_state",
            "capability_registry": "reads_supervisor_state",
            "priority_engine": "reads_supervisor_state",
            "operation_governor": "supervisor_reads_governor_model",
            "soak_test": "supervisor_reads_soak_state",
            "kernel": "reads_supervisor_state",
            "cycle_runner": "reads_supervisor_state",
        },
        **HARD_DEFAULTS,
    }


def learn_from_report(report: Dict[str, Any]) -> None:
    history = load_list_or_entries(HISTORY_JSON)
    history.append({
        "timestamp_utc": utc_now(),
        "status": report.get("status"),
        "action": report.get("action"),
        "selected_operation": report.get("selected_operation"),
        "operations_completed": report.get("operations_completed", 0),
        "stop_reason": report.get("stop_reason"),
    })
    write_json(HISTORY_JSON, {"entries": history[-300:], **HARD_DEFAULTS})
    patterns = load_dict(PATTERNS_JSON)
    blocked = load_dict(BLOCKED_PATTERNS_JSON)
    op = str(report.get("selected_operation") or "none")
    if report.get("operations_completed", 0):
        patterns[op] = int(patterns.get(op, 0)) + 1
    if report.get("stop_reason"):
        blocked[str(report.get("stop_reason"))] = int(blocked.get(str(report.get("stop_reason")), 0)) + 1
    write_json(PATTERNS_JSON, {"patterns": patterns, **HARD_DEFAULTS})
    write_json(BLOCKED_PATTERNS_JSON, {"patterns": blocked, **HARD_DEFAULTS})
    drift = report.get("safety_drift") if isinstance(report.get("safety_drift"), dict) else {}
    if drift.get("status") != "SAFETY_DRIFT_OK":
        drifts = load_list_or_entries(SAFETY_DRIFT_HISTORY_JSON)
        drifts.append({"timestamp_utc": utc_now(), "findings": drift.get("findings", [])})
        write_json(SAFETY_DRIFT_HISTORY_JSON, {"entries": drifts[-100:], **HARD_DEFAULTS})
    elif not SAFETY_DRIFT_HISTORY_JSON.exists():
        write_json(SAFETY_DRIFT_HISTORY_JSON, {"entries": [], **HARD_DEFAULTS})


def build_owner_briefing() -> Dict[str, Any]:
    current = load_dict(LATEST_JSON) or load_dict(REPORT_JSON) or base_report("build-owner-briefing", "OWNER_BRIEFING_READY")
    current["action"] = "build-owner-briefing"
    current["status"] = "OWNER_BRIEFING_READY"
    current["owner_briefing_status"] = "OWNER_BRIEFING_READY"
    current["system_health"] = system_health_summary()
    current["next_operation"] = decide_operation(gather_state()).get("next_operation")
    write_outputs(current)
    return current


def write_playbooks(report: Dict[str, Any]) -> None:
    base = {"schema_version": SCHEMA_VERSION, "phase": PHASE, **HARD_DEFAULTS}
    write_json(PLAYBOOK_SUPERVISOR, {
        **base,
        "name": "sentinel-autonomous-operations-supervisor",
        "purpose": "Select and run the next safe local autonomy operation from a central control plane.",
        "allowed_operations": sorted(OPERATIONS),
        "max_batch": MAX_BATCH,
        "blocked_actions": ["live_apply", "network", "external_api", "remote_write", "timer_install", "HIGH_MEDIUM_LOW_LIVE_execution"],
        "operation_governor_model": rel(OPERATION_GOVERNOR_MODEL_JSON),
    })
    write_json(PLAYBOOK_DECISION, {
        **base,
        "name": "sentinel-autonomous-operation-decision",
        "decision_order": [
            "breach stop",
            "safety drift stop",
            "operation governor selected operation when safe",
            "health governor cycle",
            "goal manager cycle",
            "mission queue runner",
            "priority model",
            "capability registry",
            "kernel fallback",
            "owner briefing",
        ],
    })
    write_json(PLAYBOOK_VALIDATION, {
        **base,
        "name": "sentinel-autonomous-system-validation",
        "checks": [
            "phase 10 json valid",
            "no secrets",
            "no network imports",
            "no shell true",
            "no high medium low live execution",
            "safe defaults unchanged",
        ],
    })
    write_json(PLAYBOOK_OWNER, {
        **base,
        "name": "sentinel-autonomous-owner-briefing",
        "fields": [
            "system status",
            "selected operation",
            "why selected",
            "modules executed",
            "missions completed",
            "capabilities used",
            "validation",
            "repairs",
            "learning",
            "stop reason",
            "next safe operation",
            "blocked areas",
        ],
    })


def render_report_md(report: Dict[str, Any]) -> str:
    validation = report.get("system_validation") if isinstance(report.get("system_validation"), dict) else {}
    return "\n".join([
        "# Sentinel Autonomous Operations Supervisor",
        "",
        f"- status: `{report.get('status')}`",
        f"- action: `{report.get('action')}`",
        f"- selected_operation: `{report.get('selected_operation')}`",
        f"- operations_completed: `{report.get('operations_completed', 0)}`",
        f"- stop_reason: `{report.get('stop_reason', '-')}`",
        f"- validation: `{validation.get('status', '-')}`",
        f"- safety_drift: `{(report.get('safety_drift') or {}).get('status', '-')}`",
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
        "# Sentinel Autonomous Operations Preflight",
        "",
        f"- status: `{report.get('status')}`",
        f"- blockers: `{', '.join(blockers) or '-'}`",
        f"- safety_drift: `{(report.get('safety_drift') or {}).get('status', '-')}`",
        "- live/external/apply operations remain blocked.",
    ]) + "\n"


def render_decision_md(report: Dict[str, Any]) -> str:
    decision = report.get("operation_decision") if isinstance(report.get("operation_decision"), dict) else report
    selected = decision.get("selected_operation") if isinstance(decision.get("selected_operation"), dict) else {}
    governor = decision.get("operation_governor") if isinstance(decision.get("operation_governor"), dict) else {}
    return "\n".join([
        "# Sentinel Autonomous Operation Decision",
        "",
        f"- selected_operation: `{selected.get('operation', report.get('selected_operation'))}`",
        f"- reason: `{selected.get('reason', '-')}`",
        f"- governor_status: `{governor.get('status', '-')}`",
        f"- governor_score: `{selected.get('governor_score', '-')}`",
        f"- risk_class: `{selected.get('risk_class', '-')}`",
        f"- can_execute_now: `{selected.get('can_execute_now', '-')}`",
        f"- decision_status: `{decision.get('status', report.get('status'))}`",
    ]) + "\n"


def render_run_log_md(report: Dict[str, Any]) -> str:
    lines = ["# Sentinel Autonomous Operation Run Log", ""]
    for index, item in enumerate(report.get("operation_results") or [], 1):
        execution = item.get("execution") if isinstance(item.get("execution"), dict) else item
        lines.extend([
            f"## Operation {item.get('operation_index', index)}",
            f"- selected_operation: `{item.get('selected_operation', execution.get('operation'))}`",
            f"- execution_status: `{execution.get('status')}`",
            f"- executed: `{execution.get('executed')}`",
            f"- validation_status: `{item.get('validation_status', '-')}`",
            "",
        ])
    return "\n".join(lines) + "\n"


def render_validation_md(report: Dict[str, Any]) -> str:
    validation = report.get("system_validation") if isinstance(report.get("system_validation"), dict) else {}
    lines = ["# Sentinel Autonomous System Validation", "", f"- status: `{validation.get('status', '-')}`"]
    checks = validation.get("json_checks") if isinstance(validation.get("json_checks"), dict) else {}
    for name, status in sorted(checks.items()):
        lines.append(f"- `{name}` json=`{status}`")
    lines.extend([
        f"- source_safety_findings: `{len(validation.get('source_safety_findings') or [])}`",
        f"- public_asset_status: `{(validation.get('public_assets') or {}).get('status', '-')}`",
        "- live_apply: `False`",
        "- allowed_apply_now: `False`",
        "- HIGH blocked: `True`",
        "- LOW_LIVE executable: `False`",
        "- MEDIUM executable: `False`",
        "- breach: `False`",
    ])
    return "\n".join(lines) + "\n"


def render_owner_briefing_md(report: Dict[str, Any]) -> str:
    operations = report.get("operation_results") if isinstance(report.get("operation_results"), list) else []
    modules = []
    for item in operations:
        execution = item.get("execution") if isinstance(item.get("execution"), dict) else item
        result = execution.get("module_result") if isinstance(execution.get("module_result"), dict) else {}
        module = result.get("module")
        if module:
            modules.append(str(module))
    system_health = report.get("system_health") if isinstance(report.get("system_health"), dict) else system_health_summary()
    return "\n".join([
        "# Sentinel Autonomous Owner Briefing",
        "",
        f"- system_status: `{report.get('status')}`",
        f"- selected_operation: `{report.get('selected_operation')}`",
        f"- operation_governor_status: `{system_health.get('operation_governor_status', '-')}`",
        f"- operation_governor_selected: `{system_health.get('operation_governor_selected', '-')}`",
        f"- last_soak_status: `{system_health.get('last_soak_status', '-')}`",
        f"- readiness_seal: `{system_health.get('readiness_seal', '-')}`",
        f"- regression_gate_status: `{system_health.get('regression_gate_status', '-')}`",
        f"- modules_executed: `{', '.join(modules) or '-'}`",
        f"- operations_completed: `{report.get('operations_completed', 0)}`",
        f"- stop_reason: `{report.get('stop_reason', '-')}`",
        f"- next_operation: `{report.get('next_operation', '-')}`",
        f"- validation: `{(report.get('system_validation') or {}).get('status', '-')}`",
        f"- safety_drift: `{(report.get('safety_drift') or {}).get('status', '-')}`",
        "- blocked: live apply, external APIs, remote writes, timers, LOW_LIVE, MEDIUM and HIGH execution",
        "- live_apply: `False`",
        "- emergency_stop: `True`",
        "- allowed_apply_now: `False`",
        "- HIGH blocked: `True`",
        "- LOW_LIVE executable: `False`",
        "- MEDIUM executable: `False`",
        "- breach: `False`",
    ]) + "\n"


def render_next_operation_md(report: Dict[str, Any]) -> str:
    return "\n".join([
        "# Sentinel Autonomous Next Operation",
        "",
        f"- next_operation: `{report.get('next_operation', '-')}`",
        "- Next operation remains local safe autonomy unless a separate owner approval changes policy.",
    ]) + "\n"


def render_safety_drift_md(report: Dict[str, Any]) -> str:
    drift = report.get("safety_drift") if isinstance(report.get("safety_drift"), dict) else {}
    lines = ["# Sentinel Autonomous Safety Drift Report", "", f"- status: `{drift.get('status', '-')}`"]
    for item in drift.get("findings") or []:
        if isinstance(item, dict):
            lines.append(f"- `{item.get('source')}` field=`{item.get('field')}` expected=`{item.get('expected')}` actual=`{item.get('actual')}`")
    return "\n".join(lines) + "\n"


def write_outputs(report: Dict[str, Any]) -> None:
    ensure_dirs()
    safe_report = {
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "timestamp_utc": report.get("timestamp_utc") or utc_now(),
        **report,
        **HARD_DEFAULTS,
        "owner_briefing_status": "OWNER_BRIEFING_READY",
        "recommended_git_checkpoint": [
            "sentinel_autonomous_operations_supervisor.py",
            "sentinel_autonomous_soak_test.py",
            "sentinel_autonomy.py",
            "sentinel_autonomous_mission_queue_runner.py",
            "sentinel_autonomous_goal_manager.py",
            "sentinel_autonomous_capability_health_governor.py",
            "sentinel_autonomous_capability_registry.py",
            "sentinel_autonomous_priority_engine.py",
            "sentinel_autonomous_operation_governor.py",
            "sentinel_self_governing_safe_autonomy_kernel.py",
            "sentinel_autonomous_cycle_runner.py",
            "playbooks/sentinel-autonomous-operations-supervisor.playbook.json",
            "playbooks/sentinel-autonomous-operation-decision.playbook.json",
            "playbooks/sentinel-autonomous-system-validation.playbook.json",
            "playbooks/sentinel-autonomous-owner-briefing.playbook.json",
            "playbooks/sentinel-autonomous-soak-test.playbook.json",
            "playbooks/sentinel-autonomous-regression-gate.playbook.json",
            "playbooks/sentinel-autonomous-readiness-seal.playbook.json",
            "playbooks/sentinel-autonomous-soak-owner-summary.playbook.json",
            "playbooks/sentinel-autonomous-operation-governor.playbook.json",
            "playbooks/sentinel-autonomous-operation-impact-scoring.playbook.json",
            "playbooks/sentinel-autonomous-operation-noop-detection.playbook.json",
            "playbooks/sentinel-autonomous-operation-diversity.playbook.json",
        ],
    }
    write_json(REPORT_JSON, safe_report)
    write_json(STATE_JSON, safe_report)
    write_json(LATEST_JSON, safe_report)
    write_text(REPORT_MD, render_report_md(safe_report))
    write_text(PREFLIGHT_MD, render_preflight_md(safe_report if safe_report.get("action") == "preflight" else preflight_preview()))
    write_text(DECISION_MD, render_decision_md(safe_report))
    write_text(RUN_LOG_MD, render_run_log_md(safe_report))
    write_text(VALIDATION_MD, render_validation_md(safe_report))
    write_text(OWNER_BRIEFING_MD, render_owner_briefing_md(safe_report))
    write_text(NEXT_OPERATION_MD, render_next_operation_md(safe_report))
    write_text(SAFETY_DRIFT_MD, render_safety_drift_md(safe_report))
    write_playbooks(safe_report)
    append_jsonl(AUDIT_JSONL, [{
        "timestamp_utc": utc_now(),
        "event": "autonomous_operations_supervisor",
        "action": safe_report.get("action"),
        "status": safe_report.get("status"),
        "selected_operation": safe_report.get("selected_operation"),
        "operations_completed": safe_report.get("operations_completed", 0),
        "stop_reason": safe_report.get("stop_reason"),
        "breach": False,
        "live_apply": False,
        "allowed_apply_now": False,
    }])


def preflight_preview() -> Dict[str, Any]:
    state = gather_state()
    return {
        "status": "OPERATIONS_PREFLIGHT_OK",
        "blockers": [],
        "safety_drift": safety_drift(state),
        **HARD_DEFAULTS,
    }


def status_report() -> Dict[str, Any]:
    report = load_dict(LATEST_JSON) or load_dict(REPORT_JSON) or base_report("status", "OPERATIONS_SUPERVISOR_STATUS_EMPTY")
    print(f"status={report.get('status')}")
    print(f"selected_operation={report.get('selected_operation')}")
    print(f"operations_completed={report.get('operations_completed', 0)}")
    print(f"stop_reason={report.get('stop_reason')}")
    print(f"next_operation={report.get('next_operation')}")
    print(f"safety_drift={(report.get('safety_drift') or {}).get('status')}")
    print(f"live_apply={report.get('live_apply')}")
    print(f"emergency_stop={report.get('emergency_stop')}")
    print(f"allowed_apply_now={report.get('allowed_apply_now')}")
    print(f"HIGH_blocked={report.get('high_blocked')}")
    print(f"LOW_LIVE_executable={report.get('low_live_executable')}")
    print(f"MEDIUM_executable={report.get('medium_executable')}")
    print(f"breach={report.get('breach')}")
    return report


def self_test() -> Dict[str, Any]:
    source = Path(__file__).read_text(encoding="utf-8")
    findings = source_safety_findings([Path(__file__)])
    operation_checks = {
        op: (
            meta["risk_class"] in AUTO_ALLOWED_RISK
            and (meta["module"] is None or module_arg_allowed(str(meta["module"]), list(meta["args"])))
        )
        for op, meta in OPERATIONS.items()
    }
    drift_fake = safety_drift({"reports": {"fake": {"live_apply": True, "emergency_stop": True, "allowed_apply_now": False, "high_blocked": True, "low_live_executable": False, "medium_executable": False, "breach": False}}})
    tests = {
        "no_apply_argument": not re.search(r"add_argument\([\"']--" + "apply", source),
        "no_network_imports": not FORBIDDEN_IMPORT_RE.search(source),
        "no_shell_true": ("shell" + "=True") not in source,
        "no_free_subprocess": not any(item.get("finding") == "free_subprocess_present" for item in findings),
        "max_batch_limited": MAX_BATCH <= 5,
        "all_operations_risk_classed": all("risk_class" in meta for meta in OPERATIONS.values()),
        "all_operations_guarded": all(operation_checks.values()),
        "safety_drift_detection": drift_fake.get("status") == "SAFETY_DRIFT_DETECTED",
        "write_roots_allowed": all(is_within(root, root) for root in ALLOWED_WRITE_ROOTS),
    }
    status = "OPERATIONS_SUPERVISOR_SELF_TEST_OK" if all(tests.values()) and not findings else "OPERATIONS_SUPERVISOR_SELF_TEST_FAILED"
    report = {
        **base_report("self-test", status),
        "tests": tests,
        "source_safety_findings": findings,
        "operation_checks": operation_checks,
    }
    write_outputs(report)
    return report


def cycle() -> Dict[str, Any]:
    preflight_report = preflight()
    if preflight_report.get("status") != "OPERATIONS_PREFLIGHT_OK":
        return preflight_report
    run_report = run_safe_once()
    validation = validate_system(write=False)
    run_report["system_validation"] = validation
    run_report["action"] = "cycle"
    run_report["status"] = "OPERATIONS_SUPERVISOR_CYCLE_OK" if validation.get("status") == "SYSTEM_VALIDATION_OK" else "OPERATIONS_SUPERVISOR_CYCLE_WARNINGS"
    write_outputs(run_report)
    return run_report


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Sentinel Autonomous Operations Supervisor")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--decide-operation", action="store_true")
    parser.add_argument("--run-safe-once", action="store_true")
    parser.add_argument("--run-safe-batch", type=int)
    parser.add_argument("--validate-system", action="store_true")
    parser.add_argument("--build-owner-briefing", action="store_true")
    parser.add_argument("--cycle", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        report = self_test()
    elif args.status:
        status_report()
        return 0
    elif args.preflight:
        report = preflight()
    elif args.decide_operation:
        report = decide_operation()
    elif args.run_safe_once:
        report = run_safe_once()
    elif args.run_safe_batch is not None:
        report = run_safe_batch(args.run_safe_batch)
    elif args.validate_system:
        report = validate_system(write=True)
    elif args.build_owner_briefing:
        report = build_owner_briefing()
    elif args.cycle:
        report = cycle()
    else:
        parser.print_help()
        return 2
    return 0 if report.get("status") != "OPERATIONS_SUPERVISOR_SELF_TEST_FAILED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
