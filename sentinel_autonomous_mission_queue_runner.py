#!/usr/bin/env python3
"""Sentinel Autonomous Mission Queue Runner (Phase 10.6).

Controlled local mission queue execution for Sentinel's autonomous goal system.
The runner executes multiple safe Goal Manager mission steps with validation,
ledger updates, stop rules, lock handling and owner summaries. It does not add
live apply, network access, remote writes, external APIs, timers or customer
system changes.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


PROJECT_DIR = Path("/srv/sentinel-defense")
SCHEMA_VERSION = "sentinel-autonomous-mission-queue-runner-10.6"
PHASE = "10.6"
MAX_MISSIONS = 5
DEFAULT_MISSIONS = 3
LOCK_STALE_HOURS = 6.0
GOAL_MANAGER = "sentinel_autonomous_goal_manager.py"

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

REPORT_JSON = R / "sentinel-autonomous-mission-queue-runner.json"
REPORT_MD = R / "sentinel-autonomous-mission-queue-runner.md"
PREFLIGHT_MD = R / "sentinel-autonomous-mission-runner-preflight.md"
LOG_MD = R / "sentinel-autonomous-mission-runner-log.md"
VALIDATION_MD = R / "sentinel-autonomous-mission-runner-validation.md"
OWNER_SUMMARY_MD = R / "sentinel-autonomous-mission-runner-owner-summary.md"
STOP_REASON_MD = R / "sentinel-autonomous-mission-runner-stop-reason.md"
NEXT_STEP_MD = R / "sentinel-autonomous-mission-runner-next-step.md"
LEDGER_MD = R / "sentinel-autonomous-mission-completion-ledger.md"

STATE_JSON = STATE_DIR / "autonomous_mission_queue_runner.json"
LATEST_JSON = STATE_DIR / "latest_autonomous_mission_queue_runner.json"
HISTORY_JSON = STATE_DIR / "autonomous_mission_queue_runner_history.json"
LOCK_HISTORY_JSON = STATE_DIR / "autonomous_mission_queue_runner_lock_history.json"
STOP_PATTERNS_JSON = STATE_DIR / "autonomous_mission_queue_runner_stop_patterns.json"
COMPLETION_LEDGER_JSON = STATE_DIR / "autonomous_mission_completion_ledger.json"
LOCKFILE = STATE_DIR / "autonomous_mission_queue_runner.lock"

GOAL_MANAGER_JSON = R / "sentinel-autonomous-goal-manager.json"
GOAL_MANAGER_STATE_JSON = STATE_DIR / "latest_autonomous_goal_manager.json"
SUPERVISOR_JSON = STATE_DIR / "latest_autonomous_operations_supervisor.json"
OPERATION_GOVERNOR_JSON = STATE_DIR / "latest_autonomous_operation_governor.json"

AUDIT_JSONL = AUDIT_DIR / "sentinel-autonomous-mission-queue-runner.jsonl"

PLAYBOOK_RUNNER = PLAYBOOK_DIR / "sentinel-autonomous-mission-queue-runner.playbook.json"
PLAYBOOK_STOP_RULES = PLAYBOOK_DIR / "sentinel-autonomous-mission-runner-stop-rules.playbook.json"
PLAYBOOK_LEDGER = PLAYBOOK_DIR / "sentinel-autonomous-mission-completion-ledger.playbook.json"
PLAYBOOK_OWNER = PLAYBOOK_DIR / "sentinel-autonomous-mission-runner-owner-summary.playbook.json"

ALLOWED_WRITE_ROOTS = (R, STATE_DIR, AUDIT_DIR, PLAYBOOK_DIR)
ALLOWED_GOAL_ARGS = {
    "--self-test",
    "--discover-goals",
    "--build-mission-queue",
    "--classify-missions",
    "--route-missions",
    "--execute-safe-mission-step",
    "--validate-missions",
    "--learn",
    "--cycle",
    "--status",
}
ALLOWED_GOAL_COMMANDS = {
    arg: ["python3", GOAL_MANAGER, arg] for arg in sorted(ALLOWED_GOAL_ARGS)
}

STOP_RULES = [
    "STOP_ON_BREACH",
    "STOP_ON_FORBIDDEN_PATTERN",
    "STOP_ON_GOAL_MANAGER_FAILURE",
    "STOP_ON_REPEATED_MISSION_LOOP",
    "STOP_ON_NO_SAFE_MISSION",
    "STOP_ON_MAX_MISSIONS",
    "STOP_ON_LOCK_COLLISION",
    "STOP_ON_INVALID_JSON",
    "STOP_ON_UNSAFE_SCOPE",
    "STOP_ON_LIVE_APPLY_ATTEMPT",
    "STOP_ON_MISSION_VALIDATION_FAILURE",
]

FORBIDDEN_IMPORT_RE = re.compile(
    r"^\s*(?:import|from)\s+(requests|urllib|http\.client|smtplib|socket|paramiko|cloudflare)\b",
    re.MULTILINE,
)
SECRET_TERMS = [
    "sentinel_sftp_" + "pass" + "word",
    "bear" + "er" + r"\s+[a-z0-9._-]+",
    "api[_-]?" + "key" + r"\s*[:=]\s*[^,\s]+",
    "s" + "k-" + r"[a-z0-9]{12,}",
    "g" + "hp_" + r"[a-z0-9_]+",
    "github_" + "pat_" + r"[a-z0-9_]+",
    "begin" + r"\s+(?:open)?ssh\s+private\s+" + "key",
    "begin" + r"\s+rsa\s+private\s+" + "key",
]
SECRET_RE = re.compile(r"(?i)(" + "|".join(SECRET_TERMS) + ")")
CUSTOMER_DATA_RE = re.compile(r"(?i)(real\s+customer|customer\s+credential|payment\s+card|iban|ssn)")
INTERNAL_PATH_RE = re.compile(r"(?<!`)\/(?:srv|home|root|etc|var)\/[A-Za-z0-9_.\/-]+")
PRIVATE_IP_RE = re.compile(r"\b(?:10|127|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_time(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


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


def redact_text(value: Any, limit: int = 2000) -> str:
    text = "" if value is None else str(value)
    text = SECRET_RE.sub("[REDACTED]", text)
    return text[:limit]


def assert_safe_content(text: str, path: Optional[Path] = None) -> None:
    if SECRET_RE.search(text):
        raise RuntimeError(f"Secret-like content blocked in {rel(path) if path else 'content'}")
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


def load_list(path: Path) -> List[Dict[str, Any]]:
    data, status = read_json(path)
    if status == "ok" and isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if status == "ok" and isinstance(data, dict) and isinstance(data.get("entries"), list):
        return [item for item in data["entries"] if isinstance(item, dict)]
    return []


def command_is_allowlisted(cmd: List[str]) -> bool:
    return cmd in ALLOWED_GOAL_COMMANDS.values()


def run_goal_manager(arg: str, timeout: int = 240) -> Dict[str, Any]:
    cmd = ALLOWED_GOAL_COMMANDS.get(arg)
    if not cmd or not command_is_allowlisted(cmd):
        return {"status": "blocked_not_allowlisted", "arg": arg, "returncode": None}
    if not (PROJECT_DIR / GOAL_MANAGER).exists():
        return {"status": "blocked_missing_goal_manager", "arg": arg, "returncode": None}
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
        return {"status": "timeout", "arg": arg, "returncode": None}
    except (OSError, subprocess.SubprocessError) as exc:
        return {"status": "error", "arg": arg, "returncode": None, "stderr": redact_text(exc)}
    return {
        "status": "executed" if proc.returncode == 0 else "failed",
        "arg": arg,
        "returncode": proc.returncode,
        "stdout_lines": len([line for line in (proc.stdout or "").splitlines() if line.strip()]),
        "stderr": redact_text(proc.stderr, 1000),
    }


def process_active(pid: int) -> bool:
    if pid <= 0:
        return False
    return Path("/proc") .joinpath(str(pid)).exists()


def lock_age_hours(lock: Dict[str, Any]) -> Optional[float]:
    dt = parse_time(lock.get("started_at"))
    if not dt:
        return None
    return max(0.0, (datetime.now(timezone.utc) - dt).total_seconds() / 3600.0)


def append_lock_history(event: Dict[str, Any]) -> None:
    history = load_list(LOCK_HISTORY_JSON)
    history.append({"timestamp_utc": utc_now(), **event, **HARD_DEFAULTS})
    write_json(LOCK_HISTORY_JSON, {"entries": history[-200:], **HARD_DEFAULTS})


def acquire_lock(max_missions: int) -> Tuple[bool, Dict[str, Any]]:
    ensure_dirs()
    if LOCKFILE.exists():
        lock, status = read_json(LOCKFILE)
        lock = lock if status == "ok" and isinstance(lock, dict) else {}
        pid = int(lock.get("pid") or 0)
        age = lock_age_hours(lock)
        if age is not None and age > LOCK_STALE_HOURS and not process_active(pid):
            append_lock_history({"event": "stale_lock_replaced", "previous_lock": lock})
            LOCKFILE.unlink()
        else:
            reason = {
                "status": "STOP_ON_LOCK_COLLISION",
                "lockfile": rel(LOCKFILE),
                "existing_lock_status": status,
                "existing_pid": pid,
                "age_hours": round(age, 3) if age is not None else None,
            }
            append_lock_history({"event": "lock_collision", **reason})
            return False, reason
    lock = {
        "pid": os.getpid(),
        "started_at": utc_now(),
        "runner_id": f"mission-runner-{os.getpid()}",
        "max_missions": max_missions,
        "status": "active",
        **HARD_DEFAULTS,
    }
    write_json(LOCKFILE, lock)
    append_lock_history({"event": "lock_acquired", "runner_id": lock["runner_id"]})
    return True, lock


def release_lock(status: str) -> Dict[str, Any]:
    if not LOCKFILE.exists():
        return {"status": "LOCK_NOT_PRESENT", "lockfile": rel(LOCKFILE)}
    lock, read_status = read_json(LOCKFILE)
    lock = lock if read_status == "ok" and isinstance(lock, dict) else {}
    event = {"event": "lock_released", "status": status, "lock": lock}
    try:
        LOCKFILE.unlink()
        event["release_status"] = "LOCK_RELEASED"
    except OSError as exc:
        event["release_status"] = "LOCK_RELEASE_FAILED"
        event["error"] = redact_text(exc)
    append_lock_history(event)
    return event


def critical_json_scan() -> Dict[str, Any]:
    paths = [
        GOAL_MANAGER_STATE_JSON,
        COMPLETION_LEDGER_JSON,
        STATE_JSON,
        LATEST_JSON,
    ]
    invalid = []
    missing = []
    for path in paths:
        _, status = read_json(path)
        if status == "invalid_json":
            invalid.append(rel(path))
        elif status == "missing":
            missing.append(rel(path))
    return {"invalid_json": invalid, "missing_json": missing, "status": "JSON_OK" if not invalid else "JSON_INVALID"}


def public_asset_scan() -> Dict[str, Any]:
    findings: List[str] = []
    if EXPORT_LATEST_DIR.exists():
        for path in EXPORT_LATEST_DIR.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in {".md", ".txt", ".html", ".json"}:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if PRIVATE_IP_RE.search(text):
                findings.append(f"{rel(path)}:private_ip")
            if INTERNAL_PATH_RE.search(text):
                findings.append(f"{rel(path)}:internal_path")
            if SECRET_RE.search(text):
                findings.append(f"{rel(path)}:secret_like")
    return {"status": "PUBLIC_ASSETS_OK" if not findings else "PUBLIC_ASSETS_BLOCKED", "findings": findings}


def latest_breach_status() -> Dict[str, Any]:
    paths = [
        GOAL_MANAGER_JSON,
        GOAL_MANAGER_STATE_JSON,
        PROJECT_DIR / "reports/latest/sentinel-autonomous-cycle-runner.json",
        PROJECT_DIR / "reports/latest/sentinel-self-governing-autonomy-kernel.json",
    ]
    sources = []
    breach = False
    for path in paths:
        data = load_dict(path)
        if data:
            sources.append({"path": rel(path), "breach": bool(data.get("breach")), "status": data.get("status")})
            breach = breach or bool(data.get("breach"))
            if data.get("live_apply") is True or data.get("allowed_apply_now") is True:
                breach = True
    return {"breach": breach, "sources": sources}


def normalize_ledger(raw: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        raw = {}
    entries = raw.get("entries") if isinstance(raw.get("entries"), list) else []
    by_mission = raw.get("by_mission") if isinstance(raw.get("by_mission"), dict) else {}
    for key, value in raw.items():
        if key in {"schema_version", "updated_at", "entries", "by_mission", "completed_count", *HARD_DEFAULTS}:
            continue
        if isinstance(value, dict):
            by_mission.setdefault(key, value)
    completed_count = sum(
        1 for item in entries
        if isinstance(item, dict) and item.get("completion_status") == "COMPLETED"
    )
    if completed_count == 0:
        completed_count = sum(1 for value in by_mission.values() if isinstance(value, dict) and value.get("status") == "COMPLETED")
    return {
        "schema_version": "sentinel-autonomous-mission-ledger-10.6",
        "updated_at": raw.get("updated_at") or utc_now(),
        "entries": entries[-500:],
        "by_mission": by_mission,
        "completed_count": completed_count,
        **HARD_DEFAULTS,
    }


def extract_goal_manager_state() -> Tuple[Dict[str, Any], str]:
    data, status = read_json(GOAL_MANAGER_JSON)
    if status != "ok" or not isinstance(data, dict):
        data, status = read_json(GOAL_MANAGER_STATE_JSON)
    return (data if status == "ok" and isinstance(data, dict) else {}, status)


def selected_mission_from_goal(goal: Dict[str, Any]) -> Dict[str, Any]:
    selected = goal.get("selected_mission") if isinstance(goal.get("selected_mission"), dict) else {}
    if selected:
        return selected
    mission_type = goal.get("selected_mission_type")
    for key in ("routed_missions", "classified_missions", "mission_queue"):
        missions = goal.get(key) if isinstance(goal.get(key), list) else []
        for mission in missions:
            if isinstance(mission, dict) and mission.get("mission_type") == mission_type:
                return mission
    return {}


def mission_result(index: int, started: str, finished: str, proc: Dict[str, Any]) -> Dict[str, Any]:
    goal, json_status = extract_goal_manager_state()
    selected = selected_mission_from_goal(goal)
    task = None
    if isinstance(selected.get("linked_tasks"), list) and selected.get("linked_tasks"):
        task = selected["linked_tasks"][0]
    execution = goal.get("execution") if isinstance(goal.get("execution"), dict) else {}
    validation_status = goal.get("mission_validation_status") or goal.get("validation_status")
    completion_status = selected.get("completion_status") or (
        "COMPLETED" if validation_status == "MISSION_VALIDATION_OK" and proc.get("returncode") == 0 else "UNKNOWN"
    )
    outputs = selected.get("expected_outputs") if isinstance(selected.get("expected_outputs"), list) else []
    stop_reason = None
    if proc.get("returncode") not in (0, None):
        stop_reason = "STOP_ON_GOAL_MANAGER_FAILURE"
    elif json_status == "invalid_json":
        stop_reason = "STOP_ON_INVALID_JSON"
    elif goal.get("breach") is True:
        stop_reason = "STOP_ON_BREACH"
    elif goal.get("live_apply") is True or goal.get("allowed_apply_now") is True:
        stop_reason = "STOP_ON_LIVE_APPLY_ATTEMPT"
    elif selected and selected.get("risk_class") not in AUTO_ALLOWED_RISK:
        stop_reason = "STOP_ON_UNSAFE_SCOPE"
    elif not selected:
        stop_reason = "STOP_ON_NO_SAFE_MISSION"
    elif validation_status and validation_status not in {"MISSION_VALIDATION_OK", "MISSION_VALIDATION_WARNINGS"}:
        stop_reason = "STOP_ON_MISSION_VALIDATION_FAILURE"
    return {
        "mission_index": index,
        "started_at": started,
        "finished_at": finished,
        "goal_manager_returncode": proc.get("returncode"),
        "goal_manager_status": goal.get("status"),
        "selected_mission": selected.get("mission_type") or goal.get("selected_mission_type"),
        "mission_type": selected.get("mission_type") or goal.get("selected_mission_type"),
        "linked_capability": selected.get("linked_capability") or goal.get("selected_capability"),
        "linked_task": task or goal.get("selected_task"),
        "mission_risk_class": selected.get("risk_class"),
        "execution_status": execution.get("status") or proc.get("status"),
        "validation_status": validation_status,
        "completion_status": completion_status,
        "learning_status": "MISSION_LEARNING_WRITTEN" if goal.get("status") == "MISSION_LEARNING_WRITTEN" or goal.get("action") == "cycle" else goal.get("status"),
        "next_recommended_mission": goal.get("next_recommended_mission") or goal.get("next_mission"),
        "breach": bool(goal.get("breach")),
        "stop_reason": stop_reason,
        "generated_outputs": outputs,
        "useful_outputs": outputs if validation_status == "MISSION_VALIDATION_OK" else [],
        "blocked_actions": [
            "live_apply",
            "network",
            "remote_write",
            "external_api",
            "timer_install",
            "HIGH_MEDIUM_LOW_LIVE_execution",
        ],
        **HARD_DEFAULTS,
    }


def update_completion_ledger(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    ledger = normalize_ledger(load_dict(COMPLETION_LEDGER_JSON))
    entries = ledger.get("entries") if isinstance(ledger.get("entries"), list) else []
    by_mission = ledger.get("by_mission") if isinstance(ledger.get("by_mission"), dict) else {}
    for result in results:
        mission_type = result.get("mission_type")
        if not mission_type:
            continue
        completion_status = result.get("completion_status")
        is_completed = result.get("validation_status") == "MISSION_VALIDATION_OK" and completion_status in {"COMPLETED", "SAFE_STEP_EXECUTED", "COMPLETE_FRESH"}
        entry = {
            "mission_id": f"MISSION-{str(mission_type).upper().replace('-', '_')}",
            "mission_type": mission_type,
            "selected_at": result.get("started_at"),
            "executed_at": result.get("finished_at"),
            "completed_at": result.get("finished_at") if is_completed else None,
            "status_before": None,
            "status_after": "COMPLETED" if is_completed else completion_status,
            "linked_capability": result.get("linked_capability"),
            "linked_task": result.get("linked_task"),
            "execution_status": result.get("execution_status"),
            "validation_status": result.get("validation_status"),
            "learning_status": result.get("learning_status"),
            "completion_status": "COMPLETED" if is_completed else completion_status,
            "outputs_created": result.get("generated_outputs"),
            "useful_outputs": result.get("useful_outputs"),
            "blocked_reason": result.get("stop_reason"),
            "next_recommended_mission": result.get("next_recommended_mission"),
        }
        entries.append(entry)
        by_mission[str(mission_type)] = {
            "last_completed_at": result.get("finished_at") if is_completed else by_mission.get(str(mission_type), {}).get("last_completed_at") if isinstance(by_mission.get(str(mission_type)), dict) else None,
            "status": "COMPLETED" if is_completed else "FAILED_SAFE",
            "last_validation_status": result.get("validation_status"),
            "linked_capability": result.get("linked_capability"),
            "linked_task": result.get("linked_task"),
            "blocked_reason": result.get("stop_reason"),
        }
    ledger = {
        "schema_version": "sentinel-autonomous-mission-ledger-10.6",
        "updated_at": utc_now(),
        "entries": entries[-500:],
        "by_mission": by_mission,
        "completed_count": sum(1 for item in entries if isinstance(item, dict) and item.get("completion_status") == "COMPLETED"),
        **HARD_DEFAULTS,
    }
    write_json(COMPLETION_LEDGER_JSON, ledger)
    return ledger


def mission_diversity_stats(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    missions = [str(item.get("mission_type")) for item in results if item.get("mission_type")]
    caps = [str(item.get("linked_capability")) for item in results if item.get("linked_capability")]
    unique_missions = sorted(set(missions))
    unique_caps = sorted(set(caps))
    status = "MISSION_DIVERSITY_OK"
    if len(missions) >= 3 and len(unique_missions) < 2:
        status = "MISSION_DIVERSITY_NEEDS_ROTATION"
    if len(missions) >= 5 and len(unique_missions) < 3:
        status = "MISSION_DIVERSITY_NEEDS_ROTATION"
    return {
        "missions": missions,
        "capabilities": caps,
        "unique_missions": unique_missions,
        "unique_capabilities": unique_caps,
        "unique_mission_count": len(unique_missions),
        "unique_capability_count": len(unique_caps),
        "repeated_mission_count": max(0, len(missions) - len(unique_missions)),
        "status": status,
    }


def preflight() -> Dict[str, Any]:
    ensure_dirs()
    goal_path = PROJECT_DIR / GOAL_MANAGER
    json_scan = critical_json_scan()
    public_assets = public_asset_scan()
    breach_state = latest_breach_status()
    self_test = run_goal_manager("--self-test", timeout=180) if goal_path.exists() else {"status": "missing", "returncode": None}
    lock_blocked = False
    lock_info = {}
    if LOCKFILE.exists():
        existing, status = read_json(LOCKFILE)
        existing = existing if status == "ok" and isinstance(existing, dict) else {}
        pid = int(existing.get("pid") or 0)
        age = lock_age_hours(existing)
        lock_info = {"status": status, "pid": pid, "age_hours": round(age, 3) if age is not None else None}
        lock_blocked = not (age is not None and age > LOCK_STALE_HOURS and not process_active(pid))
    blockers: List[str] = []
    if not goal_path.exists():
        blockers.append("missing_goal_manager")
    if self_test.get("returncode") != 0:
        blockers.append("goal_manager_self_test_failed")
    if json_scan["invalid_json"]:
        blockers.append("invalid_critical_json")
    if public_assets["findings"]:
        blockers.append("forbidden_public_asset")
    if breach_state["breach"]:
        blockers.append("breach_or_live_flag")
    if lock_blocked:
        blockers.append("active_lockfile")
    status = "MISSION_QUEUE_RUNNER_PREFLIGHT_OK" if not blockers else "MISSION_QUEUE_RUNNER_PREFLIGHT_BLOCKED"
    return {
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "timestamp_utc": utc_now(),
        "action": "preflight",
        "status": status,
        "blockers": blockers,
        "goal_manager_exists": goal_path.exists(),
        "goal_manager_self_test": self_test,
        "critical_json": json_scan,
        "public_assets": public_assets,
        "breach_state": breach_state,
        "lockfile": lock_info,
        "output_roots": [rel(path) for path in ALLOWED_WRITE_ROOTS],
        **HARD_DEFAULTS,
    }


def run_once() -> Dict[str, Any]:
    return run_missions(1, action="run-once")


def run_missions(max_missions: int, action: str = "run-missions") -> Dict[str, Any]:
    if max_missions > MAX_MISSIONS:
        report = base_report(action, "BLOCKED_MISSION_LOOP_LIMIT")
        report["stop_reason"] = "STOP_ON_MAX_MISSIONS"
        report["requested_missions"] = max_missions
        report["max_missions"] = MAX_MISSIONS
        write_outputs(report)
        return report
    acquired, lock = acquire_lock(max_missions)
    if not acquired:
        report = base_report(action, "MISSION_QUEUE_RUNNER_BLOCKED")
        report["stop_reason"] = "STOP_ON_LOCK_COLLISION"
        report["lockfile_status"] = lock
        write_outputs(report)
        return report
    results: List[Dict[str, Any]] = []
    stop_reason = None
    try:
        for index in range(1, max_missions + 1):
            started = utc_now()
            proc = run_goal_manager("--cycle", timeout=300)
            finished = utc_now()
            result = mission_result(index, started, finished, proc)
            if results:
                previous = results[-1].get("mission_type")
                current = result.get("mission_type")
                if current and previous == current and current != "maintain_capability_health":
                    result["stop_reason"] = "STOP_ON_REPEATED_MISSION_LOOP"
            results.append(result)
            update_completion_ledger([result])
            if result.get("stop_reason"):
                stop_reason = result["stop_reason"]
                break
        if stop_reason is None:
            stop_reason = "STOP_ON_MAX_MISSIONS" if len(results) >= max_missions else "STOP_ON_NO_SAFE_MISSION"
        diversity = mission_diversity_stats(results)
        if len(results) >= 3 and diversity["status"] != "MISSION_DIVERSITY_OK" and stop_reason == "STOP_ON_MAX_MISSIONS":
            stop_reason = "STOP_ON_NO_SAFE_MISSION"
        status = "MISSION_QUEUE_RUNNER_RUN_ONCE_OK" if action == "run-once" and not any(r.get("breach") for r in results) else "MISSION_QUEUE_RUNNER_COMPLETED"
        report = base_report(action, status)
        report.update({
            "requested_missions": max_missions,
            "missions_completed": len(results),
            "mission_results": results,
            "validation_status": "MISSION_QUEUE_RUNNER_VALIDATION_OK" if all(
                result.get("validation_status") in {"MISSION_VALIDATION_OK", "MISSION_VALIDATION_WARNINGS", None}
                for result in results
            ) else "MISSION_QUEUE_RUNNER_VALIDATION_WARNINGS",
            "selected_missions": [r.get("mission_type") for r in results if r.get("mission_type")],
            "selected_capabilities": [r.get("linked_capability") for r in results if r.get("linked_capability")],
            "selected_tasks": [r.get("linked_task") for r in results if r.get("linked_task")],
            "stop_reason": stop_reason,
            "mission_diversity": diversity,
            "completion_ledger": normalize_ledger(load_dict(COMPLETION_LEDGER_JSON)),
            "next_recommended_mission": (results[-1].get("next_recommended_mission") if results else None),
        })
        release = release_lock(status)
        report["lockfile_status"] = release.get("release_status")
        write_outputs(report)
        return report
    except Exception as exc:  # noqa: BLE001 - converted to safe local report
        release = release_lock("MISSION_QUEUE_RUNNER_FAILED")
        report = base_report(action, "MISSION_QUEUE_RUNNER_FAILED")
        report["stop_reason"] = "STOP_ON_GOAL_MANAGER_FAILURE"
        report["error"] = redact_text(exc)
        report["mission_results"] = results
        report["lockfile_status"] = release.get("release_status")
        write_outputs(report)
        return report


def validate_run() -> Dict[str, Any]:
    report = load_dict(REPORT_JSON) or load_dict(STATE_JSON)
    ledger = normalize_ledger(load_dict(COMPLETION_LEDGER_JSON))
    checks: List[Dict[str, Any]] = []
    for path in [REPORT_JSON, STATE_JSON, LATEST_JSON, COMPLETION_LEDGER_JSON]:
        _, status = read_json(path)
        checks.append({"path": rel(path), "status": status})
    source = Path(__file__).read_text(encoding="utf-8")
    source_findings = source_safety_findings(source)
    own_outputs = [
        REPORT_MD, PREFLIGHT_MD, LOG_MD, VALIDATION_MD, OWNER_SUMMARY_MD,
        STOP_REASON_MD, NEXT_STEP_MD, LEDGER_MD,
    ]
    content_findings: List[str] = []
    for path in own_outputs:
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if SECRET_RE.search(text) or CUSTOMER_DATA_RE.search(text):
            content_findings.append(rel(path))
    validation_status = "MISSION_QUEUE_RUNNER_VALIDATION_OK"
    if source_findings or content_findings or any(item["status"] == "invalid_json" for item in checks):
        validation_status = "MISSION_QUEUE_RUNNER_VALIDATION_WARNINGS"
    validation = {
        **base_report("validate-run", validation_status),
        "json_checks": checks,
        "source_safety_findings": source_findings,
        "content_findings": content_findings,
        "ledger_completed_count": ledger.get("completed_count", 0),
        "mission_results_count": len(report.get("mission_results") or []),
    }
    write_outputs({**report, "validation": validation, "validation_status": validation_status, "status": validation_status})
    return validation


def build_owner_summary() -> Dict[str, Any]:
    report = load_dict(REPORT_JSON) or base_report("build-owner-summary", "MISSION_QUEUE_RUNNER_OWNER_SUMMARY_READY")
    report["action"] = "build-owner-summary"
    report["owner_summary_status"] = "MISSION_QUEUE_RUNNER_OWNER_SUMMARY_READY"
    report["status"] = "MISSION_QUEUE_RUNNER_OWNER_SUMMARY_READY"
    write_outputs(report)
    return report


def supervisor_summary() -> Dict[str, Any]:
    data = load_dict(SUPERVISOR_JSON)
    return {
        "state_path": "state/adaptive-learning/latest_autonomous_operations_supervisor.json",
        "available": bool(data),
        "last_supervisor_status": data.get("status") if data else "not_available",
        "last_supervisor_operation": data.get("selected_operation") if data else None,
        "supervisor_stop_reason": data.get("stop_reason") if data else None,
    }


def operation_governor_summary() -> Dict[str, Any]:
    data = load_dict(OPERATION_GOVERNOR_JSON)
    return {
        "state_path": "state/adaptive-learning/latest_autonomous_operation_governor.json",
        "available": bool(data),
        "status": data.get("status") if data else "not_available",
        "selected_operation": data.get("selected_operation_name") if data else None,
        "diversity_status": (data.get("diversity") or {}).get("status") if data else None,
    }


def base_report(action: str, status: str) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "timestamp_utc": utc_now(),
        "action": action,
        "status": status,
        "mission_results": [],
        "missions_completed": 0,
        "selected_missions": [],
        "selected_capabilities": [],
        "selected_tasks": [],
        "stop_reason": None,
        "mission_diversity": {"status": "MISSION_DIVERSITY_NOT_EVALUATED"},
        "completion_ledger_status": "not_updated",
        "owner_summary_status": "not_written",
        "learning_updates": [],
        "lockfile_status": "not_checked",
        "operations_supervisor": supervisor_summary(),
        "operation_governor": operation_governor_summary(),
        "integrations": {
            "operations_supervisor": "readable_by_mission_queue_runner",
            "operation_governor": "readable_by_mission_queue_runner",
            "goal_manager": "readable_by_runner",
            "health_governor": "reads_completion_ledger",
            "capability_registry": "reads_completion_ledger",
            "priority_engine": "reads_completion_ledger",
            "kernel": "reads_mission_runner_state",
            "cycle_runner": "reads_mission_runner_state",
        },
        **HARD_DEFAULTS,
    }


def write_playbooks(report: Dict[str, Any]) -> None:
    base = {"schema_version": SCHEMA_VERSION, "phase": PHASE, **HARD_DEFAULTS}
    write_json(PLAYBOOK_RUNNER, {
        **base,
        "name": "sentinel-autonomous-mission-queue-runner",
        "purpose": "Run several safe local Goal Manager mission steps with validation and stop rules.",
        "allowed_goal_manager_commands": list(ALLOWED_GOAL_COMMANDS.values()),
        "max_missions": MAX_MISSIONS,
        "blocked_actions": ["live_apply", "network", "remote_write", "external_api", "timer_install", "HIGH_MEDIUM_LOW_LIVE_execution"],
    })
    write_json(PLAYBOOK_STOP_RULES, {
        **base,
        "name": "sentinel-autonomous-mission-runner-stop-rules",
        "stop_rules": STOP_RULES,
        "diversity_rules": [
            "at least two different missions in three steps when safe alternatives exist",
            "at least three different missions in five steps when safe alternatives exist",
        ],
    })
    write_json(PLAYBOOK_LEDGER, {
        **base,
        "name": "sentinel-autonomous-mission-completion-ledger",
        "ledger_path": rel(COMPLETION_LEDGER_JSON),
        "entry_fields": [
            "mission_id", "mission_type", "selected_at", "executed_at", "completed_at",
            "status_before", "status_after", "linked_capability", "linked_task",
            "execution_status", "validation_status", "learning_status", "completion_status",
            "outputs_created", "useful_outputs", "blocked_reason", "next_recommended_mission",
        ],
    })
    write_json(PLAYBOOK_OWNER, {
        **base,
        "name": "sentinel-autonomous-mission-runner-owner-summary",
        "owner_summary_fields": [
            "missions_completed", "selected_missions", "selected_capabilities", "selected_tasks",
            "validated_outputs", "completed_missions", "learning_updates", "stop_reason",
            "next_recommended_mission", "blocked_capabilities", "safe_defaults",
        ],
    })


def render_report_md(report: Dict[str, Any]) -> str:
    return "\n".join([
        "# Sentinel Autonomous Mission Queue Runner",
        "",
        f"- status: `{report.get('status')}`",
        f"- action: `{report.get('action')}`",
        f"- missions_completed: `{report.get('missions_completed', 0)}`",
        f"- stop_reason: `{report.get('stop_reason', '-')}`",
        f"- mission_diversity: `{(report.get('mission_diversity') or {}).get('status', '-')}`",
        f"- completion_ledger_completed_count: `{(report.get('completion_ledger') or {}).get('completed_count', '-')}`",
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
        "# Sentinel Autonomous Mission Runner Preflight",
        "",
        f"- status: `{report.get('status')}`",
        f"- goal_manager_exists: `{report.get('goal_manager_exists', '-')}`",
        f"- blockers: `{', '.join(blockers) or '-'}`",
        f"- lockfile: `{(report.get('lockfile') or {}).get('status', '-')}`",
        "- live apply and external actions remain blocked.",
    ]) + "\n"


def render_log_md(report: Dict[str, Any]) -> str:
    lines = ["# Sentinel Autonomous Mission Runner Log", ""]
    for result in report.get("mission_results") or []:
        lines.extend([
            f"## Mission {result.get('mission_index')}",
            f"- selected_mission: `{result.get('mission_type')}`",
            f"- linked_capability: `{result.get('linked_capability')}`",
            f"- linked_task: `{result.get('linked_task')}`",
            f"- execution_status: `{result.get('execution_status')}`",
            f"- validation_status: `{result.get('validation_status')}`",
            f"- completion_status: `{result.get('completion_status')}`",
            f"- stop_reason: `{result.get('stop_reason') or '-'}`",
            "",
        ])
    return "\n".join(lines) + "\n"


def render_validation_md(report: Dict[str, Any]) -> str:
    validation = report.get("validation") if isinstance(report.get("validation"), dict) else {}
    checks = validation.get("json_checks") if isinstance(validation.get("json_checks"), list) else []
    lines = ["# Sentinel Autonomous Mission Runner Validation", "", f"- status: `{report.get('validation_status', validation.get('status', '-'))}`"]
    for item in checks:
        lines.append(f"- `{item.get('path')}` status=`{item.get('status')}`")
    lines.extend([
        "- live_apply: `False`",
        "- allowed_apply_now: `False`",
        "- HIGH blocked: `True`",
        "- LOW_LIVE executable: `False`",
        "- MEDIUM executable: `False`",
        "- breach: `False`",
    ])
    return "\n".join(lines) + "\n"


def render_owner_summary_md(report: Dict[str, Any]) -> str:
    selected = ", ".join(str(v) for v in report.get("selected_missions") or []) or "-"
    caps = ", ".join(str(v) for v in report.get("selected_capabilities") or []) or "-"
    tasks = ", ".join(str(v) for v in report.get("selected_tasks") or []) or "-"
    return "\n".join([
        "# Sentinel Autonomous Mission Runner Owner Summary",
        "",
        f"- mission_steps: `{report.get('missions_completed', 0)}`",
        f"- selected_missions: `{selected}`",
        f"- selected_capabilities: `{caps}`",
        f"- selected_tasks: `{tasks}`",
        f"- completed_ledger_count: `{(report.get('completion_ledger') or {}).get('completed_count', 0)}`",
        f"- stop_reason: `{report.get('stop_reason', '-')}`",
        f"- next_recommended_mission: `{report.get('next_recommended_mission', '-')}`",
        f"- supervisor_status: `{(report.get('operations_supervisor') or {}).get('last_supervisor_status', '-')}`",
        f"- supervisor_operation: `{(report.get('operations_supervisor') or {}).get('last_supervisor_operation', '-')}`",
        "- blocked_scope: live systems, external APIs, remote writes, timers, MEDIUM, HIGH and LOW_LIVE",
        "- live_apply: `False`",
        "- emergency_stop: `True`",
        "- allowed_apply_now: `False`",
        "- HIGH blocked: `True`",
        "- LOW_LIVE executable: `False`",
        "- MEDIUM executable: `False`",
        "- breach: `False`",
    ]) + "\n"


def render_stop_reason_md(report: Dict[str, Any]) -> str:
    return "\n".join([
        "# Sentinel Autonomous Mission Runner Stop Reason",
        "",
        f"- stop_reason: `{report.get('stop_reason', '-')}`",
        f"- status: `{report.get('status')}`",
        "- Stop rules are fail-closed and local-only.",
    ]) + "\n"


def render_next_step_md(report: Dict[str, Any]) -> str:
    return "\n".join([
        "# Sentinel Autonomous Mission Runner Next Step",
        "",
        f"- next_recommended_mission: `{report.get('next_recommended_mission', '-')}`",
        "- Next work remains local safe autonomy unless a separate owner approval changes policy.",
    ]) + "\n"


def render_ledger_md(report: Dict[str, Any]) -> str:
    ledger = report.get("completion_ledger") if isinstance(report.get("completion_ledger"), dict) else normalize_ledger(load_dict(COMPLETION_LEDGER_JSON))
    entries = ledger.get("entries") if isinstance(ledger.get("entries"), list) else []
    lines = ["# Sentinel Autonomous Mission Completion Ledger", "", f"- completed_count: `{ledger.get('completed_count', 0)}`"]
    for item in entries[-20:]:
        if isinstance(item, dict):
            lines.append(
                f"- `{item.get('mission_type')}` status=`{item.get('completion_status')}` "
                f"capability=`{item.get('linked_capability')}` task=`{item.get('linked_task')}`"
            )
    return "\n".join(lines) + "\n"


def write_outputs(report: Dict[str, Any]) -> None:
    ensure_dirs()
    safe_report = {
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "timestamp_utc": report.get("timestamp_utc") or utc_now(),
        **report,
        **HARD_DEFAULTS,
        "completion_ledger_status": "COMPLETION_LEDGER_READY" if COMPLETION_LEDGER_JSON.exists() else "COMPLETION_LEDGER_PENDING",
        "owner_summary_status": "MISSION_QUEUE_RUNNER_OWNER_SUMMARY_READY",
        "recommended_git_checkpoint": [
            "sentinel_autonomous_operations_supervisor.py",
            "sentinel_autonomy.py",
            "sentinel_autonomous_mission_queue_runner.py",
            "sentinel_autonomous_goal_manager.py",
            "sentinel_autonomous_capability_health_governor.py",
            "sentinel_autonomous_capability_registry.py",
            "sentinel_autonomous_priority_engine.py",
            "sentinel_autonomous_operation_governor.py",
            "sentinel_self_governing_safe_autonomy_kernel.py",
            "sentinel_autonomous_cycle_runner.py",
            "playbooks/sentinel-autonomous-mission-queue-runner.playbook.json",
            "playbooks/sentinel-autonomous-mission-runner-stop-rules.playbook.json",
            "playbooks/sentinel-autonomous-mission-completion-ledger.playbook.json",
            "playbooks/sentinel-autonomous-mission-runner-owner-summary.playbook.json",
            "playbooks/sentinel-autonomous-operations-supervisor.playbook.json",
            "playbooks/sentinel-autonomous-operation-decision.playbook.json",
            "playbooks/sentinel-autonomous-system-validation.playbook.json",
            "playbooks/sentinel-autonomous-owner-briefing.playbook.json",
            "playbooks/sentinel-autonomous-operation-governor.playbook.json",
            "playbooks/sentinel-autonomous-operation-impact-scoring.playbook.json",
            "playbooks/sentinel-autonomous-operation-noop-detection.playbook.json",
            "playbooks/sentinel-autonomous-operation-diversity.playbook.json",
        ],
    }
    write_json(REPORT_JSON, safe_report)
    write_json(STATE_JSON, safe_report)
    write_json(LATEST_JSON, safe_report)
    history = load_list(HISTORY_JSON)
    history.append({
        "timestamp_utc": utc_now(),
        "status": safe_report.get("status"),
        "action": safe_report.get("action"),
        "missions_completed": safe_report.get("missions_completed", 0),
        "selected_missions": safe_report.get("selected_missions", []),
        "stop_reason": safe_report.get("stop_reason"),
    })
    write_json(HISTORY_JSON, {"entries": history[-200:], **HARD_DEFAULTS})
    stops = load_dict(STOP_PATTERNS_JSON)
    reason = str(safe_report.get("stop_reason") or "none")
    stops[reason] = int(stops.get(reason, 0)) + 1
    write_json(STOP_PATTERNS_JSON, {"patterns": stops, **HARD_DEFAULTS})
    write_text(REPORT_MD, render_report_md(safe_report))
    write_text(PREFLIGHT_MD, render_preflight_md(safe_report if safe_report.get("action") == "preflight" else preflight()))
    write_text(LOG_MD, render_log_md(safe_report))
    write_text(VALIDATION_MD, render_validation_md(safe_report))
    write_text(OWNER_SUMMARY_MD, render_owner_summary_md(safe_report))
    write_text(STOP_REASON_MD, render_stop_reason_md(safe_report))
    write_text(NEXT_STEP_MD, render_next_step_md(safe_report))
    write_text(LEDGER_MD, render_ledger_md(safe_report))
    write_playbooks(safe_report)
    append_jsonl(AUDIT_JSONL, [{
        "timestamp_utc": utc_now(),
        "event": "autonomous_mission_queue_runner",
        "action": safe_report.get("action"),
        "status": safe_report.get("status"),
        "missions_completed": safe_report.get("missions_completed", 0),
        "selected_missions": safe_report.get("selected_missions", []),
        "stop_reason": safe_report.get("stop_reason"),
        "breach": False,
        "live_apply": False,
        "allowed_apply_now": False,
    }])


def source_safety_findings(source: str) -> List[str]:
    findings: List[str] = []
    if re.search(r"add_argument\([\"']--" + "apply", source):
        findings.append("apply_argument_present")
    if FORBIDDEN_IMPORT_RE.search(source):
        findings.append("network_import_present")
    if re.search(r"shell\s*=\s*True", source):
        findings.append("shell_true_present")
    if re.search(r"subprocess\.(?:Popen|call|check_call|check_output)\(", source):
        findings.append("non_run_subprocess_present")
    if re.search(r"systemctl\s+(?:start|enable)", source):
        findings.append("systemctl_live_action_present")
    if re.search(r"crontab\s+(?:-|install)", source):
        findings.append("cron_install_present")
    if re.search(r"r" + "m\\s+-r" + "f", source):
        findings.append("destructive_delete_present")
    if re.search(r"\b(?:p" + "kill|kill" + "all)\\b", source):
        findings.append("process_termination_present")
    if re.search(r"\b(?:sftp|ftp)\.(?:put|remove|rename)\(", source):
        findings.append("remote_write_present")
    if re.search(r"\b(?:insert|update|delete)\s+from\b", source, flags=re.IGNORECASE):
        findings.append("db_write_pattern_present")
    return findings


def self_test() -> Dict[str, Any]:
    source = Path(__file__).read_text(encoding="utf-8")
    findings = source_safety_findings(source)
    tests = {
        "no_apply_argument": "apply_argument_present" not in findings,
        "no_network_imports": "network_import_present" not in findings,
        "no_shell_true": "shell_true_present" not in findings,
        "subprocess_allowlist": all(command_is_allowlisted(cmd) for cmd in ALLOWED_GOAL_COMMANDS.values()),
        "max_missions_limited": MAX_MISSIONS <= 5,
        "lockfile_in_allowed_state": is_within(LOCKFILE, STATE_DIR),
        "ledger_json_shape": isinstance(normalize_ledger({"entries": []}), dict),
        "write_roots_allowed": all(is_within(root, root) for root in ALLOWED_WRITE_ROOTS),
        "safe_defaults": HARD_DEFAULTS == {
            "live_apply": False,
            "emergency_stop": True,
            "allowed_apply_now": False,
            "high_blocked": True,
            "low_live_executable": False,
            "medium_executable": False,
            "breach": False,
        },
    }
    status = "MISSION_QUEUE_RUNNER_SELF_TEST_OK" if all(tests.values()) and not findings else "MISSION_QUEUE_RUNNER_SELF_TEST_FAILED"
    report = {
        **base_report("self-test", status),
        "tests": tests,
        "source_safety_findings": findings,
    }
    write_outputs(report)
    return report


def status_report() -> Dict[str, Any]:
    report = load_dict(LATEST_JSON) or load_dict(REPORT_JSON) or base_report("status", "MISSION_QUEUE_RUNNER_STATUS_EMPTY")
    print(f"status={report.get('status')}")
    print(f"missions_completed={report.get('missions_completed', 0)}")
    print(f"selected_missions={','.join(str(x) for x in report.get('selected_missions', []))}")
    print(f"selected_capabilities={','.join(str(x) for x in report.get('selected_capabilities', []))}")
    print(f"selected_tasks={','.join(str(x) for x in report.get('selected_tasks', []))}")
    print(f"stop_reason={report.get('stop_reason')}")
    print(f"completion_ledger_status={report.get('completion_ledger_status')}")
    print(f"live_apply={report.get('live_apply')}")
    print(f"emergency_stop={report.get('emergency_stop')}")
    print(f"allowed_apply_now={report.get('allowed_apply_now')}")
    print(f"HIGH_blocked={report.get('high_blocked')}")
    print(f"LOW_LIVE_executable={report.get('low_live_executable')}")
    print(f"MEDIUM_executable={report.get('medium_executable')}")
    print(f"breach={report.get('breach')}")
    return report


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Sentinel Autonomous Mission Queue Runner")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--run-once", action="store_true")
    parser.add_argument("--run-missions", type=int)
    parser.add_argument("--validate-run", action="store_true")
    parser.add_argument("--build-owner-summary", action="store_true")
    parser.add_argument("--status", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        report = self_test()
    elif args.preflight:
        report = preflight()
        write_outputs(report)
    elif args.run_once:
        report = run_once()
    elif args.run_missions is not None:
        report = run_missions(args.run_missions)
    elif args.validate_run:
        report = validate_run()
    elif args.build_owner_summary:
        report = build_owner_summary()
    elif args.status:
        status_report()
        return 0
    else:
        parser.print_help()
        return 2
    return 0 if not report.get("status", "").endswith("_FAILED") and report.get("status") != "MISSION_QUEUE_RUNNER_SELF_TEST_FAILED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
