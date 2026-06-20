#!/usr/bin/env python3
"""Sentinel Autonomous Cycle Runner (Phase 10.1).

Controlled multi-cycle runner for the Phase 10.0 self-governing safe autonomy
kernel. The runner executes only exact allowlisted local kernel commands and
keeps live apply, external systems and higher-risk execution blocked.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


PROJECT_DIR = Path("/srv/sentinel-defense")
KERNEL_FILE = PROJECT_DIR / "sentinel_self_governing_safe_autonomy_kernel.py"
KERNEL_JSON = PROJECT_DIR / "reports/latest/sentinel-self-governing-autonomy-kernel.json"
KERNEL_LATEST_JSON = PROJECT_DIR / "state/adaptive-learning/latest_self_governing_autonomy_kernel.json"
PRIORITY_MODEL_JSON = PROJECT_DIR / "state/adaptive-learning/autonomy_task_priority_model.json"
HEALTH_GOVERNOR_JSON = PROJECT_DIR / "state/adaptive-learning/latest_autonomous_capability_health_governor.json"

REPORT_JSON = PROJECT_DIR / "reports/latest/sentinel-autonomous-cycle-runner.json"
REPORT_MD = PROJECT_DIR / "reports/latest/sentinel-autonomous-cycle-runner.md"
PREFLIGHT_MD = PROJECT_DIR / "reports/latest/sentinel-autonomous-cycle-preflight.md"
LOG_MD = PROJECT_DIR / "reports/latest/sentinel-autonomous-cycle-log.md"
VALIDATION_MD = PROJECT_DIR / "reports/latest/sentinel-autonomous-cycle-validation.md"
OWNER_SUMMARY_MD = PROJECT_DIR / "reports/latest/sentinel-autonomous-cycle-owner-summary.md"
STOP_REASON_MD = PROJECT_DIR / "reports/latest/sentinel-autonomous-cycle-stop-reason.md"
NEXT_STEP_MD = PROJECT_DIR / "reports/latest/sentinel-autonomous-cycle-next-step.md"

STATE_JSON = PROJECT_DIR / "state/adaptive-learning/sentinel_autonomous_cycle_runner.json"
LATEST_JSON = PROJECT_DIR / "state/adaptive-learning/latest_autonomous_cycle_runner.json"
HISTORY_JSON = PROJECT_DIR / "state/adaptive-learning/autonomous_cycle_runner_history.json"
LOCK_HISTORY_JSON = PROJECT_DIR / "state/adaptive-learning/autonomous_cycle_runner_lock_history.json"
STOP_PATTERNS_JSON = PROJECT_DIR / "state/adaptive-learning/autonomous_cycle_runner_stop_patterns.json"
LOCKFILE = PROJECT_DIR / "state/adaptive-learning/autonomous_cycle_runner.lock"

AUDIT_JSONL = PROJECT_DIR / "audit/sentinel-autonomous-cycle-runner.jsonl"

PLAYBOOK_RUNNER = PROJECT_DIR / "playbooks/sentinel-autonomous-cycle-runner.playbook.json"
PLAYBOOK_STOP = PROJECT_DIR / "playbooks/sentinel-autonomous-cycle-stop-rules.playbook.json"
PLAYBOOK_LOCKING = PROJECT_DIR / "playbooks/sentinel-autonomous-cycle-locking.playbook.json"
PLAYBOOK_OWNER = PROJECT_DIR / "playbooks/sentinel-autonomous-cycle-owner-summary.playbook.json"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "state/adaptive-learning",
    PROJECT_DIR / "audit",
    PROJECT_DIR / "playbooks",
)

SCHEMA_VERSION = "sentinel-autonomous-cycle-runner-10.1"
MAX_CYCLES = 5
DEFAULT_CYCLES = 3
KERNEL_TIMEOUT_SECONDS = 180
LOCK_STALE_SECONDS = 6 * 60 * 60

HARD_DEFAULTS = {
    "live_apply": False,
    "emergency_stop": True,
    "allowed_apply_now": False,
    "high_blocked": True,
    "low_live_executable": False,
    "medium_executable": False,
    "breach": False,
}

ALLOWED_KERNEL_COMMANDS: Dict[str, List[str]] = {
    "self-test": ["python3", "sentinel_self_governing_safe_autonomy_kernel.py", "--self-test"],
    "cycle": ["python3", "sentinel_self_governing_safe_autonomy_kernel.py", "--cycle"],
    "status": ["python3", "sentinel_self_governing_safe_autonomy_kernel.py", "--status"],
}

STOP_ON_BREACH = "STOP_ON_BREACH"
STOP_ON_FORBIDDEN_PATTERN = "STOP_ON_FORBIDDEN_PATTERN"
STOP_ON_KERNEL_FAILURE = "STOP_ON_KERNEL_FAILURE"
STOP_ON_REPEATED_TASK_LOOP = "STOP_ON_REPEATED_TASK_LOOP"
STOP_ON_NO_DIVERSE_SAFE_TASK = "STOP_ON_NO_DIVERSE_SAFE_TASK"
STOP_ON_NO_SAFE_TASK = "STOP_ON_NO_SAFE_TASK"
STOP_ON_MAX_CYCLES = "STOP_ON_MAX_CYCLES"
STOP_ON_LOCK_COLLISION = "STOP_ON_LOCK_COLLISION"
STOP_ON_INVALID_JSON = "STOP_ON_INVALID_JSON"
STOP_ON_UNSAFE_SCOPE = "STOP_ON_UNSAFE_SCOPE"
STOP_ON_LIVE_APPLY_ATTEMPT = "STOP_ON_LIVE_APPLY_ATTEMPT"
STOP_COMPLETED_RUN_ONCE = "STOP_COMPLETED_RUN_ONCE"

STATUS_PREFLIGHT_OK = "AUTONOMOUS_CYCLE_PREFLIGHT_OK"
STATUS_RUN_OK = "AUTONOMOUS_CYCLE_RUN_OK"
STATUS_BLOCKED_LOOP_LIMIT = "BLOCKED_LOOP_LIMIT"
STATUS_BLOCKED_SAFETY = "AUTONOMOUS_CYCLE_BLOCKED_BY_SAFETY"
STATUS_VALIDATION_OK = "AUTONOMOUS_CYCLE_VALIDATION_OK"
STATUS_VALIDATION_FAILED = "AUTONOMOUS_CYCLE_VALIDATION_FAILED"
STATUS_FAILED = "AUTONOMOUS_CYCLE_FAILED"

FORBIDDEN_IMPORT_RE = re.compile(
    r"(?m)^\s*(?:import|from)\s+(?:requests|urllib|http\.client|smtplib|socket|paramiko|cloudflare)\b"
)
SECRET_RE = re.compile(
    r"(?i)(?:password|passwd|secret|token|api[_-]?key|authorization|bearer)\s*[:=]\s*['\"]?"
    r"(?!false\b|true\b|null\b|none\b|not_applied\b|<redacted\b)[A-Za-z0-9+/=_.:-]{8,}"
)
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:OPENSSH|RSA|DSA|EC) PRIVATE KEY-----")
TOKEN_FORMAT_RE = re.compile(r"\b(?:sk-(?:proj-)?[A-Za-z0-9_-]{24,}|ghp_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,})\b")
INTERNAL_PATH_RE = re.compile(r"(?<![\w.-])/(?:srv|home|root|etc|var)/(?:[A-Za-z0-9._@+-]+/){1,}[A-Za-z0-9._@+-]*")
IP_RE = re.compile(r"\b(?:(?:10|127|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3})\b")
CUSTOMER_DATA_RE = re.compile(r"(?i)\b(customer_password|customer_token|customer_api_key|real_customer|kundenzugang)\b")
FORBIDDEN_ACTION_RE = re.compile(
    r"(?i)(live_apply\s*[:=]\s*true|allowed_apply_now\s*[:=]\s*true|"
    r"risk_class\s*[:=]\s*(?:HIGH|MEDIUM|LOW_LIVE)|"
    r"systemctl\s+(?:enable|start)|crontab\s+(?:install|-)|"
    r"cloudflare\s+(?:api|cli)|nginx\s+reload|wp\s+|mysql\b|"
    r"sftp\s+(?:put|remove|rename)|sftp\.(?:put|remove|rename)|"
    r"curl\s+.*\|\s*(?:ba)?sh|wget\s+.*\|\s*(?:ba)?sh)"
)

PUBLIC_ASSET_GLOBS = [
    "reports/latest/sentinel-payhip-public*.md",
    "reports/latest/sentinel-payhip-product-file-final.txt",
    "reports/latest/sentinel-payhip-short-description.md",
    "reports/latest/sentinel-payhip-long-description.md",
    "reports/latest/sentinel-payhip-faq.md",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_utc(value: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(PROJECT_DIR))
    except Exception:
        return str(path)


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except Exception:
        return False


def assert_allowed_write(path: Path) -> None:
    if not any(is_within(path, root) for root in ALLOWED_WRITE_ROOTS):
        raise ValueError(f"write outside allowed roots refused: {rel(path)}")
    if path.resolve() == LOCKFILE.resolve():
        return
    if path.suffix.lower() not in {".json", ".jsonl", ".md"}:
        raise ValueError(f"unsupported output suffix refused: {rel(path)}")


def redact_text(value: Any, max_len: int = 3000) -> str:
    text = "" if value is None else str(value)
    text = SECRET_RE.sub(lambda m: m.group(0).split("=", 1)[0].split(":", 1)[0] + "=<redacted>", text)
    text = PRIVATE_KEY_RE.sub("<redacted-private-key-marker>", text)
    text = TOKEN_FORMAT_RE.sub("<redacted-token>", text)
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text


def assert_safe_blob(path: Path, text: str) -> None:
    if SECRET_RE.search(text) or PRIVATE_KEY_RE.search(text) or TOKEN_FORMAT_RE.search(text):
        raise ValueError(f"secret-like output refused: {rel(path)}")


def write_text(path: Path, text: str) -> None:
    assert_allowed_write(path)
    assert_safe_blob(path, text)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def write_json(path: Path, data: Any) -> None:
    write_text(path, json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def append_jsonl(path: Path, records: Iterable[Dict[str, Any]]) -> None:
    assert_allowed_write(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for record in records:
            blob = json.dumps(record, ensure_ascii=False, sort_keys=True)
            assert_safe_blob(path, blob)
            handle.write(blob + "\n")


def read_json(path: Path) -> Tuple[Optional[Any], str]:
    try:
        if not path.exists():
            return None, "missing"
        return json.loads(path.read_text(encoding="utf-8")), "ok"
    except json.JSONDecodeError:
        return None, "invalid_json"
    except OSError:
        return None, "read_error"


def load_list(path: Path) -> List[Any]:
    data, status = read_json(path)
    return data if status == "ok" and isinstance(data, list) else []


def load_dict(path: Path) -> Dict[str, Any]:
    data, status = read_json(path)
    return data if status == "ok" and isinstance(data, dict) else {}


def priority_model() -> Dict[str, Any]:
    return load_dict(PRIORITY_MODEL_JSON)


def priority_allows_repeat(task: Any) -> bool:
    model = priority_model()
    anti_loop = model.get("anti_loop") if isinstance(model.get("anti_loop"), dict) else {}
    selected = model.get("selected_task")
    return bool(selected == task and anti_loop.get("repeat_allowed") is True)


def task_diversity_stats(cycles: List[Dict[str, Any]], model: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    tasks = [str(c.get("selected_task")) for c in cycles if c.get("selected_task")]
    unique = sorted(set(tasks))
    repeated_count = max(0, len(tasks) - len(unique))
    last_three = tasks[-3:]
    last_five = tasks[-5:]
    unique_three = len(set(last_three))
    unique_five = len(set(last_five))
    model = model if model is not None else priority_model()
    anti_loop = model.get("anti_loop") if isinstance(model.get("anti_loop"), dict) else {}
    status = "DIVERSITY_OK"
    if len(last_three) >= 3 and unique_three < 2:
        status = STOP_ON_NO_DIVERSE_SAFE_TASK
    if len(last_five) >= 5 and unique_five < 3:
        status = STOP_ON_NO_DIVERSE_SAFE_TASK
    return {
        "status": status,
        "tasks": tasks,
        "unique_tasks": unique,
        "unique_task_count": len(unique),
        "repeated_task_count": repeated_count,
        "last_three_tasks": last_three,
        "last_five_tasks": last_five,
        "unique_last_three": unique_three,
        "unique_last_five": unique_five,
        "cooldown_respected": anti_loop.get("cooldown_respected", True),
        "anti_loop_status": anti_loop.get("status", "UNKNOWN"),
        "next_best_task": model.get("selected_task"),
    }


def capability_diversity_stats(cycles: List[Dict[str, Any]]) -> Dict[str, Any]:
    capabilities = [
        str(c.get("selected_capability"))
        for c in cycles
        if c.get("selected_capability")
    ]
    unique = sorted(set(capabilities))
    return {
        "capabilities": capabilities,
        "unique_capabilities": unique,
        "unique_capability_count": len(unique),
        "capability_repeated_count": max(0, len(capabilities) - len(unique)),
        "status": "CAPABILITY_DIVERSITY_OK" if len(capabilities) < 3 or len(unique) >= 2 else "CAPABILITY_DIVERSITY_NEEDS_ROTATION",
    }


def health_governor_summary() -> Dict[str, Any]:
    data = load_dict(HEALTH_GOVERNOR_JSON)
    return {
        "state_path": "state/adaptive-learning/latest_autonomous_capability_health_governor.json",
        "available": bool(data),
        "status": data.get("status") if data else "not_available",
        "capability_health_before": data.get("before_health") if data else None,
        "capability_health_after": data.get("after_health") if data else None,
        "repairs_attempted": int(data.get("planned_repair_count") or 0) if data else 0,
        "repairs_successful": int(data.get("executed_repair_count") or 0) if data else 0,
        "repairs_blocked": int(data.get("blocked_repair_count") or 0) if data else 0,
    }


def command_is_allowlisted(cmd: List[str]) -> bool:
    return cmd in ALLOWED_KERNEL_COMMANDS.values()


def run_kernel_command(kind: str, timeout: int = KERNEL_TIMEOUT_SECONDS) -> Dict[str, Any]:
    cmd = ALLOWED_KERNEL_COMMANDS[kind]
    if not command_is_allowlisted(cmd):
        return {"returncode": None, "ok": False, "kind": kind, "error": "command_not_allowlisted"}
    if cmd[1] != "sentinel_self_governing_safe_autonomy_kernel.py":
        return {"returncode": None, "ok": False, "kind": kind, "error": "kernel_file_not_exact"}
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
        return {
            "kind": kind,
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout_lines": len([ln for ln in (proc.stdout or "").splitlines() if ln.strip()]),
            "stderr": redact_text(proc.stderr, max_len=1000),
        }
    except subprocess.TimeoutExpired:
        return {"kind": kind, "ok": False, "returncode": None, "timeout": True, "stderr": "timeout"}
    except (OSError, subprocess.SubprocessError) as exc:
        return {"kind": kind, "ok": False, "returncode": None, "stderr": redact_text(exc, max_len=500)}


def process_is_active(pid: Any) -> bool:
    try:
        pid_int = int(pid)
    except Exception:
        return False
    if pid_int <= 0:
        return False
    return (Path("/proc") / str(pid_int)).exists()


def lock_state(max_cycles: int) -> Tuple[bool, Dict[str, Any]]:
    if not LOCKFILE.exists():
        return True, {"lock_status": "clear"}
    data, status = read_json(LOCKFILE)
    if status != "ok" or not isinstance(data, dict):
        return False, {"lock_status": "collision", "reason": "lock_invalid_json"}
    started = parse_utc(str(data.get("started_at") or ""))
    stale = bool(started and (datetime.now(timezone.utc) - started).total_seconds() > LOCK_STALE_SECONDS)
    active = process_is_active(data.get("pid"))
    if stale and not active:
        LOCKFILE.unlink(missing_ok=True)
        append_lock_history({"event": "stale_lock_removed", "previous_lock": data, "max_cycles": max_cycles})
        return True, {"lock_status": "stale_removed", "previous_lock": data}
    return False, {"lock_status": "collision", "reason": "active_or_not_safely_stale", "existing_lock": data}


def acquire_lock(max_cycles: int) -> Tuple[bool, Dict[str, Any]]:
    ok, status = lock_state(max_cycles)
    if not ok:
        append_lock_history({"event": "lock_collision", **status, "max_cycles": max_cycles})
        return False, status
    data = {
        "pid": os.getpid(),
        "started_at": utc_now(),
        "runner_id": str(uuid.uuid4()),
        "max_cycles": max_cycles,
        "status": "running",
    }
    write_json(LOCKFILE, data)
    append_lock_history({"event": "lock_acquired", "lock": data})
    return True, {"lock_status": "acquired", "lock": data}


def release_lock(status: str) -> Dict[str, Any]:
    data, read_status = read_json(LOCKFILE)
    if read_status == "ok" and isinstance(data, dict) and data.get("pid") == os.getpid():
        event = {"event": "lock_released", "finished_at": utc_now(), "status": status, "lock": data}
        LOCKFILE.unlink(missing_ok=True)
        append_lock_history(event)
        return {"lock_status": "released", "event": event}
    event = {"event": "lock_release_skipped", "finished_at": utc_now(), "status": status, "read_status": read_status}
    append_lock_history(event)
    return {"lock_status": "release_skipped", "event": event}


def append_lock_history(event: Dict[str, Any]) -> None:
    history = load_list(LOCK_HISTORY_JSON)
    history.append({"timestamp_utc": utc_now(), **event})
    write_json(LOCK_HISTORY_JSON, history[-200:])


def kernel_report() -> Tuple[Dict[str, Any], str]:
    data, status = read_json(KERNEL_JSON)
    return (data if status == "ok" and isinstance(data, dict) else {}), status


def public_asset_findings() -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    files: List[Path] = []
    for pattern in PUBLIC_ASSET_GLOBS:
        files.extend(PROJECT_DIR.glob(pattern))
    for path in sorted(set(files)):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        reasons = []
        if INTERNAL_PATH_RE.search(text):
            reasons.append("internal_server_path")
        if IP_RE.search(text):
            reasons.append("private_or_local_ip")
        if SECRET_RE.search(text) or TOKEN_FORMAT_RE.search(text) or PRIVATE_KEY_RE.search(text):
            reasons.append("secret_like_content")
        if CUSTOMER_DATA_RE.search(text):
            reasons.append("customer_data_marker")
        if reasons:
            findings.append({"path": rel(path), "reasons": ",".join(reasons)})
    return findings


def scan_output_files(paths: Iterable[Path]) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    for path in sorted(set(paths)):
        if not path.exists() or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        reasons = []
        if SECRET_RE.search(text) or TOKEN_FORMAT_RE.search(text) or PRIVATE_KEY_RE.search(text):
            reasons.append("secret_or_private_key")
        if FORBIDDEN_ACTION_RE.search(text):
            reasons.append("forbidden_action_pattern")
        if CUSTOMER_DATA_RE.search(text):
            reasons.append("customer_data_marker")
        if reasons:
            findings.append({"path": rel(path), "reasons": ",".join(sorted(set(reasons)))})
    return findings


def critical_json_status() -> Dict[str, str]:
    paths = [
        KERNEL_JSON,
        KERNEL_LATEST_JSON,
        STATE_JSON,
        LATEST_JSON,
        HISTORY_JSON,
        LOCK_HISTORY_JSON,
        STOP_PATTERNS_JSON,
    ]
    return {rel(path): read_json(path)[1] for path in paths if path.exists()}


def safety_from_kernel(data: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "live_apply": data.get("live_apply", False),
        "emergency_stop": data.get("emergency_stop", True),
        "allowed_apply_now": data.get("allowed_apply_now", False),
        "high_blocked": data.get("high_blocked", True),
        "high_risk_blocked": data.get("high_risk_blocked", True),
        "low_live_executable": data.get("low_live_executable", False),
        "breach": data.get("breach", False),
        "network_access": data.get("network_access", False),
        "uploads_anything": data.get("uploads_anything", False),
    }


def preflight_checks(run_kernel_self_test: bool = True) -> Dict[str, Any]:
    dirs = [PROJECT_DIR / "reports/latest", PROJECT_DIR / "state/adaptive-learning", PROJECT_DIR / "audit", PROJECT_DIR / "playbooks"]
    for directory in dirs:
        directory.mkdir(parents=True, exist_ok=True)
    kernel_data, kernel_status = kernel_report()
    lock_ok, lock_info = lock_state(DEFAULT_CYCLES)
    json_status = critical_json_status()
    invalid_json = [path for path, status in json_status.items() if status == "invalid_json"]
    public_findings = public_asset_findings()
    kernel_self = run_kernel_command("self-test", timeout=KERNEL_TIMEOUT_SECONDS) if run_kernel_self_test else {"ok": True, "skipped": True}
    safety = safety_from_kernel(kernel_data)
    reasons: List[str] = []
    if not KERNEL_FILE.exists():
        reasons.append("kernel_file_missing")
    if not kernel_self.get("ok"):
        reasons.append("kernel_self_test_failed")
    if not lock_ok:
        reasons.append(STOP_ON_LOCK_COLLISION)
    if invalid_json:
        reasons.append(STOP_ON_INVALID_JSON)
    if public_findings:
        reasons.append("public_asset_violation")
    if safety.get("breach") is True:
        reasons.append("last_kernel_breach_true")
    if safety.get("live_apply") is not False or safety.get("allowed_apply_now") is not False:
        reasons.append(STOP_ON_LIVE_APPLY_ATTEMPT)
    if safety.get("high_blocked") is not True or safety.get("high_risk_blocked") is not True:
        reasons.append("high_not_blocked")
    return {
        "status": STATUS_PREFLIGHT_OK if not reasons else STATUS_BLOCKED_SAFETY,
        "ok": not reasons,
        "timestamp_utc": utc_now(),
        "kernel_file_exists": KERNEL_FILE.exists(),
        "kernel_json_status": kernel_status,
        "kernel_self_test": kernel_self,
        "directories_ok": all(d.exists() and d.is_dir() for d in dirs),
        "lock": lock_info,
        "last_safety": safety,
        "critical_json_status": json_status,
        "invalid_json": invalid_json,
        "public_asset_findings": public_findings,
        "live_apply": False,
        "emergency_stop": True,
        "allowed_apply_now": False,
        "high_blocked": True,
        "breach": bool(reasons),
        "reasons": reasons,
    }


def cycle_result(cycle_index: int, started_at: str, finished_at: str, proc: Dict[str, Any], data: Dict[str, Any], status: str) -> Dict[str, Any]:
    decision = data.get("decision") if isinstance(data.get("decision"), dict) else {}
    classification = data.get("classification") if isinstance(data.get("classification"), dict) else {}
    execution = data.get("execution") if isinstance(data.get("execution"), dict) else {}
    validation = data.get("validation") if isinstance(data.get("validation"), dict) else {}
    repair = data.get("repair") if isinstance(data.get("repair"), dict) else {}
    learning = data.get("learning") if isinstance(data.get("learning"), dict) else {}
    owner = data.get("owner_summary") if isinstance(data.get("owner_summary"), dict) else {}
    priority = data.get("priority_engine_integration") if isinstance(data.get("priority_engine_integration"), dict) else {}
    capability = data.get("capability_registry_integration") if isinstance(data.get("capability_registry_integration"), dict) else {}
    governor = data.get("capability_health_governor_integration") if isinstance(data.get("capability_health_governor_integration"), dict) else {}
    decision_priority = decision.get("priority_engine") if isinstance(decision.get("priority_engine"), dict) else {}
    generated = list(classification.get("expected_outputs") or owner.get("what_was_created") or [])
    useful = list(learning.get("useful_outputs") or [])
    blocked = list(classification.get("forbidden_actions") or owner.get("what_stays_forbidden") or [])
    return {
        "cycle_index": cycle_index,
        "started_at": started_at,
        "finished_at": finished_at,
        "kernel_returncode": proc.get("returncode"),
        "kernel_json_status": status,
        "selected_task": decision.get("selected_task"),
        "task_risk_class": classification.get("risk_class"),
        "execution_status": execution.get("status"),
        "execution_executed": execution.get("executed"),
        "validation_status": validation.get("status"),
        "repair_status": repair.get("status"),
        "repair_repaired": repair.get("repaired"),
        "learning_status": "learned" if learning else "missing",
        "next_suggested_task": data.get("next_suggested_task") or learning.get("next_suggested_task"),
        "selected_capability": capability.get("selected_capability"),
        "capability_status": capability.get("capability_health"),
        "capability_risk": capability.get("capability_risk"),
        "capability_freshness": capability.get("capability_freshness"),
        "capability_health_before": governor.get("before_health"),
        "capability_health_after": governor.get("after_health"),
        "repairs_attempted": governor.get("repairs_attempted"),
        "repairs_successful": governor.get("repairs_successful"),
        "repairs_blocked": governor.get("repairs_blocked"),
        "capability_cooldown_respected": priority.get("cooldown_respected") if "cooldown_respected" in priority else decision_priority.get("cooldown_respected"),
        "breach": bool(data.get("breach")),
        "stop_reason": None,
        "generated_outputs": generated,
        "useful_outputs": useful,
        "blocked_actions": blocked,
        "priority_engine": {
            "used": bool(priority.get("used") or decision_priority.get("used")),
            "status": priority.get("status") or decision.get("priority_model_status"),
            "anti_loop_status": priority.get("anti_loop_status") or decision_priority.get("anti_loop_status"),
            "diversity_status": priority.get("diversity_status") or decision_priority.get("diversity_status"),
            "cooldown_respected": priority.get("cooldown_respected") if "cooldown_respected" in priority else decision_priority.get("cooldown_respected"),
            "dynamic_selection_status": decision_priority.get("dynamic_selection_status"),
        },
        "live_apply": data.get("live_apply", False),
        "allowed_apply_now": data.get("allowed_apply_now", False),
        "high_blocked": data.get("high_blocked", True),
        "low_live_executable": data.get("low_live_executable", False),
        "network_access": data.get("network_access", False),
        "uploads_anything": data.get("uploads_anything", False),
    }


def evaluate_cycle_stop(result: Dict[str, Any], task_counts: Dict[str, int]) -> Optional[str]:
    if result.get("kernel_returncode") != 0:
        return STOP_ON_KERNEL_FAILURE
    if result.get("kernel_json_status") != "ok":
        return STOP_ON_INVALID_JSON
    if result.get("breach") is True:
        return STOP_ON_BREACH
    if result.get("live_apply") is not False or result.get("allowed_apply_now") is not False:
        return STOP_ON_LIVE_APPLY_ATTEMPT
    if result.get("network_access") is True or result.get("uploads_anything") is True:
        return STOP_ON_UNSAFE_SCOPE
    if result.get("task_risk_class") in {"HIGH", "MEDIUM", "LOW_LIVE"} and result.get("execution_executed") is True:
        return STOP_ON_UNSAFE_SCOPE
    if result.get("low_live_executable") is True or result.get("high_blocked") is not True:
        return STOP_ON_UNSAFE_SCOPE
    task = result.get("selected_task")
    if not task or task == "halt_and_report" or not result.get("next_suggested_task"):
        return STOP_ON_NO_SAFE_TASK
    if task_counts.get(str(task), 0) >= 4 and not priority_allows_repeat(task):
        return STOP_ON_REPEATED_TASK_LOOP
    generated_paths = [PROJECT_DIR / p for p in result.get("generated_outputs", []) if isinstance(p, str)]
    useful_paths = [PROJECT_DIR / p for p in result.get("useful_outputs", []) if isinstance(p, str)]
    if scan_output_files(generated_paths + useful_paths):
        return STOP_ON_FORBIDDEN_PATTERN
    return None


def run_cycles(max_cycles: int, run_once: bool = False) -> Dict[str, Any]:
    if max_cycles > MAX_CYCLES:
        report = base_report("run-cycles", STATUS_BLOCKED_LOOP_LIMIT)
        report.update({
            "requested_cycles": max_cycles,
            "cycles_completed": 0,
            "cycle_results": [],
            "stop_reason": "BLOCKED_LOOP_LIMIT",
            "owner_summary_status": "written",
            "breach": False,
        })
        write_all(report)
        return report
    preflight = preflight_checks(run_kernel_self_test=True)
    if not preflight["ok"]:
        report = base_report("run-once" if run_once else "run-cycles", STATUS_BLOCKED_SAFETY)
        report.update({
            "requested_cycles": max_cycles,
            "cycles_completed": 0,
            "cycle_results": [],
            "preflight": preflight,
            "stop_reason": preflight["reasons"][0] if preflight["reasons"] else STATUS_BLOCKED_SAFETY,
            "breach": True,
        })
        write_all(report)
        return report
    lock_ok, lock_info = acquire_lock(max_cycles)
    if not lock_ok:
        report = base_report("run-once" if run_once else "run-cycles", STATUS_BLOCKED_SAFETY)
        report.update({
            "requested_cycles": max_cycles,
            "cycles_completed": 0,
            "cycle_results": [],
            "preflight": preflight,
            "lock": lock_info,
            "stop_reason": STOP_ON_LOCK_COLLISION,
            "breach": True,
        })
        write_all(report)
        return report

    cycles: List[Dict[str, Any]] = []
    task_counts: Dict[str, int] = {}
    stop_reason = STOP_COMPLETED_RUN_ONCE if run_once else STOP_ON_MAX_CYCLES
    status = STATUS_RUN_OK
    try:
        limit = 1 if run_once else max_cycles
        for idx in range(1, limit + 1):
            started = utc_now()
            proc = run_kernel_command("cycle", timeout=KERNEL_TIMEOUT_SECONDS)
            finished = utc_now()
            data, json_status = kernel_report()
            result = cycle_result(idx, started, finished, proc, data, json_status)
            task = str(result.get("selected_task") or "")
            task_counts[task] = task_counts.get(task, 0) + 1
            cycle_stop = evaluate_cycle_stop(result, task_counts)
            result["task_diversity"] = task_diversity_stats(cycles + [result])
            if not cycle_stop and result["task_diversity"].get("status") == STOP_ON_NO_DIVERSE_SAFE_TASK:
                cycle_stop = STOP_ON_NO_DIVERSE_SAFE_TASK
            result["stop_reason"] = cycle_stop
            cycles.append(result)
            append_jsonl(AUDIT_JSONL, [{"timestamp_utc": utc_now(), "event": "cycle", "cycle": result}])
            if cycle_stop:
                stop_reason = cycle_stop
                if cycle_stop not in {STOP_ON_MAX_CYCLES, STOP_COMPLETED_RUN_ONCE,
                                      STOP_ON_NO_DIVERSE_SAFE_TASK}:
                    status = STATUS_BLOCKED_SAFETY
                break
        else:
            stop_reason = STOP_COMPLETED_RUN_ONCE if run_once else STOP_ON_MAX_CYCLES
    finally:
        lock_release = release_lock(status)

    report = base_report("run-once" if run_once else "run-cycles", status)
    governor_summary = health_governor_summary()
    report.update({
        "requested_cycles": max_cycles,
        "cycles_completed": len(cycles),
        "cycle_results": cycles,
        "preflight": preflight,
        "lock": lock_info,
        "lock_release": lock_release,
        "stop_reason": stop_reason,
        "selected_tasks": [c.get("selected_task") for c in cycles],
        "task_diversity": task_diversity_stats(cycles),
        "selected_capabilities": [c.get("selected_capability") for c in cycles if c.get("selected_capability")],
        "capability_diversity": capability_diversity_stats(cycles),
        "capability_health_before": governor_summary.get("capability_health_before"),
        "capability_health_after": governor_summary.get("capability_health_after"),
        "repairs_attempted": governor_summary.get("repairs_attempted"),
        "repairs_successful": governor_summary.get("repairs_successful"),
        "repairs_blocked": governor_summary.get("repairs_blocked"),
        "health_governor": governor_summary,
        "anti_loop_status": task_diversity_stats(cycles).get("anti_loop_status"),
        "next_best_task": task_diversity_stats(cycles).get("next_best_task"),
        "validation_status": STATUS_VALIDATION_OK if status == STATUS_RUN_OK else STATUS_VALIDATION_FAILED,
        "breach": status == STATUS_BLOCKED_SAFETY,
    })
    write_all(report)
    return report


def base_report(action: str, status: str) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "timestamp_utc": utc_now(),
        "action": action,
        "status": status,
        "doctrine": "automatisch autonom sicher kontrolliert automatisch autonom",
        "live_apply": False,
        "emergency_stop": True,
        "allowed_apply_now": False,
        "high_blocked": True,
        "high_risk_blocked": True,
        "low_live_executable": False,
        "medium_executable": False,
        "breach": False,
    }


def validate_run() -> Dict[str, Any]:
    report = load_dict(LATEST_JSON)
    expected_json = [
        REPORT_JSON,
        STATE_JSON,
        LATEST_JSON,
        HISTORY_JSON,
        LOCK_HISTORY_JSON,
        STOP_PATTERNS_JSON,
        PLAYBOOK_RUNNER,
        PLAYBOOK_STOP,
        PLAYBOOK_LOCKING,
        PLAYBOOK_OWNER,
        KERNEL_JSON,
    ]
    json_status = {rel(path): read_json(path)[1] for path in expected_json}
    invalid = [path for path, status in json_status.items() if status != "ok"]
    output_paths = [
        REPORT_MD,
        PREFLIGHT_MD,
        LOG_MD,
        VALIDATION_MD,
        OWNER_SUMMARY_MD,
        STOP_REASON_MD,
        NEXT_STEP_MD,
        STATE_JSON,
        LATEST_JSON,
        HISTORY_JSON,
        LOCK_HISTORY_JSON,
        STOP_PATTERNS_JSON,
        AUDIT_JSONL,
        PLAYBOOK_RUNNER,
        PLAYBOOK_STOP,
        PLAYBOOK_LOCKING,
        PLAYBOOK_OWNER,
    ]
    findings = scan_output_files(output_paths) + public_asset_findings()
    source = Path(__file__).read_text(encoding="utf-8")
    source_findings = source_safety_findings(source)
    kernel = load_dict(KERNEL_JSON)
    safety = safety_from_kernel(kernel)
    reasons: List[str] = []
    if invalid:
        reasons.append(STOP_ON_INVALID_JSON)
    if findings:
        reasons.append(STOP_ON_FORBIDDEN_PATTERN)
    if source_findings:
        reasons.append("runner_source_safety_findings")
    if safety.get("live_apply") is not False or safety.get("allowed_apply_now") is not False:
        reasons.append(STOP_ON_LIVE_APPLY_ATTEMPT)
    if safety.get("high_blocked") is not True or safety.get("high_risk_blocked") is not True:
        reasons.append("high_not_blocked")
    if safety.get("breach") is True:
        reasons.append(STOP_ON_BREACH)
    validation = {
        "timestamp_utc": utc_now(),
        "status": STATUS_VALIDATION_OK if not reasons else STATUS_VALIDATION_FAILED,
        "all_runner_json_valid": not invalid,
        "kernel_json_valid": json_status.get(rel(KERNEL_JSON)) == "ok",
        "json_status": json_status,
        "invalid_json": invalid,
        "forbidden_findings": findings,
        "source_safety_findings": source_findings,
        "live_apply": False,
        "allowed_apply_now": False,
        "high_blocked": True,
        "breach": bool(reasons),
        "reasons": reasons,
        "cycles_completed": report.get("cycles_completed", 0),
        "stop_reason": report.get("stop_reason"),
    }
    current = base_report("validate-run", validation["status"])
    current.update(report)
    current["validation"] = validation
    current["validation_status"] = validation["status"]
    current["breach"] = bool(reasons)
    write_all(current)
    return current


def source_safety_findings(source: str) -> List[str]:
    findings: List[str] = []
    if FORBIDDEN_IMPORT_RE.search(source):
        findings.append("network_import")
    for literal in [
        "shell" + "=True",
        "apt " + "install",
        "pip " + "install",
        "npm " + "install",
        "systemctl " + "enable",
        "systemctl " + "start",
        "crontab " + "install",
        "rm " + "-rf",
        "pk" + "ill",
        "kill" + "all",
    ]:
        if literal in source:
            findings.append(f"forbidden_literal:{literal}")
    remote_write_tokens = ["." + "put(", "." + "remove(", "." + "rename("]
    if any(token in source for token in remote_write_tokens):
        findings.append("remote_write_method_pattern")
    return sorted(set(findings))


def build_owner_summary() -> Dict[str, Any]:
    report = load_dict(LATEST_JSON)
    if not report:
        report = base_report("build-owner-summary", STATUS_FAILED)
        report.update({"cycles_completed": 0, "cycle_results": [], "stop_reason": "no_run_available", "breach": True})
    else:
        report["action"] = "build-owner-summary"
        report["owner_summary_status"] = "written"
    write_all(report)
    return report


def status_report() -> Dict[str, Any]:
    report = load_dict(LATEST_JSON)
    if not report:
        report = base_report("status", "NO_RUN_AVAILABLE")
    return report


def write_all(report: Dict[str, Any]) -> None:
    write_json(REPORT_JSON, report)
    write_json(STATE_JSON, report)
    write_json(LATEST_JSON, report)
    history = load_list(HISTORY_JSON)
    history.append({
        "timestamp_utc": utc_now(),
        "action": report.get("action"),
        "status": report.get("status"),
        "cycles_completed": report.get("cycles_completed", 0),
        "selected_tasks": report.get("selected_tasks", []),
        "selected_capabilities": report.get("selected_capabilities", []),
        "task_diversity": report.get("task_diversity", {}),
        "capability_diversity": report.get("capability_diversity", {}),
        "stop_reason": report.get("stop_reason"),
        "breach": report.get("breach"),
    })
    write_json(HISTORY_JSON, history[-200:])
    write_json(STOP_PATTERNS_JSON, stop_patterns_data(report))
    write_playbooks()
    write_markdown_outputs(report)
    append_jsonl(AUDIT_JSONL, [{"timestamp_utc": utc_now(), "event": report.get("action"), "status": report.get("status"), "stop_reason": report.get("stop_reason"), "breach": report.get("breach")}])


def stop_patterns_data(report: Dict[str, Any]) -> Dict[str, Any]:
    stops = [
        STOP_ON_BREACH,
        STOP_ON_FORBIDDEN_PATTERN,
        STOP_ON_KERNEL_FAILURE,
        STOP_ON_REPEATED_TASK_LOOP,
        STOP_ON_NO_DIVERSE_SAFE_TASK,
        STOP_ON_NO_SAFE_TASK,
        STOP_ON_MAX_CYCLES,
        STOP_ON_LOCK_COLLISION,
        STOP_ON_INVALID_JSON,
        STOP_ON_UNSAFE_SCOPE,
        STOP_ON_LIVE_APPLY_ATTEMPT,
    ]
    return {
        "timestamp_utc": utc_now(),
        "known_stop_reasons": stops,
        "last_stop_reason": report.get("stop_reason"),
        "last_status": report.get("status"),
        "repeated_task_threshold": 4,
        "diversity_rule": "at least 2 unique main tasks in 3 cycles when safe alternatives exist",
        "max_cycles": MAX_CYCLES,
    }


def write_playbooks() -> None:
    common = {
        "phase": "10.1",
        "live_apply": False,
        "emergency_stop": True,
        "allowed_apply_now": False,
        "high_blocked": True,
        "kernel_allowlist": ALLOWED_KERNEL_COMMANDS,
        "max_cycles": MAX_CYCLES,
        "priority_model_path": rel(PRIORITY_MODEL_JSON),
    }
    write_json(PLAYBOOK_RUNNER, {
        **common,
        "name": "sentinel-autonomous-cycle-runner",
        "purpose": "Run multiple safe local kernel cycles with validation and learning after each cycle.",
        "allowed_actions": ["kernel_self_test", "kernel_cycle", "kernel_status", "local_reports", "local_state", "local_audit", "local_playbooks"],
        "blocked_actions": ["live_apply", "network", "email", "external_api", "wordpress", "cloudflare", "db", "sftp", "systemd", "cron", "customer_data"],
        "priority_engine_integration": "read model only; kernel still enforces allowlist and risk classification",
    })
    write_json(PLAYBOOK_STOP, {
        **common,
        "name": "sentinel-autonomous-cycle-stop-rules",
        "stop_reasons": stop_patterns_data({})["known_stop_reasons"],
    })
    write_json(PLAYBOOK_LOCKING, {
        **common,
        "name": "sentinel-autonomous-cycle-locking",
        "lockfile": rel(LOCKFILE),
        "stale_after_hours": 6,
        "active_process_check": "proc_pid_exists",
        "dangerous_process_actions": "never",
    })
    write_json(PLAYBOOK_OWNER, {
        **common,
        "name": "sentinel-autonomous-cycle-owner-summary",
        "summary_fields": ["cycles_completed", "selected_tasks", "selected_capabilities", "task_diversity", "capability_diversity", "repeated_task_count", "cooldown_respected", "anti_loop_status", "next_best_task", "validated", "repair", "learning", "stop_reason", "next_safe_step", "blocked_capabilities"],
    })


def write_markdown_outputs(report: Dict[str, Any]) -> None:
    cycles = report.get("cycle_results") or []
    preflight = report.get("preflight") or {}
    validation = report.get("validation") or {}
    write_text(REPORT_MD, render_report_md(report))
    write_text(PREFLIGHT_MD, render_preflight_md(preflight if preflight else report))
    write_text(LOG_MD, render_log_md(report))
    write_text(VALIDATION_MD, render_validation_md(validation if validation else report))
    write_text(OWNER_SUMMARY_MD, render_owner_summary_md(report))
    write_text(STOP_REASON_MD, f"# Stop Reason\n\n- stop_reason: `{report.get('stop_reason', '-')}`\n- status: `{report.get('status')}`\n- cycles_completed: `{len(cycles)}`\n")
    write_text(NEXT_STEP_MD, render_next_step_md(report))


def render_report_md(report: Dict[str, Any]) -> str:
    lines = [
        "# Sentinel Autonomous Cycle Runner",
        "",
        f"- status: `{report.get('status')}`",
        f"- action: `{report.get('action')}`",
        f"- cycles_completed: `{report.get('cycles_completed', 0)}`",
        f"- stop_reason: `{report.get('stop_reason', '-')}`",
        f"- task_diversity: `{(report.get('task_diversity') or {}).get('status', '-')}`",
        f"- capability_diversity: `{(report.get('capability_diversity') or {}).get('status', '-')}`",
        f"- unique_task_count: `{(report.get('task_diversity') or {}).get('unique_task_count', '-')}`",
        f"- anti_loop_status: `{report.get('anti_loop_status', '-')}`",
        f"- live_apply: `{report.get('live_apply')}`",
        f"- emergency_stop: `{report.get('emergency_stop')}`",
        f"- allowed_apply_now: `{report.get('allowed_apply_now')}`",
        f"- HIGH blocked: `{report.get('high_blocked')}`",
        f"- breach: `{report.get('breach')}`",
        "",
        "The runner executes only exact allowlisted local kernel commands and never installs timers, sends mail, uses external APIs, or performs live apply.",
    ]
    return "\n".join(lines) + "\n"


def render_preflight_md(preflight: Dict[str, Any]) -> str:
    lines = [
        "# Autonomous Cycle Preflight",
        "",
        f"- status: `{preflight.get('status')}`",
        f"- ok: `{preflight.get('ok', preflight.get('status') == STATUS_PREFLIGHT_OK)}`",
        f"- kernel_file_exists: `{preflight.get('kernel_file_exists', '-')}`",
        f"- directories_ok: `{preflight.get('directories_ok', '-')}`",
        f"- lock: `{(preflight.get('lock') or {}).get('lock_status', '-')}`",
        f"- reasons: `{', '.join(preflight.get('reasons', [])) or '-'}`",
    ]
    return "\n".join(lines) + "\n"


def render_log_md(report: Dict[str, Any]) -> str:
    lines = ["# Autonomous Cycle Log", ""]
    for cycle in report.get("cycle_results") or []:
        lines.extend([
            f"## Cycle {cycle.get('cycle_index')}",
            f"- selected_task: `{cycle.get('selected_task')}`",
            f"- risk: `{cycle.get('task_risk_class')}`",
            f"- execution: `{cycle.get('execution_status')}`",
            f"- validation: `{cycle.get('validation_status')}`",
            f"- repair: `{cycle.get('repair_status')}`",
            f"- learning: `{cycle.get('learning_status')}`",
            f"- next_suggested_task: `{cycle.get('next_suggested_task')}`",
            f"- priority_engine: `{(cycle.get('priority_engine') or {}).get('status', '-')}`",
            f"- selected_capability: `{cycle.get('selected_capability', '-')}`",
            f"- capability_status: `{cycle.get('capability_status', '-')}`",
            f"- diversity: `{(cycle.get('task_diversity') or {}).get('status', '-')}`",
            f"- breach: `{cycle.get('breach')}`",
            "",
        ])
    if not report.get("cycle_results"):
        lines.append("- no cycles recorded")
    return "\n".join(lines) + "\n"


def render_validation_md(validation: Dict[str, Any]) -> str:
    return "\n".join([
        "# Autonomous Cycle Validation",
        "",
        f"- status: `{validation.get('status') or validation.get('validation_status')}`",
        f"- all_runner_json_valid: `{validation.get('all_runner_json_valid', '-')}`",
        f"- kernel_json_valid: `{validation.get('kernel_json_valid', '-')}`",
        f"- breach: `{validation.get('breach')}`",
        f"- reasons: `{', '.join(validation.get('reasons', [])) or '-'}`",
    ]) + "\n"


def render_owner_summary_md(report: Dict[str, Any]) -> str:
    cycles = report.get("cycle_results") or []
    selected_tasks = [str(c.get("selected_task")) for c in cycles]
    selected_capabilities = [str(c.get("selected_capability")) for c in cycles if c.get("selected_capability")]
    executed = [f"{c.get('selected_task')} ({c.get('execution_status')})" for c in cycles]
    repaired = [f"{c.get('selected_task')} ({c.get('repair_status')})" for c in cycles]
    learned = [str(c.get("next_suggested_task")) for c in cycles if c.get("next_suggested_task")]
    diversity = report.get("task_diversity") or {}
    capability_diversity = report.get("capability_diversity") or {}
    lines = [
        "# Autonomous Cycle Owner Summary",
        "",
        f"- cycles_liefen: `{len(cycles)}`",
        f"- selected_tasks: `{', '.join(selected_tasks) or '-'}`",
        f"- selected_capabilities: `{', '.join(selected_capabilities) or '-'}`",
        f"- task_diversity: `{diversity.get('status', '-')}`",
        f"- capability_diversity: `{capability_diversity.get('status', '-')}`",
        f"- unique_capability_count: `{capability_diversity.get('unique_capability_count', '-')}`",
        f"- capability_health_before: `{report.get('capability_health_before', '-')}`",
        f"- capability_health_after: `{report.get('capability_health_after', '-')}`",
        f"- repairs_attempted: `{report.get('repairs_attempted', 0)}`",
        f"- repairs_successful: `{report.get('repairs_successful', 0)}`",
        f"- repairs_blocked: `{report.get('repairs_blocked', 0)}`",
        f"- unique_task_count: `{diversity.get('unique_task_count', '-')}`",
        f"- repeated_task_count: `{diversity.get('repeated_task_count', '-')}`",
        f"- cooldown_respected: `{diversity.get('cooldown_respected', '-')}`",
        f"- anti_loop_status: `{diversity.get('anti_loop_status', '-')}`",
        f"- next_best_task: `{diversity.get('next_best_task', '-')}`",
        f"- ausgeführt: `{', '.join(executed) or '-'}`",
        f"- validiert: `{', '.join(str(c.get('validation_status')) for c in cycles) or '-'}`",
        f"- repariert: `{', '.join(repaired) or '-'}`",
        f"- gelernt: `{', '.join(learned) or '-'}`",
        f"- stop_reason: `{report.get('stop_reason', '-')}`",
        f"- next_safe_step: `{next_safe_step(report)}`",
        f"- live_apply: `{report.get('live_apply')}`",
        f"- emergency_stop: `{report.get('emergency_stop')}`",
        f"- allowed_apply_now: `{report.get('allowed_apply_now')}`",
        f"- HIGH blocked: `{report.get('high_blocked')}`",
        f"- breach: `{report.get('breach')}`",
        "",
        "Weiterhin blockiert: Live-Apply, Netzwerk, E-Mail, externe APIs, WordPress, Cloudflare, Datenbank, SFTP, Nginx, .htaccess, Timer, Cron, Kundendaten und HIGH/MEDIUM/LOW_LIVE-Ausführung.",
    ]
    return "\n".join(lines) + "\n"


def next_safe_step(report: Dict[str, Any]) -> str:
    cycles = report.get("cycle_results") or []
    if not cycles:
        return "Run preflight, then one safe local cycle."
    last = cycles[-1]
    if report.get("breach"):
        return "Stop and review safety finding before any further cycle."
    if report.get("stop_reason") == STOP_ON_MAX_CYCLES:
        return "Review owner summary; next run may repeat controlled local cycles if still needed."
    if report.get("stop_reason") == STOP_ON_NO_DIVERSE_SAFE_TASK:
        return "Review priority model; no additional diverse safe task was available in this run."
    return str(last.get("next_suggested_task") or "Review owner summary.")


def render_next_step_md(report: Dict[str, Any]) -> str:
    return "\n".join([
        "# Autonomous Cycle Next Step",
        "",
        f"- recommended_next_safe_step: {next_safe_step(report)}",
        f"- stop_reason: `{report.get('stop_reason', '-')}`",
        "- Any further action remains inside the same local safe autonomy boundaries.",
    ]) + "\n"


def print_summary(report: Dict[str, Any]) -> None:
    print(f"status={report.get('status')}")
    print(f"action={report.get('action')}")
    print(f"cycles_completed={report.get('cycles_completed', 0)}")
    print(f"selected_tasks={','.join(str(x) for x in report.get('selected_tasks', [])) or '-'}")
    print(f"selected_capabilities={','.join(str(x) for x in report.get('selected_capabilities', [])) or '-'}")
    diversity = report.get("task_diversity") or {}
    cap_diversity = report.get("capability_diversity") or {}
    print(f"task_diversity={diversity.get('status', '-')}")
    print(f"capability_diversity={cap_diversity.get('status', '-')}")
    print(f"unique_task_count={diversity.get('unique_task_count', '-')}")
    print(f"anti_loop_status={report.get('anti_loop_status', '-')}")
    print(f"stop_reason={report.get('stop_reason', '-')}")
    print(f"validation_status={report.get('validation_status', (report.get('validation') or {}).get('status', '-'))}")
    print(f"lockfile_exists={LOCKFILE.exists()}")
    print(f"live_apply={report.get('live_apply')}")
    print(f"emergency_stop={report.get('emergency_stop')}")
    print(f"allowed_apply_now={report.get('allowed_apply_now')}")
    print(f"high_blocked={report.get('high_blocked')}")
    print(f"breach={report.get('breach')}")


def action_preflight() -> Dict[str, Any]:
    preflight = preflight_checks(run_kernel_self_test=True)
    report = base_report("preflight", preflight["status"])
    report.update({
        "preflight": preflight,
        "cycles_completed": 0,
        "cycle_results": [],
        "stop_reason": None if preflight["ok"] else (preflight["reasons"][0] if preflight["reasons"] else STATUS_BLOCKED_SAFETY),
        "validation_status": STATUS_VALIDATION_OK if preflight["ok"] else STATUS_VALIDATION_FAILED,
        "breach": not preflight["ok"],
    })
    write_all(report)
    return report


def action_self_test() -> Dict[str, Any]:
    failures: List[str] = []
    parser = build_parser()
    if "--apply" in parser.format_help():
        failures.append("apply_mode_present")
    source = Path(__file__).read_text(encoding="utf-8")
    failures.extend(source_safety_findings(source))
    for cmd in ALLOWED_KERNEL_COMMANDS.values():
        if not command_is_allowlisted(cmd):
            failures.append("allowlist_command_rejected")
        if cmd[0] != "python3" or cmd[1] != "sentinel_self_governing_safe_autonomy_kernel.py" or cmd[2] not in {"--self-test", "--cycle", "--status"}:
            failures.append("unexpected_kernel_command")
    if MAX_CYCLES > 5:
        failures.append("max_cycles_too_high")
    if HARD_DEFAULTS["emergency_stop"] is not True or HARD_DEFAULTS["live_apply"] is not False:
        failures.append("hard_defaults_invalid")
    if STOP_ON_NO_DIVERSE_SAFE_TASK not in stop_patterns_data({})["known_stop_reasons"]:
        failures.append("no_diverse_stop_reason_missing")
    fake_cycles = [
        {"selected_task": "generate_next_safe_actions"},
        {"selected_task": "check_public_asset_safety"},
        {"selected_task": "check_missing_inputs"},
    ]
    if task_diversity_stats(fake_cycles)["unique_task_count"] < 2:
        failures.append("diversity_stats_failed")
    fake_cap_cycles = [
        {"selected_capability": "autonomy_kernel"},
        {"selected_capability": "public_client_assets"},
        {"selected_capability": "autonomy_kernel"},
    ]
    if capability_diversity_stats(fake_cap_cycles)["unique_capability_count"] < 2:
        failures.append("capability_diversity_stats_failed")
    for path in [REPORT_JSON, STATE_JSON, AUDIT_JSONL, PLAYBOOK_RUNNER]:
        try:
            assert_allowed_write(path)
        except Exception as exc:
            failures.append(f"output_root_invalid:{exc}")
    test_json = json.dumps({"ok": True})
    try:
        json.loads(test_json)
    except json.JSONDecodeError:
        failures.append("json_invalid")
    status = "AUTONOMOUS_CYCLE_SELF_TEST_OK" if not failures else "AUTONOMOUS_CYCLE_SELF_TEST_FAILED"
    report = base_report("self-test", status)
    report.update({"self_test_failures": failures, "cycles_completed": 0, "cycle_results": [], "breach": bool(failures), "validation_status": STATUS_VALIDATION_OK if not failures else STATUS_VALIDATION_FAILED})
    write_all(report)
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Sentinel Autonomous Cycle Runner.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--preflight", action="store_true")
    group.add_argument("--run-once", action="store_true")
    group.add_argument("--run-cycles", type=int, metavar="N")
    group.add_argument("--validate-run", action="store_true")
    group.add_argument("--build-owner-summary", action="store_true")
    group.add_argument("--status", action="store_true")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.self_test:
            report = action_self_test()
        elif args.preflight:
            report = action_preflight()
        elif args.run_once:
            report = run_cycles(1, run_once=True)
        elif args.run_cycles is not None:
            report = run_cycles(args.run_cycles, run_once=False)
        elif args.validate_run:
            report = validate_run()
        elif args.build_owner_summary:
            report = build_owner_summary()
        elif args.status:
            report = status_report()
        else:
            raise AssertionError("unreachable")
        print_summary(report)
        return 0 if not report.get("breach") else 2
    except Exception as exc:
        report = base_report("failed", STATUS_FAILED)
        report.update({"error": redact_text(exc, max_len=500), "breach": True, "cycles_completed": 0, "cycle_results": [], "stop_reason": STATUS_FAILED})
        try:
            write_all(report)
        except Exception:
            pass
        print_summary(report)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
