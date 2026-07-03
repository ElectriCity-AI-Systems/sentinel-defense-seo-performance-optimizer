#!/usr/bin/env python3
"""Sentinel Autonomous Goal Manager (Phase 10.5).

Local-only mission queue and goal routing for Sentinel's controlled autonomy
stack. The manager discovers safe missions, scores them, routes them to known
capabilities and can execute at most one safe local mission step. It never
performs live apply, network access, remote writes, timer installation,
customer-system changes, or HIGH/MEDIUM/LOW_LIVE execution.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


PROJECT_DIR = Path("/srv/sentinel-defense")
SCHEMA_VERSION = "sentinel-autonomous-goal-manager-10.5"
PHASE = "10.5"
MAX_AGE_HOURS = 24.0

READ_ONLY = "READ_ONLY"
DRAFT = "DRAFT"
LOW_LOCAL = "LOW_LOCAL"
LOW_EXPORT = "LOW_EXPORT"
LOW_STATE = "LOW_STATE"
LOW_LIVE = "LOW_LIVE"
MEDIUM = "MEDIUM"
HIGH = "HIGH"

AUTO_ALLOWED_RISK = {READ_ONLY, DRAFT, LOW_LOCAL, LOW_EXPORT, LOW_STATE}
BLOCKED_RISK = {LOW_LIVE, MEDIUM, HIGH}

MISSION_TYPES = [
    "maintain_capability_health",
    "keep_payhip_upload_pack_ready",
    "keep_payhip_launch_qa_ready",
    "keep_fulfillment_board_ready",
    "keep_first_order_dryrun_ready",
    "maintain_service_proof",
    "maintain_public_client_assets",
    "maintain_owner_summary",
    "monitor_website_warning_readiness",
    "monitor_sourcemap_warning",
    "monitor_ai_radio_timeout_decay",
    "maintain_priority_model",
    "maintain_capability_registry",
    "maintain_learning_state",
    "generate_git_checkpoint_suggestion",
    "generate_next_safe_actions",
]

MISSION_STATUSES = {
    "DISCOVERED",
    "QUEUED",
    "ROUTED",
    "EXECUTABLE_SAFE_LOCAL",
    "EXECUTED_SAFE_STEP",
    "VALIDATED",
    "COMPLETED",
    "BLOCKED_MISSING_INPUT",
    "BLOCKED_BY_RISK",
    "BLOCKED_BY_EMERGENCY_STOP",
    "OWNER_REVIEW_REQUIRED",
    "MONITOR_ONLY",
    "FAILED_SAFE",
}

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
EXPORT_DIR = PROJECT_DIR / "exports/payhip-upload-pack"
EXPORT_LATEST_DIR = EXPORT_DIR / "latest"

REPORT_JSON = R / "sentinel-autonomous-goal-manager.json"
REPORT_MD = R / "sentinel-autonomous-goal-manager.md"
MISSION_QUEUE_MD = R / "sentinel-autonomous-mission-queue.md"
MISSION_ROUTING_MD = R / "sentinel-autonomous-mission-routing.md"
MISSION_EXECUTION_MD = R / "sentinel-autonomous-mission-execution.md"
MISSION_VALIDATION_MD = R / "sentinel-autonomous-mission-validation.md"
MISSION_LEARNING_MD = R / "sentinel-autonomous-mission-learning.md"
OWNER_SUMMARY_MD = R / "sentinel-autonomous-mission-owner-summary.md"
NEXT_MISSION_MD = R / "sentinel-autonomous-next-mission.md"

STATE_JSON = STATE_DIR / "autonomous_goal_manager.json"
LATEST_JSON = STATE_DIR / "latest_autonomous_goal_manager.json"
MISSION_QUEUE_JSON = STATE_DIR / "autonomous_mission_queue.json"
MISSION_HISTORY_JSON = STATE_DIR / "autonomous_mission_history.json"
MISSION_PATTERNS_JSON = STATE_DIR / "autonomous_mission_patterns.json"
BLOCKED_MISSION_PATTERNS_JSON = STATE_DIR / "autonomous_blocked_mission_patterns.json"
MISSION_LEDGER_JSON = STATE_DIR / "autonomous_mission_completion_ledger.json"
MISSION_RUNNER_JSON = STATE_DIR / "latest_autonomous_mission_queue_runner.json"
SUPERVISOR_JSON = STATE_DIR / "latest_autonomous_operations_supervisor.json"
OPERATION_GOVERNOR_JSON = STATE_DIR / "latest_autonomous_operation_governor.json"
SOAK_TEST_JSON = STATE_DIR / "latest_autonomous_soak_test.json"

AUDIT_JSONL = AUDIT_DIR / "sentinel-autonomous-goal-manager.jsonl"

PLAYBOOK_GOAL_MANAGER = PLAYBOOK_DIR / "sentinel-autonomous-goal-manager.playbook.json"
PLAYBOOK_QUEUE = PLAYBOOK_DIR / "sentinel-autonomous-mission-queue.playbook.json"
PLAYBOOK_ROUTING = PLAYBOOK_DIR / "sentinel-autonomous-mission-routing.playbook.json"
PLAYBOOK_VALIDATION = PLAYBOOK_DIR / "sentinel-autonomous-mission-validation.playbook.json"

CAPABILITY_REGISTRY_JSON = STATE_DIR / "autonomous_capability_registry.json"
HEALTH_GOVERNOR_JSON = STATE_DIR / "autonomous_capability_health_governor.json"
LATEST_HEALTH_GOVERNOR_JSON = STATE_DIR / "latest_autonomous_capability_health_governor.json"
PRIORITY_MODEL_JSON = STATE_DIR / "autonomy_task_priority_model.json"
CYCLE_RUNNER_HISTORY_JSON = STATE_DIR / "autonomous_cycle_runner_history.json"
KERNEL_JSON = R / "sentinel-self-governing-autonomy-kernel.json"
RUNNER_JSON = R / "sentinel-autonomous-cycle-runner.json"
PRIORITY_JSON = R / "sentinel-autonomous-priority-engine.json"
REGISTRY_REPORT_JSON = R / "sentinel-autonomous-capability-registry.json"
HEALTH_GOVERNOR_REPORT_JSON = R / "sentinel-autonomous-capability-health-governor.json"

ALLOWED_WRITE_ROOTS = (
    R,
    STATE_DIR,
    AUDIT_DIR,
    PLAYBOOK_DIR,
)

ALLOWED_MODULES = {
    "sentinel_autonomous_capability_health_governor.py",
    "sentinel_autonomous_capability_registry.py",
    "sentinel_autonomous_priority_engine.py",
    "sentinel_self_governing_safe_autonomy_kernel.py",
    "sentinel_autonomous_cycle_runner.py",
    "sentinel_payhip_upload_pack_export_helper.py",
    "sentinel_payhip_launch_qa_finalizer.py",
    "sentinel_payhip_fulfillment_board.py",
    "sentinel_payhip_first_order_dryrun.py",
    "sentinel_service_proof_trend.py",
    "sentinel_payhip_public_client_assets.py",
    "sentinel_payhip_customer_intake_delivery.py",
    "sentinel_owner_dashboard_service_packaging.py",
}

ALLOWED_ARGS = {
    "--self-test",
    "--cycle",
    "--status",
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
    "--scan-health",
    "--classify-warnings",
    "--plan-repairs",
    "--execute-safe-repairs",
    "--validate-repairs",
    "--learn",
    "--build-export",
    "--build-copy-fields",
    "--build-upload-checklist",
    "--build-zip",
    "--scan-upload-pack",
    "--validate-fields",
    "--build-launch-console",
    "--build-final-checklist",
    "--build-board",
    "--build-case-template",
    "--build-delivery-checklists",
    "--build-risk-review",
    "--build-completion-pack",
    "--build-dummy-case",
    "--simulate-intake",
    "--simulate-package-workflows",
    "--build-sample-report",
    "--build-delivery-pack",
    "--collect-proof",
    "--analyze-decay",
    "--build-client-summary",
    "--build-payhip-proof",
    "--build-product-file",
    "--build-public-assets",
    "--build-descriptions",
    "--build-faq",
    "--build-pdf-source",
    "--build-intake",
    "--build-delivery-workflow",
    "--build-message-templates",
    "--build-client-pack",
    "--build-dashboard",
    "--build-service-packages",
    "--build-owner-next-actions",
    "--build-roadmap",
}

MISSION_EXECUTION: Dict[str, Tuple[str, List[str]]] = {
    "maintain_capability_health": ("sentinel_autonomous_capability_health_governor.py", ["--cycle"]),
    "keep_payhip_upload_pack_ready": ("sentinel_payhip_upload_pack_export_helper.py", ["--build-export"]),
    "keep_payhip_launch_qa_ready": ("sentinel_payhip_launch_qa_finalizer.py", ["--scan-upload-pack"]),
    "keep_fulfillment_board_ready": ("sentinel_payhip_fulfillment_board.py", ["--build-board"]),
    "keep_first_order_dryrun_ready": ("sentinel_payhip_first_order_dryrun.py", ["--status"]),
    "maintain_service_proof": ("sentinel_service_proof_trend.py", ["--status"]),
    "maintain_public_client_assets": ("sentinel_payhip_public_client_assets.py", ["--build-public-assets"]),
    "maintain_owner_summary": ("sentinel_owner_dashboard_service_packaging.py", ["--build-dashboard"]),
    "maintain_priority_model": ("sentinel_autonomous_priority_engine.py", ["--score-tasks"]),
    "maintain_capability_registry": ("sentinel_autonomous_capability_registry.py", ["--evaluate-capabilities"]),
    "maintain_learning_state": ("sentinel_self_governing_safe_autonomy_kernel.py", ["--cycle"]),
}

MISSION_ROUTING = {
    "maintain_capability_health": ("capability_health_governor", "repair_capability_health_warning"),
    "keep_payhip_upload_pack_ready": ("payhip_upload_pack_export", "rebuild_payhip_upload_pack"),
    "keep_payhip_launch_qa_ready": ("payhip_launch_qa", "rerun_payhip_launch_qa"),
    "keep_fulfillment_board_ready": ("payhip_fulfillment_board", "update_fulfillment_board"),
    "keep_first_order_dryrun_ready": ("first_order_dryrun", "run_first_order_dryrun"),
    "maintain_service_proof": ("service_proof_trend", "update_service_proof"),
    "maintain_public_client_assets": ("public_client_assets", "check_public_asset_safety"),
    "maintain_owner_summary": ("owner_dashboard_service_packaging", "update_owner_summary"),
    "monitor_website_warning_readiness": ("autonomy_kernel", "observe_project_state"),
    "monitor_sourcemap_warning": ("autonomy_kernel", "observe_project_state"),
    "monitor_ai_radio_timeout_decay": ("autonomy_kernel", "observe_project_state"),
    "maintain_priority_model": ("priority_engine", "generate_next_safe_actions"),
    "maintain_capability_registry": ("capability_registry", "generate_next_safe_actions"),
    "maintain_learning_state": ("autonomy_kernel", "update_learning_state"),
    "generate_git_checkpoint_suggestion": ("priority_engine", "generate_git_checkpoint_suggestion"),
    "generate_next_safe_actions": ("autonomy_kernel", "generate_next_safe_actions"),
}

MISSION_META = {
    "maintain_capability_health": (LOW_STATE, 28, 45, 26),
    "keep_payhip_upload_pack_ready": (LOW_EXPORT, 42, 26, 18),
    "keep_payhip_launch_qa_ready": (LOW_STATE, 34, 28, 16),
    "keep_fulfillment_board_ready": (LOW_STATE, 30, 24, 16),
    "keep_first_order_dryrun_ready": (LOW_STATE, 28, 22, 18),
    "maintain_service_proof": (LOW_STATE, 27, 24, 20),
    "maintain_public_client_assets": (LOW_STATE, 32, 30, 20),
    "maintain_owner_summary": (LOW_STATE, 24, 24, 15),
    "monitor_website_warning_readiness": (READ_ONLY, 20, 34, 16),
    "monitor_sourcemap_warning": (READ_ONLY, 16, 26, 14),
    "monitor_ai_radio_timeout_decay": (READ_ONLY, 18, 28, 14),
    "maintain_priority_model": (LOW_STATE, 24, 32, 28),
    "maintain_capability_registry": (LOW_STATE, 25, 34, 26),
    "maintain_learning_state": (LOW_STATE, 18, 30, 30),
    "generate_git_checkpoint_suggestion": (DRAFT, 14, 18, 12),
    "generate_next_safe_actions": (DRAFT, 12, 20, 18),
}

MISSION_OUTPUTS = {
    "maintain_capability_health": ["reports/latest/sentinel-autonomous-capability-health-governor.json"],
    "keep_payhip_upload_pack_ready": [
        "reports/latest/sentinel-payhip-upload-pack-export.json",
        "exports/payhip-upload-pack/latest/MANIFEST.json",
        "exports/payhip-upload-pack/latest/CHECKSUMS.sha256",
    ],
    "keep_payhip_launch_qa_ready": ["reports/latest/sentinel-payhip-launch-qa.json"],
    "keep_fulfillment_board_ready": ["reports/latest/sentinel-payhip-fulfillment-board.json"],
    "keep_first_order_dryrun_ready": ["reports/latest/sentinel-payhip-first-order-dryrun.json"],
    "maintain_service_proof": ["reports/latest/sentinel-service-proof.json"],
    "maintain_public_client_assets": [
        "reports/latest/sentinel-payhip-public-intake-form.md",
        "reports/latest/sentinel-payhip-public-safety-agreement.md",
        "reports/latest/sentinel-payhip-public-service-overview.md",
    ],
    "maintain_owner_summary": ["reports/latest/sentinel-owner-dashboard.json"],
    "monitor_website_warning_readiness": ["reports/latest/sentinel-autonomous-mission-owner-summary.md"],
    "monitor_sourcemap_warning": ["reports/latest/sentinel-autonomous-mission-owner-summary.md"],
    "monitor_ai_radio_timeout_decay": ["reports/latest/sentinel-autonomous-mission-owner-summary.md"],
    "maintain_priority_model": ["reports/latest/sentinel-autonomous-priority-engine.json", "state/adaptive-learning/autonomy_task_priority_model.json"],
    "maintain_capability_registry": ["reports/latest/sentinel-autonomous-capability-registry.json", "state/adaptive-learning/autonomous_capability_registry.json"],
    "maintain_learning_state": ["state/adaptive-learning/autonomy_task_memory.json"],
    "generate_git_checkpoint_suggestion": ["reports/latest/sentinel-autonomy-git-checkpoint-suggestion.md"],
    "generate_next_safe_actions": ["reports/latest/sentinel-autonomy-next-cycle.md"],
}

MONITOR_ONLY = {
    "monitor_website_warning_readiness",
    "monitor_sourcemap_warning",
    "monitor_ai_radio_timeout_decay",
}

SECRET_RE = re.compile(
    r"(?i)(?:password|passwd|secret|token|api[_-]?key|authorization|bearer)\s*[:=]\s*['\"]?"
    r"(?!false\b|true\b|null\b|none\b|not_applied\b|<redacted\b)[A-Za-z0-9+/=_.:-]{8,}"
)
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:OPENSSH|RSA|DSA|EC) PRIVATE KEY-----")
TOKEN_FORMAT_RE = re.compile(
    r"\b(?:sk-(?:proj-)?[A-Za-z0-9_-]{24,}|ghp_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,})\b"
)
FORBIDDEN_IMPORT_RE = re.compile(
    r"(?m)^\s*(?:import|from)\s+(?:requests|urllib|http\.client|smtplib|socket|paramiko|cloudflare)\b"
)
CUSTOMER_DATA_RE = re.compile(r"(?i)\b(customer_password|customer_token|customer_api_key|real_customer|kundenzugang)\b")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


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
    if path.suffix.lower() not in {".json", ".jsonl", ".md"}:
        raise ValueError(f"unsupported output suffix refused: {rel(path)}")


def redact_text(value: Any, max_len: int = 3000) -> str:
    text = "" if value is None else str(value)
    text = SECRET_RE.sub(lambda m: m.group(0).split("=", 1)[0].split(":", 1)[0] + "=<redacted>", text)
    text = PRIVATE_KEY_RE.sub("<redacted-private-key-marker>", text)
    text = TOKEN_FORMAT_RE.sub("<redacted-token>", text)
    return text if len(text) <= max_len else text[: max_len - 3] + "..."


def secret_like(text: str) -> bool:
    return bool(SECRET_RE.search(text) or PRIVATE_KEY_RE.search(text) or TOKEN_FORMAT_RE.search(text))


def assert_safe_blob(path: Path, text: str) -> None:
    if secret_like(text):
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


def load_dict(path: Path) -> Dict[str, Any]:
    data, status = read_json(path)
    return data if status == "ok" and isinstance(data, dict) else {}


def load_list(path: Path) -> List[Any]:
    data, status = read_json(path)
    return data if status == "ok" and isinstance(data, list) else []


def file_age_hours(path: Path) -> Optional[float]:
    try:
        return round((datetime.now(timezone.utc).timestamp() - path.stat().st_mtime) / 3600.0, 3)
    except OSError:
        return None


def output_status(paths: List[str]) -> Dict[str, Any]:
    missing: List[str] = []
    stale: List[str] = []
    invalid_json: List[str] = []
    fresh: List[str] = []
    ages: List[float] = []
    for value in paths:
        path = PROJECT_DIR / value
        if not path.exists():
            missing.append(value)
            continue
        age = file_age_hours(path)
        if age is not None:
            ages.append(age)
            if age > MAX_AGE_HOURS:
                stale.append(value)
            else:
                fresh.append(value)
        if path.suffix == ".json" and read_json(path)[1] != "ok":
            invalid_json.append(value)
    return {
        "missing": missing,
        "stale": stale,
        "invalid_json": invalid_json,
        "fresh": fresh,
        "oldest_age_hours": round(max(ages), 3) if ages else None,
    }


def module_arg_allowed(module: str, args: List[str]) -> bool:
    return module in ALLOWED_MODULES and all(arg in ALLOWED_ARGS for arg in args)


def run_allowlisted_module(module: str, args: List[str], timeout: int = 180) -> Dict[str, Any]:
    if not module_arg_allowed(module, args):
        return {"status": "blocked_not_allowlisted", "module": module, "args": args, "returncode": None}
    module_path = PROJECT_DIR / module
    if not module_path.exists():
        return {"status": "blocked_missing_module", "module": module, "args": args, "returncode": None}
    try:
        proc = subprocess.run(
            [sys.executable, str(module_path), *args],
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
        return {"status": "error", "module": module, "args": args, "returncode": None, "stderr": redact_text(exc, 500)}
    return {
        "status": "executed" if proc.returncode == 0 else "failed",
        "module": module,
        "args": args,
        "returncode": proc.returncode,
        "stdout_lines": len([ln for ln in (proc.stdout or "").splitlines() if ln.strip()]),
        "stderr": redact_text(proc.stderr, 1000),
    }


def read_inputs() -> Dict[str, Any]:
    paths = [
        CAPABILITY_REGISTRY_JSON,
        HEALTH_GOVERNOR_JSON,
        LATEST_HEALTH_GOVERNOR_JSON,
        PRIORITY_MODEL_JSON,
        CYCLE_RUNNER_HISTORY_JSON,
        MISSION_LEDGER_JSON,
        MISSION_RUNNER_JSON,
        HEALTH_GOVERNOR_REPORT_JSON,
        REGISTRY_REPORT_JSON,
        PRIORITY_JSON,
        RUNNER_JSON,
        KERNEL_JSON,
    ]
    statuses: Dict[str, str] = {}
    missing: List[str] = []
    for path in paths:
        _, status = read_json(path)
        statuses[rel(path)] = status
        if status == "missing":
            missing.append(rel(path))
    return {
        "timestamp_utc": utc_now(),
        "input_status": statuses,
        "missing_inputs": missing,
        "registry": load_dict(CAPABILITY_REGISTRY_JSON) or load_dict(REGISTRY_REPORT_JSON),
        "health_governor": load_dict(LATEST_HEALTH_GOVERNOR_JSON) or load_dict(HEALTH_GOVERNOR_JSON) or load_dict(HEALTH_GOVERNOR_REPORT_JSON),
        "priority": load_dict(PRIORITY_MODEL_JSON) or load_dict(PRIORITY_JSON),
        "runner": load_dict(RUNNER_JSON),
        "mission_runner": load_dict(MISSION_RUNNER_JSON),
        "mission_ledger": load_dict(MISSION_LEDGER_JSON),
        "kernel": load_dict(KERNEL_JSON),
    }


def mission_id(mission_type: str) -> str:
    return f"MISSION-{mission_type.upper().replace('-', '_')}"


def normalize_completion_ledger(raw: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        raw = {}
    entries = raw.get("entries") if isinstance(raw.get("entries"), list) else []
    by_mission = raw.get("by_mission") if isinstance(raw.get("by_mission"), dict) else {}
    for key, value in raw.items():
        if key in {"schema_version", "updated_at", "entries", "by_mission", "completed_count", "live_apply", "emergency_stop", "allowed_apply_now", "high_blocked", "low_live_executable", "medium_executable", "breach"}:
            continue
        if isinstance(value, dict) and key in MISSION_TYPES:
            by_mission.setdefault(key, value)
            if not any(isinstance(item, dict) and item.get("mission_type") == key for item in entries):
                entries.append({
                    "mission_id": mission_id(key),
                    "mission_type": key,
                    "completed_at": value.get("last_completed_at"),
                    "completion_status": value.get("status", "COMPLETED"),
                    "validation_status": value.get("last_validation_status", "MISSION_VALIDATION_OK"),
                    "linked_capability": MISSION_ROUTING.get(key, ["unknown", "unknown"])[0],
                    "linked_task": MISSION_ROUTING.get(key, ["unknown", "unknown"])[1],
                })
    return {
        "schema_version": raw.get("schema_version", "sentinel-autonomous-mission-ledger-10.6"),
        "updated_at": raw.get("updated_at"),
        "entries": entries[-500:],
        "by_mission": by_mission,
        "completed_count": int(raw.get("completed_count") or len(entries)),
        **HARD_DEFAULTS,
    }


def mission_ledger_summary(inputs: Dict[str, Any], mission_type: str) -> Dict[str, Any]:
    ledger = normalize_completion_ledger(inputs.get("mission_ledger") if isinstance(inputs.get("mission_ledger"), dict) else {})
    by_mission = ledger.get("by_mission") if isinstance(ledger.get("by_mission"), dict) else {}
    info = by_mission.get(mission_type) if isinstance(by_mission.get(mission_type), dict) else {}
    completed_at = info.get("last_completed_at") or info.get("completed_at")
    age_hours = None
    if completed_at:
        try:
            dt = datetime.fromisoformat(str(completed_at).replace("Z", "+00:00"))
            age_hours = max(0.0, (datetime.now(timezone.utc) - dt).total_seconds() / 3600.0)
        except ValueError:
            age_hours = None
    return {
        "completed": bool(info),
        "last_completed_at": completed_at,
        "completion_status": info.get("status") or info.get("completion_status"),
        "validation_status": info.get("last_validation_status") or info.get("validation_status"),
        "age_hours": round(age_hours, 3) if age_hours is not None else None,
        "fresh_from_runner": bool(info) and (age_hours is None or age_hours < MAX_AGE_HOURS),
    }


def mission_runner_summary() -> Dict[str, Any]:
    runner = load_dict(MISSION_RUNNER_JSON)
    ledger = normalize_completion_ledger(load_dict(MISSION_LEDGER_JSON))
    return {
        "state_path": "state/adaptive-learning/latest_autonomous_mission_queue_runner.json",
        "available": bool(runner),
        "last_mission_runner_status": runner.get("status") if runner else "not_available",
        "completed_mission_count": int(ledger.get("completed_count") or 0),
        "stop_reason": runner.get("stop_reason") if runner else None,
        "next_recommended_mission": runner.get("next_recommended_mission") if runner else None,
    }


def supervisor_summary() -> Dict[str, Any]:
    supervisor = load_dict(SUPERVISOR_JSON)
    return {
        "state_path": "state/adaptive-learning/latest_autonomous_operations_supervisor.json",
        "available": bool(supervisor),
        "operation_context": supervisor.get("action") if supervisor else None,
        "active_operation_type": supervisor.get("selected_operation") if supervisor else None,
        "completed_operation_count": int(supervisor.get("operations_completed") or 0) if supervisor else 0,
        "last_supervisor_status": supervisor.get("status") if supervisor else "not_available",
    }


def operation_governor_summary() -> Dict[str, Any]:
    governor = load_dict(OPERATION_GOVERNOR_JSON)
    return {
        "state_path": "state/adaptive-learning/latest_autonomous_operation_governor.json",
        "available": bool(governor),
        "status": governor.get("status") if governor else "not_available",
        "selected_operation": governor.get("selected_operation_name") if governor else None,
        "cooldown_status": governor.get("cooldown_status") if governor else None,
    }


def soak_context_summary() -> Dict[str, Any]:
    soak = load_dict(SOAK_TEST_JSON)
    return {
        "state_path": "state/adaptive-learning/latest_autonomous_soak_test.json",
        "available": bool(soak),
        "status": soak.get("status") if soak else "not_available",
        "readiness_seal": soak.get("readiness_seal") if soak else None,
        "completed_missions_during_soak": soak.get("soak_steps_completed") if soak else 0,
    }


def mission_scope(risk: str) -> List[str]:
    scope = ["reports/latest", "state/adaptive-learning", "audit", "playbooks"]
    if risk == LOW_EXPORT:
        scope.append("exports/payhip-upload-pack")
    return scope


def path_scope_allowed(paths: List[str], risk: str) -> bool:
    roots = [R, STATE_DIR, AUDIT_DIR, PLAYBOOK_DIR]
    if risk == LOW_EXPORT:
        roots.append(EXPORT_DIR)
    for value in paths:
        path = PROJECT_DIR / value
        if not any(is_within(path, root) for root in roots):
            return False
    return True


def mission_base(mission_type: str, inputs: Dict[str, Any]) -> Dict[str, Any]:
    risk, business, safety, learning = MISSION_META[mission_type]
    capability, task = MISSION_ROUTING[mission_type]
    outputs = MISSION_OUTPUTS[mission_type]
    status = output_status(outputs)
    health = inputs.get("health_governor") if isinstance(inputs.get("health_governor"), dict) else {}
    priority = inputs.get("priority") if isinstance(inputs.get("priority"), dict) else {}
    runner = inputs.get("runner") if isinstance(inputs.get("runner"), dict) else {}
    kernel = inputs.get("kernel") if isinstance(inputs.get("kernel"), dict) else {}
    ledger_info = mission_ledger_summary(inputs, mission_type)

    missing_output_score = min(60, len(status["missing"]) * 18 + len(status["invalid_json"]) * 30)
    warning_score = 0
    repair_score = 0
    repetition_penalty = 0
    trigger = "scheduled_safe_autonomy"
    if mission_type == "maintain_capability_health":
        warning_count = int(health.get("warning_count") or 0)
        warning_score = min(70, warning_count * 20)
        repair_score = 35 if warning_count else 0
        trigger = "capability_health_governor"
    elif status["stale"]:
        warning_score = min(40, len(status["stale"]) * 12)
        trigger = "stale_output"
    elif status["missing"]:
        trigger = "missing_output"
    if mission_type == "maintain_priority_model" and priority.get("status") not in {"PRIORITY_TASKS_SCORED", "PRIORITY_MODEL_READY"}:
        warning_score += 20
    if mission_type == "monitor_website_warning_readiness":
        site_status = str(kernel.get("status") or runner.get("status") or "")
        if "WARNING" in site_status or "CRITICAL" in site_status:
            warning_score += 18
    if mission_type == "generate_git_checkpoint_suggestion":
        git_info = kernel.get("git_checkpoint") if isinstance(kernel.get("git_checkpoint"), dict) else {}
        if git_info.get("recommended"):
            warning_score += 20
            trigger = "git_changes_present"
    if ledger_info.get("fresh_from_runner"):
        repetition_penalty = 42
        trigger = "recently_completed_mission"

    freshness = 100
    if status["missing"]:
        freshness = 20
    elif status["invalid_json"]:
        freshness = 10
    elif status["stale"]:
        freshness = 55
    elif status["oldest_age_hours"] is not None and status["oldest_age_hours"] > 12:
        freshness = 80

    urgency = min(85, missing_output_score + warning_score + repair_score + max(0, 100 - freshness) // 3)
    blocked_penalty = 0
    reason_if_blocked = None
    completion = "COMPLETE_FRESH" if not status["missing"] and not status["stale"] and not status["invalid_json"] else "NEEDS_ATTENTION"
    mission_status = "DISCOVERED"
    if mission_type in MONITOR_ONLY:
        mission_status = "MONITOR_ONLY"
        completion = "MONITORING"
    if risk in BLOCKED_RISK:
        blocked_penalty += 1000
        mission_status = "BLOCKED_BY_RISK"
        reason_if_blocked = f"risk {risk} is not autonomous"
    if not path_scope_allowed(outputs, risk):
        blocked_penalty += 900
        mission_status = "FAILED_SAFE"
        reason_if_blocked = "output scope outside allowed local roots"

    priority_score = (
        urgency
        + business
        + safety
        + learning
        + missing_output_score
        + warning_score
        + repair_score
        + max(0, 100 - freshness)
        - repetition_penalty
        - blocked_penalty
    )
    can_execute = (
        risk in AUTO_ALLOWED_RISK
        and mission_type not in MONITOR_ONLY
        and blocked_penalty == 0
        and path_scope_allowed(outputs, risk)
    )
    if mission_type in {"generate_git_checkpoint_suggestion", "generate_next_safe_actions"}:
        can_execute = True
    if mission_type in MONITOR_ONLY:
        can_execute = False
        reason_if_blocked = "monitor-only mission writes reports but does not execute changes"
    if completion == "COMPLETE_FRESH" and mission_type not in {"maintain_priority_model", "generate_git_checkpoint_suggestion", "generate_next_safe_actions"}:
        priority_score -= 15
    if ledger_info.get("fresh_from_runner") and mission_type not in {"repair_invalid_json_output", "repair_missing_public_asset"}:
        priority_score -= 25

    return {
        "mission_id": mission_id(mission_type),
        "mission_type": mission_type,
        "title": mission_type.replace("_", " ").title(),
        "objective": f"Keep {mission_type.replace('_', ' ')} safe, current and locally validated.",
        "trigger_source": trigger,
        "priority_score": int(priority_score),
        "business_value_score": business,
        "safety_value_score": safety,
        "learning_value_score": learning,
        "freshness_score": freshness,
        "urgency_score": urgency,
        "missing_output_score": missing_output_score,
        "warning_score": warning_score,
        "repair_score": repair_score,
        "blocked_penalty": blocked_penalty,
        "repetition_penalty": repetition_penalty,
        "risk_penalty": 0 if risk in AUTO_ALLOWED_RISK else 1000,
        "risk_class": risk,
        "allowed_scope": mission_scope(risk),
        "linked_capability": capability,
        "linked_tasks": [task],
        "input_paths": [],
        "output_paths": outputs,
        "expected_outputs": outputs,
        "required_guards": [
            "live_apply=false",
            "emergency_stop=true",
            "allowed_apply_now=false",
            "HIGH blocked=true",
            "LOW_LIVE executable=false",
            "MEDIUM executable=false",
            "no network",
            "no remote write",
            "hard module allowlist",
        ],
        "can_execute_autonomously": can_execute,
        "reason_if_blocked": reason_if_blocked,
        "status": mission_status,
        "last_run": None,
        "completion_status": completion,
        "validation_status": "not_validated",
        "next_step": "execute_safe_local_step" if can_execute else "monitor_or_owner_review",
        "output_status": status,
        "completion_ledger": ledger_info,
    }


def discover_goals() -> Dict[str, Any]:
    inputs = read_inputs()
    missions = [mission_base(mission_type, inputs) for mission_type in MISSION_TYPES]
    return {
        "timestamp_utc": utc_now(),
        "action": "discover-goals",
        "status": "GOAL_DISCOVERY_OK",
        "input_status": inputs.get("input_status"),
        "missing_inputs": inputs.get("missing_inputs"),
        "missions": missions,
        "discovered_goals": [m["mission_type"] for m in missions],
        "discovered_goal_count": len(missions),
        **HARD_DEFAULTS,
    }


def build_mission_queue(discovered: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    discovered = discovered or discover_goals()
    history = load_list(MISSION_HISTORY_JSON)
    recent = [str(item.get("mission_type")) for item in history[-8:] if isinstance(item, dict) and item.get("mission_type")]
    queued: List[Dict[str, Any]] = []
    for mission in discovered.get("missions") or []:
        mission = dict(mission)
        repeats = recent[-3:].count(mission["mission_type"])
        if repeats:
            mission["repetition_penalty"] = repeats * 18
            mission["priority_score"] -= mission["repetition_penalty"]
        if mission["risk_class"] in BLOCKED_RISK:
            mission["status"] = "BLOCKED_BY_RISK"
            mission["can_execute_autonomously"] = False
        elif mission["status"] == "DISCOVERED":
            mission["status"] = "QUEUED"
        queued.append(mission)
    queued.sort(key=lambda m: (int(m.get("can_execute_autonomously") is True), int(m.get("priority_score") or 0), m.get("mission_type")), reverse=True)
    return {
        **discovered,
        "action": "build-mission-queue",
        "status": "MISSION_QUEUE_READY",
        "mission_queue": queued,
        "mission_queue_count": len(queued),
        "top_missions": queued[:5],
    }


def classify_missions(queue: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    queue = queue or build_mission_queue()
    classified: List[Dict[str, Any]] = []
    for mission in queue.get("mission_queue") or []:
        mission = dict(mission)
        if mission["risk_class"] in BLOCKED_RISK:
            mission["status"] = "BLOCKED_BY_RISK"
            mission["can_execute_autonomously"] = False
            mission["reason_if_blocked"] = f"{mission['risk_class']} is never automatic"
        elif mission["mission_type"] in MONITOR_ONLY:
            mission["status"] = "MONITOR_ONLY"
            mission["can_execute_autonomously"] = False
        elif mission.get("can_execute_autonomously"):
            mission["status"] = "EXECUTABLE_SAFE_LOCAL"
        classified.append(mission)
    return {
        **queue,
        "action": "classify-missions",
        "status": "MISSION_CLASSIFICATION_OK",
        "classified_missions": classified,
        "blocked_missions": [m for m in classified if str(m.get("status", "")).startswith("BLOCKED")],
        "executable_mission_count": sum(1 for m in classified if m.get("can_execute_autonomously")),
    }


def route_missions(classified: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    classified = classified or classify_missions()
    missions = list(classified.get("classified_missions") or [])
    selected = next((m for m in missions if m.get("can_execute_autonomously")), None)
    routed = []
    for mission in missions:
        item = dict(mission)
        item["status"] = "ROUTED" if item.get("status") == "EXECUTABLE_SAFE_LOCAL" else item.get("status")
        routed.append(item)
    return {
        **classified,
        "action": "route-missions",
        "status": "MISSION_ROUTING_READY" if selected else "MISSION_ROUTING_MONITOR_ONLY",
        "routed_missions": routed,
        "selected_mission": selected,
        "selected_mission_type": selected.get("mission_type") if selected else None,
        "selected_capability": selected.get("linked_capability") if selected else None,
        "selected_task": (selected.get("linked_tasks") or [None])[0] if selected else None,
        "next_mission": selected.get("mission_type") if selected else "owner_review_or_monitor",
    }


def execute_safe_mission_step(routed: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    routed = routed or route_missions()
    selected = routed.get("selected_mission") if isinstance(routed.get("selected_mission"), dict) else None
    if not selected:
        return {
            **routed,
            "action": "execute-safe-mission-step",
            "status": "MISSION_EXECUTION_NO_SAFE_STEP",
            "execution": {"status": "not_executed", "reason": "no executable safe mission"},
            "executed_mission": None,
        }
    mission_type = str(selected.get("mission_type"))
    execution: Dict[str, Any]
    if mission_type in {"generate_git_checkpoint_suggestion", "generate_next_safe_actions"}:
        execution = {
            "status": "executed_internal_report_step",
            "module": None,
            "args": [],
            "returncode": 0,
            "detail": "mission represented in local goal-manager reports only",
        }
    elif mission_type in MISSION_EXECUTION:
        module, args = MISSION_EXECUTION[mission_type]
        execution = run_allowlisted_module(module, args)
    else:
        execution = {"status": "blocked_no_safe_executor", "module": None, "args": [], "returncode": None}

    executed_mission = dict(selected)
    if execution.get("status") in {"executed", "executed_internal_report_step"}:
        executed_mission["status"] = "EXECUTED_SAFE_STEP"
        executed_mission["completion_status"] = "SAFE_STEP_EXECUTED"
    else:
        executed_mission["status"] = "FAILED_SAFE"
        executed_mission["reason_if_blocked"] = execution.get("status")
    return {
        **routed,
        "action": "execute-safe-mission-step",
        "status": "MISSION_SAFE_STEP_EXECUTED" if executed_mission["status"] == "EXECUTED_SAFE_STEP" else "MISSION_SAFE_STEP_BLOCKED",
        "execution": execution,
        "executed_mission": executed_mission,
        "selected_mission": executed_mission,
    }


def validate_path(path_value: str) -> Dict[str, Any]:
    path = PROJECT_DIR / path_value
    status = "ok"
    reasons: List[str] = []
    if not path.exists():
        status = "missing"
        reasons.append("missing")
    elif path.suffix == ".json" and read_json(path)[1] != "ok":
        status = "invalid_json"
        reasons.append("invalid_json")
    elif path.suffix in {".md", ".txt", ".html"}:
        try:
            if path.stat().st_size == 0:
                status = "empty"
                reasons.append("empty")
        except OSError:
            status = "read_error"
            reasons.append("read_error")
    if path.exists():
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            if secret_like(text):
                status = "unsafe"
                reasons.append("secret_like_content")
            if CUSTOMER_DATA_RE.search(text):
                status = "unsafe"
                reasons.append("customer_data_marker")
        except UnicodeDecodeError:
            pass
        except OSError:
            status = "read_error"
            reasons.append("read_error")
    return {"path": path_value, "status": status, "reasons": reasons}


def validate_missions(executed: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    executed = executed or execute_safe_mission_step()
    selected = executed.get("executed_mission") if isinstance(executed.get("executed_mission"), dict) else None
    outputs = list((selected or {}).get("expected_outputs") or [])
    checks = [validate_path(path) for path in outputs]
    failed = [c for c in checks if c["status"] not in {"ok"}]
    validation_status = "MISSION_VALIDATION_OK" if not failed else "MISSION_VALIDATION_WARNINGS"
    completed_missions = []
    if selected and not failed and (executed.get("execution") or {}).get("status") in {"executed", "executed_internal_report_step"}:
        selected = dict(selected)
        selected["status"] = "VALIDATED"
        selected["validation_status"] = validation_status
        selected["completion_status"] = "COMPLETED"
        completed_missions.append(selected)
    return {
        **executed,
        "action": "validate-missions",
        "status": validation_status,
        "mission_validation_status": validation_status,
        "output_checks": checks,
        "failed_output_checks": failed,
        "completed_missions": completed_missions,
        "completed_mission_count": len(completed_missions),
        **HARD_DEFAULTS,
    }


def learn(validated: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    validated = validated or validate_missions()
    selected = validated.get("selected_mission") if isinstance(validated.get("selected_mission"), dict) else {}
    history = load_list(MISSION_HISTORY_JSON)
    patterns = load_dict(MISSION_PATTERNS_JSON)
    blocked = load_dict(BLOCKED_MISSION_PATTERNS_JSON)
    ledger = normalize_completion_ledger(load_dict(MISSION_LEDGER_JSON))
    ledger_entries = ledger.get("entries") if isinstance(ledger.get("entries"), list) else []
    ledger_by_mission = ledger.get("by_mission") if isinstance(ledger.get("by_mission"), dict) else {}
    now = utc_now()
    if selected:
        success = validated.get("mission_validation_status") == "MISSION_VALIDATION_OK"
        key = str(selected.get("mission_type"))
        ledger_entry = {
            "mission_id": selected.get("mission_id") or mission_id(key),
            "mission_type": key,
            "selected_at": selected.get("selected_at"),
            "executed_at": now,
            "completed_at": now if success else None,
            "status_before": selected.get("status"),
            "status_after": "COMPLETED" if success else selected.get("status"),
            "linked_capability": selected.get("linked_capability"),
            "linked_task": (selected.get("linked_tasks") or [None])[0],
            "execution_status": (validated.get("execution") or {}).get("status") if isinstance(validated.get("execution"), dict) else None,
            "validation_status": validated.get("mission_validation_status"),
            "learning_status": "MISSION_LEARNING_WRITTEN",
            "completion_status": "COMPLETED" if success else selected.get("completion_status"),
            "outputs_created": selected.get("expected_outputs"),
            "useful_outputs": selected.get("expected_outputs") if success else [],
            "blocked_reason": selected.get("reason_if_blocked"),
            "next_recommended_mission": validated.get("next_mission"),
        }
        history.append({
            "timestamp_utc": now,
            "mission_type": key,
            "linked_capability": selected.get("linked_capability"),
            "linked_task": (selected.get("linked_tasks") or [None])[0],
            "mission_success": success,
            "completion_status": selected.get("completion_status"),
            "blocked_reason": selected.get("reason_if_blocked"),
            "useful_outputs": selected.get("expected_outputs"),
        })
        if success:
            patterns[key] = int(patterns.get(key, 0)) + 1
            ledger_entries.append(ledger_entry)
            ledger_by_mission[key] = {
                "last_completed_at": now,
                "status": "COMPLETED",
                "last_validation_status": validated.get("mission_validation_status"),
                "linked_capability": selected.get("linked_capability"),
                "linked_task": (selected.get("linked_tasks") or [None])[0],
            }
        else:
            reason = str(selected.get("reason_if_blocked") or validated.get("status") or "unknown")
            blocked[reason] = int(blocked.get(reason, 0)) + 1
            ledger_entries.append(ledger_entry)
            ledger_by_mission[key] = {
                "last_completed_at": ledger_by_mission.get(key, {}).get("last_completed_at") if isinstance(ledger_by_mission.get(key), dict) else None,
                "status": "FAILED_SAFE",
                "last_validation_status": validated.get("mission_validation_status"),
                "blocked_reason": reason,
                "linked_capability": selected.get("linked_capability"),
                "linked_task": (selected.get("linked_tasks") or [None])[0],
            }
    ledger = {
        "schema_version": "sentinel-autonomous-mission-ledger-10.6",
        "updated_at": now,
        "entries": ledger_entries[-500:],
        "by_mission": ledger_by_mission,
        "completed_count": sum(1 for item in ledger_entries if isinstance(item, dict) and item.get("completion_status") == "COMPLETED"),
        **HARD_DEFAULTS,
    }
    write_json(MISSION_HISTORY_JSON, history[-300:])
    write_json(MISSION_PATTERNS_JSON, patterns)
    write_json(BLOCKED_MISSION_PATTERNS_JSON, blocked)
    write_json(MISSION_LEDGER_JSON, ledger)
    return {
        **validated,
        "action": "learn",
        "status": "MISSION_LEARNING_WRITTEN",
        "learning_updates": {
            "mission_patterns": patterns,
            "blocked_mission_patterns": blocked,
            "completion_ledger_count": int(ledger.get("completed_count") or 0),
        },
        "next_recommended_mission": validated.get("next_mission"),
        "not_stored": ["passwords", "tokens", "API keys", "private keys", "real customer data", "customer access data", "payment data"],
    }


def cycle() -> Dict[str, Any]:
    discovered = discover_goals()
    queue = build_mission_queue(discovered)
    classified = classify_missions(queue)
    routed = route_missions(classified)
    executed = execute_safe_mission_step(routed)
    validated = validate_missions(executed)
    learned = learn(validated)
    return {**learned, "action": "cycle"}


def write_playbooks(report: Dict[str, Any]) -> None:
    base = {
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        **HARD_DEFAULTS,
    }
    write_json(PLAYBOOK_GOAL_MANAGER, {
        **base,
        "name": "sentinel-autonomous-goal-manager",
        "purpose": "Discover goals, manage safe local mission queues and route one safe mission step.",
        "mission_types": MISSION_TYPES,
        "blocked_actions": ["live_apply", "network", "remote_write", "external_api", "timer_install", "HIGH_or_MEDIUM_execution"],
    })
    write_json(PLAYBOOK_QUEUE, {
        **base,
        "name": "sentinel-autonomous-mission-queue",
        "sorting": ["can_execute_autonomously", "priority_score", "mission_type"],
        "score_components": ["urgency", "business", "safety", "learning", "freshness", "missing_outputs", "warnings", "repair", "penalties"],
    })
    write_json(PLAYBOOK_ROUTING, {
        **base,
        "name": "sentinel-autonomous-mission-routing",
        "routing": MISSION_ROUTING,
        "subprocess_modules": sorted(ALLOWED_MODULES),
    })
    write_json(PLAYBOOK_VALIDATION, {
        **base,
        "name": "sentinel-autonomous-mission-validation",
        "checks": ["queue json valid", "mission status consistent", "expected outputs valid", "no secrets", "safe defaults unchanged"],
    })


def render_report_md(report: Dict[str, Any]) -> str:
    runner = report.get("mission_queue_runner") if isinstance(report.get("mission_queue_runner"), dict) else {}
    supervisor = report.get("operations_supervisor") if isinstance(report.get("operations_supervisor"), dict) else {}
    return "\n".join([
        "# Sentinel Autonomous Goal Manager",
        "",
        f"- status: `{report.get('status')}`",
        f"- action: `{report.get('action')}`",
        f"- discovered_goals: `{report.get('discovered_goal_count', 0)}`",
        f"- mission_queue_count: `{report.get('mission_queue_count', 0)}`",
        f"- selected_mission: `{report.get('selected_mission_type')}`",
        f"- selected_capability: `{report.get('selected_capability')}`",
        f"- selected_task: `{report.get('selected_task')}`",
        f"- validation: `{report.get('mission_validation_status', '-')}`",
        f"- mission_runner_status: `{runner.get('last_mission_runner_status', '-')}`",
        f"- mission_runner_completed_count: `{runner.get('completed_mission_count', 0)}`",
        f"- supervisor_status: `{supervisor.get('last_supervisor_status', '-')}`",
        f"- active_operation_type: `{supervisor.get('active_operation_type', '-')}`",
        "- live_apply: `False`",
        "- emergency_stop: `True`",
        "- allowed_apply_now: `False`",
        "- HIGH blocked: `True`",
        "- LOW_LIVE executable: `False`",
        "- MEDIUM executable: `False`",
        "- breach: `False`",
    ]) + "\n"


def render_queue_md(report: Dict[str, Any]) -> str:
    lines = ["# Sentinel Autonomous Mission Queue", ""]
    for mission in report.get("mission_queue") or report.get("classified_missions") or report.get("routed_missions") or []:
        lines.append(
            f"- `{mission.get('mission_type')}` priority=`{mission.get('priority_score')}` "
            f"risk=`{mission.get('risk_class')}` status=`{mission.get('status')}` "
            f"capability=`{mission.get('linked_capability')}` task=`{','.join(mission.get('linked_tasks') or [])}`"
        )
    return "\n".join(lines) + "\n"


def render_routing_md(report: Dict[str, Any]) -> str:
    lines = ["# Sentinel Autonomous Mission Routing", ""]
    lines.append(f"- selected_mission: `{report.get('selected_mission_type')}`")
    lines.append(f"- selected_capability: `{report.get('selected_capability')}`")
    lines.append(f"- selected_task: `{report.get('selected_task')}`")
    lines.append("")
    for mission in report.get("routed_missions") or []:
        lines.append(f"- `{mission.get('mission_type')}` -> `{mission.get('linked_capability')}` / `{','.join(mission.get('linked_tasks') or [])}`")
    return "\n".join(lines) + "\n"


def render_execution_md(report: Dict[str, Any]) -> str:
    execution = report.get("execution") if isinstance(report.get("execution"), dict) else {}
    return "\n".join([
        "# Sentinel Autonomous Mission Execution",
        "",
        f"- selected_mission: `{report.get('selected_mission_type')}`",
        f"- execution_status: `{execution.get('status')}`",
        f"- module: `{execution.get('module', '-')}`",
        f"- returncode: `{execution.get('returncode', '-')}`",
        "- scope: one safe local mission step maximum",
    ]) + "\n"


def render_validation_md(report: Dict[str, Any]) -> str:
    lines = ["# Sentinel Autonomous Mission Validation", "", f"- status: `{report.get('mission_validation_status', report.get('status'))}`"]
    for check in report.get("output_checks") or []:
        lines.append(f"- `{check.get('path')}` status=`{check.get('status')}` reasons=`{','.join(check.get('reasons') or []) or '-'}`")
    return "\n".join(lines) + "\n"


def render_learning_md(report: Dict[str, Any]) -> str:
    updates = report.get("learning_updates") if isinstance(report.get("learning_updates"), dict) else {}
    return "\n".join([
        "# Sentinel Autonomous Mission Learning",
        "",
        f"- status: `{report.get('status')}`",
        f"- next_recommended_mission: `{report.get('next_recommended_mission', report.get('next_mission'))}`",
        f"- completion_ledger_count: `{updates.get('completion_ledger_count', 0)}`",
    ]) + "\n"


def render_owner_summary_md(report: Dict[str, Any]) -> str:
    selected = report.get("selected_mission") if isinstance(report.get("selected_mission"), dict) else {}
    completed = report.get("completed_missions") if isinstance(report.get("completed_missions"), list) else []
    blocked = report.get("blocked_missions") if isinstance(report.get("blocked_missions"), list) else []
    runner = report.get("mission_queue_runner") if isinstance(report.get("mission_queue_runner"), dict) else {}
    supervisor = report.get("operations_supervisor") if isinstance(report.get("operations_supervisor"), dict) else {}
    return "\n".join([
        "# Sentinel Autonomous Mission Owner Summary",
        "",
        f"- selected_mission: `{selected.get('mission_type', report.get('selected_mission_type'))}`",
        f"- linked_capability: `{selected.get('linked_capability', report.get('selected_capability'))}`",
        f"- linked_task: `{','.join(selected.get('linked_tasks') or ([report.get('selected_task')] if report.get('selected_task') else []))}`",
        f"- mission_status: `{selected.get('status', '-')}`",
        f"- mission_risk: `{selected.get('risk_class', '-')}`",
        f"- completed_missions: `{len(completed)}`",
        f"- blocked_missions: `{len(blocked)}`",
        f"- mission_runner_status: `{runner.get('last_mission_runner_status', '-')}`",
        f"- mission_runner_completed_count: `{runner.get('completed_mission_count', 0)}`",
        f"- mission_runner_stop_reason: `{runner.get('stop_reason', '-')}`",
        f"- supervisor_status: `{supervisor.get('last_supervisor_status', '-')}`",
        f"- active_operation_type: `{supervisor.get('active_operation_type', '-')}`",
        f"- next_mission: `{report.get('next_mission', report.get('next_recommended_mission'))}`",
        "- live_apply: `False`",
        "- emergency_stop: `True`",
        "- allowed_apply_now: `False`",
        "- HIGH blocked: `True`",
        "- LOW_LIVE executable: `False`",
        "- MEDIUM executable: `False`",
        "- breach: `False`",
    ]) + "\n"


def render_next_mission_md(report: Dict[str, Any]) -> str:
    return "\n".join([
        "# Sentinel Autonomous Next Mission",
        "",
        f"- next_mission: `{report.get('next_mission', report.get('next_recommended_mission'))}`",
        f"- selected_mission: `{report.get('selected_mission_type')}`",
        "- Any further step stays inside local safe autonomy boundaries.",
    ]) + "\n"


def write_outputs(report: Dict[str, Any]) -> None:
    safe_report = {
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "timestamp_utc": report.get("timestamp_utc") or utc_now(),
        **report,
        **HARD_DEFAULTS,
        "mission_queue_runner": mission_runner_summary(),
        "operations_supervisor": supervisor_summary(),
        "operation_governor": operation_governor_summary(),
        "soak_context": soak_context_summary(),
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
            "playbooks/sentinel-autonomous-goal-manager.playbook.json",
            "playbooks/sentinel-autonomous-mission-queue.playbook.json",
            "playbooks/sentinel-autonomous-mission-routing.playbook.json",
            "playbooks/sentinel-autonomous-mission-validation.playbook.json",
            "playbooks/sentinel-autonomous-mission-queue-runner.playbook.json",
            "playbooks/sentinel-autonomous-mission-runner-stop-rules.playbook.json",
            "playbooks/sentinel-autonomous-mission-completion-ledger.playbook.json",
            "playbooks/sentinel-autonomous-mission-runner-owner-summary.playbook.json",
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
    queue_data = {
        "timestamp_utc": utc_now(),
        "mission_queue": safe_report.get("mission_queue") or safe_report.get("classified_missions") or safe_report.get("routed_missions") or [],
        "selected_mission": safe_report.get("selected_mission"),
        **HARD_DEFAULTS,
    }
    write_json(MISSION_QUEUE_JSON, queue_data)
    write_text(REPORT_MD, render_report_md(safe_report))
    write_text(MISSION_QUEUE_MD, render_queue_md(safe_report))
    write_text(MISSION_ROUTING_MD, render_routing_md(safe_report))
    write_text(MISSION_EXECUTION_MD, render_execution_md(safe_report))
    write_text(MISSION_VALIDATION_MD, render_validation_md(safe_report))
    write_text(MISSION_LEARNING_MD, render_learning_md(safe_report))
    write_text(OWNER_SUMMARY_MD, render_owner_summary_md(safe_report))
    write_text(NEXT_MISSION_MD, render_next_mission_md(safe_report))
    write_playbooks(safe_report)
    append_jsonl(AUDIT_JSONL, [{
        "timestamp_utc": utc_now(),
        "event": "autonomous_goal_manager",
        "action": safe_report.get("action"),
        "status": safe_report.get("status"),
        "selected_mission": safe_report.get("selected_mission_type"),
        "selected_capability": safe_report.get("selected_capability"),
        "selected_task": safe_report.get("selected_task"),
        "breach": False,
        "live_apply": False,
        "allowed_apply_now": False,
    }])


def source_safety_findings(source: str) -> List[str]:
    findings: List[str] = []
    if re.search(r"add_argument\([\"']--" + "apply", source):
        findings.append("apply_argument_present")
    if FORBIDDEN_IMPORT_RE.search(source):
        findings.append("network_import")
    if re.search(r"shell\s*=\s*True", source):
        findings.append("shell_true")
    for literal in [
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
    for token in ["." + "put(", "." + "remove(", "." + "rename("]:
        if token in source:
            findings.append("remote_write_method_pattern")
    return sorted(set(findings))


def action_self_test() -> Dict[str, Any]:
    source = Path(__file__).read_text(encoding="utf-8")
    findings = source_safety_findings(source)
    fake = discover_goals()
    queue_a = build_mission_queue(fake)
    queue_b = build_mission_queue(fake)
    first = queue_a.get("mission_queue", [{}])[0]
    checks = {
        "no_apply_argument": ("--" + "apply") not in source,
        "no_source_safety_findings": not findings,
        "mission_type_count": len(MISSION_TYPES) == 16,
        "every_mission_has_risk": all(MISSION_META[m][0] for m in MISSION_TYPES),
        "mission_queue_reproducible": json.dumps(queue_a.get("mission_queue"), sort_keys=True) == json.dumps(queue_b.get("mission_queue"), sort_keys=True),
        "selected_has_capability": bool(first.get("linked_capability")),
        "allowed_module_accepts_priority": module_arg_allowed("sentinel_autonomous_priority_engine.py", ["--score-tasks"]),
        "unknown_module_blocked": not module_arg_allowed("unknown.py", ["--status"]),
        "unknown_arg_blocked": not module_arg_allowed("sentinel_autonomous_priority_engine.py", ["--bad"]),
        "outside_scope_blocked": path_scope_allowed(["/tmp/not-allowed.json"], LOW_STATE) is False,
        "secret_redaction": "ABCDEF1234567890" not in redact_text("api_key" + "=" + "ABCDEF1234567890"),
        "json_serializable": isinstance(json.dumps(queue_a), str),
        "live_apply_false": HARD_DEFAULTS["live_apply"] is False,
        "allowed_apply_now_false": HARD_DEFAULTS["allowed_apply_now"] is False,
        "high_blocked": HARD_DEFAULTS["high_blocked"] is True,
        "low_live_not_executable": HARD_DEFAULTS["low_live_executable"] is False,
        "medium_not_executable": HARD_DEFAULTS["medium_executable"] is False,
    }
    failures = [k for k, ok in checks.items() if not ok] + findings
    return {
        "timestamp_utc": utc_now(),
        "action": "self-test",
        "status": "GOAL_MANAGER_SELF_TEST_OK" if not failures else "GOAL_MANAGER_SELF_TEST_FAILED",
        "checks": checks,
        "self_test_failures": failures,
        **HARD_DEFAULTS,
        "breach": bool(failures),
    }


def action_status() -> Dict[str, Any]:
    data = load_dict(LATEST_JSON) or load_dict(STATE_JSON)
    if data:
        return data
    return {
        "timestamp_utc": utc_now(),
        "action": "status",
        "status": "GOAL_MANAGER_NO_STATE",
        "mission_queue_count": 0,
        **HARD_DEFAULTS,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Sentinel Autonomous Goal Manager")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--discover-goals", action="store_true")
    group.add_argument("--build-mission-queue", action="store_true")
    group.add_argument("--classify-missions", action="store_true")
    group.add_argument("--route-missions", action="store_true")
    group.add_argument("--execute-safe-mission-step", action="store_true")
    group.add_argument("--validate-missions", action="store_true")
    group.add_argument("--learn", action="store_true")
    group.add_argument("--cycle", action="store_true")
    group.add_argument("--status", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        report = action_self_test()
        print(report["status"])
        return 0 if report["status"] == "GOAL_MANAGER_SELF_TEST_OK" else 1
    if args.discover_goals:
        report = discover_goals()
    elif args.build_mission_queue:
        report = build_mission_queue()
    elif args.classify_missions:
        report = classify_missions()
    elif args.route_missions:
        report = route_missions()
    elif args.execute_safe_mission_step:
        report = execute_safe_mission_step()
    elif args.validate_missions:
        report = validate_missions()
    elif args.learn:
        report = learn()
    elif args.cycle:
        report = cycle()
    else:
        report = action_status()

    write_outputs(report)
    if args.status:
        print(
            "status={status} queue={queue} selected={mission} capability={capability} "
            "task={task} validation={validation} breach={breach}".format(
                status=report.get("status"),
                queue=report.get("mission_queue_count", 0),
                mission=report.get("selected_mission_type"),
                capability=report.get("selected_capability"),
                task=report.get("selected_task"),
                validation=report.get("mission_validation_status", "-"),
                breach=report.get("breach", False),
            )
        )
    else:
        print(report.get("status"))
    return 0 if report.get("breach") is not True else 1


if __name__ == "__main__":
    raise SystemExit(main())
