#!/usr/bin/env python3
"""Sentinel Autonomous Priority Engine (Phase 10.2).

Autonomous task diversity, priority scoring and anti-loop governance for the
self-governing safe autonomy kernel. This module is local-only: it writes
reports, state, audit events and playbooks, but it performs no live apply, no
network activity, no remote writes and no installation.
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
SCHEMA_VERSION = "sentinel-autonomous-priority-engine-10.2"
PHASE = "10.2"
MAX_SIMULATION_CYCLES = 5
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

ALLOWED_TASKS = [
    "observe_project_state",
    "update_owner_summary",
    "update_service_proof",
    "rebuild_payhip_upload_pack",
    "rerun_payhip_launch_qa",
    "update_fulfillment_board",
    "run_first_order_dryrun",
    "check_public_asset_safety",
    "check_missing_inputs",
    "generate_next_safe_actions",
    "repair_missing_public_asset",
    "repair_invalid_json_output",
    "rebuild_manifest_and_checksums",
    "update_learning_state",
    "write_audit_event",
    "generate_git_checkpoint_suggestion",
]

COMPANION_ONLY_TASKS = {"write_audit_event", "update_learning_state"}
RECOVERY_REPEAT_ALLOWED = {
    "repair_invalid_json_output",
    "repair_missing_public_asset",
    "rebuild_manifest_and_checksums",
}

TASK_RISK: Dict[str, str] = {
    "observe_project_state": READ_ONLY,
    "check_public_asset_safety": READ_ONLY,
    "check_missing_inputs": READ_ONLY,
    "generate_next_safe_actions": DRAFT,
    "generate_git_checkpoint_suggestion": DRAFT,
    "update_owner_summary": LOW_STATE,
    "update_service_proof": LOW_STATE,
    "rerun_payhip_launch_qa": LOW_STATE,
    "update_fulfillment_board": LOW_STATE,
    "run_first_order_dryrun": LOW_STATE,
    "update_learning_state": LOW_STATE,
    "write_audit_event": LOW_STATE,
    "repair_invalid_json_output": LOW_STATE,
    "repair_missing_public_asset": LOW_STATE,
    "rebuild_payhip_upload_pack": LOW_EXPORT,
    "rebuild_manifest_and_checksums": LOW_EXPORT,
}

TASK_COOLDOWNS = {
    "generate_next_safe_actions": 2,
    "update_owner_summary": 2,
    "rebuild_payhip_upload_pack": 3,
    "rerun_payhip_launch_qa": 3,
    "update_fulfillment_board": 3,
    "run_first_order_dryrun": 5,
}

MAX_IN_LAST_WINDOW = {
    "check_public_asset_safety": (2, 5),
    "check_missing_inputs": (2, 5),
}

BUSINESS_VALUE = {
    "rebuild_payhip_upload_pack": 34,
    "rerun_payhip_launch_qa": 28,
    "update_fulfillment_board": 24,
    "run_first_order_dryrun": 22,
    "update_service_proof": 19,
    "update_owner_summary": 16,
    "check_public_asset_safety": 14,
    "check_missing_inputs": 13,
    "generate_next_safe_actions": 10,
    "generate_git_checkpoint_suggestion": 9,
    "observe_project_state": 8,
    "repair_invalid_json_output": 45,
    "repair_missing_public_asset": 40,
    "rebuild_manifest_and_checksums": 38,
    "write_audit_event": 3,
    "update_learning_state": 4,
}

LEARNING_VALUE = {
    "check_missing_inputs": 15,
    "check_public_asset_safety": 14,
    "observe_project_state": 12,
    "generate_next_safe_actions": 10,
    "generate_git_checkpoint_suggestion": 9,
    "update_owner_summary": 8,
}

TASK_OUTPUTS: Dict[str, List[str]] = {
    "update_owner_summary": ["reports/latest/sentinel-autonomy-owner-summary.md"],
    "update_service_proof": ["reports/latest/sentinel-service-proof.json"],
    "rebuild_payhip_upload_pack": [
        "reports/latest/sentinel-payhip-upload-pack-export.json",
        "exports/payhip-upload-pack/latest/MANIFEST.json",
        "exports/payhip-upload-pack/latest/CHECKSUMS.sha256",
    ],
    "rerun_payhip_launch_qa": ["reports/latest/sentinel-payhip-launch-qa.json"],
    "update_fulfillment_board": ["reports/latest/sentinel-payhip-fulfillment-board.json"],
    "run_first_order_dryrun": ["reports/latest/sentinel-payhip-first-order-dryrun.json"],
    "check_public_asset_safety": [
        "reports/latest/sentinel-payhip-public-intake-form.md",
        "reports/latest/sentinel-payhip-public-safety-agreement.md",
        "reports/latest/sentinel-payhip-public-service-overview.md",
    ],
    "check_missing_inputs": ["reports/latest/sentinel-autonomy-observation.md"],
    "generate_next_safe_actions": ["reports/latest/sentinel-autonomy-next-cycle.md"],
    "repair_missing_public_asset": ["reports/latest/sentinel-payhip-public-service-overview.md"],
    "repair_invalid_json_output": ["reports/latest/sentinel-autonomy-validation.md"],
    "rebuild_manifest_and_checksums": [
        "exports/payhip-upload-pack/latest/MANIFEST.json",
        "exports/payhip-upload-pack/latest/CHECKSUMS.sha256",
    ],
    "generate_git_checkpoint_suggestion": ["reports/latest/sentinel-autonomy-git-checkpoint-suggestion.md"],
}

TASK_TO_CAPABILITY = {
    "observe_project_state": "autonomy_kernel",
    "update_owner_summary": "owner_dashboard_service_packaging",
    "update_service_proof": "service_proof_trend",
    "rebuild_payhip_upload_pack": "payhip_upload_pack_export",
    "rerun_payhip_launch_qa": "payhip_launch_qa",
    "update_fulfillment_board": "payhip_fulfillment_board",
    "run_first_order_dryrun": "first_order_dryrun",
    "check_public_asset_safety": "public_client_assets",
    "check_missing_inputs": "autonomy_kernel",
    "generate_next_safe_actions": "priority_engine",
    "repair_missing_public_asset": "public_client_assets",
    "repair_invalid_json_output": "autonomy_kernel",
    "rebuild_manifest_and_checksums": "payhip_upload_pack_export",
    "update_learning_state": "autonomy_kernel",
    "write_audit_event": "autonomy_kernel",
    "generate_git_checkpoint_suggestion": "priority_engine",
}

KERNEL_JSON = PROJECT_DIR / "reports/latest/sentinel-self-governing-autonomy-kernel.json"
RUNNER_JSON = PROJECT_DIR / "reports/latest/sentinel-autonomous-cycle-runner.json"
TASK_DECISION_MD = PROJECT_DIR / "reports/latest/sentinel-autonomy-task-decision.md"
NEXT_CYCLE_MD = PROJECT_DIR / "reports/latest/sentinel-autonomy-next-cycle.md"
TASK_MEMORY_JSON = PROJECT_DIR / "state/adaptive-learning/autonomy_task_memory.json"
CYCLE_HISTORY_JSON = PROJECT_DIR / "state/adaptive-learning/autonomy_cycle_history.json"
RUNNER_HISTORY_JSON = PROJECT_DIR / "state/adaptive-learning/autonomous_cycle_runner_history.json"
SUCCESS_PATTERNS_JSON = PROJECT_DIR / "state/adaptive-learning/autonomy_success_patterns.json"
BLOCKED_PATTERNS_JSON = PROJECT_DIR / "state/adaptive-learning/autonomy_blocked_patterns.json"
REPAIR_PATTERNS_JSON = PROJECT_DIR / "state/adaptive-learning/autonomy_repair_patterns.json"
LATEST_KERNEL_JSON = PROJECT_DIR / "state/adaptive-learning/latest_self_governing_autonomy_kernel.json"
LATEST_RUNNER_JSON = PROJECT_DIR / "state/adaptive-learning/latest_autonomous_cycle_runner.json"
EXPORT_LATEST_DIR = PROJECT_DIR / "exports/payhip-upload-pack/latest"
CAPABILITY_REGISTRY_JSON = PROJECT_DIR / "state/adaptive-learning/autonomous_capability_registry.json"

REPORT_JSON = PROJECT_DIR / "reports/latest/sentinel-autonomous-priority-engine.json"
REPORT_MD = PROJECT_DIR / "reports/latest/sentinel-autonomous-priority-engine.md"
TASK_SCORES_MD = PROJECT_DIR / "reports/latest/sentinel-autonomous-task-scores.md"
DIVERSITY_MD = PROJECT_DIR / "reports/latest/sentinel-autonomous-task-diversity.md"
ANTI_LOOP_MD = PROJECT_DIR / "reports/latest/sentinel-autonomous-anti-loop-governor.md"
SELECTION_MD = PROJECT_DIR / "reports/latest/sentinel-autonomous-priority-selection.md"
OWNER_SUMMARY_MD = PROJECT_DIR / "reports/latest/sentinel-autonomous-priority-owner-summary.md"

STATE_MODEL_JSON = PROJECT_DIR / "state/adaptive-learning/autonomy_task_priority_model.json"
LATEST_MODEL_JSON = PROJECT_DIR / "state/adaptive-learning/latest_autonomy_task_priority_model.json"
COOLDOWNS_JSON = PROJECT_DIR / "state/adaptive-learning/autonomy_task_cooldowns.json"
DIVERSITY_HISTORY_JSON = PROJECT_DIR / "state/adaptive-learning/autonomy_task_diversity_history.json"
SCORE_HISTORY_JSON = PROJECT_DIR / "state/adaptive-learning/autonomy_task_score_history.json"
ANTI_LOOP_JSON = PROJECT_DIR / "state/adaptive-learning/autonomy_anti_loop_patterns.json"

AUDIT_JSONL = PROJECT_DIR / "audit/sentinel-autonomous-priority-engine.jsonl"

PLAYBOOK_ENGINE = PROJECT_DIR / "playbooks/sentinel-autonomous-priority-engine.playbook.json"
PLAYBOOK_ANTI_LOOP = PROJECT_DIR / "playbooks/sentinel-autonomy-anti-loop-governor.playbook.json"
PLAYBOOK_DIVERSITY = PROJECT_DIR / "playbooks/sentinel-autonomy-task-diversity.playbook.json"
PLAYBOOK_INTEGRATION = PROJECT_DIR / "playbooks/sentinel-autonomy-priority-integration.playbook.json"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "state/adaptive-learning",
    PROJECT_DIR / "audit",
    PROJECT_DIR / "playbooks",
)

HARD_DEFAULTS = {
    "live_apply": False,
    "emergency_stop": True,
    "allowed_apply_now": False,
    "high_blocked": True,
    "low_live_executable": False,
    "medium_executable": False,
    "breach": False,
}

SECRET_RE = re.compile(
    r"(?i)(?:password|passwd|secret|token|api[_-]?key|authorization|bearer)\s*[:=]\s*['\"]?"
    r"(?!false\b|true\b|null\b|none\b|not_applied\b|<redacted\b)[A-Za-z0-9+/=_.:-]{8,}"
)
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:OPENSSH|RSA|DSA|EC) PRIVATE KEY-----")
TOKEN_FORMAT_RE = re.compile(r"\b(?:sk-(?:proj-)?[A-Za-z0-9_-]{24,}|ghp_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,})\b")
FORBIDDEN_IMPORT_RE = re.compile(
    r"(?m)^\s*(?:import|from)\s+(?:requests|urllib|http\.client|smtplib|socket|paramiko|cloudflare)\b"
)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_utc(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
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
    except ValueError:
        return False


def assert_allowed_write(path: Path) -> None:
    if not any(is_within(path, root) for root in ALLOWED_WRITE_ROOTS):
        raise ValueError(f"write outside allowed roots refused: {rel(path)}")
    if path.suffix.lower() not in {".json", ".jsonl", ".md"}:
        raise ValueError(f"unsupported output suffix refused: {rel(path)}")


def redact_text(value: Any, max_len: int = 4000) -> str:
    text = "" if value is None else str(value)
    text = SECRET_RE.sub(lambda m: m.group(0).split("=", 1)[0].split(":", 1)[0] + "=<redacted>", text)
    text = PRIVATE_KEY_RE.sub("<redacted-private-key-marker>", text)
    text = TOKEN_FORMAT_RE.sub("<redacted-token>", text)
    return text if len(text) <= max_len else text[: max_len - 3] + "..."


def safe_blob(path: Path, text: str) -> None:
    if SECRET_RE.search(text) or PRIVATE_KEY_RE.search(text) or TOKEN_FORMAT_RE.search(text):
        raise ValueError(f"secret-like output refused: {rel(path)}")


def write_text(path: Path, text: str) -> None:
    assert_allowed_write(path)
    safe_blob(path, text)
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
            safe_blob(path, blob)
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


def read_text_optional(path: Path) -> Tuple[str, str]:
    try:
        if not path.exists():
            return "", "missing"
        return path.read_text(encoding="utf-8", errors="replace"), "ok"
    except OSError:
        return "", "read_error"


def file_age_hours(path: Path) -> Optional[float]:
    try:
        if not path.exists():
            return None
        age_seconds = datetime.now(timezone.utc).timestamp() - path.stat().st_mtime
        return max(0.0, age_seconds / 3600.0)
    except OSError:
        return None


def output_status(paths: List[str]) -> Dict[str, Any]:
    if not paths:
        return {"missing": [], "stale": [], "fresh": [], "oldest_age_hours": None}
    missing: List[str] = []
    stale: List[str] = []
    fresh: List[str] = []
    ages: List[float] = []
    for item in paths:
        path = PROJECT_DIR / item
        age = file_age_hours(path)
        if age is None:
            missing.append(item)
        else:
            ages.append(age)
            if age > MAX_AGE_HOURS:
                stale.append(item)
            else:
                fresh.append(item)
    return {
        "missing": missing,
        "stale": stale,
        "fresh": fresh,
        "oldest_age_hours": round(max(ages), 3) if ages else None,
    }


def exact_git_command(kind: str) -> Dict[str, Any]:
    commands = {
        "status": ["git", "status", "--short"],
        "log": ["git", "log", "--oneline", "-n", "20"],
    }
    cmd = commands[kind]
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(PROJECT_DIR),
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
            shell=False,
        )
        lines = [redact_text(line, 500) for line in (proc.stdout or "").splitlines()]
        return {"ok": proc.returncode == 0, "returncode": proc.returncode, "lines": lines[:80]}
    except (OSError, subprocess.SubprocessError) as exc:
        return {"ok": False, "returncode": None, "error": redact_text(exc, 500), "lines": []}


def collect_recent_tasks() -> List[str]:
    tasks: List[str] = []
    runner = load_dict(RUNNER_JSON)
    for item in runner.get("cycle_results") or []:
        if isinstance(item, dict) and item.get("selected_task"):
            tasks.append(str(item["selected_task"]))
    for item in load_list(RUNNER_HISTORY_JSON):
        if isinstance(item, dict):
            for task in item.get("selected_tasks") or []:
                if task:
                    tasks.append(str(task))
    for item in load_list(CYCLE_HISTORY_JSON):
        if isinstance(item, dict) and item.get("selected_task"):
            tasks.append(str(item["selected_task"]))
    return tasks[-50:]


def critical_json_scan() -> Dict[str, Any]:
    broken: List[str] = []
    checked = 0
    for root in (PROJECT_DIR / "reports/latest", PROJECT_DIR / "state/adaptive-learning"):
        if not root.exists():
            continue
        for path in sorted(root.glob("*.json")):
            checked += 1
            _, status = read_json(path)
            if status == "invalid_json":
                broken.append(rel(path))
    return {"checked_json_count": checked, "broken_json": broken}


def public_assets_status() -> Dict[str, Any]:
    paths = TASK_OUTPUTS["check_public_asset_safety"]
    missing = [p for p in paths if not (PROJECT_DIR / p).exists()]
    return {"expected_public_assets": paths, "missing_public_assets": missing}


def manifest_status() -> Dict[str, Any]:
    manifest = EXPORT_LATEST_DIR / "MANIFEST.json"
    checksums = EXPORT_LATEST_DIR / "CHECKSUMS.sha256"
    return {
        "manifest_present": manifest.exists(),
        "manifest_json_status": read_json(manifest)[1] if manifest.exists() else "missing",
        "checksums_present": checksums.exists(),
        "latest_dir_present": EXPORT_LATEST_DIR.exists(),
    }


def read_inputs() -> Dict[str, Any]:
    input_paths = [
        KERNEL_JSON,
        RUNNER_JSON,
        TASK_DECISION_MD,
        NEXT_CYCLE_MD,
        TASK_MEMORY_JSON,
        CYCLE_HISTORY_JSON,
        RUNNER_HISTORY_JSON,
        SUCCESS_PATTERNS_JSON,
        BLOCKED_PATTERNS_JSON,
        REPAIR_PATTERNS_JSON,
        LATEST_KERNEL_JSON,
        LATEST_RUNNER_JSON,
        CAPABILITY_REGISTRY_JSON,
    ]
    statuses: Dict[str, str] = {}
    missing: List[str] = []
    for path in input_paths:
        if path.suffix == ".json":
            _, status = read_json(path)
        else:
            _, status = read_text_optional(path)
        statuses[rel(path)] = status
        if status == "missing":
            missing.append(rel(path))
    kernel = load_dict(KERNEL_JSON) or load_dict(LATEST_KERNEL_JSON)
    runner = load_dict(RUNNER_JSON) or load_dict(LATEST_RUNNER_JSON)
    capability_registry = load_dict(CAPABILITY_REGISTRY_JSON)
    git_status = exact_git_command("status")
    git_log = exact_git_command("log")
    return {
        "timestamp_utc": utc_now(),
        "input_status": statuses,
        "missing_inputs": missing,
        "kernel": kernel,
        "runner": runner,
        "capability_registry": capability_registry,
        "recent_tasks": collect_recent_tasks(),
        "critical_json": critical_json_scan(),
        "public_assets": public_assets_status(),
        "manifest": manifest_status(),
        "git_status": git_status,
        "git_log": git_log,
    }


def capability_index(inputs: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    registry = inputs.get("capability_registry")
    if not isinstance(registry, dict):
        return {}
    caps = registry.get("capabilities")
    if not isinstance(caps, list):
        return {}
    return {
        str(cap.get("capability_id")): cap
        for cap in caps
        if isinstance(cap, dict) and cap.get("capability_id")
    }


def risk_penalty(task: str) -> int:
    risk = TASK_RISK.get(task, HIGH)
    if risk in AUTO_ALLOWED_RISK:
        return 0
    if risk == LOW_LIVE:
        return 1000
    if risk == MEDIUM:
        return 2000
    return 3000


def cooldown_remaining(task: str, recent: List[str]) -> int:
    cooldown = TASK_COOLDOWNS.get(task, 0)
    if cooldown <= 0:
        return 0
    last_index = None
    for index, item in enumerate(reversed(recent), start=1):
        if item == task:
            last_index = index
            break
    if last_index is None:
        return 0
    return max(0, cooldown - (last_index - 1))


def max_window_block(task: str, recent: List[str]) -> bool:
    rule = MAX_IN_LAST_WINDOW.get(task)
    if not rule:
        return False
    max_count, window = rule
    return recent[-window:].count(task) >= max_count


def freshness_penalty_for(task: str, outputs: Dict[str, Any]) -> int:
    status = outputs.get(task, {})
    paths = TASK_OUTPUTS.get(task, [])
    if not paths:
        return 0
    if status.get("missing") or status.get("stale"):
        return 0
    return 18


def staleness_score_for(task: str, outputs: Dict[str, Any]) -> int:
    status = outputs.get(task, {})
    stale_count = len(status.get("stale") or [])
    if stale_count:
        return min(40, 15 + stale_count * 8)
    age = status.get("oldest_age_hours")
    if isinstance(age, (int, float)) and age > 12:
        return 8
    return 0


def missing_score_for(task: str, outputs: Dict[str, Any], inputs: Dict[str, Any]) -> int:
    status = outputs.get(task, {})
    missing_count = len(status.get("missing") or [])
    if missing_count:
        return min(60, 22 + missing_count * 10)
    if task == "check_missing_inputs" and inputs["missing_inputs"]:
        return min(50, 15 + len(inputs["missing_inputs"]) * 4)
    return 0


def score_tasks(inputs: Optional[Dict[str, Any]] = None, recent_override: Optional[List[str]] = None) -> Dict[str, Any]:
    inputs = inputs or read_inputs()
    recent = list(recent_override if recent_override is not None else inputs["recent_tasks"])
    outputs = {task: output_status(TASK_OUTPUTS.get(task, [])) for task in ALLOWED_TASKS}
    broken_json = inputs["critical_json"]["broken_json"]
    missing_assets = inputs["public_assets"]["missing_public_assets"]
    manifest = inputs["manifest"]
    kernel = inputs["kernel"]
    runner = inputs["runner"]
    capabilities = capability_index(inputs)
    breach = bool(kernel.get("breach") or runner.get("breach"))
    forbidden_stop = breach
    scores: List[Dict[str, Any]] = []
    last_task = recent[-1] if recent else None

    for task in ALLOWED_TASKS:
        risk = TASK_RISK.get(task, HIGH)
        cap_id = TASK_TO_CAPABILITY.get(task)
        cap = capabilities.get(cap_id or "", {})
        capability_usefulness = 0
        capability_freshness_gap = 0
        capability_blocked = False
        if cap:
            capability_usefulness = min(18, max(-20, int(cap.get("usefulness_score") or 0) // 4))
            capability_freshness_gap = max(0, 100 - int(cap.get("freshness_score") or 100)) // 8
            capability_blocked = cap.get("can_run_autonomously") is False
        urgency = 0
        repair_value = 0
        validation_failure = 0
        reason_parts: List[str] = []

        if broken_json and task == "repair_invalid_json_output":
            urgency += 100
            repair_value += 60
            reason_parts.append("broken_json_detected")
        if missing_assets and task == "repair_missing_public_asset":
            urgency += 90
            repair_value += 55
            reason_parts.append("missing_public_asset_detected")
        if task == "rebuild_manifest_and_checksums" and (
            not manifest["manifest_present"]
            or manifest["manifest_json_status"] != "ok"
            or not manifest["checksums_present"]
        ):
            urgency += 82
            repair_value += 45
            reason_parts.append("manifest_or_checksums_missing")
        if task == "rebuild_payhip_upload_pack":
            out = outputs[task]
            if out.get("missing") or out.get("stale"):
                urgency += 45
                reason_parts.append("upload_pack_missing_or_stale")
        if task == "rerun_payhip_launch_qa" and (outputs[task].get("missing") or outputs[task].get("stale")):
            urgency += 38
            reason_parts.append("launch_qa_missing_or_stale")
        if task == "update_fulfillment_board" and (outputs[task].get("missing") or outputs[task].get("stale")):
            urgency += 34
            reason_parts.append("fulfillment_board_missing_or_stale")
        if task == "run_first_order_dryrun" and outputs[task].get("missing"):
            urgency += 32
            reason_parts.append("first_order_dryrun_missing")
        if task == "update_service_proof" and (outputs[task].get("missing") or outputs[task].get("stale")):
            urgency += 30
            reason_parts.append("service_proof_missing_or_stale")
        if task == "update_owner_summary" and (outputs[task].get("missing") or outputs[task].get("stale")):
            urgency += 28
            reason_parts.append("owner_summary_missing_or_stale")
        if task == "check_public_asset_safety":
            urgency += 12
            reason_parts.append("safe_public_asset_watch")
        if task == "check_missing_inputs":
            urgency += 11
            reason_parts.append("safe_missing_input_watch")
        if task == "observe_project_state":
            urgency += 8
            reason_parts.append("safe_observation")
        if task == "generate_git_checkpoint_suggestion" and inputs["git_status"].get("lines"):
            urgency += 14
            reason_parts.append("git_changes_present")
        if task == "generate_next_safe_actions":
            urgency += 8
            reason_parts.append("fallback_safe_action_generation")

        if kernel.get("validation", {}).get("status") not in (None, "PASS"):
            validation_failure += 18
            reason_parts.append("kernel_validation_attention")

        cooldown = cooldown_remaining(task, recent)
        repetition = 0
        if last_task == task and task not in RECOVERY_REPEAT_ALLOWED:
            repetition += 35
            reason_parts.append("direct_repeat_penalty")
        if cooldown:
            repetition += cooldown * 22
            reason_parts.append(f"cooldown_remaining_{cooldown}")
        if max_window_block(task, recent):
            repetition += 75
            reason_parts.append("window_frequency_limit")

        blocked_penalty = 0
        if task in COMPANION_ONLY_TASKS:
            blocked_penalty += 120
            reason_parts.append("companion_only_not_main_task")
        if cap and capability_blocked:
            blocked_penalty += 85
            reason_parts.append(f"capability_blocked:{cap_id}")
        if task == "repair_invalid_json_output" and not broken_json:
            blocked_penalty += 90
            reason_parts.append("no_broken_json_to_repair")
        if task == "repair_missing_public_asset" and not missing_assets:
            blocked_penalty += 90
            reason_parts.append("no_missing_public_asset_to_repair")
        if task == "rebuild_manifest_and_checksums" and (
            manifest["manifest_present"]
            and manifest["manifest_json_status"] == "ok"
            and manifest["checksums_present"]
        ):
            blocked_penalty += 30
            reason_parts.append("manifest_and_checksums_present")
        if forbidden_stop:
            blocked_penalty += 10000
            reason_parts.append("breach_or_forbidden_stop")

        r_penalty = risk_penalty(task)
        if r_penalty:
            reason_parts.append(f"risk_blocked_{risk}")

        components = {
            "urgency_score": urgency,
            "staleness_score": staleness_score_for(task, outputs),
            "missing_output_score": missing_score_for(task, outputs, inputs),
            "validation_failure_score": validation_failure,
            "business_value_score": BUSINESS_VALUE.get(task, 0),
            "learning_value_score": LEARNING_VALUE.get(task, 5),
            "capability_usefulness_score": capability_usefulness,
            "capability_freshness_score": capability_freshness_gap,
            "repair_value_score": repair_value,
            "freshness_penalty": freshness_penalty_for(task, outputs),
            "repetition_penalty": repetition,
            "blocked_penalty": blocked_penalty,
            "risk_penalty": r_penalty,
        }
        total = (
            components["urgency_score"]
            + components["staleness_score"]
            + components["missing_output_score"]
            + components["validation_failure_score"]
            + components["business_value_score"]
            + components["learning_value_score"]
            + components["capability_usefulness_score"]
            + components["capability_freshness_score"]
            + components["repair_value_score"]
            - components["freshness_penalty"]
            - components["repetition_penalty"]
            - components["blocked_penalty"]
            - components["risk_penalty"]
        )
        can_execute_now = (
            task in ALLOWED_TASKS
            and risk in AUTO_ALLOWED_RISK
            and task not in COMPANION_ONLY_TASKS
            and not forbidden_stop
            and blocked_penalty == 0
            and r_penalty == 0
            and not max_window_block(task, recent)
        )
        scores.append({
            "task": task,
            "risk_class": risk,
            "score": int(total),
            "can_execute_now": can_execute_now,
            "cooldown_remaining": cooldown,
            "capability_id": cap_id,
            "capability_status": cap.get("health_status") if cap else "registry_missing_or_unmapped",
            "capability_can_run_autonomously": cap.get("can_run_autonomously") if cap else None,
            "reason": ", ".join(reason_parts) if reason_parts else "normal_rotation",
            "components": components,
            "outputs": outputs.get(task, {}),
        })

    scores.sort(key=lambda item: (item["can_execute_now"], item["score"], item["task"]), reverse=True)
    selected = next((item for item in scores if item["can_execute_now"]), None)
    if selected and selected["score"] < -100:
        selected = None
    diversity = diversity_status(recent, selected["task"] if selected else None)
    anti_loop = anti_loop_status(recent, scores, selected)
    return {
        "timestamp_utc": utc_now(),
        "status": "PRIORITY_TASKS_SCORED",
        "scores": scores,
        "top_scores": scores[:5],
        "selected": selected,
        "recent_tasks": recent,
        "task_output_status": outputs,
        "inputs": summarize_inputs(inputs),
        "cooldowns": cooldowns_data(recent),
        "diversity": diversity,
        "anti_loop": anti_loop,
        "breach": forbidden_stop,
        "live_apply": False,
        "emergency_stop": True,
        "allowed_apply_now": False,
        "high_blocked": True,
        "low_live_executable": False,
        "medium_executable": False,
    }


def summarize_inputs(inputs: Dict[str, Any]) -> Dict[str, Any]:
    registry = inputs.get("capability_registry")
    registry_status = "ok" if isinstance(registry, dict) and registry.get("capabilities") else "missing_or_invalid"
    return {
        "missing_inputs": inputs.get("missing_inputs", []),
        "critical_json": inputs.get("critical_json", {}),
        "public_assets": inputs.get("public_assets", {}),
        "manifest": inputs.get("manifest", {}),
        "capability_registry_status": registry_status,
        "capability_count": len(registry.get("capabilities", [])) if isinstance(registry, dict) else 0,
        "git_status_count": len((inputs.get("git_status") or {}).get("lines") or []),
        "git_log_count": len((inputs.get("git_log") or {}).get("lines") or []),
    }


def cooldowns_data(recent: List[str]) -> Dict[str, Any]:
    return {
        "recent_tasks": recent[-10:],
        "cooldowns": {
            task: {
                "configured_cycles": TASK_COOLDOWNS.get(task, 0),
                "remaining_cycles": cooldown_remaining(task, recent),
            }
            for task in ALLOWED_TASKS
        },
        "window_limits": {
            task: {
                "limit": rule[0],
                "window": rule[1],
                "current_count": recent[-rule[1]:].count(task),
                "blocked_now": max_window_block(task, recent),
            }
            for task, rule in MAX_IN_LAST_WINDOW.items()
        },
    }


def diversity_status(recent: List[str], selected_task: Optional[str] = None) -> Dict[str, Any]:
    candidate_history = recent[-4:] + ([selected_task] if selected_task else [])
    last_three = candidate_history[-3:]
    last_five = candidate_history[-5:]
    unique_three = len(set(last_three))
    unique_five = len(set(last_five))
    return {
        "last_three_tasks": last_three,
        "last_five_tasks": last_five,
        "unique_last_three": unique_three,
        "unique_last_five": unique_five,
        "meets_three_cycle_rule": unique_three >= 2 if len(last_three) >= 3 else True,
        "meets_five_cycle_rule": unique_five >= 3 if len(last_five) >= 5 else True,
        "status": "DIVERSITY_OK" if (unique_three >= 2 or len(last_three) < 3) else "DIVERSITY_NEEDS_ROTATION",
    }


def anti_loop_status(recent: List[str], scores: List[Dict[str, Any]], selected: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    task = selected.get("task") if selected else None
    direct_repeat = bool(task and recent and recent[-1] == task)
    allowed_repeat = task in RECOVERY_REPEAT_ALLOWED
    cooldown_ok = bool(selected and selected.get("cooldown_remaining", 0) == 0)
    safe_alternatives = [
        s["task"] for s in scores
        if s["can_execute_now"] and s["task"] != task and s["task"] not in COMPANION_ONLY_TASKS
    ]
    status = "ANTI_LOOP_OK"
    if direct_repeat and not allowed_repeat:
        status = "ANTI_LOOP_ROTATION_REQUIRED"
    if not selected:
        status = "STOP_ON_NO_DIVERSE_SAFE_TASK" if safe_alternatives else "STOP_ON_NO_SAFE_TASK"
    return {
        "status": status,
        "selected_task": task,
        "direct_repeat": direct_repeat,
        "repeat_allowed": allowed_repeat,
        "cooldown_respected": cooldown_ok,
        "safe_alternative_count": len(safe_alternatives),
        "safe_alternatives": safe_alternatives[:8],
    }


def select_next() -> Dict[str, Any]:
    scoring = score_tasks()
    selected = scoring["selected"]
    status = "PRIORITY_SELECTION_READY" if selected else "STOP_ON_NO_DIVERSE_SAFE_TASK"
    model = priority_model_from_scoring(scoring, status)
    write_outputs(model)
    return model


def priority_model_from_scoring(scoring: Dict[str, Any], status: str = "PRIORITY_MODEL_READY") -> Dict[str, Any]:
    selected = scoring.get("selected") or {}
    selected_task = selected.get("task")
    selected_capability = selected.get("capability_id")
    selected_capability_status = selected.get("capability_status")
    model = {
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "timestamp_utc": utc_now(),
        "status": status,
        "integration_enabled": True,
        "selected_task": selected_task,
        "selected_task_reason": selected.get("reason") or "no safe diverse task selected",
        "selected_task_score": selected.get("score"),
        "selected_task_risk_class": selected.get("risk_class"),
        "selected_task_executable": bool(selected.get("can_execute_now")),
        "selected_capability": selected_capability,
        "selected_capability_status": selected_capability_status,
        "selected_capability_can_run_autonomously": selected.get("capability_can_run_autonomously"),
        "can_execute_now": bool(selected.get("can_execute_now")),
        "task_scores": scoring["scores"],
        "top_scores": scoring["top_scores"],
        "cooldowns": scoring["cooldowns"],
        "diversity": scoring["diversity"],
        "anti_loop": scoring["anti_loop"],
        "recent_tasks": scoring["recent_tasks"],
        "inputs": scoring["inputs"],
        "runner_integration": {
            "allow_repeated_task_loop_if_reason": False,
            "stop_reason_when_no_diverse_task": "STOP_ON_NO_DIVERSE_SAFE_TASK",
            "companion_tasks_not_main": sorted(COMPANION_ONLY_TASKS),
        },
        "capability_registry_integration": {
            "registry_path": "state/adaptive-learning/autonomous_capability_registry.json",
            "registry_status": (scoring.get("inputs") or {}).get("capability_registry_status"),
            "selected_capability": selected_capability,
            "selected_capability_status": selected_capability_status,
        },
        "hard_defaults": HARD_DEFAULTS,
        "live_apply": False,
        "emergency_stop": True,
        "allowed_apply_now": False,
        "high_blocked": True,
        "low_live_executable": False,
        "medium_executable": False,
        "breach": bool(scoring.get("breach")),
        "recommended_git_checkpoint": [
            "sentinel_autonomous_priority_engine.py",
            "sentinel_self_governing_safe_autonomy_kernel.py",
            "sentinel_autonomous_cycle_runner.py",
            "playbooks/sentinel-autonomous-priority-engine.playbook.json",
            "playbooks/sentinel-autonomy-anti-loop-governor.playbook.json",
            "playbooks/sentinel-autonomy-task-diversity.playbook.json",
            "playbooks/sentinel-autonomy-priority-integration.playbook.json",
        ],
    }
    return model


def simulate_diversity(cycles: int = 3) -> Dict[str, Any]:
    cycles = max(1, min(MAX_SIMULATION_CYCLES, int(cycles)))
    inputs = read_inputs()
    recent = list(inputs["recent_tasks"])
    selected_tasks: List[str] = []
    cycle_models: List[Dict[str, Any]] = []
    for idx in range(1, cycles + 1):
        scoring = score_tasks(inputs, recent_override=recent)
        selected = scoring.get("selected")
        if not selected:
            cycle_models.append({"cycle_index": idx, "selected_task": None, "stop_reason": "STOP_ON_NO_DIVERSE_SAFE_TASK"})
            break
        task = str(selected["task"])
        selected_tasks.append(task)
        recent.append(task)
        cycle_models.append({
            "cycle_index": idx,
            "selected_task": task,
            "score": selected["score"],
            "reason": selected["reason"],
            "cooldown_remaining_before": selected["cooldown_remaining"],
            "diversity": scoring["diversity"],
        })
    unique_count = len(set(selected_tasks))
    status = "DIVERSITY_SIMULATION_OK"
    if len(selected_tasks) >= 3 and unique_count < 2:
        status = "STOP_ON_NO_DIVERSE_SAFE_TASK"
    if len(selected_tasks) >= 5 and unique_count < 3:
        status = "STOP_ON_NO_DIVERSE_SAFE_TASK"
    report = {
        "schema_version": SCHEMA_VERSION,
        "timestamp_utc": utc_now(),
        "status": status,
        "requested_cycles": cycles,
        "simulated_cycles": len(selected_tasks),
        "selected_tasks": selected_tasks,
        "unique_task_count": unique_count,
        "cycle_models": cycle_models,
        "diversity_status": diversity_status(inputs["recent_tasks"], selected_tasks[0] if selected_tasks else None),
        "live_apply": False,
        "emergency_stop": True,
        "allowed_apply_now": False,
        "high_blocked": True,
        "breach": False,
    }
    write_outputs(priority_model_from_scoring(score_tasks(inputs), "PRIORITY_MODEL_READY"), simulation=report)
    return report


def write_model() -> Dict[str, Any]:
    scoring = score_tasks()
    model = priority_model_from_scoring(scoring, "PRIORITY_MODEL_READY")
    write_outputs(model)
    return model


def write_outputs(model: Dict[str, Any], simulation: Optional[Dict[str, Any]] = None) -> None:
    write_json(REPORT_JSON, model)
    write_json(STATE_MODEL_JSON, model)
    write_json(LATEST_MODEL_JSON, model)
    write_json(COOLDOWNS_JSON, model["cooldowns"])
    diversity_history = load_list(DIVERSITY_HISTORY_JSON)
    diversity_history.append({
        "timestamp_utc": utc_now(),
        "selected_task": model.get("selected_task"),
        "diversity": model.get("diversity"),
        "simulation": simulation,
    })
    write_json(DIVERSITY_HISTORY_JSON, diversity_history[-200:])
    score_history = load_list(SCORE_HISTORY_JSON)
    score_history.append({
        "timestamp_utc": utc_now(),
        "selected_task": model.get("selected_task"),
        "top_scores": model.get("top_scores"),
    })
    write_json(SCORE_HISTORY_JSON, score_history[-200:])
    write_json(ANTI_LOOP_JSON, {
        "timestamp_utc": utc_now(),
        "anti_loop": model.get("anti_loop"),
        "cooldowns": model.get("cooldowns"),
        "rules": {
            "direct_repeat_limit": 1,
            "cooldowns": TASK_COOLDOWNS,
            "max_in_window": MAX_IN_LAST_WINDOW,
            "companion_only_tasks": sorted(COMPANION_ONLY_TASKS),
        },
    })
    write_markdown_outputs(model, simulation)
    write_playbooks()
    append_jsonl(AUDIT_JSONL, [{
        "timestamp_utc": utc_now(),
        "event": "priority_model",
        "status": model.get("status"),
        "selected_task": model.get("selected_task"),
        "selected_task_score": model.get("selected_task_score"),
        "breach": model.get("breach"),
        "live_apply": False,
        "allowed_apply_now": False,
    }])


def write_markdown_outputs(model: Dict[str, Any], simulation: Optional[Dict[str, Any]]) -> None:
    write_text(REPORT_MD, render_engine_md(model))
    write_text(TASK_SCORES_MD, render_scores_md(model))
    write_text(DIVERSITY_MD, render_diversity_md(model, simulation))
    write_text(ANTI_LOOP_MD, render_anti_loop_md(model))
    write_text(SELECTION_MD, render_selection_md(model))
    write_text(OWNER_SUMMARY_MD, render_owner_summary_md(model))


def render_engine_md(model: Dict[str, Any]) -> str:
    return "\n".join([
        "# Sentinel Autonomous Priority Engine",
        "",
        f"- status: `{model.get('status')}`",
        f"- selected_task: `{model.get('selected_task')}`",
        f"- selected_capability: `{model.get('selected_capability')}`",
        f"- selected_task_score: `{model.get('selected_task_score')}`",
        f"- risk_class: `{model.get('selected_task_risk_class')}`",
        f"- can_execute_now: `{model.get('can_execute_now')}`",
        f"- live_apply: `{model.get('live_apply')}`",
        f"- emergency_stop: `{model.get('emergency_stop')}`",
        f"- allowed_apply_now: `{model.get('allowed_apply_now')}`",
        f"- HIGH blocked: `{model.get('high_blocked')}`",
        f"- breach: `{model.get('breach')}`",
        "",
        "The engine only scores and selects safe local allowed tasks. It does not perform live apply or external actions.",
    ]) + "\n"


def render_scores_md(model: Dict[str, Any]) -> str:
    lines = ["# Sentinel Autonomous Task Scores", ""]
    for index, item in enumerate(model.get("task_scores") or [], start=1):
        lines.append(
            f"{index}. `{item.get('task')}` score=`{item.get('score')}` "
            f"risk=`{item.get('risk_class')}` executable=`{item.get('can_execute_now')}` "
            f"capability=`{item.get('capability_id')}` "
            f"reason={redact_text(item.get('reason'), 220)}"
        )
    return "\n".join(lines) + "\n"


def render_diversity_md(model: Dict[str, Any], simulation: Optional[Dict[str, Any]]) -> str:
    d = model.get("diversity") or {}
    lines = [
        "# Sentinel Autonomous Task Diversity",
        "",
        f"- status: `{d.get('status')}`",
        f"- last_three: `{', '.join(d.get('last_three_tasks') or []) or '-'}`",
        f"- unique_last_three: `{d.get('unique_last_three')}`",
        f"- unique_last_five: `{d.get('unique_last_five')}`",
    ]
    if simulation:
        lines.extend([
            "",
            "## Simulation",
            f"- status: `{simulation.get('status')}`",
            f"- selected_tasks: `{', '.join(simulation.get('selected_tasks') or []) or '-'}`",
            f"- unique_task_count: `{simulation.get('unique_task_count')}`",
        ])
    return "\n".join(lines) + "\n"


def render_anti_loop_md(model: Dict[str, Any]) -> str:
    a = model.get("anti_loop") or {}
    return "\n".join([
        "# Sentinel Autonomous Anti-Loop Governor",
        "",
        f"- status: `{a.get('status')}`",
        f"- selected_task: `{a.get('selected_task')}`",
        f"- direct_repeat: `{a.get('direct_repeat')}`",
        f"- cooldown_respected: `{a.get('cooldown_respected')}`",
        f"- safe_alternative_count: `{a.get('safe_alternative_count')}`",
        f"- safe_alternatives: `{', '.join(a.get('safe_alternatives') or []) or '-'}`",
    ]) + "\n"


def render_selection_md(model: Dict[str, Any]) -> str:
    return "\n".join([
        "# Sentinel Autonomous Priority Selection",
        "",
        f"- selected_task: `{model.get('selected_task')}`",
        f"- selected_capability: `{model.get('selected_capability')}`",
        f"- reason: {redact_text(model.get('selected_task_reason'), 400)}",
        f"- score: `{model.get('selected_task_score')}`",
        f"- risk_class: `{model.get('selected_task_risk_class')}`",
        f"- executable: `{model.get('selected_task_executable')}`",
        "",
        "If the selected task fails kernel classification, the kernel falls back to its built-in decision order.",
    ]) + "\n"


def render_owner_summary_md(model: Dict[str, Any]) -> str:
    top = model.get("top_scores") or []
    lines = [
        "# Sentinel Autonomous Priority Owner Summary",
        "",
        f"- selected next task: `{model.get('selected_task')}`",
        f"- selected capability: `{model.get('selected_capability')}`",
        f"- anti-loop status: `{(model.get('anti_loop') or {}).get('status')}`",
        f"- diversity status: `{(model.get('diversity') or {}).get('status')}`",
        f"- cooldown respected: `{(model.get('anti_loop') or {}).get('cooldown_respected')}`",
        "- live_apply: `False`",
        "- emergency_stop: `True`",
        "- allowed_apply_now: `False`",
        "- HIGH blocked: `True`",
        "- LOW_LIVE executable: `False`",
        "- MEDIUM executable: `False`",
        "- breach: `False`",
        "",
        "## Top Scores",
    ]
    for item in top:
        lines.append(f"- `{item.get('task')}`: score `{item.get('score')}` ({item.get('reason')})")
    return "\n".join(lines) + "\n"


def write_playbooks() -> None:
    base = {
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "live_apply": False,
        "emergency_stop": True,
        "allowed_apply_now": False,
        "high_blocked": True,
        "allowed_tasks": ALLOWED_TASKS,
        "auto_allowed_risk": sorted(AUTO_ALLOWED_RISK),
        "blocked_risk": sorted(BLOCKED_RISK),
    }
    write_json(PLAYBOOK_ENGINE, {
        **base,
        "name": "sentinel-autonomous-priority-engine",
        "purpose": "Score safe local autonomous tasks and select the next diverse task.",
        "score_components": [
            "urgency_score",
            "staleness_score",
            "missing_output_score",
            "validation_failure_score",
            "business_value_score",
            "learning_value_score",
            "repair_value_score",
            "freshness_penalty",
            "repetition_penalty",
            "blocked_penalty",
            "risk_penalty",
        ],
        "blocked_actions": ["live_apply", "network", "external_api", "wordpress", "cloudflare", "db", "sftp", "systemd", "cron"],
    })
    write_json(PLAYBOOK_ANTI_LOOP, {
        **base,
        "name": "sentinel-autonomy-anti-loop-governor",
        "cooldowns": TASK_COOLDOWNS,
        "max_in_window": MAX_IN_LAST_WINDOW,
        "companion_only_tasks": sorted(COMPANION_ONLY_TASKS),
        "stop_reason": "STOP_ON_NO_DIVERSE_SAFE_TASK",
    })
    write_json(PLAYBOOK_DIVERSITY, {
        **base,
        "name": "sentinel-autonomy-task-diversity",
        "rules": [
            "at least two distinct main tasks in three cycles when safe tasks exist",
            "at least three distinct main tasks in five cycles when safe tasks exist",
            "otherwise stop with STOP_ON_NO_DIVERSE_SAFE_TASK",
        ],
    })
    write_json(PLAYBOOK_INTEGRATION, {
        **base,
        "name": "sentinel-autonomy-priority-integration",
        "kernel_model_path": rel(STATE_MODEL_JSON),
        "kernel_accepts_model_only_when": [
            "integration_enabled=true",
            "selected task is allowed",
            "risk class is auto allowed",
            "can_execute_now=true",
            "breach=false",
        ],
        "fallback": "built-in kernel decision order",
    })


def action_scan_history() -> Dict[str, Any]:
    inputs = read_inputs()
    model = priority_model_from_scoring(score_tasks(inputs), "PRIORITY_HISTORY_SCANNED")
    write_outputs(model)
    return model


def action_score_tasks() -> Dict[str, Any]:
    scoring = score_tasks()
    model = priority_model_from_scoring(scoring, "PRIORITY_TASKS_SCORED")
    write_outputs(model)
    return model


def action_status() -> Dict[str, Any]:
    model = load_dict(LATEST_MODEL_JSON) or load_dict(STATE_MODEL_JSON)
    if not model:
        return {"status": "NO_PRIORITY_MODEL", "breach": False, **HARD_DEFAULTS}
    return model


def source_safety_findings(source: str) -> List[str]:
    findings: List[str] = []
    if re.search(r"add_argument\([\"']--apply", source):
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
    failures: List[str] = []
    source = Path(__file__).read_text(encoding="utf-8")
    failures.extend(source_safety_findings(source))
    if set(ALLOWED_TASKS) != set(TASK_RISK):
        failures.append("allowed_tasks_and_risk_map_mismatch")
    if len(ALLOWED_TASKS) != 16:
        failures.append("allowed_task_count_mismatch")
    for task in ALLOWED_TASKS:
        if TASK_RISK.get(task) in BLOCKED_RISK:
            failures.append(f"blocked_risk_in_allowed_task:{task}")
    scoring_a = score_tasks(read_inputs(), recent_override=["generate_next_safe_actions"] * 3)
    scoring_b = score_tasks(read_inputs(), recent_override=["generate_next_safe_actions"] * 3)
    if json.dumps(scoring_a["top_scores"], sort_keys=True) != json.dumps(scoring_b["top_scores"], sort_keys=True):
        failures.append("scores_not_reproducible")
    if scoring_a["selected"] and scoring_a["selected"]["task"] == "generate_next_safe_actions":
        failures.append("generate_next_safe_actions_not_cooled_down")
    simulated = simulate_diversity(3)
    if simulated["simulated_cycles"] >= 3 and simulated["unique_task_count"] < 2:
        failures.append("diversity_rule_failed")
    model = priority_model_from_scoring(scoring_a)
    if model.get("live_apply") is not False or model.get("allowed_apply_now") is not False:
        failures.append("hard_defaults_changed")
    for path in [REPORT_JSON, STATE_MODEL_JSON, AUDIT_JSONL, PLAYBOOK_ENGINE]:
        try:
            assert_allowed_write(path)
        except Exception as exc:
            failures.append(f"write_root_invalid:{exc}")
    secret_sample = "password" + "=" + "abcdefghijklmnop"
    if detect_secret_like(secret_sample):
        masked = redact_text(secret_sample)
        if "abcdefghijklmnop" in masked:
            failures.append("secret_redaction_failed")
    if not failures:
        write_outputs(model)
    status = "PRIORITY_ENGINE_SELF_TEST_OK" if not failures else "PRIORITY_ENGINE_SELF_TEST_FAILED"
    report = {
        "schema_version": SCHEMA_VERSION,
        "timestamp_utc": utc_now(),
        "status": status,
        "self_test_failures": failures,
        **HARD_DEFAULTS,
        "breach": bool(failures),
    }
    if failures:
        write_json(REPORT_JSON, report)
    return report


def detect_secret_like(text: str) -> bool:
    return bool(SECRET_RE.search(text) or PRIVATE_KEY_RE.search(text) or TOKEN_FORMAT_RE.search(text))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Sentinel Autonomous Priority Engine.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--scan-history", action="store_true")
    group.add_argument("--score-tasks", action="store_true")
    group.add_argument("--select-next", action="store_true")
    group.add_argument("--simulate-diversity", action="store_true")
    group.add_argument("--write-model", action="store_true")
    group.add_argument("--status", action="store_true")
    return parser


def print_summary(report: Dict[str, Any]) -> None:
    selected = report.get("selected_task")
    if not selected and isinstance(report.get("selected"), dict):
        selected = report["selected"].get("task")
    print(f"status={report.get('status')}")
    print(f"selected_task={selected or '-'}")
    print(f"selected_capability={report.get('selected_capability') or '-'}")
    print(f"live_apply={report.get('live_apply', False)}")
    print(f"emergency_stop={report.get('emergency_stop', True)}")
    print(f"allowed_apply_now={report.get('allowed_apply_now', False)}")
    print(f"high_blocked={report.get('high_blocked', True)}")
    print(f"low_live_executable={report.get('low_live_executable', False)}")
    print(f"medium_executable={report.get('medium_executable', False)}")
    print(f"breach={report.get('breach', False)}")
    top = report.get("top_scores") or []
    if top:
        print("top_tasks=" + ",".join(f"{item['task']}:{item['score']}" for item in top[:5]))


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.self_test:
            report = action_self_test()
        elif args.scan_history:
            report = action_scan_history()
        elif args.score_tasks:
            report = action_score_tasks()
        elif args.select_next:
            report = select_next()
        elif args.simulate_diversity:
            report = simulate_diversity(3)
        elif args.write_model:
            report = write_model()
        elif args.status:
            report = action_status()
        else:
            raise AssertionError("unreachable")
        print_summary(report)
        return 0 if not report.get("breach") else 2
    except Exception as exc:
        report = {
            "schema_version": SCHEMA_VERSION,
            "timestamp_utc": utc_now(),
            "status": "PRIORITY_ENGINE_FAILED",
            "error": redact_text(exc, 500),
            **HARD_DEFAULTS,
            "breach": True,
        }
        try:
            write_json(REPORT_JSON, report)
        except Exception:
            pass
        print_summary(report)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
