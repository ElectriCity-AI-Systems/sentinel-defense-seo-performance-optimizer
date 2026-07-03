#!/usr/bin/env python3
"""Sentinel Autonomous Operation Governor (Phase 10.8).

Scores safe local supervisor operations by impact, freshness, repetition,
cooldown and no-op signals. The governor writes a machine-readable operation
model for the Operations Supervisor. It never performs live apply, network
access, external API calls, remote writes, timer installation or customer
system changes.
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


PROJECT_DIR = Path("/srv/sentinel-defense")
SCHEMA_VERSION = "sentinel-autonomous-operation-governor-10.8"
PHASE = "10.8"

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

REPORT_JSON = R / "sentinel-autonomous-operation-governor.json"
REPORT_MD = R / "sentinel-autonomous-operation-governor.md"
SCORES_MD = R / "sentinel-autonomous-operation-scores.md"
NOOP_MD = R / "sentinel-autonomous-operation-noop-analysis.md"
DIVERSITY_MD = R / "sentinel-autonomous-operation-diversity.md"
SELECTION_MD = R / "sentinel-autonomous-operation-selection.md"
OWNER_SUMMARY_MD = R / "sentinel-autonomous-operation-governor-owner-summary.md"

STATE_JSON = STATE_DIR / "autonomous_operation_governor.json"
LATEST_JSON = STATE_DIR / "latest_autonomous_operation_governor.json"
MODEL_JSON = STATE_DIR / "autonomous_operation_governor_model.json"
COOLDOWNS_JSON = STATE_DIR / "autonomous_operation_cooldowns.json"
NOOP_HISTORY_JSON = STATE_DIR / "autonomous_operation_noop_history.json"
DIVERSITY_HISTORY_JSON = STATE_DIR / "autonomous_operation_diversity_history.json"
SCORE_HISTORY_JSON = STATE_DIR / "autonomous_operation_score_history.json"

AUDIT_JSONL = AUDIT_DIR / "sentinel-autonomous-operation-governor.jsonl"

PLAYBOOK_GOVERNOR = PLAYBOOK_DIR / "sentinel-autonomous-operation-governor.playbook.json"
PLAYBOOK_IMPACT = PLAYBOOK_DIR / "sentinel-autonomous-operation-impact-scoring.playbook.json"
PLAYBOOK_NOOP = PLAYBOOK_DIR / "sentinel-autonomous-operation-noop-detection.playbook.json"
PLAYBOOK_DIVERSITY = PLAYBOOK_DIR / "sentinel-autonomous-operation-diversity.playbook.json"

SUPERVISOR_JSON = STATE_DIR / "autonomous_operations_supervisor.json"
LATEST_SUPERVISOR_JSON = STATE_DIR / "latest_autonomous_operations_supervisor.json"
OPERATIONS_HISTORY_JSON = STATE_DIR / "autonomous_operations_history.json"
OPERATION_PATTERNS_JSON = STATE_DIR / "autonomous_operation_patterns.json"
BLOCKED_OPERATION_PATTERNS_JSON = STATE_DIR / "autonomous_blocked_operation_patterns.json"
MISSION_RUNNER_JSON = STATE_DIR / "autonomous_mission_queue_runner.json"
MISSION_RUNNER_LATEST_JSON = STATE_DIR / "latest_autonomous_mission_queue_runner.json"
MISSION_LEDGER_JSON = STATE_DIR / "autonomous_mission_completion_ledger.json"
GOAL_MANAGER_JSON = STATE_DIR / "autonomous_goal_manager.json"
GOAL_MANAGER_LATEST_JSON = STATE_DIR / "latest_autonomous_goal_manager.json"
HEALTH_GOVERNOR_JSON = STATE_DIR / "autonomous_capability_health_governor.json"
HEALTH_GOVERNOR_LATEST_JSON = STATE_DIR / "latest_autonomous_capability_health_governor.json"
CAPABILITY_REGISTRY_JSON = STATE_DIR / "autonomous_capability_registry.json"
PRIORITY_MODEL_JSON = STATE_DIR / "autonomy_task_priority_model.json"
SOAK_TEST_JSON = STATE_DIR / "latest_autonomous_soak_test.json"
SOAK_TEST_REPORT_JSON = R / "sentinel-autonomous-soak-test.json"

REPORT_INPUTS = {
    "supervisor": R / "sentinel-autonomous-operations-supervisor.json",
    "mission_runner": R / "sentinel-autonomous-mission-queue-runner.json",
    "goal_manager": R / "sentinel-autonomous-goal-manager.json",
    "health_governor": R / "sentinel-autonomous-capability-health-governor.json",
    "capability_registry": R / "sentinel-autonomous-capability-registry.json",
    "priority_engine": R / "sentinel-autonomous-priority-engine.json",
    "kernel": R / "sentinel-self-governing-autonomy-kernel.json",
    "cycle_runner": R / "sentinel-autonomous-cycle-runner.json",
    "soak_test": SOAK_TEST_REPORT_JSON,
}

ALLOWED_WRITE_ROOTS = (R, STATE_DIR, AUDIT_DIR, PLAYBOOK_DIR)

OPERATION_DEFS = {
    "run_health_governor_cycle": {
        "risk_class": LOW_STATE,
        "linked_module": "sentinel_autonomous_capability_health_governor.py",
        "allowed_args": ["--cycle"],
        "business": 22,
        "safety": 40,
        "learning": 32,
        "expected_outputs": [
            "reports/latest/sentinel-autonomous-capability-health-governor.json",
            "state/adaptive-learning/latest_autonomous_capability_health_governor.json",
        ],
        "freshness_outputs": ["state/adaptive-learning/latest_autonomous_capability_health_governor.json"],
    },
    "run_goal_manager_cycle": {
        "risk_class": LOW_STATE,
        "linked_module": "sentinel_autonomous_goal_manager.py",
        "allowed_args": ["--cycle"],
        "business": 26,
        "safety": 34,
        "learning": 34,
        "expected_outputs": [
            "reports/latest/sentinel-autonomous-goal-manager.json",
            "state/adaptive-learning/autonomous_mission_queue.json",
        ],
        "freshness_outputs": ["state/adaptive-learning/autonomous_mission_queue.json"],
    },
    "run_mission_queue_runner": {
        "risk_class": LOW_STATE,
        "linked_module": "sentinel_autonomous_mission_queue_runner.py",
        "allowed_args": ["--run-missions", "3"],
        "business": 34,
        "safety": 30,
        "learning": 36,
        "expected_outputs": [
            "reports/latest/sentinel-autonomous-mission-queue-runner.json",
            "state/adaptive-learning/autonomous_mission_completion_ledger.json",
        ],
        "freshness_outputs": ["state/adaptive-learning/latest_autonomous_mission_queue_runner.json"],
    },
    "run_priority_engine_model": {
        "risk_class": LOW_STATE,
        "linked_module": "sentinel_autonomous_priority_engine.py",
        "allowed_args": ["--write-model"],
        "business": 24,
        "safety": 30,
        "learning": 42,
        "expected_outputs": ["state/adaptive-learning/autonomy_task_priority_model.json"],
        "freshness_outputs": ["state/adaptive-learning/autonomy_task_priority_model.json"],
    },
    "run_capability_registry_refresh": {
        "risk_class": LOW_STATE,
        "linked_module": "sentinel_autonomous_capability_registry.py",
        "allowed_args": ["--write-registry"],
        "business": 24,
        "safety": 34,
        "learning": 36,
        "expected_outputs": ["state/adaptive-learning/autonomous_capability_registry.json"],
        "freshness_outputs": ["state/adaptive-learning/autonomous_capability_registry.json"],
    },
    "run_kernel_safe_cycle": {
        "risk_class": LOW_STATE,
        "linked_module": "sentinel_self_governing_safe_autonomy_kernel.py",
        "allowed_args": ["--cycle"],
        "business": 20,
        "safety": 28,
        "learning": 34,
        "expected_outputs": ["reports/latest/sentinel-self-governing-autonomy-kernel.json"],
        "freshness_outputs": ["state/adaptive-learning/latest_self_governing_autonomy_kernel.json"],
    },
    "build_owner_briefing": {
        "risk_class": DRAFT,
        "linked_module": None,
        "allowed_args": [],
        "business": 18,
        "safety": 26,
        "learning": 18,
        "expected_outputs": ["reports/latest/sentinel-autonomous-owner-briefing.md"],
        "freshness_outputs": ["reports/latest/sentinel-autonomous-owner-briefing.md"],
    },
    "validate_system": {
        "risk_class": READ_ONLY,
        "linked_module": None,
        "allowed_args": [],
        "business": 10,
        "safety": 42,
        "learning": 14,
        "expected_outputs": ["reports/latest/sentinel-autonomous-system-validation.md"],
        "freshness_outputs": ["reports/latest/sentinel-autonomous-system-validation.md"],
    },
    "status_only": {
        "risk_class": READ_ONLY,
        "linked_module": None,
        "allowed_args": [],
        "business": 4,
        "safety": 12,
        "learning": 6,
        "expected_outputs": ["reports/latest/sentinel-autonomous-operations-supervisor.json"],
        "freshness_outputs": ["reports/latest/sentinel-autonomous-operations-supervisor.json"],
    },
}

COOLDOWN_RULES = {
    "run_mission_queue_runner": 1,
    "run_health_governor_cycle": 2,
    "run_priority_engine_model": 2,
    "run_capability_registry_refresh": 3,
    "run_kernel_safe_cycle": 1,
    "build_owner_briefing": 1,
    "validate_system": 0,
    "status_only": 0,
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
CUSTOMER_DATA_RE = re.compile(
    r"(?i)(customer\s+credential\s*[:=]|payment\s+card\s*[:=]|iban\s*[:=]|ssn\s*[:=])"
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
        raise RuntimeError(f"Refusing write outside allowed local roots: {rel(path)}")


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


def append_jsonl(path: Path, rows: List[Dict[str, Any]]) -> None:
    assert_write_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for row in rows:
            line = json.dumps(row, sort_keys=True)
            assert_safe_text(line, path)
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
    if status == "ok" and isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if status == "ok" and isinstance(data, dict) and isinstance(data.get("entries"), list):
        return [item for item in data["entries"] if isinstance(item, dict)]
    return []


def age_hours(path_value: str) -> Optional[float]:
    path = PROJECT_DIR / path_value
    if not path.exists():
        return None
    return max(0.0, (datetime.now(timezone.utc).timestamp() - path.stat().st_mtime) / 3600.0)


def scan_operations() -> Dict[str, Any]:
    inputs = {
        "state_inputs": {},
        "report_inputs": {},
        "missing_inputs": [],
        "operations_history": load_entries(OPERATIONS_HISTORY_JSON),
        "operation_patterns": load_dict(OPERATION_PATTERNS_JSON),
        "blocked_operation_patterns": load_dict(BLOCKED_OPERATION_PATTERNS_JSON),
    }
    state_paths = {
        "supervisor": SUPERVISOR_JSON,
        "latest_supervisor": LATEST_SUPERVISOR_JSON,
        "mission_runner": MISSION_RUNNER_JSON,
        "completion_ledger": MISSION_LEDGER_JSON,
        "goal_manager": GOAL_MANAGER_JSON,
        "health_governor": HEALTH_GOVERNOR_JSON,
        "capability_registry": CAPABILITY_REGISTRY_JSON,
        "priority_model": PRIORITY_MODEL_JSON,
        "soak_test": SOAK_TEST_JSON,
    }
    for name, path in state_paths.items():
        data, status = read_json(path)
        inputs["state_inputs"][name] = {"status": status, "path": rel(path), "data": data if isinstance(data, dict) else {}}
        if status == "missing":
            inputs["missing_inputs"].append(rel(path))
    soak_data = load_dict(SOAK_TEST_JSON) or load_dict(SOAK_TEST_REPORT_JSON)
    inputs["soak_context"] = {
        "last_soak_status": soak_data.get("status") if soak_data else "not_available",
        "readiness_seal": soak_data.get("readiness_seal") if soak_data else None,
        "no_op_status": ((soak_data.get("readiness") or {}).get("noop_status") or {}).get("status") if soak_data else None,
        "diversity_status": ((soak_data.get("readiness") or {}).get("operation_diversity") or {}).get("status") if soak_data else None,
    }
    for name, path in REPORT_INPUTS.items():
        data, status = read_json(path)
        inputs["report_inputs"][name] = {"status": status, "path": rel(path), "data": data if isinstance(data, dict) else {}}
        if status == "missing":
            inputs["missing_inputs"].append(rel(path))
    report = {
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "timestamp_utc": utc_now(),
        "action": "scan-operations",
        "status": "OPERATION_SCAN_OK",
        "operations": list(OPERATION_DEFS),
        "operation_count": len(OPERATION_DEFS),
        "inputs": inputs,
        **HARD_DEFAULTS,
    }
    write_outputs(report)
    return report


def recent_operations(inputs: Dict[str, Any]) -> List[str]:
    history = inputs.get("operations_history") if isinstance(inputs.get("operations_history"), list) else []
    return [str(item.get("selected_operation")) for item in history if isinstance(item, dict) and item.get("selected_operation")]


def cooldown_remaining(operation: str, recent: List[str]) -> int:
    cooldown = COOLDOWN_RULES.get(operation, 0)
    if cooldown <= 0 or operation not in recent:
        return 0
    distance = len(recent) - 1 - max(i for i, op in enumerate(recent) if op == operation)
    return max(0, cooldown - distance)


def output_freshness(outputs: List[str]) -> int:
    if not outputs:
        return 75
    scores: List[int] = []
    for output in outputs:
        path = PROJECT_DIR / output
        if not path.exists():
            scores.append(15)
            continue
        age = age_hours(output)
        if age is None:
            scores.append(35)
        elif age < 1:
            scores.append(100)
        elif age < 6:
            scores.append(85)
        elif age < 24:
            scores.append(60)
        else:
            scores.append(30)
    return int(sum(scores) / len(scores))


def ledger_count(inputs: Dict[str, Any]) -> int:
    data = ((inputs.get("state_inputs") or {}).get("completion_ledger") or {}).get("data") or {}
    return int(data.get("completed_count") or 0) if isinstance(data, dict) else 0


def health_warning_count(inputs: Dict[str, Any]) -> int:
    data = ((inputs.get("state_inputs") or {}).get("health_governor") or {}).get("data") or {}
    return int(data.get("warning_count") or 0) if isinstance(data, dict) else 0


def mission_queue_open(inputs: Dict[str, Any]) -> bool:
    goal = ((inputs.get("state_inputs") or {}).get("goal_manager") or {}).get("data") or {}
    count = int(goal.get("executable_mission_count") or 0) if isinstance(goal, dict) else 0
    if count > 0:
        return True
    queue = goal.get("mission_queue") or goal.get("classified_missions") or goal.get("routed_missions") or []
    return isinstance(queue, list) and any(isinstance(item, dict) and item.get("can_execute_autonomously") for item in queue)


def detect_noops(scan: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    scan = scan or scan_operations()
    inputs = scan.get("inputs") if isinstance(scan.get("inputs"), dict) else {}
    recent = recent_operations(inputs)
    noops: Dict[str, Dict[str, Any]] = {}
    repeated = {operation: recent[-5:].count(operation) for operation in OPERATION_DEFS}
    supervisor = ((inputs.get("state_inputs") or {}).get("latest_supervisor") or {}).get("data") or {}
    for operation in OPERATION_DEFS:
        reasons: List[str] = []
        if repeated.get(operation, 0) >= 3:
            reasons.append("same_operation_repeated_in_recent_window")
        if operation == "run_mission_queue_runner":
            if repeated.get(operation, 0) >= 3 and supervisor.get("stop_reason") == "STOP_ON_MAX_BATCH":
                reasons.append("repeated_max_batch_without_operation_diversity")
            if not mission_queue_open(inputs):
                reasons.append("no_executable_mission_queue_signal")
        if operation == "validate_system" and repeated.get(operation, 0) >= 2:
            reasons.append("validation_only_not_counted_as_progress")
        if operation == "status_only":
            reasons.append("status_only_low_progress")
        noops[operation] = {
            "operation": operation,
            "is_noop_candidate": bool(reasons),
            "reasons": reasons,
            "recent_count": repeated.get(operation, 0),
        }
    report = {
        **scan,
        "action": "detect-noops",
        "status": "OPERATION_NOOP_ANALYSIS_READY",
        "noop_analysis": noops,
        "noop_count": sum(1 for item in noops.values() if item["is_noop_candidate"]),
        **HARD_DEFAULTS,
    }
    write_outputs(report)
    write_json(NOOP_HISTORY_JSON, {"entries": [{"timestamp_utc": utc_now(), "noop_analysis": noops}], **HARD_DEFAULTS})
    return report


def impact_for_operation(operation: str, inputs: Dict[str, Any]) -> Tuple[int, List[str]]:
    reasons: List[str] = []
    impact = 0
    if operation == "run_mission_queue_runner":
        count = ledger_count(inputs)
        if count > 0:
            impact += min(50, 16 + count)
            reasons.append(f"completion_ledger_count_{count}")
        if mission_queue_open(inputs):
            impact += 18
            reasons.append("safe_missions_open")
    elif operation == "run_health_governor_cycle":
        warnings = health_warning_count(inputs)
        if warnings:
            impact += min(55, 22 + warnings * 12)
            reasons.append(f"capability_warnings_{warnings}")
        else:
            impact += 8
            reasons.append("health_ok_validation_value")
    elif operation == "run_goal_manager_cycle":
        if ((inputs.get("state_inputs") or {}).get("goal_manager") or {}).get("status") != "ok":
            impact += 45
            reasons.append("goal_manager_state_missing")
        else:
            impact += 16
            reasons.append("mission_queue_refresh_value")
    elif operation == "run_priority_engine_model":
        if ((inputs.get("state_inputs") or {}).get("priority_model") or {}).get("status") != "ok":
            impact += 46
            reasons.append("priority_model_missing")
        else:
            impact += 22
            reasons.append("priority_rescore_value")
    elif operation == "run_capability_registry_refresh":
        if ((inputs.get("state_inputs") or {}).get("capability_registry") or {}).get("status") != "ok":
            impact += 46
            reasons.append("capability_registry_missing")
        else:
            impact += 20
            reasons.append("capability_refresh_value")
    elif operation == "run_kernel_safe_cycle":
        impact += 18
        reasons.append("safe_kernel_fallback_value")
    elif operation == "build_owner_briefing":
        impact += 14
        reasons.append("owner_briefing_value")
    elif operation == "validate_system":
        impact += 16
        reasons.append("validation_value")
    else:
        impact += 2
        reasons.append("status_only_value")
    return min(100, impact), reasons


def score_operations(scan: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    scan = scan or scan_operations()
    inputs = scan.get("inputs") if isinstance(scan.get("inputs"), dict) else {}
    recent = recent_operations(inputs)
    noop_report = detect_noops(scan)
    noop_map = noop_report.get("noop_analysis") if isinstance(noop_report.get("noop_analysis"), dict) else {}
    scores: List[Dict[str, Any]] = []
    for operation, meta in OPERATION_DEFS.items():
        freshness = output_freshness(meta["freshness_outputs"])
        impact, impact_reasons = impact_for_operation(operation, inputs)
        cooldown = cooldown_remaining(operation, recent)
        repetition = recent[-3:].count(operation) * 22
        noop_penalty = 45 if (noop_map.get(operation) or {}).get("is_noop_candidate") else 0
        blocked_penalty = 0
        risk_penalty = 0 if meta["risk_class"] in AUTO_ALLOWED_RISK else 1000
        if cooldown:
            blocked_penalty += cooldown * 35
        if operation == "run_mission_queue_runner" and not mission_queue_open(inputs):
            blocked_penalty += 40
        if operation == "status_only" and any(score > 0 for score in [impact]):
            blocked_penalty += 30
        urgency = max(0, 100 - freshness) // 2
        repair = min(40, health_warning_count(inputs) * 12) if operation == "run_health_governor_cycle" else 0
        mission_value = 32 if operation == "run_mission_queue_runner" and mission_queue_open(inputs) else 0
        validation_value = 18 if operation == "validate_system" else 0
        final = (
            urgency
            + freshness // 5
            + impact
            + meta["business"]
            + meta["safety"]
            + meta["learning"]
            + repair
            + mission_value
            + validation_value
            - repetition
            - noop_penalty
            - blocked_penalty
            - risk_penalty
        )
        can_execute = (
            meta["risk_class"] in AUTO_ALLOWED_RISK
            and cooldown == 0
            and blocked_penalty < 80
            and risk_penalty == 0
            and final > 0
        )
        reason_if_blocked = None
        if not can_execute:
            reason_if_blocked = "cooldown_or_penalty_or_nonpositive_score"
        scores.append({
            "operation_id": operation.upper(),
            "operation_name": operation,
            "risk_class": meta["risk_class"],
            "linked_module": meta["linked_module"],
            "allowed_args": meta["allowed_args"],
            "allowed_scope": ["reports/latest", "state/adaptive-learning", "audit", "playbooks"],
            "expected_outputs": meta["expected_outputs"],
            "freshness_outputs": meta["freshness_outputs"],
            "urgency_score": urgency,
            "freshness_score": freshness,
            "impact_score": impact,
            "impact_reasons": impact_reasons,
            "business_value_score": meta["business"],
            "safety_value_score": meta["safety"],
            "learning_value_score": meta["learning"],
            "repair_value_score": repair,
            "mission_value_score": mission_value,
            "validation_value_score": validation_value,
            "repetition_penalty": repetition,
            "noop_penalty": noop_penalty,
            "blocked_penalty": blocked_penalty,
            "risk_penalty": risk_penalty,
            "cooldown_remaining": cooldown,
            "final_score": int(final),
            "can_execute_now": can_execute,
            "reason_if_blocked": reason_if_blocked,
        })
    scores.sort(key=lambda item: (item["can_execute_now"], item["final_score"], item["operation_name"]), reverse=True)
    report = {
        **scan,
        "action": "score-operations",
        "status": "OPERATION_SCORES_READY",
        "operation_scores": scores,
        "top_scores": scores[:5],
        "noop_analysis": noop_map,
        "noop_count": sum(1 for item in noop_map.values() if isinstance(item, dict) and item.get("is_noop_candidate")),
        "recent_operations": recent[-10:],
        "cooldown_status": "OPERATION_COOLDOWNS_CLEAR" if not any(item.get("cooldown_remaining") for item in scores) else "OPERATION_COOLDOWNS_ACTIVE",
        **HARD_DEFAULTS,
    }
    write_outputs(report)
    write_json(SCORE_HISTORY_JSON, {"entries": [{"timestamp_utc": utc_now(), "top_scores": scores[:5]}], **HARD_DEFAULTS})
    return report


def diversity_status(scores: List[Dict[str, Any]], recent: List[str], selected: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    last_three = recent[-3:]
    last_five = recent[-5:]
    safe_ops = [item["operation_name"] for item in scores if item.get("can_execute_now") and item.get("final_score", 0) > 0]
    status = "OPERATION_DIVERSITY_OK"
    if len(last_three) >= 3 and len(set(last_three)) < 2 and len(set(safe_ops)) >= 2:
        status = "STOP_ON_NO_DIVERSE_SAFE_OPERATION"
    if len(last_five) >= 5 and len(set(last_five)) < 3 and len(set(safe_ops)) >= 3:
        status = "STOP_ON_NO_DIVERSE_SAFE_OPERATION"
    return {
        "status": status,
        "recent_three": last_three,
        "recent_five": last_five,
        "safe_alternatives": safe_ops[:8],
        "selected_operation": selected.get("operation_name") if selected else None,
    }


def select_operation(scoring: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    scoring = scoring or score_operations()
    scores = scoring.get("operation_scores") if isinstance(scoring.get("operation_scores"), list) else []
    recent = scoring.get("recent_operations") if isinstance(scoring.get("recent_operations"), list) else []
    selected = next((item for item in scores if item.get("can_execute_now")), None)
    diversity = diversity_status(scores, recent, selected)
    if diversity["status"] != "OPERATION_DIVERSITY_OK":
        alternatives = [
            item for item in scores
            if item.get("can_execute_now")
            and item.get("operation_name") not in set(recent[-3:])
        ]
        if alternatives:
            selected = alternatives[0]
            diversity["selected_operation"] = selected.get("operation_name")
            diversity["status"] = "OPERATION_DIVERSITY_OK"
    status = "OPERATION_SELECTION_READY" if selected else "STOP_ON_NO_DIVERSE_SAFE_OPERATION"
    report = {
        **scoring,
        "action": "select-operation",
        "status": status,
        "selected_operation": selected,
        "selected_operation_name": selected.get("operation_name") if selected else None,
        "diversity": diversity,
        **HARD_DEFAULTS,
    }
    write_outputs(report)
    write_json(DIVERSITY_HISTORY_JSON, {"entries": [{"timestamp_utc": utc_now(), "diversity": diversity}], **HARD_DEFAULTS})
    return report


def write_model() -> Dict[str, Any]:
    selection = select_operation()
    selected = selection.get("selected_operation") if isinstance(selection.get("selected_operation"), dict) else None
    model = {
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "timestamp_utc": utc_now(),
        "status": "OPERATION_GOVERNOR_MODEL_READY" if selected else "OPERATION_GOVERNOR_NO_SAFE_OPERATION",
        "selected_operation": selected,
        "selected_operation_name": selected.get("operation_name") if selected else None,
        "operation_scores": selection.get("operation_scores", []),
        "top_scores": selection.get("top_scores", []),
        "noop_analysis": selection.get("noop_analysis", {}),
        "noop_count": selection.get("noop_count", 0),
        "diversity": selection.get("diversity", {}),
        "recent_operations": selection.get("recent_operations", []),
        "cooldown_status": selection.get("cooldown_status", "OPERATION_COOLDOWNS_UNKNOWN"),
        "cooldowns": {
            item["operation_name"]: item.get("cooldown_remaining", 0)
            for item in selection.get("operation_scores", [])
            if isinstance(item, dict)
        },
        **HARD_DEFAULTS,
    }
    write_json(MODEL_JSON, model)
    write_json(COOLDOWNS_JSON, {"cooldowns": model["cooldowns"], "cooldown_status": model["cooldown_status"], **HARD_DEFAULTS})
    write_outputs({**selection, "status": model["status"], "model": model})
    return model


def write_playbooks(report: Dict[str, Any]) -> None:
    base = {"schema_version": SCHEMA_VERSION, "phase": PHASE, **HARD_DEFAULTS}
    write_json(PLAYBOOK_GOVERNOR, {
        **base,
        "name": "sentinel-autonomous-operation-governor",
        "purpose": "Score safe local operations by impact, no-op, cooldown and diversity.",
        "allowed_operations": list(OPERATION_DEFS),
        "blocked_actions": ["live_apply", "network", "remote_write", "external_api", "timer_install", "HIGH_MEDIUM_LOW_LIVE_execution"],
    })
    write_json(PLAYBOOK_IMPACT, {
        **base,
        "name": "sentinel-autonomous-operation-impact-scoring",
        "impact_signals": [
            "completion ledger extended",
            "mission completions increased",
            "health warnings reduced",
            "registry or priority model refreshed",
            "validation or owner briefing updated",
        ],
    })
    write_json(PLAYBOOK_NOOP, {
        **base,
        "name": "sentinel-autonomous-operation-noop-detection",
        "noop_signals": [
            "same operation repeated",
            "no new ledger entry",
            "no health or score change",
            "same selected operation without new reason",
            "STOP_ON_MAX_BATCH without other effect",
        ],
    })
    write_json(PLAYBOOK_DIVERSITY, {
        **base,
        "name": "sentinel-autonomous-operation-diversity",
        "rules": [
            "at least two different operations in three steps when safe alternatives exist",
            "at least three different operations in five steps when safe alternatives exist",
            "choose safe alternative when repeated operation is in cooldown",
        ],
    })


def render_report_md(report: Dict[str, Any]) -> str:
    return "\n".join([
        "# Sentinel Autonomous Operation Governor",
        "",
        f"- status: `{report.get('status')}`",
        f"- action: `{report.get('action')}`",
        f"- selected_operation: `{report.get('selected_operation_name')}`",
        f"- operations_scanned: `{report.get('operation_count', len(OPERATION_DEFS))}`",
        f"- breach: `False`",
        f"- live_apply: `False`",
        f"- emergency_stop: `True`",
        f"- allowed_apply_now: `False`",
        f"- HIGH blocked: `True`",
        f"- LOW_LIVE executable: `False`",
        f"- MEDIUM executable: `False`",
    ]) + "\n"


def render_scores_md(report: Dict[str, Any]) -> str:
    lines = ["# Sentinel Autonomous Operation Scores", ""]
    for item in report.get("top_scores") or report.get("operation_scores", [])[:5]:
        lines.append(
            f"- `{item.get('operation_name')}` score=`{item.get('final_score')}` "
            f"impact=`{item.get('impact_score')}` noop_penalty=`{item.get('noop_penalty')}` "
            f"cooldown=`{item.get('cooldown_remaining')}` can_execute=`{item.get('can_execute_now')}`"
        )
    return "\n".join(lines) + "\n"


def render_noop_md(report: Dict[str, Any]) -> str:
    lines = ["# Sentinel Autonomous Operation No-Op Analysis", ""]
    noop = report.get("noop_analysis") if isinstance(report.get("noop_analysis"), dict) else {}
    for operation, item in sorted(noop.items()):
        lines.append(f"- `{operation}` noop=`{item.get('is_noop_candidate')}` reasons=`{','.join(item.get('reasons') or []) or '-'}`")
    return "\n".join(lines) + "\n"


def render_diversity_md(report: Dict[str, Any]) -> str:
    diversity = report.get("diversity") if isinstance(report.get("diversity"), dict) else {}
    return "\n".join([
        "# Sentinel Autonomous Operation Diversity",
        "",
        f"- status: `{diversity.get('status', '-')}`",
        f"- recent_three: `{', '.join(diversity.get('recent_three') or []) or '-'}`",
        f"- selected_operation: `{diversity.get('selected_operation', report.get('selected_operation_name'))}`",
        f"- safe_alternatives: `{', '.join(diversity.get('safe_alternatives') or []) or '-'}`",
    ]) + "\n"


def render_selection_md(report: Dict[str, Any]) -> str:
    selected = report.get("selected_operation") if isinstance(report.get("selected_operation"), dict) else {}
    return "\n".join([
        "# Sentinel Autonomous Operation Selection",
        "",
        f"- selected_operation: `{selected.get('operation_name')}`",
        f"- final_score: `{selected.get('final_score')}`",
        f"- risk_class: `{selected.get('risk_class')}`",
        f"- reason_if_blocked: `{selected.get('reason_if_blocked', '-')}`",
    ]) + "\n"


def render_owner_summary_md(report: Dict[str, Any]) -> str:
    return "\n".join([
        "# Sentinel Autonomous Operation Governor Owner Summary",
        "",
        f"- selected_operation: `{report.get('selected_operation_name')}`",
        f"- status: `{report.get('status')}`",
        f"- diversity: `{(report.get('diversity') or {}).get('status', '-')}`",
        f"- noop_count: `{report.get('noop_count', 0)}`",
        "- blocked_scope: live systems, external APIs, remote writes, timers, LOW_LIVE, MEDIUM and HIGH",
        "- breach: `False`",
    ]) + "\n"


def write_outputs(report: Dict[str, Any]) -> None:
    ensure_dirs()
    safe = {
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "timestamp_utc": report.get("timestamp_utc") or utc_now(),
        **report,
        **HARD_DEFAULTS,
        "recommended_git_checkpoint": [
            "sentinel_autonomous_operation_governor.py",
            "sentinel_autonomous_soak_test.py",
            "sentinel_autonomous_operations_supervisor.py",
            "sentinel_autonomy.py",
            "sentinel_autonomous_mission_queue_runner.py",
            "sentinel_autonomous_goal_manager.py",
            "sentinel_autonomous_capability_health_governor.py",
            "sentinel_autonomous_capability_registry.py",
            "sentinel_autonomous_priority_engine.py",
            "sentinel_self_governing_safe_autonomy_kernel.py",
            "sentinel_autonomous_cycle_runner.py",
            "playbooks/sentinel-autonomous-operation-governor.playbook.json",
            "playbooks/sentinel-autonomous-operation-impact-scoring.playbook.json",
            "playbooks/sentinel-autonomous-operation-noop-detection.playbook.json",
            "playbooks/sentinel-autonomous-operation-diversity.playbook.json",
            "playbooks/sentinel-autonomous-soak-test.playbook.json",
            "playbooks/sentinel-autonomous-regression-gate.playbook.json",
            "playbooks/sentinel-autonomous-readiness-seal.playbook.json",
            "playbooks/sentinel-autonomous-soak-owner-summary.playbook.json",
        ],
    }
    write_json(REPORT_JSON, safe)
    write_json(STATE_JSON, safe)
    write_json(LATEST_JSON, safe)
    write_text(REPORT_MD, render_report_md(safe))
    write_text(SCORES_MD, render_scores_md(safe))
    write_text(NOOP_MD, render_noop_md(safe))
    write_text(DIVERSITY_MD, render_diversity_md(safe))
    write_text(SELECTION_MD, render_selection_md(safe))
    write_text(OWNER_SUMMARY_MD, render_owner_summary_md(safe))
    write_playbooks(safe)
    append_jsonl(AUDIT_JSONL, [{
        "timestamp_utc": utc_now(),
        "event": "autonomous_operation_governor",
        "action": safe.get("action"),
        "status": safe.get("status"),
        "selected_operation": safe.get("selected_operation_name"),
        "breach": False,
        "live_apply": False,
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
        findings.append("free_subprocess_present")
    if re.search(r"systemctl\s+(?:start|enable)", source):
        findings.append("systemctl_live_present")
    if re.search(r"crontab\s+(?:-|install)", source):
        findings.append("cron_install_present")
    if re.search(r"r" + "m\\s+-r" + "f", source):
        findings.append("destructive_delete_present")
    if re.search(r"\b(?:p" + "kill|kill" + "all)\\b", source):
        findings.append("process_termination_present")
    return findings


def self_test() -> Dict[str, Any]:
    source = Path(__file__).read_text(encoding="utf-8")
    findings = source_safety_findings(source)
    fake_scan = {
        "inputs": {
            "operations_history": [
                {"selected_operation": "run_mission_queue_runner"},
                {"selected_operation": "run_mission_queue_runner"},
                {"selected_operation": "run_mission_queue_runner"},
            ],
            "state_inputs": {
                "completion_ledger": {"data": {"completed_count": 3}},
                "goal_manager": {"data": {"executable_mission_count": 0}},
                "health_governor": {"data": {"warning_count": 0}},
            },
        },
        "operations": list(OPERATION_DEFS),
    }
    noop = detect_noops(fake_scan)
    scoring = score_operations(fake_scan)
    selected = select_operation(scoring)
    tests = {
        "no_apply_argument": "apply_argument_present" not in findings,
        "no_network_imports": "network_import_present" not in findings,
        "no_shell_true": "shell_true_present" not in findings,
        "no_free_subprocess": "free_subprocess_present" not in findings,
        "all_operations_risk_classed": all("risk_class" in item for item in OPERATION_DEFS.values()),
        "all_operations_can_execute_checked": all("can_execute_now" in item for item in scoring.get("operation_scores", [])),
        "noop_detection_works": (noop.get("noop_analysis") or {}).get("run_mission_queue_runner", {}).get("is_noop_candidate") is True,
        "cooldowns_work": any(item.get("operation_name") == "run_mission_queue_runner" and item.get("cooldown_remaining", 0) >= 0 for item in scoring.get("operation_scores", [])),
        "diversity_works": (selected.get("diversity") or {}).get("status") in {"OPERATION_DIVERSITY_OK", "STOP_ON_NO_DIVERSE_SAFE_OPERATION"},
        "scores_reproducible": score_operations(fake_scan).get("top_scores", [])[:1] == scoring.get("top_scores", [])[:1],
    }
    status = "OPERATION_GOVERNOR_SELF_TEST_OK" if all(tests.values()) and not findings else "OPERATION_GOVERNOR_SELF_TEST_FAILED"
    report = {
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "timestamp_utc": utc_now(),
        "action": "self-test",
        "status": status,
        "tests": tests,
        "source_safety_findings": findings,
        **HARD_DEFAULTS,
    }
    write_outputs(report)
    return report


def status_report() -> Dict[str, Any]:
    data = load_dict(MODEL_JSON) or load_dict(LATEST_JSON) or {"status": "NO_OPERATION_GOVERNOR_MODEL", **HARD_DEFAULTS}
    print(f"status={data.get('status')}")
    print(f"selected_operation={data.get('selected_operation_name')}")
    print(f"top_operation={(data.get('top_scores') or [{}])[0].get('operation_name') if data.get('top_scores') else '-'}")
    print(f"diversity={(data.get('diversity') or {}).get('status')}")
    print(f"breach={data.get('breach')}")
    print(f"live_apply={data.get('live_apply')}")
    print(f"emergency_stop={data.get('emergency_stop')}")
    print(f"allowed_apply_now={data.get('allowed_apply_now')}")
    print(f"HIGH_blocked={data.get('high_blocked')}")
    print(f"LOW_LIVE_executable={data.get('low_live_executable')}")
    print(f"MEDIUM_executable={data.get('medium_executable')}")
    return data


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Sentinel Autonomous Operation Governor")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--scan-operations", action="store_true")
    parser.add_argument("--score-operations", action="store_true")
    parser.add_argument("--detect-noops", action="store_true")
    parser.add_argument("--select-operation", action="store_true")
    parser.add_argument("--write-model", action="store_true")
    parser.add_argument("--status", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        report = self_test()
    elif args.scan_operations:
        report = scan_operations()
    elif args.score_operations:
        report = score_operations()
    elif args.detect_noops:
        report = detect_noops()
    elif args.select_operation:
        report = select_operation()
    elif args.write_model:
        report = write_model()
    elif args.status:
        status_report()
        return 0
    else:
        parser.print_help()
        return 2
    return 0 if report.get("status") != "OPERATION_GOVERNOR_SELF_TEST_FAILED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
