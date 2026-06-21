#!/usr/bin/env python3
"""Sentinel Autonomous Capability Registry (Phase 10.3).

Local capability registry and skill router for the self-governing safe autonomy
system. It knows available Sentinel capabilities, their hard module/argument
allowlists, expected inputs/outputs, risk, guards, health, usefulness and
freshness. It does not execute live apply, network actions, remote writes,
timers, external APIs or customer-system changes.
"""

from __future__ import annotations

import argparse
import json
import py_compile
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


PROJECT_DIR = Path("/srv/sentinel-defense")
SCHEMA_VERSION = "sentinel-autonomous-capability-registry-10.3"
PHASE = "10.3"
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

HARD_DEFAULTS = {
    "live_apply": False,
    "emergency_stop": True,
    "allowed_apply_now": False,
    "high_blocked": True,
    "low_live_executable": False,
    "medium_executable": False,
    "breach": False,
}

FORBIDDEN_ACTIONS = [
    "live_apply",
    "network",
    "email",
    "payhip_api",
    "wordpress",
    "cloudflare",
    "database",
    "sftp_write",
    "nginx",
    "htaccess",
    "systemd",
    "cron",
    "customer_data",
    "HIGH_or_MEDIUM_execution",
]

REQUIRED_GUARDS = [
    "live_apply=false",
    "emergency_stop=true",
    "allowed_apply_now=false",
    "HIGH blocked=true",
    "LOW_LIVE executable=false",
    "MEDIUM executable=false",
    "no network",
    "no free shell",
    "hard module allowlist",
    "hard argument allowlist",
]

CAPABILITY_DEFINITIONS: List[Dict[str, Any]] = [
    {
        "capability_id": "payhip_upload_pack_export",
        "display_name": "Payhip Upload Pack Export",
        "module_path": "sentinel_payhip_upload_pack_export_helper.py",
        "allowed_args": ["--self-test", "--build-export", "--build-copy-fields",
                         "--build-upload-checklist", "--build-zip", "--status"],
        "risk_class": LOW_EXPORT,
        "allowed_scope": ["exports/payhip-upload-pack", "reports/latest", "state/adaptive-learning", "audit"],
        "input_paths": ["reports/latest/sentinel-payhip-public-service-overview.md"],
        "output_paths": ["exports/payhip-upload-pack/latest", "reports/latest/sentinel-payhip-upload-pack-export.json"],
        "expected_outputs": ["reports/latest/sentinel-payhip-upload-pack-export.json",
                             "exports/payhip-upload-pack/latest/MANIFEST.json",
                             "exports/payhip-upload-pack/latest/CHECKSUMS.sha256"],
        "freshness_outputs": ["reports/latest/sentinel-payhip-upload-pack-export.json",
                              "exports/payhip-upload-pack/latest/MANIFEST.json",
                              "exports/payhip-upload-pack/latest/CHECKSUMS.sha256"],
        "business_value": 34,
        "learning_value": 8,
        "task_ids": ["rebuild_payhip_upload_pack", "rebuild_manifest_and_checksums"],
    },
    {
        "capability_id": "payhip_launch_qa",
        "display_name": "Payhip Launch QA",
        "module_path": "sentinel_payhip_launch_qa_finalizer.py",
        "allowed_args": ["--self-test", "--scan-upload-pack", "--validate-fields",
                         "--build-launch-console", "--build-final-checklist", "--status"],
        "risk_class": LOW_LOCAL,
        "allowed_scope": ["reports/latest", "state/adaptive-learning", "audit", "playbooks"],
        "input_paths": ["exports/payhip-upload-pack/latest/MANIFEST.json"],
        "output_paths": ["reports/latest/sentinel-payhip-launch-qa.json"],
        "expected_outputs": ["reports/latest/sentinel-payhip-launch-qa.json"],
        "freshness_outputs": ["reports/latest/sentinel-payhip-launch-qa.json"],
        "business_value": 28,
        "learning_value": 7,
        "task_ids": ["rerun_payhip_launch_qa"],
    },
    {
        "capability_id": "payhip_fulfillment_board",
        "display_name": "Payhip Fulfillment Board",
        "module_path": "sentinel_payhip_fulfillment_board.py",
        "allowed_args": ["--self-test", "--build-board", "--build-case-template",
                         "--build-delivery-checklists", "--build-risk-review",
                         "--build-completion-pack", "--status"],
        "risk_class": LOW_STATE,
        "allowed_scope": ["reports/latest", "state/adaptive-learning", "audit", "playbooks"],
        "input_paths": ["reports/latest/sentinel-payhip-launch-qa.json"],
        "output_paths": ["reports/latest/sentinel-payhip-fulfillment-board.json"],
        "expected_outputs": ["reports/latest/sentinel-payhip-fulfillment-board.json"],
        "freshness_outputs": ["reports/latest/sentinel-payhip-fulfillment-board.json"],
        "business_value": 24,
        "learning_value": 8,
        "task_ids": ["update_fulfillment_board"],
    },
    {
        "capability_id": "first_order_dryrun",
        "display_name": "First Order Dry-run",
        "module_path": "sentinel_payhip_first_order_dryrun.py",
        "allowed_args": ["--self-test", "--build-dummy-case", "--simulate-intake",
                         "--simulate-package-workflows", "--build-sample-report",
                         "--build-delivery-pack", "--status"],
        "risk_class": LOW_LOCAL,
        "allowed_scope": ["reports/latest", "state/adaptive-learning", "audit", "playbooks"],
        "input_paths": ["reports/latest/sentinel-payhip-fulfillment-board.json"],
        "output_paths": ["reports/latest/sentinel-payhip-first-order-dryrun.json"],
        "expected_outputs": ["reports/latest/sentinel-payhip-first-order-dryrun.json"],
        "freshness_outputs": ["reports/latest/sentinel-payhip-first-order-dryrun.json"],
        "business_value": 22,
        "learning_value": 8,
        "task_ids": ["run_first_order_dryrun"],
    },
    {
        "capability_id": "service_proof_trend",
        "display_name": "Service Proof Trend",
        "module_path": "sentinel_service_proof_trend.py",
        "allowed_args": ["--self-test", "--collect-proof", "--analyze-decay",
                         "--build-client-summary", "--build-payhip-proof", "--status"],
        "risk_class": LOW_STATE,
        "allowed_scope": ["reports/latest", "state/adaptive-learning", "audit", "playbooks"],
        "input_paths": ["reports/latest/sentinel-payhip-first-order-dryrun.json"],
        "output_paths": ["reports/latest/sentinel-service-proof.json"],
        "expected_outputs": ["reports/latest/sentinel-service-proof.json"],
        "freshness_outputs": ["reports/latest/sentinel-service-proof.json"],
        "business_value": 19,
        "learning_value": 9,
        "task_ids": ["update_service_proof"],
    },
    {
        "capability_id": "public_client_assets",
        "display_name": "Public Client Assets",
        "module_path": "sentinel_payhip_public_client_assets.py",
        "allowed_args": ["--self-test", "--build-product-file", "--build-public-assets",
                         "--build-descriptions", "--build-faq", "--build-pdf-source",
                         "--status"],
        "risk_class": LOW_EXPORT,
        "allowed_scope": ["reports/latest", "state/adaptive-learning", "audit", "playbooks"],
        "input_paths": ["reports/latest/sentinel-payhip-upload-pack-export.json"],
        "output_paths": ["reports/latest/sentinel-payhip-public-service-overview.md"],
        "expected_outputs": ["reports/latest/sentinel-payhip-public-intake-form.md",
                             "reports/latest/sentinel-payhip-public-safety-agreement.md",
                             "reports/latest/sentinel-payhip-public-service-overview.md"],
        "freshness_outputs": ["reports/latest/sentinel-payhip-public-intake-form.md",
                              "reports/latest/sentinel-payhip-public-safety-agreement.md",
                              "reports/latest/sentinel-payhip-public-service-overview.md"],
        "business_value": 26,
        "learning_value": 10,
        "task_ids": ["check_public_asset_safety", "repair_missing_public_asset"],
    },
    {
        "capability_id": "customer_intake_delivery",
        "display_name": "Customer Intake Delivery",
        "module_path": "sentinel_payhip_customer_intake_delivery.py",
        "allowed_args": ["--self-test", "--build-intake", "--build-delivery-workflow",
                         "--build-message-templates", "--build-client-pack", "--status"],
        "risk_class": LOW_STATE,
        "allowed_scope": ["reports/latest", "state/adaptive-learning", "audit", "playbooks"],
        "input_paths": ["reports/latest/sentinel-payhip-fulfillment-board.json"],
        "output_paths": ["reports/latest/sentinel-payhip-customer-intake.json"],
        "expected_outputs": ["reports/latest/sentinel-payhip-customer-intake.json"],
        "freshness_outputs": ["reports/latest/sentinel-payhip-customer-intake.json"],
        "business_value": 18,
        "learning_value": 9,
        "task_ids": [],
    },
    {
        "capability_id": "owner_dashboard_service_packaging",
        "display_name": "Owner Dashboard Service Packaging",
        "module_path": "sentinel_owner_dashboard_service_packaging.py",
        "allowed_args": ["--self-test", "--build-dashboard", "--build-service-packages",
                         "--build-owner-next-actions", "--build-roadmap", "--status"],
        "risk_class": LOW_STATE,
        "allowed_scope": ["reports/latest", "state/adaptive-learning", "audit", "playbooks"],
        "input_paths": ["reports/latest/sentinel-service-proof.json"],
        "output_paths": ["reports/latest/sentinel-owner-dashboard.json"],
        "expected_outputs": ["reports/latest/sentinel-owner-dashboard.json"],
        "freshness_outputs": ["reports/latest/sentinel-owner-dashboard.json"],
        "business_value": 20,
        "learning_value": 8,
        "task_ids": ["update_owner_summary"],
    },
    {
        "capability_id": "priority_engine",
        "display_name": "Autonomous Priority Engine",
        "module_path": "sentinel_autonomous_priority_engine.py",
        "allowed_args": ["--self-test", "--scan-history", "--score-tasks", "--select-next",
                         "--simulate-diversity", "--write-model", "--status"],
        "risk_class": LOW_STATE,
        "allowed_scope": ["reports/latest", "state/adaptive-learning", "audit", "playbooks"],
        "input_paths": ["state/adaptive-learning/autonomy_cycle_history.json"],
        "output_paths": ["state/adaptive-learning/autonomy_task_priority_model.json"],
        "expected_outputs": ["state/adaptive-learning/autonomy_task_priority_model.json",
                             "reports/latest/sentinel-autonomous-priority-engine.json"],
        "freshness_outputs": ["state/adaptive-learning/autonomy_task_priority_model.json"],
        "business_value": 17,
        "learning_value": 18,
        "task_ids": ["generate_next_safe_actions", "generate_git_checkpoint_suggestion"],
    },
    {
        "capability_id": "cycle_runner",
        "display_name": "Autonomous Cycle Runner",
        "module_path": "sentinel_autonomous_cycle_runner.py",
        "allowed_args": ["--self-test", "--preflight", "--run-once", "--validate-run",
                         "--build-owner-summary", "--status"],
        "risk_class": LOW_STATE,
        "allowed_scope": ["reports/latest", "state/adaptive-learning", "audit", "playbooks"],
        "input_paths": ["state/adaptive-learning/autonomy_task_priority_model.json"],
        "output_paths": ["reports/latest/sentinel-autonomous-cycle-runner.json"],
        "expected_outputs": ["reports/latest/sentinel-autonomous-cycle-runner.json"],
        "freshness_outputs": ["reports/latest/sentinel-autonomous-cycle-runner.json"],
        "business_value": 16,
        "learning_value": 16,
        "task_ids": [],
    },
    {
        "capability_id": "autonomy_kernel",
        "display_name": "Self-Governing Safe Autonomy Kernel",
        "module_path": "sentinel_self_governing_safe_autonomy_kernel.py",
        "allowed_args": ["--self-test", "--observe", "--decide", "--classify", "--execute",
                         "--validate", "--repair", "--learn", "--cycle", "--status"],
        "risk_class": LOW_STATE,
        "allowed_scope": ["reports/latest", "state/adaptive-learning", "audit", "playbooks"],
        "input_paths": ["reports/latest/sentinel-owner-dashboard.json"],
        "output_paths": ["reports/latest/sentinel-self-governing-autonomy-kernel.json"],
        "expected_outputs": ["reports/latest/sentinel-self-governing-autonomy-kernel.json",
                             "state/adaptive-learning/latest_self_governing_autonomy_kernel.json"],
        "freshness_outputs": ["reports/latest/sentinel-self-governing-autonomy-kernel.json"],
        "business_value": 18,
        "learning_value": 20,
        "task_ids": ["observe_project_state", "check_missing_inputs", "update_learning_state",
                     "write_audit_event"],
    },
]

REPORT_JSON = PROJECT_DIR / "reports/latest/sentinel-autonomous-capability-registry.json"
REPORT_MD = PROJECT_DIR / "reports/latest/sentinel-autonomous-capability-registry.md"
HEALTH_MD = PROJECT_DIR / "reports/latest/sentinel-autonomous-capability-health.md"
ROUTING_MD = PROJECT_DIR / "reports/latest/sentinel-autonomous-capability-routing.md"
SKILL_MAP_MD = PROJECT_DIR / "reports/latest/sentinel-autonomous-skill-map.md"
OWNER_SUMMARY_MD = PROJECT_DIR / "reports/latest/sentinel-autonomous-skill-router-owner-summary.md"

REGISTRY_JSON = PROJECT_DIR / "state/adaptive-learning/autonomous_capability_registry.json"
LATEST_REGISTRY_JSON = PROJECT_DIR / "state/adaptive-learning/latest_autonomous_capability_registry.json"
HEALTH_JSON = PROJECT_DIR / "state/adaptive-learning/autonomous_capability_health.json"
HISTORY_JSON = PROJECT_DIR / "state/adaptive-learning/autonomous_capability_history.json"
ROUTER_JSON = PROJECT_DIR / "state/adaptive-learning/autonomous_skill_router_state.json"
COOLDOWNS_JSON = PROJECT_DIR / "state/adaptive-learning/autonomous_capability_cooldowns.json"
HEALTH_GOVERNOR_JSON = PROJECT_DIR / "state/adaptive-learning/latest_autonomous_capability_health_governor.json"
GOAL_MANAGER_JSON = PROJECT_DIR / "state/adaptive-learning/latest_autonomous_goal_manager.json"

TASK_MEMORY_JSON = PROJECT_DIR / "state/adaptive-learning/autonomy_task_memory.json"
SUCCESS_PATTERNS_JSON = PROJECT_DIR / "state/adaptive-learning/autonomy_success_patterns.json"
BLOCKED_PATTERNS_JSON = PROJECT_DIR / "state/adaptive-learning/autonomy_blocked_patterns.json"
RUNNER_HISTORY_JSON = PROJECT_DIR / "state/adaptive-learning/autonomous_cycle_runner_history.json"
PRIORITY_MODEL_JSON = PROJECT_DIR / "state/adaptive-learning/autonomy_task_priority_model.json"

AUDIT_JSONL = PROJECT_DIR / "audit/sentinel-autonomous-capability-registry.jsonl"

PLAYBOOK_REGISTRY = PROJECT_DIR / "playbooks/sentinel-autonomous-capability-registry.playbook.json"
PLAYBOOK_ROUTER = PROJECT_DIR / "playbooks/sentinel-autonomous-skill-router.playbook.json"
PLAYBOOK_HEALTH = PROJECT_DIR / "playbooks/sentinel-autonomous-capability-health.playbook.json"
PLAYBOOK_INTEGRATION = PROJECT_DIR / "playbooks/sentinel-autonomy-capability-integration.playbook.json"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "state/adaptive-learning",
    PROJECT_DIR / "audit",
    PROJECT_DIR / "playbooks",
)

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


def load_dict(path: Path) -> Dict[str, Any]:
    data, status = read_json(path)
    return data if status == "ok" and isinstance(data, dict) else {}


def load_list(path: Path) -> List[Any]:
    data, status = read_json(path)
    return data if status == "ok" and isinstance(data, list) else []


def detect_secret_like(text: str) -> bool:
    return bool(SECRET_RE.search(text) or PRIVATE_KEY_RE.search(text) or TOKEN_FORMAT_RE.search(text))


def file_age_hours(path: Path) -> Optional[float]:
    try:
        if not path.exists():
            return None
        return max(0.0, (datetime.now(timezone.utc).timestamp() - path.stat().st_mtime) / 3600.0)
    except OSError:
        return None


def path_status(paths: List[str]) -> Dict[str, Any]:
    missing: List[str] = []
    stale: List[str] = []
    fresh: List[str] = []
    ages: List[float] = []
    invalid_json: List[str] = []
    for item in paths:
        path = PROJECT_DIR / item
        age = file_age_hours(path)
        if age is None:
            missing.append(item)
            continue
        ages.append(age)
        if age > MAX_AGE_HOURS:
            stale.append(item)
        else:
            fresh.append(item)
        if path.suffix == ".json" and read_json(path)[1] != "ok":
            invalid_json.append(item)
    return {
        "missing": missing,
        "stale": stale,
        "fresh": fresh,
        "invalid_json": invalid_json,
        "oldest_age_hours": round(max(ages), 3) if ages else None,
    }


def source_declares_arg(module_path: Path, arg: str) -> bool:
    try:
        text = module_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return arg in text


def compile_status(module_path: Path) -> str:
    if not module_path.exists():
        return "missing"
    try:
        py_compile.compile(str(module_path), doraise=True)
        return "ok"
    except py_compile.PyCompileError:
        return "py_compile_failed"
    except OSError:
        return "read_error"


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


def event_counts(capability_id: str, task_ids: List[str]) -> Dict[str, Any]:
    success = 0
    blocked = 0
    failure = 0
    last_run = None
    last_status = "never_run"
    task_set = set(task_ids)

    for item in load_list(SUCCESS_PATTERNS_JSON):
        if isinstance(item, dict) and item.get("task") in task_set:
            success += 1
            last_run = item.get("ts") or item.get("timestamp_utc") or last_run
            last_status = "success"
    for item in load_list(BLOCKED_PATTERNS_JSON):
        if isinstance(item, dict) and item.get("task") in task_set:
            blocked += 1
            last_run = item.get("ts") or item.get("timestamp_utc") or last_run
            last_status = "blocked"
    for item in load_list(RUNNER_HISTORY_JSON):
        if not isinstance(item, dict):
            continue
        for task in item.get("selected_tasks") or []:
            if task in task_set:
                last_run = item.get("timestamp_utc") or last_run
                if item.get("breach"):
                    failure += 1
                    last_status = "failed"
    task_memory = load_dict(TASK_MEMORY_JSON)
    if task_memory.get("last_task") in task_set:
        last_run = task_memory.get("last_updated") or last_run
        last_status = str(task_memory.get("last_validation") or task_memory.get("last_status") or last_status)

    return {
        "last_run": last_run,
        "last_status": last_status,
        "success_count": success,
        "failure_count": failure,
        "blocked_count": blocked,
    }


def build_capability(defn: Dict[str, Any]) -> Dict[str, Any]:
    module = PROJECT_DIR / defn["module_path"]
    module_exists = module.exists()
    module_compile_status = compile_status(module)
    declared_args = [arg for arg in defn["allowed_args"] if source_declares_arg(module, arg)] if module_exists else []
    missing_declared_args = [arg for arg in defn["allowed_args"] if arg not in declared_args]
    outputs = path_status(defn["freshness_outputs"])
    expected = path_status(defn["expected_outputs"])
    counts = event_counts(defn["capability_id"], defn["task_ids"])

    missing_outputs = len(expected["missing"])
    stale_outputs = len(outputs["stale"])
    invalid_outputs = len(expected["invalid_json"])
    freshness_score = max(0, 100 - missing_outputs * 25 - stale_outputs * 15 - invalid_outputs * 40)
    usefulness_score = int(defn.get("business_value", 0) + defn.get("learning_value", 0)
                           + counts["success_count"] * 2 - counts["failure_count"] * 10
                           - counts["blocked_count"] * 3)
    priority_score = usefulness_score + max(0, 100 - freshness_score) + missing_outputs * 15

    reason_if_blocked = None
    if not module_exists:
        reason_if_blocked = "module_missing"
    elif module_compile_status != "ok":
        reason_if_blocked = module_compile_status
    elif defn["risk_class"] not in AUTO_ALLOWED_RISK:
        reason_if_blocked = f"risk_class_not_auto_allowed:{defn['risk_class']}"
    elif missing_declared_args and len(declared_args) == 0:
        reason_if_blocked = "allowed_args_not_detected_in_source"

    can_run = (
        module_exists
        and module_compile_status == "ok"
        and defn["risk_class"] in AUTO_ALLOWED_RISK
        and reason_if_blocked is None
    )
    health_status = "CAPABILITY_HEALTH_OK"
    if not module_exists:
        health_status = "CAPABILITY_MISSING"
    elif module_compile_status != "ok":
        health_status = "CAPABILITY_BLOCKED"
    elif missing_outputs or stale_outputs or invalid_outputs:
        health_status = "CAPABILITY_NEEDS_REFRESH"
    elif counts["blocked_count"] > counts["success_count"] and counts["blocked_count"] > 0:
        health_status = "CAPABILITY_WARNINGS"

    capability = {
        "capability_id": defn["capability_id"],
        "display_name": defn["display_name"],
        "module_path": defn["module_path"],
        "module_exists": module_exists,
        "module_compile_status": module_compile_status,
        "allowed_args": defn["allowed_args"],
        "declared_allowed_args": declared_args,
        "missing_declared_args": missing_declared_args,
        "risk_class": defn["risk_class"],
        "allowed_scope": defn["allowed_scope"],
        "input_paths": defn["input_paths"],
        "output_paths": defn["output_paths"],
        "expected_outputs": defn["expected_outputs"],
        "forbidden_actions": FORBIDDEN_ACTIONS,
        "required_guards": REQUIRED_GUARDS,
        "freshness_outputs": defn["freshness_outputs"],
        "freshness": outputs,
        "expected_output_status": expected,
        "last_run": counts["last_run"],
        "last_status": counts["last_status"],
        "success_count": counts["success_count"],
        "failure_count": counts["failure_count"],
        "blocked_count": counts["blocked_count"],
        "usefulness_score": usefulness_score,
        "freshness_score": freshness_score,
        "priority_score": priority_score,
        "business_value": defn.get("business_value", 0),
        "learning_value": defn.get("learning_value", 0),
        "task_ids": defn["task_ids"],
        "health_status": health_status,
        "can_run_autonomously": can_run,
        "reason_if_blocked": reason_if_blocked,
    }
    return capability


def discover_capabilities() -> Dict[str, Any]:
    capabilities = [build_capability(defn) for defn in CAPABILITY_DEFINITIONS]
    missing = [c["capability_id"] for c in capabilities if not c["module_exists"]]
    compile_failed = [c["capability_id"] for c in capabilities if c["module_compile_status"] not in {"ok", "missing"}]
    return {
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "timestamp_utc": utc_now(),
        "status": "CAPABILITY_DISCOVERY_OK" if not compile_failed else "CAPABILITY_DISCOVERY_WARNINGS",
        "capabilities": capabilities,
        "discovered_capabilities": [c["capability_id"] for c in capabilities if c["module_exists"]],
        "missing_capabilities": missing,
        "compile_failed_capabilities": compile_failed,
        "capability_count": len(capabilities),
        "live_apply": False,
        "emergency_stop": True,
        "allowed_apply_now": False,
        "high_blocked": True,
        "low_live_executable": False,
        "medium_executable": False,
        "breach": False,
    }


def route_next_skill(registry: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    registry = registry or build_registry(write=False)
    capabilities = [c for c in registry.get("capabilities", []) if c.get("can_run_autonomously")]
    capabilities.sort(key=lambda c: (int(c.get("priority_score") or 0), c.get("capability_id")), reverse=True)
    selected = capabilities[0] if capabilities else None
    status = "SKILL_ROUTER_READY" if selected else "SKILL_ROUTER_NO_SAFE_CAPABILITY"
    router = {
        "timestamp_utc": utc_now(),
        "status": status,
        "selected_capability": selected.get("capability_id") if selected else None,
        "selected_module": selected.get("module_path") if selected else None,
        "selected_risk_class": selected.get("risk_class") if selected else None,
        "selected_reason": (
            f"priority_score={selected.get('priority_score')} freshness_score={selected.get('freshness_score')}"
            if selected else "no autonomous capability available"
        ),
        "capability_usefulness_top_5": [
            {
                "capability_id": c["capability_id"],
                "usefulness_score": c["usefulness_score"],
                "freshness_score": c["freshness_score"],
                "priority_score": c["priority_score"],
                "health_status": c["health_status"],
            }
            for c in capabilities[:5]
        ],
        "blocked_capabilities": [
            {"capability_id": c["capability_id"], "reason": c["reason_if_blocked"]}
            for c in registry.get("capabilities", []) if not c.get("can_run_autonomously")
        ],
        "live_apply": False,
        "emergency_stop": True,
        "allowed_apply_now": False,
        "high_blocked": True,
        "low_live_executable": False,
        "medium_executable": False,
        "breach": False,
    }
    return router


def health_summary(registry: Dict[str, Any]) -> Dict[str, Any]:
    caps = registry.get("capabilities", [])
    return {
        "timestamp_utc": utc_now(),
        "status": "CAPABILITY_HEALTH_OK" if all(c.get("health_status") == "CAPABILITY_HEALTH_OK" for c in caps)
        else "CAPABILITY_HEALTH_WARNINGS",
        "capability_count": len(caps),
        "healthy_count": sum(1 for c in caps if c.get("health_status") == "CAPABILITY_HEALTH_OK"),
        "needs_refresh_count": sum(1 for c in caps if c.get("health_status") == "CAPABILITY_NEEDS_REFRESH"),
        "missing_count": sum(1 for c in caps if c.get("health_status") == "CAPABILITY_MISSING"),
        "blocked_count": sum(1 for c in caps if c.get("health_status") == "CAPABILITY_BLOCKED"),
        "health_by_capability": {c["capability_id"]: c["health_status"] for c in caps},
    }


def health_governor_summary() -> Dict[str, Any]:
    governor = load_dict(HEALTH_GOVERNOR_JSON)
    executed = governor.get("executed_repairs") if isinstance(governor.get("executed_repairs"), list) else []
    last_repair = executed[-1] if executed else {}
    return {
        "state_path": "state/adaptive-learning/latest_autonomous_capability_health_governor.json",
        "available": bool(governor),
        "last_status": governor.get("status") if governor else "not_available",
        "last_repair_action": last_repair.get("repair_action"),
        "repaired_warning_count": int(governor.get("executed_repair_count") or 0) if governor else 0,
        "blocked_repair_count": int(governor.get("blocked_repair_count") or 0) if governor else 0,
        "after_health_status": governor.get("after_health") if governor else None,
    }


def goal_manager_summary() -> Dict[str, Any]:
    goal = load_dict(GOAL_MANAGER_JSON)
    missions = goal.get("mission_queue") or goal.get("classified_missions") or goal.get("routed_missions") or []
    if not isinstance(missions, list):
        missions = []
    by_capability: Dict[str, List[str]] = {}
    active: List[Dict[str, Any]] = []
    for mission in missions:
        if not isinstance(mission, dict):
            continue
        cap = str(mission.get("linked_capability") or "unmapped")
        mission_type = str(mission.get("mission_type") or "unknown")
        by_capability.setdefault(cap, []).append(mission_type)
        if mission.get("completion_status") != "COMPLETE_FRESH" and mission.get("status") not in {"COMPLETED"}:
            active.append(mission)
    return {
        "state_path": "state/adaptive-learning/latest_autonomous_goal_manager.json",
        "available": bool(goal),
        "goal_manager_status": goal.get("status") if goal else "not_available",
        "selected_mission": goal.get("selected_mission_type") if goal else None,
        "mission_count": len(missions),
        "active_mission_count": len(active),
        "mission_linked_capabilities": sorted(by_capability),
        "capability_mission_status": {
            cap: ",".join(sorted(set(items))) for cap, items in sorted(by_capability.items())
        },
    }


def build_registry(write: bool = True, status: str = "CAPABILITY_REGISTRY_READY") -> Dict[str, Any]:
    registry = discover_capabilities()
    router = route_next_skill(registry)
    health = health_summary(registry)
    governor = health_governor_summary()
    goals = goal_manager_summary()
    registry.update({
        "status": status,
        "health": health,
        "health_governor": governor,
        "goal_manager": goals,
        "router": router,
        "recommended_capability": router.get("selected_capability"),
        "recommended_git_checkpoint": [
            "sentinel_autonomous_capability_health_governor.py",
            "sentinel_autonomous_goal_manager.py",
            "sentinel_autonomous_capability_registry.py",
            "sentinel_autonomous_priority_engine.py",
            "sentinel_self_governing_safe_autonomy_kernel.py",
            "sentinel_autonomous_cycle_runner.py",
            "playbooks/sentinel-autonomous-capability-health-governor.playbook.json",
            "playbooks/sentinel-autonomous-capability-self-repair.playbook.json",
            "playbooks/sentinel-autonomous-capability-warning-classification.playbook.json",
            "playbooks/sentinel-autonomous-capability-repair-validation.playbook.json",
            "playbooks/sentinel-autonomous-goal-manager.playbook.json",
            "playbooks/sentinel-autonomous-mission-queue.playbook.json",
            "playbooks/sentinel-autonomous-mission-routing.playbook.json",
            "playbooks/sentinel-autonomous-mission-validation.playbook.json",
            "playbooks/sentinel-autonomous-capability-registry.playbook.json",
            "playbooks/sentinel-autonomous-skill-router.playbook.json",
            "playbooks/sentinel-autonomous-capability-health.playbook.json",
            "playbooks/sentinel-autonomy-capability-integration.playbook.json",
        ],
    })
    if write:
        write_registry_outputs(registry)
    return registry


def write_registry_outputs(registry: Dict[str, Any]) -> None:
    health = registry["health"]
    router = registry["router"]
    write_json(REPORT_JSON, registry)
    write_json(REGISTRY_JSON, registry)
    write_json(LATEST_REGISTRY_JSON, registry)
    write_json(HEALTH_JSON, health)
    write_json(ROUTER_JSON, router)
    write_json(COOLDOWNS_JSON, capability_cooldowns(registry))
    history = load_list(HISTORY_JSON)
    history.append({
        "timestamp_utc": utc_now(),
        "status": registry.get("status"),
        "capability_count": registry.get("capability_count"),
        "recommended_capability": registry.get("recommended_capability"),
        "health_status": health.get("status"),
        "breach": False,
    })
    write_json(HISTORY_JSON, history[-200:])
    write_text(REPORT_MD, render_registry_md(registry))
    write_text(HEALTH_MD, render_health_md(registry))
    write_text(ROUTING_MD, render_routing_md(registry))
    write_text(SKILL_MAP_MD, render_skill_map_md(registry))
    write_text(OWNER_SUMMARY_MD, render_owner_summary_md(registry))
    write_playbooks(registry)
    append_jsonl(AUDIT_JSONL, [{
        "timestamp_utc": utc_now(),
        "event": "capability_registry",
        "status": registry.get("status"),
        "capability_count": registry.get("capability_count"),
        "recommended_capability": registry.get("recommended_capability"),
        "breach": False,
        "live_apply": False,
        "allowed_apply_now": False,
    }])


def capability_cooldowns(registry: Dict[str, Any]) -> Dict[str, Any]:
    data: Dict[str, Any] = {"timestamp_utc": utc_now(), "cooldowns": {}}
    for cap in registry.get("capabilities", []):
        cooldown = 2 if cap["risk_class"] == LOW_STATE else 3 if cap["risk_class"] == LOW_EXPORT else 1
        data["cooldowns"][cap["capability_id"]] = {
            "configured_cycles": cooldown,
            "remaining_cycles": 0 if cap.get("can_run_autonomously") else cooldown,
            "reason": cap.get("reason_if_blocked") or "available",
        }
    return data


def render_registry_md(registry: Dict[str, Any]) -> str:
    governor = registry.get("health_governor") if isinstance(registry.get("health_governor"), dict) else {}
    goals = registry.get("goal_manager") if isinstance(registry.get("goal_manager"), dict) else {}
    lines = [
        "# Sentinel Autonomous Capability Registry",
        "",
        f"- status: `{registry.get('status')}`",
        f"- capability_count: `{registry.get('capability_count')}`",
        f"- discovered: `{len(registry.get('discovered_capabilities') or [])}`",
        f"- missing: `{len(registry.get('missing_capabilities') or [])}`",
        f"- recommended_capability: `{registry.get('recommended_capability')}`",
        f"- health_governor_status: `{governor.get('last_status', 'not_available')}`",
        f"- goal_manager_status: `{goals.get('goal_manager_status', 'not_available')}`",
        f"- active_mission_count: `{goals.get('active_mission_count', 0)}`",
        f"- mission_linked_capabilities: `{', '.join(goals.get('mission_linked_capabilities') or []) or '-'}`",
        f"- repaired_warning_count: `{governor.get('repaired_warning_count', 0)}`",
        f"- blocked_repair_count: `{governor.get('blocked_repair_count', 0)}`",
        "- live_apply: `False`",
        "- emergency_stop: `True`",
        "- allowed_apply_now: `False`",
        "- HIGH blocked: `True`",
        "- breach: `False`",
        "",
        "## Capabilities",
    ]
    for cap in registry.get("capabilities", []):
        lines.append(
            f"- `{cap['capability_id']}` module=`{cap['module_path']}` "
            f"risk=`{cap['risk_class']}` health=`{cap['health_status']}` "
            f"can_run=`{cap['can_run_autonomously']}` priority=`{cap['priority_score']}`"
        )
    return "\n".join(lines) + "\n"


def render_health_md(registry: Dict[str, Any]) -> str:
    health = registry.get("health", {})
    governor = registry.get("health_governor") if isinstance(registry.get("health_governor"), dict) else {}
    lines = [
        "# Sentinel Autonomous Capability Health",
        "",
        f"- status: `{health.get('status')}`",
        f"- healthy_count: `{health.get('healthy_count')}`",
        f"- needs_refresh_count: `{health.get('needs_refresh_count')}`",
        f"- missing_count: `{health.get('missing_count')}`",
        f"- blocked_count: `{health.get('blocked_count')}`",
        f"- governor_after_health: `{governor.get('after_health_status', '-')}`",
        f"- governor_last_repair_action: `{governor.get('last_repair_action', '-')}`",
        "",
    ]
    for cap in registry.get("capabilities", []):
        lines.append(f"- `{cap['capability_id']}`: `{cap['health_status']}` freshness=`{cap['freshness_score']}`")
    return "\n".join(lines) + "\n"


def render_routing_md(registry: Dict[str, Any]) -> str:
    router = registry.get("router", {})
    lines = [
        "# Sentinel Autonomous Capability Routing",
        "",
        f"- status: `{router.get('status')}`",
        f"- selected_capability: `{router.get('selected_capability')}`",
        f"- selected_module: `{router.get('selected_module')}`",
        f"- selected_risk_class: `{router.get('selected_risk_class')}`",
        f"- reason: {redact_text(router.get('selected_reason'), 500)}",
        "",
        "## Top Capabilities",
    ]
    for item in router.get("capability_usefulness_top_5") or []:
        lines.append(
            f"- `{item['capability_id']}` usefulness=`{item['usefulness_score']}` "
            f"freshness=`{item['freshness_score']}` priority=`{item['priority_score']}`"
        )
    return "\n".join(lines) + "\n"


def render_skill_map_md(registry: Dict[str, Any]) -> str:
    lines = ["# Sentinel Autonomous Skill Map", ""]
    for cap in registry.get("capabilities", []):
        lines.extend([
            f"## {cap['capability_id']}",
            f"- module: `{cap['module_path']}`",
            f"- args: `{', '.join(cap['allowed_args'])}`",
            f"- risk: `{cap['risk_class']}`",
            f"- task_ids: `{', '.join(cap['task_ids']) or '-'}`",
            f"- expected_outputs: `{', '.join(cap['expected_outputs']) or '-'}`",
            "",
        ])
    return "\n".join(lines) + "\n"


def render_owner_summary_md(registry: Dict[str, Any]) -> str:
    router = registry.get("router", {})
    governor = registry.get("health_governor") if isinstance(registry.get("health_governor"), dict) else {}
    goals = registry.get("goal_manager") if isinstance(registry.get("goal_manager"), dict) else {}
    return "\n".join([
        "# Sentinel Skill Router Owner Summary",
        "",
        f"- registry_status: `{registry.get('status')}`",
        f"- capability_health: `{(registry.get('health') or {}).get('status')}`",
        f"- health_governor_status: `{governor.get('last_status', 'not_available')}`",
        f"- last_repair_action: `{governor.get('last_repair_action', '-')}`",
        f"- repaired_warning_count: `{governor.get('repaired_warning_count', 0)}`",
        f"- blocked_repair_count: `{governor.get('blocked_repair_count', 0)}`",
        f"- after_health_status: `{governor.get('after_health_status', '-')}`",
        f"- goal_manager_status: `{goals.get('goal_manager_status', 'not_available')}`",
        f"- selected_mission: `{goals.get('selected_mission', '-')}`",
        f"- active_mission_count: `{goals.get('active_mission_count', 0)}`",
        f"- routed_next_skill: `{router.get('selected_capability')}`",
        f"- routed_module: `{router.get('selected_module')}`",
        f"- missing_capabilities: `{', '.join(registry.get('missing_capabilities') or []) or '-'}`",
        f"- live_apply: `{registry.get('live_apply')}`",
        f"- emergency_stop: `{registry.get('emergency_stop')}`",
        f"- allowed_apply_now: `{registry.get('allowed_apply_now')}`",
        f"- HIGH blocked: `{registry.get('high_blocked')}`",
        f"- LOW_LIVE executable: `{registry.get('low_live_executable')}`",
        f"- MEDIUM executable: `{registry.get('medium_executable')}`",
        f"- breach: `{registry.get('breach')}`",
        "",
        "Sentinel now knows capabilities as registered skills, but still routes only safe local autonomous work.",
    ]) + "\n"


def write_playbooks(registry: Dict[str, Any]) -> None:
    base = {
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "live_apply": False,
        "emergency_stop": True,
        "allowed_apply_now": False,
        "high_blocked": True,
        "low_live_executable": False,
        "medium_executable": False,
        "capability_count": registry.get("capability_count"),
    }
    write_json(PLAYBOOK_REGISTRY, {
        **base,
        "name": "sentinel-autonomous-capability-registry",
        "purpose": "Maintain hard allowlisted local Sentinel capabilities and their health metadata.",
        "capability_ids": [c["capability_id"] for c in registry.get("capabilities", [])],
        "blocked_actions": FORBIDDEN_ACTIONS,
    })
    write_json(PLAYBOOK_ROUTER, {
        **base,
        "name": "sentinel-autonomous-skill-router",
        "purpose": "Route the next safe local capability using usefulness, freshness and guard status.",
        "selected_capability": (registry.get("router") or {}).get("selected_capability"),
        "routing_inputs": ["priority_model", "capability_freshness", "success_patterns", "blocked_patterns"],
    })
    write_json(PLAYBOOK_HEALTH, {
        **base,
        "name": "sentinel-autonomous-capability-health",
        "health_status": (registry.get("health") or {}).get("status"),
        "health_checks": ["module_exists", "py_compile", "expected_outputs", "freshness", "json_valid", "guard_status"],
    })
    write_json(PLAYBOOK_INTEGRATION, {
        **base,
        "name": "sentinel-autonomy-capability-integration",
        "priority_engine_reads": rel(REGISTRY_JSON),
        "kernel_displays_capability_context": True,
        "runner_records_capability_context": True,
        "fallback": "missing registry never blocks safe defaults",
    })


def action_discover() -> Dict[str, Any]:
    registry = discover_capabilities()
    registry["status"] = "CAPABILITY_DISCOVERY_OK"
    write_registry_outputs(registry | {"health": health_summary(registry), "router": route_next_skill(registry),
                                       "recommended_capability": route_next_skill(registry).get("selected_capability"),
                                       "recommended_git_checkpoint": []})
    return registry


def action_evaluate() -> Dict[str, Any]:
    return build_registry(write=True, status="CAPABILITY_EVALUATION_OK")


def action_route() -> Dict[str, Any]:
    registry = build_registry(write=True, status="CAPABILITY_ROUTING_OK")
    return registry


def action_status() -> Dict[str, Any]:
    return load_dict(LATEST_REGISTRY_JSON) or {"status": "NO_CAPABILITY_REGISTRY", **HARD_DEFAULTS}


def action_self_test() -> Dict[str, Any]:
    failures: List[str] = []
    source = Path(__file__).read_text(encoding="utf-8")
    failures.extend(source_safety_findings(source))
    ids = [c["capability_id"] for c in CAPABILITY_DEFINITIONS]
    if len(ids) != len(set(ids)):
        failures.append("duplicate_capability_id")
    for cap in CAPABILITY_DEFINITIONS:
        if not cap.get("module_path", "").startswith("sentinel_"):
            failures.append(f"module_not_allowlisted:{cap.get('capability_id')}")
        if not cap.get("allowed_args"):
            failures.append(f"missing_arg_allowlist:{cap.get('capability_id')}")
        if cap.get("risk_class") in BLOCKED_RISK:
            failures.append(f"blocked_risk_registered:{cap.get('capability_id')}")
    reg_a = build_registry(write=False)
    reg_b = build_registry(write=False)
    scores_a = [(c["capability_id"], c["priority_score"]) for c in reg_a["capabilities"]]
    scores_b = [(c["capability_id"], c["priority_score"]) for c in reg_b["capabilities"]]
    if scores_a != scores_b:
        failures.append("scores_not_reproducible")
    sample_text = "password" + "=" + "abcdefghijklmnop"
    if detect_secret_like(sample_text) and "abcdefghijklmnop" in redact_text(sample_text):
        failures.append("secret_redaction_failed")
    json.dumps(reg_a)
    for path in [REPORT_JSON, REGISTRY_JSON, AUDIT_JSONL, PLAYBOOK_REGISTRY]:
        try:
            assert_allowed_write(path)
        except Exception as exc:
            failures.append(f"write_root_invalid:{exc}")
    status = "CAPABILITY_REGISTRY_SELF_TEST_OK" if not failures else "CAPABILITY_REGISTRY_SELF_TEST_FAILED"
    report = {
        "schema_version": SCHEMA_VERSION,
        "timestamp_utc": utc_now(),
        "status": status,
        "self_test_failures": failures,
        **HARD_DEFAULTS,
        "breach": bool(failures),
    }
    write_json(REPORT_JSON, report)
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Sentinel Autonomous Capability Registry.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--discover", action="store_true")
    group.add_argument("--build-registry", action="store_true")
    group.add_argument("--evaluate-capabilities", action="store_true")
    group.add_argument("--route-next-skill", action="store_true")
    group.add_argument("--write-registry", action="store_true")
    group.add_argument("--status", action="store_true")
    return parser


def print_summary(report: Dict[str, Any]) -> None:
    router = report.get("router") if isinstance(report.get("router"), dict) else {}
    print(f"status={report.get('status')}")
    print(f"capability_count={report.get('capability_count', '-')}")
    print(f"discovered_capabilities={len(report.get('discovered_capabilities') or [])}")
    print(f"missing_capabilities={len(report.get('missing_capabilities') or [])}")
    print(f"routed_next_skill={router.get('selected_capability') or report.get('recommended_capability') or '-'}")
    print(f"live_apply={report.get('live_apply', False)}")
    print(f"emergency_stop={report.get('emergency_stop', True)}")
    print(f"allowed_apply_now={report.get('allowed_apply_now', False)}")
    print(f"high_blocked={report.get('high_blocked', True)}")
    print(f"low_live_executable={report.get('low_live_executable', False)}")
    print(f"medium_executable={report.get('medium_executable', False)}")
    print(f"breach={report.get('breach', False)}")


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.self_test:
            report = action_self_test()
        elif args.discover:
            report = action_discover()
        elif args.build_registry:
            report = build_registry(write=True, status="CAPABILITY_REGISTRY_READY")
        elif args.evaluate_capabilities:
            report = action_evaluate()
        elif args.route_next_skill:
            report = action_route()
        elif args.write_registry:
            report = build_registry(write=True, status="CAPABILITY_REGISTRY_WRITTEN")
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
            "status": "CAPABILITY_REGISTRY_FAILED",
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
