#!/usr/bin/env python3
"""Sentinel Autonomous Capability Health Governor (Phase 10.4).

Local-only health warning analysis and safe self-repair for registered
Sentinel capabilities. This module repairs only Sentinel-owned local reports,
state, playbooks and export artifacts through hard allowlisted modules or safe
templates. It never performs live apply, network access, remote writes,
customer-system changes, timer installation or HIGH/MEDIUM/LOW_LIVE execution.
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
SCHEMA_VERSION = "sentinel-autonomous-capability-health-governor-10.4"
PHASE = "10.4"
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

STATUS_OK = "CAPABILITY_HEALTH_GOVERNOR_OK"
STATUS_WARNINGS = "CAPABILITY_HEALTH_GOVERNOR_WARNINGS"
STATUS_REPAIRS_EXECUTED = "CAPABILITY_HEALTH_GOVERNOR_REPAIRS_EXECUTED"
STATUS_BLOCKED = "CAPABILITY_HEALTH_GOVERNOR_BLOCKED_BY_SAFETY"
STATUS_FAILED = "CAPABILITY_HEALTH_GOVERNOR_FAILED"

WARNING_CLASSES = {
    "MISSING_EXPECTED_OUTPUT",
    "STALE_OUTPUT",
    "INVALID_JSON",
    "EMPTY_MARKDOWN",
    "EMPTY_TEXT",
    "MISSING_PLAYBOOK",
    "MISSING_EXPORT_FILE",
    "MISSING_STATUS_REPORT",
    "MISSING_OWNER_SUMMARY",
    "LOW_USEFULNESS",
    "REPEATED_FAILURE",
    "BLOCKED_CAPABILITY",
    "UNKNOWN_WARNING",
}

ALLOWED_REPAIR_ACTIONS = {
    "rewrite_capability_registry_reports",
    "rewrite_capability_health_reports",
    "rewrite_skill_map",
    "rewrite_owner_summary",
    "regenerate_playbooks",
    "rebuild_payhip_upload_pack",
    "rebuild_manifest_and_checksums",
    "rebuild_launch_qa",
    "rebuild_fulfillment_board",
    "rebuild_first_order_dryrun",
    "rebuild_service_proof",
    "rebuild_public_client_assets",
    "rebuild_customer_intake_delivery",
    "rebuild_owner_dashboard_packaging",
    "rewrite_safe_default_json",
    "rewrite_safe_markdown_template",
}

ALLOWED_MODULES = {
    "sentinel_autonomous_capability_registry.py",
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
    "--discover",
    "--build-registry",
    "--evaluate-capabilities",
    "--route-next-skill",
    "--write-registry",
    "--status",
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

REPAIR_COMMANDS: Dict[str, Tuple[str, List[str]]] = {
    "rewrite_capability_registry_reports": ("sentinel_autonomous_capability_registry.py", ["--write-registry"]),
    "rewrite_capability_health_reports": ("sentinel_autonomous_capability_registry.py", ["--evaluate-capabilities"]),
    "rewrite_skill_map": ("sentinel_autonomous_capability_registry.py", ["--write-registry"]),
    "rewrite_owner_summary": ("sentinel_autonomous_capability_registry.py", ["--write-registry"]),
    "regenerate_playbooks": ("sentinel_autonomous_capability_registry.py", ["--write-registry"]),
    "rebuild_payhip_upload_pack": ("sentinel_payhip_upload_pack_export_helper.py", ["--build-export"]),
    "rebuild_manifest_and_checksums": ("sentinel_payhip_upload_pack_export_helper.py", ["--build-export"]),
    "rebuild_launch_qa": ("sentinel_payhip_launch_qa_finalizer.py", ["--scan-upload-pack"]),
    "rebuild_fulfillment_board": ("sentinel_payhip_fulfillment_board.py", ["--build-board"]),
    "rebuild_first_order_dryrun": ("sentinel_payhip_first_order_dryrun.py", ["--status"]),
    "rebuild_service_proof": ("sentinel_service_proof_trend.py", ["--status"]),
    "rebuild_public_client_assets": ("sentinel_payhip_public_client_assets.py", ["--build-public-assets"]),
    "rebuild_customer_intake_delivery": ("sentinel_payhip_customer_intake_delivery.py", ["--build-client-pack"]),
    "rebuild_owner_dashboard_packaging": ("sentinel_owner_dashboard_service_packaging.py", ["--build-dashboard"]),
}

CAPABILITY_REPAIR_ACTION = {
    "payhip_upload_pack_export": "rebuild_payhip_upload_pack",
    "payhip_launch_qa": "rebuild_launch_qa",
    "payhip_fulfillment_board": "rebuild_fulfillment_board",
    "first_order_dryrun": "rebuild_first_order_dryrun",
    "service_proof_trend": "rebuild_service_proof",
    "public_client_assets": "rebuild_public_client_assets",
    "customer_intake_delivery": "rebuild_customer_intake_delivery",
    "owner_dashboard_service_packaging": "rebuild_owner_dashboard_packaging",
    "priority_engine": "rewrite_capability_registry_reports",
    "cycle_runner": "rewrite_capability_registry_reports",
    "autonomy_kernel": "rewrite_capability_registry_reports",
}

FORBIDDEN_REPAIRS = [
    "WordPress change",
    "Cloudflare change",
    "database change",
    "remote write",
    "Nginx change",
    ".htaccess change",
    "Payhip API",
    "email sending",
    "network access",
    "customer data processing",
    "timer installation",
    "cache purge",
    "redirect change",
    "WAF rule change",
    "live theme or plugin change",
    "HIGH/MEDIUM/LOW_LIVE execution",
]

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

REGISTRY_JSON = STATE_DIR / "autonomous_capability_registry.json"
REGISTRY_LATEST_JSON = STATE_DIR / "latest_autonomous_capability_registry.json"
CAPABILITY_HEALTH_JSON = STATE_DIR / "autonomous_capability_health.json"
CAPABILITY_HISTORY_JSON = STATE_DIR / "autonomous_capability_history.json"
SKILL_ROUTER_JSON = STATE_DIR / "autonomous_skill_router_state.json"
REGISTRY_REPORT_JSON = R / "sentinel-autonomous-capability-registry.json"
PRIORITY_JSON = R / "sentinel-autonomous-priority-engine.json"
RUNNER_JSON = R / "sentinel-autonomous-cycle-runner.json"

REPORT_JSON = R / "sentinel-autonomous-capability-health-governor.json"
REPORT_MD = R / "sentinel-autonomous-capability-health-governor.md"
WARNING_ANALYSIS_MD = R / "sentinel-autonomous-capability-warning-analysis.md"
REPAIR_PLAN_MD = R / "sentinel-autonomous-capability-repair-plan.md"
REPAIR_RESULT_MD = R / "sentinel-autonomous-capability-repair-result.md"
REPAIR_VALIDATION_MD = R / "sentinel-autonomous-capability-repair-validation.md"
REPAIR_LEARNING_MD = R / "sentinel-autonomous-capability-repair-learning.md"
OWNER_SUMMARY_MD = R / "sentinel-autonomous-capability-health-owner-summary.md"

STATE_JSON = STATE_DIR / "autonomous_capability_health_governor.json"
STATE_LATEST_JSON = STATE_DIR / "latest_autonomous_capability_health_governor.json"
WARNING_HISTORY_JSON = STATE_DIR / "autonomous_capability_warning_history.json"
REPAIR_HISTORY_JSON = STATE_DIR / "autonomous_capability_repair_history.json"
REPAIR_PATTERNS_JSON = STATE_DIR / "autonomous_capability_repair_patterns.json"
BLOCKED_REPAIR_PATTERNS_JSON = STATE_DIR / "autonomous_capability_blocked_repair_patterns.json"

AUDIT_JSONL = AUDIT_DIR / "sentinel-autonomous-capability-health-governor.jsonl"

PLAYBOOK_GOVERNOR = PLAYBOOK_DIR / "sentinel-autonomous-capability-health-governor.playbook.json"
PLAYBOOK_SELF_REPAIR = PLAYBOOK_DIR / "sentinel-autonomous-capability-self-repair.playbook.json"
PLAYBOOK_WARNING = PLAYBOOK_DIR / "sentinel-autonomous-capability-warning-classification.playbook.json"
PLAYBOOK_VALIDATION = PLAYBOOK_DIR / "sentinel-autonomous-capability-repair-validation.playbook.json"

ALLOWED_WRITE_ROOTS = (
    R,
    STATE_DIR,
    AUDIT_DIR,
    PLAYBOOK_DIR,
    EXPORT_DIR,
)

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
    except Exception:
        return False


def assert_allowed_write(path: Path) -> None:
    if not any(is_within(path, root) for root in ALLOWED_WRITE_ROOTS):
        raise ValueError(f"write outside allowed roots refused: {rel(path)}")
    if path.suffix.lower() not in {".json", ".jsonl", ".md", ".txt", ".sha256"}:
        raise ValueError(f"unsupported output suffix refused: {rel(path)}")


def redact_text(value: Any, max_len: int = 3000) -> str:
    text = "" if value is None else str(value)
    text = SECRET_RE.sub(lambda m: m.group(0).split("=", 1)[0].split(":", 1)[0] + "=<redacted>", text)
    text = PRIVATE_KEY_RE.sub("<redacted-private-key-marker>", text)
    text = TOKEN_FORMAT_RE.sub("<redacted-token>", text)
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text


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


def load_dict(path: Path) -> Dict[str, Any]:
    data, status = read_json(path)
    return data if status == "ok" and isinstance(data, dict) else {}


def load_list(path: Path) -> List[Any]:
    data, status = read_json(path)
    return data if status == "ok" and isinstance(data, list) else []


def read_json(path: Path) -> Tuple[Optional[Any], str]:  # type: ignore[no-redef]
    try:
        if not path.exists():
            return None, "missing"
        return json.loads(path.read_text(encoding="utf-8")), "ok"
    except json.JSONDecodeError:
        return None, "invalid_json"
    except OSError:
        return None, "read_error"


def file_age_hours(path: Path) -> Optional[float]:
    try:
        return round((datetime.now(timezone.utc).timestamp() - path.stat().st_mtime) / 3600.0, 3)
    except OSError:
        return None


def path_empty(path: Path) -> bool:
    try:
        return path.exists() and path.stat().st_size == 0
    except OSError:
        return False


def module_arg_allowed(module: str, args: List[str]) -> bool:
    return module in ALLOWED_MODULES and all(arg in ALLOWED_ARGS for arg in args)


def run_allowlisted_module(module: str, args: List[str], timeout: int = 180) -> Dict[str, Any]:
    if not module_arg_allowed(module, args):
        return {
            "status": "blocked_not_allowlisted",
            "module": module,
            "args": args,
            "returncode": None,
            "stdout_lines": 0,
            "stderr": "module or args not on hard allowlist",
        }
    module_path = PROJECT_DIR / module
    if not module_path.exists():
        return {
            "status": "blocked_missing_module",
            "module": module,
            "args": args,
            "returncode": None,
            "stdout_lines": 0,
            "stderr": "module missing",
        }
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
        return {"status": "timeout", "module": module, "args": args, "returncode": None, "stdout_lines": 0, "stderr": "timeout"}
    except (OSError, subprocess.SubprocessError) as exc:
        return {"status": "error", "module": module, "args": args, "returncode": None, "stdout_lines": 0, "stderr": redact_text(exc, 500)}
    return {
        "status": "executed" if proc.returncode == 0 else "failed",
        "module": module,
        "args": args,
        "returncode": proc.returncode,
        "stdout_lines": len([ln for ln in (proc.stdout or "").splitlines() if ln.strip()]),
        "stderr": redact_text(proc.stderr, 1000),
    }


def read_registry() -> Tuple[Dict[str, Any], str]:
    for path in (REGISTRY_JSON, REGISTRY_LATEST_JSON, REGISTRY_REPORT_JSON):
        data, status = read_json(path)
        if status == "ok" and isinstance(data, dict):
            return data, rel(path)
    return {}, "missing"


def classify_path_warning(path_value: str, default_capability: str = "registry") -> Dict[str, Any]:
    path = PROJECT_DIR / path_value
    suffix = path.suffix.lower()
    warning_class = "UNKNOWN_WARNING"
    if not path.exists():
        if is_within(path, PLAYBOOK_DIR):
            warning_class = "MISSING_PLAYBOOK"
        elif is_within(path, EXPORT_DIR):
            warning_class = "MISSING_EXPORT_FILE"
        elif path.name.endswith("owner-summary.md"):
            warning_class = "MISSING_OWNER_SUMMARY"
        elif is_within(path, R):
            warning_class = "MISSING_STATUS_REPORT"
        else:
            warning_class = "MISSING_EXPECTED_OUTPUT"
    elif suffix == ".json" and read_json(path)[1] != "ok":
        warning_class = "INVALID_JSON"
    elif suffix == ".md" and path_empty(path):
        warning_class = "EMPTY_MARKDOWN"
    elif suffix in {".txt", ".html"} and path_empty(path):
        warning_class = "EMPTY_TEXT"
    return {
        "capability_id": default_capability,
        "path": rel(path),
        "warning_class": warning_class,
        "detail": f"path status warning for {rel(path)}",
    }


def scan_health() -> Dict[str, Any]:
    registry, registry_source = read_registry()
    caps = registry.get("capabilities") if isinstance(registry.get("capabilities"), list) else []
    warnings: List[Dict[str, Any]] = []
    missing_inputs: List[str] = []

    required_inputs = [
        REGISTRY_JSON,
        CAPABILITY_HEALTH_JSON,
        REGISTRY_LATEST_JSON,
        CAPABILITY_HISTORY_JSON,
        SKILL_ROUTER_JSON,
        REGISTRY_REPORT_JSON,
        R / "sentinel-autonomous-capability-health.md",
        R / "sentinel-autonomous-capability-routing.md",
        R / "sentinel-autonomous-skill-map.md",
        PRIORITY_JSON,
        RUNNER_JSON,
    ]
    for path in required_inputs:
        if not path.exists():
            missing_inputs.append(rel(path))

    if not caps:
        warnings.append({
            "warning_id": "W-registry-missing",
            "capability_id": "registry",
            "warning_class": "MISSING_STATUS_REPORT",
            "path": rel(REGISTRY_JSON),
            "before_health": "registry_missing_or_invalid",
            "detail": "capability registry missing or invalid",
            "repairable": True,
            "recommended_repair_action": "rewrite_capability_registry_reports",
            "risk_class": LOW_STATE,
        })
    for cap in caps:
        cap_id = str(cap.get("capability_id") or "unknown")
        before_health = str(cap.get("health_status") or "UNKNOWN")
        if cap.get("module_exists") is False or cap.get("can_run_autonomously") is False and cap.get("reason_if_blocked"):
            warnings.append({
                "warning_id": f"W-{cap_id}-blocked",
                "capability_id": cap_id,
                "warning_class": "BLOCKED_CAPABILITY",
                "path": cap.get("module_path"),
                "before_health": before_health,
                "detail": redact_text(cap.get("reason_if_blocked"), 500),
                "repairable": False,
                "recommended_repair_action": None,
                "risk_class": cap.get("risk_class", HIGH),
            })
        expected = cap.get("expected_output_status") if isinstance(cap.get("expected_output_status"), dict) else {}
        fresh = cap.get("freshness") if isinstance(cap.get("freshness"), dict) else {}
        for item in expected.get("missing") or []:
            path_info = classify_path_warning(str(item), cap_id)
            warnings.append({
                "warning_id": f"W-{cap_id}-missing-{len(warnings)+1}",
                "before_health": before_health,
                "repairable": True,
                "recommended_repair_action": CAPABILITY_REPAIR_ACTION.get(cap_id, "rewrite_capability_registry_reports"),
                "risk_class": cap.get("risk_class", LOW_STATE),
                **path_info,
            })
        for item in expected.get("invalid_json") or []:
            warnings.append({
                "warning_id": f"W-{cap_id}-invalid-json-{len(warnings)+1}",
                "capability_id": cap_id,
                "warning_class": "INVALID_JSON",
                "path": str(item),
                "before_health": before_health,
                "detail": f"invalid JSON expected output: {item}",
                "repairable": True,
                "recommended_repair_action": CAPABILITY_REPAIR_ACTION.get(cap_id, "rewrite_safe_default_json"),
                "risk_class": cap.get("risk_class", LOW_STATE),
            })
        for item in fresh.get("stale") or []:
            warnings.append({
                "warning_id": f"W-{cap_id}-stale-{len(warnings)+1}",
                "capability_id": cap_id,
                "warning_class": "STALE_OUTPUT",
                "path": str(item),
                "before_health": before_health,
                "detail": f"stale output: {item}",
                "repairable": True,
                "recommended_repair_action": CAPABILITY_REPAIR_ACTION.get(cap_id, "rewrite_capability_registry_reports"),
                "risk_class": cap.get("risk_class", LOW_STATE),
            })
        if int(cap.get("usefulness_score") or 0) < 5:
            warnings.append({
                "warning_id": f"W-{cap_id}-low-usefulness",
                "capability_id": cap_id,
                "warning_class": "LOW_USEFULNESS",
                "path": None,
                "before_health": before_health,
                "detail": "low usefulness score",
                "repairable": False,
                "recommended_repair_action": None,
                "risk_class": cap.get("risk_class", LOW_STATE),
            })
        if int(cap.get("failure_count") or 0) > int(cap.get("success_count") or 0) and int(cap.get("failure_count") or 0) > 0:
            warnings.append({
                "warning_id": f"W-{cap_id}-repeated-failure",
                "capability_id": cap_id,
                "warning_class": "REPEATED_FAILURE",
                "path": None,
                "before_health": before_health,
                "detail": "failure count exceeds success count",
                "repairable": False,
                "recommended_repair_action": None,
                "risk_class": cap.get("risk_class", LOW_STATE),
            })

    for path in [
        R / "sentinel-autonomous-capability-health.md",
        R / "sentinel-autonomous-capability-routing.md",
        R / "sentinel-autonomous-skill-map.md",
        R / "sentinel-autonomous-skill-router-owner-summary.md",
        PLAYBOOK_DIR / "sentinel-autonomous-capability-registry.playbook.json",
        PLAYBOOK_DIR / "sentinel-autonomous-skill-router.playbook.json",
        PLAYBOOK_DIR / "sentinel-autonomous-capability-health.playbook.json",
        PLAYBOOK_DIR / "sentinel-autonomy-capability-integration.playbook.json",
    ]:
        if not path.exists() or path_empty(path) or (path.suffix == ".json" and read_json(path)[1] != "ok"):
            path_warning = classify_path_warning(rel(path), "registry")
            warnings.append({
                "warning_id": f"W-required-{len(warnings)+1}",
                "before_health": (registry.get("health") or {}).get("status", "UNKNOWN"),
                "repairable": True,
                "recommended_repair_action": "rewrite_capability_registry_reports",
                "risk_class": LOW_STATE,
                **path_warning,
            })

    dedup: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    for warning in warnings:
        warning["warning_class"] = warning.get("warning_class") if warning.get("warning_class") in WARNING_CLASSES else "UNKNOWN_WARNING"
        key = (str(warning.get("capability_id")), str(warning.get("warning_class")), str(warning.get("path")))
        dedup[key] = warning
    warnings = list(dedup.values())

    status = STATUS_WARNINGS if warnings else STATUS_OK
    return {
        "timestamp_utc": utc_now(),
        "action": "scan-health",
        "status": status,
        "registry_source": registry_source,
        "missing_inputs": missing_inputs,
        "before_health": (registry.get("health") or {}).get("status", "UNKNOWN"),
        "capability_count": len(caps),
        "warning_count": len(warnings),
        "warnings": warnings,
        "warning_classes": sorted(set(str(w.get("warning_class")) for w in warnings)),
        "live_apply": False,
        "emergency_stop": True,
        "allowed_apply_now": False,
        "high_blocked": True,
        "low_live_executable": False,
        "medium_executable": False,
        "breach": False,
    }


def classify_warnings(scan: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    scan = scan or scan_health()
    classified: List[Dict[str, Any]] = []
    for item in scan.get("warnings") or []:
        action = item.get("recommended_repair_action")
        risk = str(item.get("risk_class") or LOW_STATE)
        can_repair = bool(item.get("repairable") and action in ALLOWED_REPAIR_ACTIONS and risk in AUTO_ALLOWED_RISK)
        if item.get("warning_class") in {"BLOCKED_CAPABILITY", "LOW_USEFULNESS", "REPEATED_FAILURE"}:
            can_repair = False
        classified.append({
            **item,
            "can_plan_repair": can_repair,
            "classification_reason": "safe local repair class" if can_repair else "blocked or informational warning",
        })
    return {
        **scan,
        "action": "classify-warnings",
        "status": STATUS_WARNINGS if classified else STATUS_OK,
        "classified_warnings": classified,
        "repairable_warning_count": sum(1 for w in classified if w.get("can_plan_repair")),
        "blocked_warning_count": sum(1 for w in classified if not w.get("can_plan_repair")),
    }


def output_scope_allowed(paths: Iterable[str], risk_class: str) -> bool:
    allowed_roots = [R, STATE_DIR, AUDIT_DIR, PLAYBOOK_DIR]
    if risk_class == LOW_EXPORT:
        allowed_roots.append(EXPORT_DIR)
    for value in paths:
        path = PROJECT_DIR / str(value)
        if not any(is_within(path, root) for root in allowed_roots):
            return False
    return True


def repair_expected_outputs(action: str, warning: Dict[str, Any]) -> List[str]:
    if action in {
        "rewrite_capability_registry_reports",
        "rewrite_capability_health_reports",
        "rewrite_skill_map",
        "rewrite_owner_summary",
        "regenerate_playbooks",
    }:
        return [
            "reports/latest/sentinel-autonomous-capability-registry.json",
            "reports/latest/sentinel-autonomous-capability-health.md",
            "reports/latest/sentinel-autonomous-skill-map.md",
        ]
    if action == "rebuild_customer_intake_delivery":
        return ["reports/latest/sentinel-payhip-customer-intake.json"]
    if action == "rebuild_owner_dashboard_packaging":
        return ["reports/latest/sentinel-owner-dashboard.json"]
    if action == "rebuild_payhip_upload_pack":
        return ["reports/latest/sentinel-payhip-upload-pack-export.json"]
    if action == "rebuild_manifest_and_checksums":
        return ["exports/payhip-upload-pack/latest/MANIFEST.json", "exports/payhip-upload-pack/latest/CHECKSUMS.sha256"]
    if action == "rebuild_launch_qa":
        return ["reports/latest/sentinel-payhip-launch-qa.json"]
    if action == "rebuild_fulfillment_board":
        return ["reports/latest/sentinel-payhip-fulfillment-board.json"]
    if action == "rebuild_first_order_dryrun":
        return ["reports/latest/sentinel-payhip-first-order-dryrun.json"]
    if action == "rebuild_service_proof":
        return ["reports/latest/sentinel-service-proof.json"]
    if action == "rebuild_public_client_assets":
        return [
            "reports/latest/sentinel-payhip-public-intake-form.md",
            "reports/latest/sentinel-payhip-public-safety-agreement.md",
            "reports/latest/sentinel-payhip-public-service-overview.md",
        ]
    path = warning.get("path")
    return [str(path)] if path else []


def plan_repairs(classified: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    classified = classified or classify_warnings()
    plans: List[Dict[str, Any]] = []
    for warning in classified.get("classified_warnings") or []:
        action = warning.get("recommended_repair_action")
        risk = str(warning.get("risk_class") or LOW_STATE)
        outputs = repair_expected_outputs(str(action), warning)
        module = None
        args: List[str] = []
        if action in REPAIR_COMMANDS:
            module, args = REPAIR_COMMANDS[str(action)]
        can_execute = bool(
            warning.get("can_plan_repair")
            and action in ALLOWED_REPAIR_ACTIONS
            and risk in AUTO_ALLOWED_RISK
            and output_scope_allowed(outputs, risk)
            and (module is None or module_arg_allowed(module, args))
        )
        reason = "ready for safe local repair" if can_execute else "blocked by safety guard or informational warning"
        plans.append({
            "repair_id": f"R-{len(plans)+1:03d}",
            "warning_id": warning.get("warning_id"),
            "capability_id": warning.get("capability_id"),
            "warning_class": warning.get("warning_class"),
            "repair_action": action,
            "risk_class": risk,
            "allowed_scope": ["reports/latest", "state/adaptive-learning", "audit", "playbooks"]
            + (["exports/payhip-upload-pack"] if risk == LOW_EXPORT else []),
            "input_paths": [warning.get("path")] if warning.get("path") else [],
            "output_paths": outputs,
            "expected_outputs": outputs,
            "guard_requirements": [
                "live_apply=false",
                "emergency_stop=true",
                "allowed_apply_now=false",
                "HIGH blocked=true",
                "LOW_LIVE executable=false",
                "MEDIUM executable=false",
                "hard subprocess allowlist",
                "no network",
                "no remote write",
            ],
            "module": module,
            "args": args,
            "can_execute_now": can_execute,
            "reason_if_blocked": None if can_execute else reason,
        })
    return {
        **classified,
        "action": "plan-repairs",
        "status": STATUS_WARNINGS if plans else STATUS_OK,
        "planned_repairs": plans,
        "planned_repair_count": len(plans),
        "executable_repair_count": sum(1 for p in plans if p.get("can_execute_now")),
        "blocked_repair_count": sum(1 for p in plans if not p.get("can_execute_now")),
    }


def safe_template_repair(plan: Dict[str, Any]) -> Dict[str, Any]:
    action = plan.get("repair_action")
    outputs = [PROJECT_DIR / p for p in plan.get("expected_outputs") or [] if isinstance(p, str)]
    written: List[str] = []
    if action == "rewrite_safe_markdown_template":
        for path in outputs:
            write_text(path, f"# Safe Local Repair Placeholder\n\n- generated_at: `{utc_now()}`\n- repair_id: `{plan.get('repair_id')}`\n- live_apply: `False`\n- emergency_stop: `True`\n")
            written.append(rel(path))
    elif action == "rewrite_safe_default_json":
        for path in outputs:
            write_json(path, {
                "generated_at": utc_now(),
                "repair_id": plan.get("repair_id"),
                "status": "SAFE_DEFAULT_REWRITTEN",
                "live_apply": False,
                "emergency_stop": True,
                "allowed_apply_now": False,
                "breach": False,
            })
            written.append(rel(path))
    else:
        return {"status": "blocked_no_template_repair", "written": []}
    return {"status": "executed", "written": written}


def execute_safe_repairs(planned: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    planned = planned or plan_repairs()
    executed: List[Dict[str, Any]] = []
    blocked: List[Dict[str, Any]] = []
    executed_actions: set = set()
    for plan in planned.get("planned_repairs") or []:
        if not plan.get("can_execute_now"):
            blocked.append({"repair_id": plan.get("repair_id"), "capability_id": plan.get("capability_id"), "reason": plan.get("reason_if_blocked")})
            continue
        action = plan.get("repair_action")
        if action in executed_actions and action in REPAIR_COMMANDS:
            executed.append({
                "repair_id": plan.get("repair_id"),
                "capability_id": plan.get("capability_id"),
                "repair_action": action,
                "status": "deduplicated_already_executed",
            })
            continue
        if action in REPAIR_COMMANDS:
            module, args = REPAIR_COMMANDS[str(action)]
            result = run_allowlisted_module(module, args)
            executed_actions.add(action)
            executed.append({
                "repair_id": plan.get("repair_id"),
                "capability_id": plan.get("capability_id"),
                "repair_action": action,
                "status": result.get("status"),
                "module": result.get("module"),
                "args": result.get("args"),
                "returncode": result.get("returncode"),
                "stdout_lines": result.get("stdout_lines"),
                "stderr": result.get("stderr"),
            })
        elif action in {"rewrite_safe_markdown_template", "rewrite_safe_default_json"}:
            result = safe_template_repair(plan)
            executed_actions.add(action)
            executed.append({
                "repair_id": plan.get("repair_id"),
                "capability_id": plan.get("capability_id"),
                "repair_action": action,
                **result,
            })
        else:
            blocked.append({"repair_id": plan.get("repair_id"), "capability_id": plan.get("capability_id"), "reason": "repair action has no safe executor"})

    # Refresh registry after any safe repair attempt so health is recalculated.
    if executed:
        refresh = run_allowlisted_module("sentinel_autonomous_capability_registry.py", ["--evaluate-capabilities"])
        executed.append({
            "repair_id": "R-refresh-registry",
            "capability_id": "registry",
            "repair_action": "rewrite_capability_health_reports",
            "status": refresh.get("status"),
            "module": refresh.get("module"),
            "args": refresh.get("args"),
            "returncode": refresh.get("returncode"),
            "stdout_lines": refresh.get("stdout_lines"),
            "stderr": refresh.get("stderr"),
        })

    success_count = sum(1 for r in executed if r.get("status") in {"executed", "deduplicated_already_executed"})
    status = STATUS_REPAIRS_EXECUTED if success_count else (STATUS_WARNINGS if blocked else STATUS_OK)
    return {
        **planned,
        "action": "execute-safe-repairs",
        "status": status,
        "executed_repairs": executed,
        "blocked_repairs": blocked,
        "executed_repair_count": success_count,
        "blocked_repair_count": len(blocked),
    }


def validate_output(path_value: str) -> Dict[str, Any]:
    path = PROJECT_DIR / path_value
    status = "ok"
    reasons: List[str] = []
    if not path.exists():
        status = "missing"
        reasons.append("missing")
    elif path.suffix == ".json" and read_json(path)[1] != "ok":
        status = "invalid_json"
        reasons.append("invalid_json")
    elif path.suffix in {".md", ".txt", ".html"} and path_empty(path):
        status = "empty"
        reasons.append("empty")
    if path.exists():
        try:
            blob = path.read_text(encoding="utf-8", errors="replace")
            if secret_like(blob):
                status = "unsafe"
                reasons.append("secret_like_content")
            if CUSTOMER_DATA_RE.search(blob):
                status = "unsafe"
                reasons.append("customer_data_marker")
        except OSError:
            status = "read_error"
            reasons.append("read_error")
    return {"path": path_value, "status": status, "reasons": reasons}


def validate_repairs(executed: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    executed = executed or execute_safe_repairs()
    registry, _ = read_registry()
    after_health = (registry.get("health") or {}).get("status", "UNKNOWN")
    outputs = sorted({
        item
        for plan in executed.get("planned_repairs") or []
        for item in (plan.get("expected_outputs") or [])
        if isinstance(item, str)
    })
    output_checks = [validate_output(path) for path in outputs]
    failed = [c for c in output_checks if c.get("status") not in {"ok"}]
    reasons: List[str] = []
    if failed:
        reasons.append("output_validation_attention")
    if executed.get("live_apply") is not False or executed.get("allowed_apply_now") is not False:
        reasons.append("safety_default_changed")
    status = "CAPABILITY_REPAIR_VALIDATION_OK" if not reasons else "CAPABILITY_REPAIR_VALIDATION_WARNINGS"
    return {
        **executed,
        "action": "validate-repairs",
        "validation_status": status,
        "status": status,
        "after_health": after_health,
        "output_checks": output_checks,
        "failed_output_checks": failed,
        "validation_reasons": reasons,
        "live_apply": False,
        "emergency_stop": True,
        "allowed_apply_now": False,
        "high_blocked": True,
        "low_live_executable": False,
        "medium_executable": False,
        "breach": False,
    }


def learn(validated: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    validated = validated or validate_repairs()
    warning_history = load_list(WARNING_HISTORY_JSON)
    repair_history = load_list(REPAIR_HISTORY_JSON)
    repair_patterns = load_dict(REPAIR_PATTERNS_JSON)
    blocked_patterns = load_dict(BLOCKED_REPAIR_PATTERNS_JSON)

    now = utc_now()
    warning_history.append({
        "timestamp_utc": now,
        "warning_count": validated.get("warning_count"),
        "warning_classes": validated.get("warning_classes"),
        "before_health": validated.get("before_health"),
        "after_health": validated.get("after_health"),
        "breach": False,
    })
    for item in validated.get("executed_repairs") or []:
        repair_history.append({
            "timestamp_utc": now,
            "repair_id": item.get("repair_id"),
            "capability_id": item.get("capability_id"),
            "repair_action": item.get("repair_action"),
            "repair_success": item.get("status") in {"executed", "deduplicated_already_executed"},
            "repair_failure_reason": item.get("stderr") if item.get("status") not in {"executed", "deduplicated_already_executed"} else None,
        })
    for item in validated.get("executed_repairs") or []:
        action = str(item.get("repair_action"))
        if item.get("status") in {"executed", "deduplicated_already_executed"}:
            repair_patterns[action] = int(repair_patterns.get(action, 0)) + 1
    for item in validated.get("blocked_repairs") or []:
        reason = str(item.get("reason") or "unknown")
        blocked_patterns[reason] = int(blocked_patterns.get(reason, 0)) + 1

    write_json(WARNING_HISTORY_JSON, warning_history[-300:])
    write_json(REPAIR_HISTORY_JSON, repair_history[-300:])
    write_json(REPAIR_PATTERNS_JSON, repair_patterns)
    write_json(BLOCKED_REPAIR_PATTERNS_JSON, blocked_patterns)

    learning = {
        **validated,
        "action": "learn",
        "learning_status": "CAPABILITY_REPAIR_LEARNING_WRITTEN",
        "successful_repair_patterns": repair_patterns,
        "blocked_repair_patterns": blocked_patterns,
        "next_health_recommendation": "Re-run capability registry evaluation, then run controlled cycles if health remains acceptable.",
        "not_stored": ["passwords", "tokens", "API keys", "private keys", "real customer data", "customer access data", "payment data"],
    }
    return learning


def build_cycle() -> Dict[str, Any]:
    scanned = scan_health()
    classified = classify_warnings(scanned)
    planned = plan_repairs(classified)
    executed = execute_safe_repairs(planned)
    validated = validate_repairs(executed)
    learned = learn(validated)
    return {
        **learned,
        "action": "cycle",
        "status": learned.get("status"),
    }


def write_playbooks(report: Dict[str, Any]) -> None:
    base = {
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "live_apply": False,
        "emergency_stop": True,
        "allowed_apply_now": False,
        "high_blocked": True,
        "low_live_executable": False,
        "medium_executable": False,
        "breach": False,
    }
    write_json(PLAYBOOK_GOVERNOR, {
        **base,
        "name": "sentinel-autonomous-capability-health-governor",
        "purpose": "Classify capability health warnings and execute only safe local self-repairs.",
        "allowed_repairs": sorted(ALLOWED_REPAIR_ACTIONS),
        "blocked_repairs": FORBIDDEN_REPAIRS,
    })
    write_json(PLAYBOOK_SELF_REPAIR, {
        **base,
        "name": "sentinel-autonomous-capability-self-repair",
        "safe_repair_risks": sorted(AUTO_ALLOWED_RISK),
        "blocked_risks": sorted(BLOCKED_RISK),
        "subprocess_allowlist": sorted(ALLOWED_MODULES),
    })
    write_json(PLAYBOOK_WARNING, {
        **base,
        "name": "sentinel-autonomous-capability-warning-classification",
        "warning_classes": sorted(WARNING_CLASSES),
        "current_warning_classes": report.get("warning_classes", []),
    })
    write_json(PLAYBOOK_VALIDATION, {
        **base,
        "name": "sentinel-autonomous-capability-repair-validation",
        "validation_checks": ["expected files present", "json valid", "markdown non-empty", "no secrets", "no customer markers", "safe defaults unchanged"],
        "after_health": report.get("after_health"),
    })


def render_report_md(report: Dict[str, Any]) -> str:
    return "\n".join([
        "# Sentinel Autonomous Capability Health Governor",
        "",
        f"- status: `{report.get('status')}`",
        f"- action: `{report.get('action')}`",
        f"- warning_count: `{report.get('warning_count', 0)}`",
        f"- planned_repairs: `{report.get('planned_repair_count', 0)}`",
        f"- executed_safe_repairs: `{report.get('executed_repair_count', 0)}`",
        f"- blocked_repairs: `{report.get('blocked_repair_count', 0)}`",
        f"- before_health: `{report.get('before_health')}`",
        f"- after_health: `{report.get('after_health', '-')}`",
        "- live_apply: `False`",
        "- emergency_stop: `True`",
        "- allowed_apply_now: `False`",
        "- HIGH blocked: `True`",
        "- LOW_LIVE executable: `False`",
        "- MEDIUM executable: `False`",
        "- breach: `False`",
    ]) + "\n"


def render_warning_analysis_md(report: Dict[str, Any]) -> str:
    lines = ["# Capability Warning Analysis", ""]
    for warning in report.get("classified_warnings") or report.get("warnings") or []:
        lines.append(
            f"- `{warning.get('warning_id')}` capability=`{warning.get('capability_id')}` "
            f"class=`{warning.get('warning_class')}` path=`{warning.get('path') or '-'}` "
            f"repairable=`{warning.get('can_plan_repair', warning.get('repairable'))}`"
        )
    if not (report.get("classified_warnings") or report.get("warnings")):
        lines.append("- No capability warnings detected.")
    return "\n".join(lines) + "\n"


def render_repair_plan_md(report: Dict[str, Any]) -> str:
    lines = ["# Capability Repair Plan", ""]
    for plan in report.get("planned_repairs") or []:
        lines.extend([
            f"## {plan.get('repair_id')}",
            f"- capability: `{plan.get('capability_id')}`",
            f"- warning_class: `{plan.get('warning_class')}`",
            f"- action: `{plan.get('repair_action')}`",
            f"- risk: `{plan.get('risk_class')}`",
            f"- can_execute_now: `{plan.get('can_execute_now')}`",
            f"- reason_if_blocked: `{plan.get('reason_if_blocked') or '-'}`",
            "",
        ])
    if not report.get("planned_repairs"):
        lines.append("- No repair plan needed.")
    return "\n".join(lines) + "\n"


def render_repair_result_md(report: Dict[str, Any]) -> str:
    lines = ["# Capability Repair Result", ""]
    for item in report.get("executed_repairs") or []:
        lines.append(
            f"- `{item.get('repair_id')}` capability=`{item.get('capability_id')}` "
            f"action=`{item.get('repair_action')}` status=`{item.get('status')}` "
            f"returncode=`{item.get('returncode', '-')}`"
        )
    for item in report.get("blocked_repairs") or []:
        lines.append(f"- blocked `{item.get('repair_id')}` capability=`{item.get('capability_id')}` reason=`{item.get('reason')}`")
    if not report.get("executed_repairs") and not report.get("blocked_repairs"):
        lines.append("- No repairs executed or blocked.")
    return "\n".join(lines) + "\n"


def render_validation_md(report: Dict[str, Any]) -> str:
    lines = ["# Capability Repair Validation", "", f"- status: `{report.get('validation_status', report.get('status'))}`"]
    for check in report.get("output_checks") or []:
        lines.append(f"- `{check.get('path')}` status=`{check.get('status')}` reasons=`{','.join(check.get('reasons') or []) or '-'}`")
    if not report.get("output_checks"):
        lines.append("- No output checks required.")
    return "\n".join(lines) + "\n"


def render_learning_md(report: Dict[str, Any]) -> str:
    lines = ["# Capability Repair Learning", "", f"- learning_status: `{report.get('learning_status', '-')}`"]
    lines.append(f"- next_health_recommendation: {report.get('next_health_recommendation', '-')}")
    lines.append("")
    lines.append("## Successful Repair Patterns")
    patterns = report.get("successful_repair_patterns") if isinstance(report.get("successful_repair_patterns"), dict) else {}
    for key, count in sorted(patterns.items()):
        lines.append(f"- `{key}`: `{count}`")
    if not patterns:
        lines.append("- none yet")
    lines.append("")
    lines.append("## Blocked Repair Patterns")
    blocked = report.get("blocked_repair_patterns") if isinstance(report.get("blocked_repair_patterns"), dict) else {}
    for key, count in sorted(blocked.items()):
        lines.append(f"- `{key}`: `{count}`")
    if not blocked:
        lines.append("- none")
    return "\n".join(lines) + "\n"


def render_owner_summary_md(report: Dict[str, Any]) -> str:
    repaired_caps = sorted(set(str(item.get("capability_id")) for item in report.get("executed_repairs") or [] if item.get("capability_id")))
    return "\n".join([
        "# Capability Health Owner Summary",
        "",
        f"- before_health: `{report.get('before_health')}`",
        f"- after_health: `{report.get('after_health', '-')}`",
        f"- warning_count: `{report.get('warning_count', 0)}`",
        f"- planned_repairs: `{report.get('planned_repair_count', 0)}`",
        f"- executed_safe_repairs: `{report.get('executed_repair_count', 0)}`",
        f"- blocked_repairs: `{report.get('blocked_repair_count', 0)}`",
        f"- repaired_capabilities: `{', '.join(repaired_caps) or '-'}`",
        "- live_apply: `False`",
        "- emergency_stop: `True`",
        "- allowed_apply_now: `False`",
        "- HIGH blocked: `True`",
        "- LOW_LIVE executable: `False`",
        "- MEDIUM executable: `False`",
        "- breach: `False`",
        "",
        "Self-repair is limited to Sentinel-owned local capability artifacts. Live or external systems remain blocked.",
    ]) + "\n"


def write_outputs(report: Dict[str, Any]) -> None:
    safe_report = {
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "timestamp_utc": report.get("timestamp_utc") or utc_now(),
        **report,
        **HARD_DEFAULTS,
        "recommended_git_checkpoint": [
            "sentinel_autonomous_capability_health_governor.py",
            "sentinel_autonomous_capability_registry.py",
            "sentinel_autonomous_priority_engine.py",
            "sentinel_self_governing_safe_autonomy_kernel.py",
            "sentinel_autonomous_cycle_runner.py",
            "playbooks/sentinel-autonomous-capability-health-governor.playbook.json",
            "playbooks/sentinel-autonomous-capability-self-repair.playbook.json",
            "playbooks/sentinel-autonomous-capability-warning-classification.playbook.json",
            "playbooks/sentinel-autonomous-capability-repair-validation.playbook.json",
        ],
    }
    write_json(REPORT_JSON, safe_report)
    write_json(STATE_JSON, safe_report)
    write_json(STATE_LATEST_JSON, safe_report)
    write_text(REPORT_MD, render_report_md(safe_report))
    write_text(WARNING_ANALYSIS_MD, render_warning_analysis_md(safe_report))
    write_text(REPAIR_PLAN_MD, render_repair_plan_md(safe_report))
    write_text(REPAIR_RESULT_MD, render_repair_result_md(safe_report))
    write_text(REPAIR_VALIDATION_MD, render_validation_md(safe_report))
    write_text(REPAIR_LEARNING_MD, render_learning_md(safe_report))
    write_text(OWNER_SUMMARY_MD, render_owner_summary_md(safe_report))
    write_playbooks(safe_report)
    append_jsonl(AUDIT_JSONL, [{
        "timestamp_utc": utc_now(),
        "event": "capability_health_governor",
        "action": safe_report.get("action"),
        "status": safe_report.get("status"),
        "warning_count": safe_report.get("warning_count", 0),
        "executed_repair_count": safe_report.get("executed_repair_count", 0),
        "blocked_repair_count": safe_report.get("blocked_repair_count", 0),
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
    sample_warning = {
        "warning_id": "W-test",
        "capability_id": "customer_intake_delivery",
        "warning_class": "STALE_OUTPUT",
        "path": "reports/latest/sentinel-payhip-customer-intake.json",
        "before_health": "CAPABILITY_NEEDS_REFRESH",
        "repairable": True,
        "recommended_repair_action": "rebuild_customer_intake_delivery",
        "risk_class": LOW_STATE,
        "can_plan_repair": True,
    }
    fake_classified = {
        "timestamp_utc": utc_now(),
        "status": STATUS_WARNINGS,
        "classified_warnings": [sample_warning],
        "warning_count": 1,
        "warning_classes": ["STALE_OUTPUT"],
        "live_apply": False,
        "allowed_apply_now": False,
        "breach": False,
    }
    plan = plan_repairs(fake_classified)
    blocked_fake = plan_repairs({
        **fake_classified,
        "classified_warnings": [{
            **sample_warning,
            "warning_id": "W-blocked",
            "recommended_repair_action": "unsafe_unknown_action",
            "can_plan_repair": True,
        }],
    })
    checks = {
        "no_apply_argument": ("--" + "apply") not in source,
        "no_source_safety_findings": not findings,
        "allowed_module_accepts_registry": module_arg_allowed("sentinel_autonomous_capability_registry.py", ["--write-registry"]),
        "unknown_module_blocked": not module_arg_allowed("unknown.py", ["--status"]),
        "unknown_arg_blocked": not module_arg_allowed("sentinel_autonomous_capability_registry.py", ["--bad"]),
        "repair_has_risk_class": bool(plan["planned_repairs"][0].get("risk_class")),
        "repair_can_execute": plan["planned_repairs"][0].get("can_execute_now") is True,
        "unsafe_action_blocked": blocked_fake["planned_repairs"][0].get("can_execute_now") is False,
        "output_scope_blocks_outside": output_scope_allowed(["/tmp/not-allowed.json"], LOW_STATE) is False,
        "secret_redaction": "ABCDEF1234567890" not in redact_text("api_key" + "=" + "ABCDEF1234567890"),
        "json_serializable": isinstance(json.dumps(plan), str),
        "live_apply_false": HARD_DEFAULTS["live_apply"] is False,
        "allowed_apply_now_false": HARD_DEFAULTS["allowed_apply_now"] is False,
        "high_blocked": HARD_DEFAULTS["high_blocked"] is True,
        "low_live_not_executable": HARD_DEFAULTS["low_live_executable"] is False,
        "medium_not_executable": HARD_DEFAULTS["medium_executable"] is False,
    }
    status = "SELF_TEST_OK" if all(checks.values()) else "SELF_TEST_FAILED"
    report = {
        "timestamp_utc": utc_now(),
        "action": "self-test",
        "status": status,
        "checks": checks,
        "source_safety_findings": findings,
        "breach": status != "SELF_TEST_OK",
        "live_apply": False,
        "emergency_stop": True,
        "allowed_apply_now": False,
        "high_blocked": True,
        "low_live_executable": False,
        "medium_executable": False,
    }
    return report


def action_status() -> Dict[str, Any]:
    data = load_dict(STATE_LATEST_JSON) or load_dict(STATE_JSON)
    if not data:
        data = {
            "timestamp_utc": utc_now(),
            "action": "status",
            "status": "CAPABILITY_HEALTH_GOVERNOR_NO_STATE",
            "warning_count": 0,
            "executed_repair_count": 0,
            "blocked_repair_count": 0,
            **HARD_DEFAULTS,
        }
    return data


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Sentinel Autonomous Capability Health Governor")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--scan-health", action="store_true")
    group.add_argument("--classify-warnings", action="store_true")
    group.add_argument("--plan-repairs", action="store_true")
    group.add_argument("--execute-safe-repairs", action="store_true")
    group.add_argument("--validate-repairs", action="store_true")
    group.add_argument("--learn", action="store_true")
    group.add_argument("--cycle", action="store_true")
    group.add_argument("--status", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        report = action_self_test()
        print(report["status"])
        return 0 if report["status"] == "SELF_TEST_OK" else 1
    if args.scan_health:
        report = scan_health()
    elif args.classify_warnings:
        report = classify_warnings()
    elif args.plan_repairs:
        report = plan_repairs()
    elif args.execute_safe_repairs:
        report = execute_safe_repairs()
    elif args.validate_repairs:
        report = validate_repairs()
    elif args.learn:
        report = learn()
    elif args.cycle:
        report = build_cycle()
    else:
        report = action_status()

    write_outputs(report)
    if args.status:
        print(
            "status={status} warnings={warnings} executed_repairs={executed} "
            "blocked_repairs={blocked} before={before} after={after} breach={breach}".format(
                status=report.get("status"),
                warnings=report.get("warning_count", 0),
                executed=report.get("executed_repair_count", 0),
                blocked=report.get("blocked_repair_count", 0),
                before=report.get("before_health", "-"),
                after=report.get("after_health", "-"),
                breach=report.get("breach", False),
            )
        )
    else:
        print(report.get("status"))
    return 0 if report.get("breach") is not True and report.get("status") != STATUS_FAILED else 1


if __name__ == "__main__":
    raise SystemExit(main())
