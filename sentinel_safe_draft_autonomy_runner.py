#!/usr/bin/env python3
"""Sentinel Safe Draft-Only Autonomous Runner (Phase 3.6).

May automatically regenerate/refresh registered, validated and allowed
*draft-only* candidates — strictly within draft/report/validation paths and
only while the owner runtime lock permits it. It performs no live/production
changes and has no live-apply function.

Hard safety guarantees (enforced structurally):
- No live changes; no live-apply function exists in this module.
- Never edits WordPress files, .htaccess, Cloudflare rules, or Nginx config.
- No external writes, no network access, no WordPress login, no API calls.
- No secrets/cookies/auth values are stored or printed.
- apply_status stays not_applied; can_execute_live stays false.
- Writes are confined to drafts/seo, drafts/performance, drafts/owner,
  drafts/apply, drafts/validation, reports/latest, and audit.
- It refuses to run while emergency_stop is set or autonomy is disabled.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


PROJECT_DIR = Path("/srv/sentinel-defense")

INPUT_RUNTIME_LOCK = PROJECT_DIR / "config/autonomy-runtime-lock.json"
INPUT_DRY_RUN = PROJECT_DIR / "drafts/apply/safe-apply-dry-run-plan.json"
INPUT_PREFLIGHT = PROJECT_DIR / "drafts/apply/safe-apply-preflight-validation.json"
INPUT_SCOPE = PROJECT_DIR / "drafts/apply/safe-apply-scope-allowlist.json"
INPUT_GUARD = PROJECT_DIR / "drafts/apply/safe-apply-guard-check.json"
INPUT_REGISTRY = PROJECT_DIR / "drafts/apply/safe-apply-candidate-registry.json"
INPUT_OWNER_DAILY = PROJECT_DIR / "reports/latest/owner-daily-action-summary.json"
INPUT_POST_VALIDATION = PROJECT_DIR / "reports/latest/post-manual-validation-report.json"
INPUT_MASTER = PROJECT_DIR / "reports/latest/sentinel-master-report.json"

REPORT_JSON = PROJECT_DIR / "reports/latest/safe-draft-autonomy-runner-report.json"
REPORT_MD = PROJECT_DIR / "reports/latest/safe-draft-autonomy-runner-report.md"
SUMMARY_MD = PROJECT_DIR / "drafts/apply/safe-draft-autonomy-runner-summary.md"
AUDIT_JSONL = PROJECT_DIR / "audit/safe-draft-autonomy-runner.jsonl"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "drafts/seo",
    PROJECT_DIR / "drafts/performance",
    PROJECT_DIR / "drafts/owner",
    PROJECT_DIR / "drafts/apply",
    PROJECT_DIR / "drafts/validation",
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "audit",
)

SCHEMA_VERSION = "safe-draft-autonomy-runner-3.6"

APPLY_NOT_APPLIED = "not_applied"
RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"
RISK_REVIEW_ONLY = "REVIEW_ONLY"

DRY_RUN_READY_FOR_DRAFT_ONLY = "DRY_RUN_READY_FOR_DRAFT_ONLY"
DRY_RUN_READY_FOR_VALIDATION_ONLY = "DRY_RUN_READY_FOR_VALIDATION_ONLY"
PREFLIGHT_READY_DRAFT_ONLY = "PREFLIGHT_READY_DRAFT_ONLY"
PREFLIGHT_READY_VALIDATION_ONLY = "PREFLIGHT_READY_VALIDATION_ONLY"
SCOPE_ALLOWED_DRAFT_ONLY = "SCOPE_ALLOWED_DRAFT_ONLY"
SCOPE_ALLOWED_VALIDATION_ONLY = "SCOPE_ALLOWED_VALIDATION_ONLY"
GUARDS_READY_DRAFT_ONLY = "GUARDS_READY_DRAFT_ONLY"
GUARDS_READY_VALIDATION_ONLY = "GUARDS_READY_VALIDATION_ONLY"
REGISTERED_DRAFT_ONLY = "REGISTERED_DRAFT_ONLY"
REGISTERED_VALIDATION_ONLY = "REGISTERED_VALIDATION_ONLY"

DRY_RUN_READY = {DRY_RUN_READY_FOR_DRAFT_ONLY, DRY_RUN_READY_FOR_VALIDATION_ONLY}
PREFLIGHT_READY = {PREFLIGHT_READY_DRAFT_ONLY, PREFLIGHT_READY_VALIDATION_ONLY}
SCOPE_ALLOWED = {SCOPE_ALLOWED_DRAFT_ONLY, SCOPE_ALLOWED_VALIDATION_ONLY}
GUARDS_READY = {GUARDS_READY_DRAFT_ONLY, GUARDS_READY_VALIDATION_ONLY}
REGISTERED_OK = {REGISTERED_DRAFT_ONLY, REGISTERED_VALIDATION_ONLY}
VALIDATION_SIGNALS = {
    DRY_RUN_READY_FOR_VALIDATION_ONLY,
    PREFLIGHT_READY_VALIDATION_ONLY,
    SCOPE_ALLOWED_VALIDATION_ONLY,
    GUARDS_READY_VALIDATION_ONLY,
    REGISTERED_VALIDATION_ONLY,
}

# Runner status vocabulary (Phase 3.6).
BLOCKED_BY_EMERGENCY_STOP = "BLOCKED_BY_EMERGENCY_STOP"
BLOCKED_BY_RUNTIME_LOCK = "BLOCKED_BY_RUNTIME_LOCK"
EXECUTED_DRAFT_ONLY = "EXECUTED_DRAFT_ONLY"
EXECUTED_VALIDATION_ONLY = "EXECUTED_VALIDATION_ONLY"
SKIPPED_NOT_ALLOWED = "SKIPPED_NOT_ALLOWED"
SKIPPED_MISSING_PREFLIGHT = "SKIPPED_MISSING_PREFLIGHT"
SKIPPED_HIGH_RISK = "SKIPPED_HIGH_RISK"
SKIPPED_MEDIUM_REVIEW_ONLY = "SKIPPED_MEDIUM_REVIEW_ONLY"
SKIPPED_PROHIBITED_ACTION = "SKIPPED_PROHIBITED_ACTION"

EXECUTED_STATUSES = {EXECUTED_DRAFT_ONLY, EXECUTED_VALIDATION_ONLY}
SKIPPED_STATUSES = {
    SKIPPED_NOT_ALLOWED,
    SKIPPED_MISSING_PREFLIGHT,
    SKIPPED_HIGH_RISK,
    SKIPPED_MEDIUM_REVIEW_ONLY,
    SKIPPED_PROHIBITED_ACTION,
}

ALLOWED_ACTIONS = {
    "report_update_only",
    "draft_refresh_only",
    "owner_summary_only",
    "validation_only",
    "seo_meta_draft_prepare",
    "seo_social_draft_prepare",
    "image_status_check",
    "width_height_check",
    "internal_link_suggestion_prepare",
}

PROHIBITED_ACTIONS = {
    "wordpress_live_write",
    "yoast_live_write",
    "cloudflare_change",
    "nginx_change",
    "htaccess_change",
    "dns_change",
    "redirect_change",
    "service_worker_change",
    "js_minify",
    "player_radio_code_change",
    "waf_botfight_change",
    "external_network_call",
    "browser_automation",
    "cms_login",
}

# Dedicated draft files generated per action type (Phase 3.6 task #11).
ACTION_DRAFT_FILES = {
    "seo_meta_draft_prepare": PROJECT_DIR / "drafts/seo/autonomous-meta-draft-refresh.json",
    "seo_social_draft_prepare": PROJECT_DIR / "drafts/seo/autonomous-social-draft-refresh.json",
    "image_status_check": PROJECT_DIR / "drafts/performance/autonomous-image-status-check.md",
    "width_height_check": PROJECT_DIR / "drafts/performance/autonomous-width-height-check.md",
    "owner_summary_only": PROJECT_DIR / "drafts/owner/autonomous-owner-summary.md",
    "validation_only": PROJECT_DIR / "drafts/validation/autonomous-validation-refresh.md",
}
ACTION_DRAFT_JSON = {"seo_meta_draft_prepare", "seo_social_draft_prepare"}

# Always prohibited write targets (used for breach detection on outputs).
ALWAYS_PROHIBITED_PATHS = [
    "/etc",
    "/etc/nginx",
    ".htaccess",
    "wp-config.php",
    "wp-content/plugins",
    "wp-content/themes",
    "cloudflare-api-targets",
    "dns-provider-configs",
    "systemd-units",
    "live-public-html",
]

SECRETISH_RE = re.compile(
    r"(?i)(api[_-]?key|token|secret|password|passwd|bearer|authorization|"
    r"cookie|set-cookie|credential|x-api-key|access[_-]?key|session)"
)
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|token|secret|password|passwd|bearer|authorization|"
    r"cookie|credential|session)\s*[:=]\s*[^\s,;]+"
)
LONG_HEX_RE = re.compile(r"\b[A-Fa-f0-9]{32,}\b")


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def redact_text(value: Any, default: str = "-", max_len: int = 500) -> str:
    if value is None:
        return default
    text = str(value).replace("\r", " ").strip()
    text = SECRET_ASSIGNMENT_RE.sub(lambda match: f"{match.group(1)}=<redacted>", text)
    text = LONG_HEX_RE.sub("<redacted-hex>", text)
    if SECRETISH_RE.search(text):
        return "[redacted]"
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text or default


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def within_allowed_roots(path: Path) -> bool:
    return any(is_within(path, root) for root in ALLOWED_WRITE_ROOTS)


def assert_allowed_write(path: Path) -> None:
    if not within_allowed_roots(path):
        raise ValueError(f"Refusing to write outside allowed runner roots: {path}")


def write_text_atomic(path: Path, content: str) -> None:
    assert_allowed_write(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)


def write_json_atomic(path: Path, data: Dict[str, Any]) -> None:
    write_text_atomic(path, json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def append_jsonl(path: Path, records: List[Dict[str, Any]]) -> None:
    assert_allowed_write(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def read_json_status(path: Path) -> Tuple[Optional[Any], str]:
    try:
        if ".env" in str(path).lower() or SECRETISH_RE.search(path.name):
            return None, "refused_secret_like_path"
        if path.suffix.lower() != ".json":
            return None, "unsupported_suffix"
        if not path.exists():
            return None, "not_available"
        return json.loads(path.read_text(encoding="utf-8")), "ok"
    except (OSError, ValueError, json.JSONDecodeError):
        return None, "read_error"


def normalize_risk(value: Any) -> str:
    risk = str(value or "").strip().upper()
    if risk in {RISK_LOW, RISK_MEDIUM, RISK_HIGH, RISK_REVIEW_ONLY}:
        return risk
    return RISK_REVIEW_ONLY


def safe_lock_default() -> Dict[str, Any]:
    return {
        "autonomy_enabled": False,
        "draft_only_enabled": False,
        "validation_only_enabled": False,
        "live_apply_enabled": False,
        "owner_disable_switch": True,
        "emergency_stop": True,
    }


def load_inputs() -> Tuple[Dict[str, Optional[Any]], Dict[str, str]]:
    lock, lock_status = read_json_status(INPUT_RUNTIME_LOCK)
    inputs = {
        "lock": lock if isinstance(lock, dict) else None,
        "dry_run": read_json_status(INPUT_DRY_RUN)[0],
        "preflight": read_json_status(INPUT_PREFLIGHT)[0],
        "scope": read_json_status(INPUT_SCOPE)[0],
        "guard": read_json_status(INPUT_GUARD)[0],
        "registry": read_json_status(INPUT_REGISTRY)[0],
        "owner_daily": read_json_status(INPUT_OWNER_DAILY)[0],
        "post_validation": read_json_status(INPUT_POST_VALIDATION)[0],
    }
    statuses = {
        "autonomy_runtime_lock": lock_status,
        "safe_apply_dry_run_plan": read_json_status(INPUT_DRY_RUN)[1],
        "safe_apply_preflight_validation": read_json_status(INPUT_PREFLIGHT)[1],
        "safe_apply_scope_allowlist": read_json_status(INPUT_SCOPE)[1],
        "safe_apply_guard_check": read_json_status(INPUT_GUARD)[1],
        "safe_apply_candidate_registry": read_json_status(INPUT_REGISTRY)[1],
        "sentinel_master": read_json_status(INPUT_MASTER)[1],
    }
    return inputs, statuses


def index_by_candidate(items: Any, key: str) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    if not isinstance(items, list):
        return mapping
    for item in items:
        if not isinstance(item, dict):
            continue
        candidate_id = str(item.get("candidate_id") or "")
        value = str(item.get(key) or "")
        if candidate_id and value:
            mapping[candidate_id] = value
    return mapping


def gate_from_lock(lock: Optional[Dict[str, Any]]) -> Tuple[str, Dict[str, bool]]:
    state = safe_lock_default()
    if isinstance(lock, dict):
        for key in state:
            if key in lock:
                state[key] = bool(lock.get(key))
    # live_apply is never honored as enabled by this runner.
    state["live_apply_enabled"] = bool(lock.get("live_apply_enabled")) if isinstance(lock, dict) else False
    if state["emergency_stop"]:
        return BLOCKED_BY_EMERGENCY_STOP, state
    if not state["autonomy_enabled"] or not state["draft_only_enabled"] or state["live_apply_enabled"]:
        return BLOCKED_BY_RUNTIME_LOCK, state
    return "RUN", state


def classify_candidate(
    dry_item: Dict[str, Any],
    preflight_status: str,
    scope_status: str,
    guard_status: str,
    registry_status: str,
    gate: str,
) -> Tuple[str, str]:
    """Return (runner_status, reason) for one candidate."""
    candidate_type = str(dry_item.get("candidate_type") or "")
    risk = normalize_risk(dry_item.get("risk_classification"))
    apply_status = dry_item.get("apply_status")
    dry_run_status = str(dry_item.get("dry_run_status") or "")
    can_execute_now = bool(dry_item.get("can_execute_now"))

    if gate == BLOCKED_BY_EMERGENCY_STOP:
        return BLOCKED_BY_EMERGENCY_STOP, "Emergency stop is active; nothing is executed."
    if gate == BLOCKED_BY_RUNTIME_LOCK:
        return BLOCKED_BY_RUNTIME_LOCK, "Runtime lock disables autonomy; nothing is executed."

    if candidate_type in PROHIBITED_ACTIONS:
        return SKIPPED_PROHIBITED_ACTION, "Prohibited action type is never executed."
    if risk == RISK_HIGH:
        return SKIPPED_HIGH_RISK, "HIGH risk candidate is never executed."
    if risk in {RISK_MEDIUM, RISK_REVIEW_ONLY}:
        return SKIPPED_MEDIUM_REVIEW_ONLY, "MEDIUM/REVIEW_ONLY candidate is never executed."
    if candidate_type not in ALLOWED_ACTIONS:
        return SKIPPED_NOT_ALLOWED, "Action type is not in the allowed draft-only allowlist."
    if apply_status != APPLY_NOT_APPLIED or can_execute_now:
        return SKIPPED_NOT_ALLOWED, "apply_status must be not_applied and can_execute_now must be false."

    all_ready = (
        dry_run_status in DRY_RUN_READY
        and preflight_status in PREFLIGHT_READY
        and scope_status in SCOPE_ALLOWED
        and guard_status in GUARDS_READY
        and registry_status in REGISTERED_OK
    )
    if not all_ready:
        if preflight_status not in PREFLIGHT_READY:
            return SKIPPED_MISSING_PREFLIGHT, "Preflight is not ready for this candidate."
        return SKIPPED_NOT_ALLOWED, "One or more gates (dry-run/scope/guard/registry) are not ready."

    validation = (
        dry_run_status == DRY_RUN_READY_FOR_VALIDATION_ONLY
        or candidate_type == "validation_only"
        or preflight_status == PREFLIGHT_READY_VALIDATION_ONLY
        or scope_status == SCOPE_ALLOWED_VALIDATION_ONLY
        or guard_status == GUARDS_READY_VALIDATION_ONLY
        or registry_status == REGISTERED_VALIDATION_ONLY
    )
    if validation:
        return EXECUTED_VALIDATION_ONLY, "LOW validation-only candidate executed as local validation refresh."
    return EXECUTED_DRAFT_ONLY, "LOW draft-only candidate executed as local draft refresh."


def planned_outputs_for(action_type: str) -> List[str]:
    """Local-only output path(s) recorded for an executed item."""
    if action_type in ACTION_DRAFT_FILES:
        return [str(ACTION_DRAFT_FILES[action_type])]
    if action_type == "draft_refresh_only":
        return [str(SUMMARY_MD)]
    # report_update_only / internal_link_suggestion_prepare are captured by the report.
    return [str(REPORT_JSON)]


def build_runner_item(
    dry_item: Dict[str, Any],
    index: int,
    preflight_status: str,
    scope_status: str,
    guard_status: str,
    registry_status: str,
    gate: str,
    live_apply_enabled: bool,
) -> Dict[str, Any]:
    candidate_type = str(dry_item.get("candidate_type") or "")
    runner_status, reason = classify_candidate(
        dry_item, preflight_status, scope_status, guard_status, registry_status, gate
    )
    executed = runner_status in EXECUTED_STATUSES
    generated_outputs = planned_outputs_for(candidate_type) if executed else []
    raw_apply = dry_item.get("apply_status")
    apply_status = APPLY_NOT_APPLIED if raw_apply == APPLY_NOT_APPLIED else redact_text(raw_apply, max_len=80)

    return {
        "runner_item_id": f"safe_draft_runner:{index:03d}",
        "candidate_id": redact_text(dry_item.get("candidate_id"), max_len=160),
        "candidate_type": redact_text(candidate_type, max_len=120) if candidate_type else "-",
        "action_type": redact_text(candidate_type, max_len=120) if candidate_type else "-",
        "title": redact_text(dry_item.get("title"), max_len=320),
        "risk_classification": normalize_risk(dry_item.get("risk_classification")),
        "runner_status": runner_status,
        "generated_outputs": generated_outputs,
        "skipped_reason": reason if runner_status not in EXECUTED_STATUSES else "-",
        "requires_network_access": bool(dry_item.get("requires_network_access")),
        "requires_api_access": bool(dry_item.get("requires_api_access")),
        "requires_login": bool(dry_item.get("requires_login")),
        "apply_status": apply_status,
        "productive_change": False,
        "live_apply": bool(live_apply_enabled) if executed else False,
        "can_execute_live": False,
        "audit_event_id": f"audit:{uuid.uuid4().hex[:16]}",
        "reason": reason,
    }


def outputs_outside_allowed(generated_outputs: Any) -> bool:
    if not isinstance(generated_outputs, list):
        return False
    for raw in generated_outputs:
        text = str(raw)
        lower = text.lower()
        for prohibited in ALWAYS_PROHIBITED_PATHS:
            if prohibited.lower() in lower:
                return True
        if not within_allowed_roots(Path(text)):
            return True
    return False


def runner_breach(items: List[Dict[str, Any]], state: Dict[str, bool]) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    emergency_stop = bool(state.get("emergency_stop"))
    for item in items:
        item_id = item.get("runner_item_id")
        executed = item.get("runner_status") in EXECUTED_STATUSES
        if item.get("live_apply") is True:
            reasons.append(f"{item_id}: live_apply is true")
        if item.get("productive_change") is True:
            reasons.append(f"{item_id}: productive_change is true")
        if item.get("apply_status") != APPLY_NOT_APPLIED:
            reasons.append(f"{item_id}: apply_status != not_applied")
        if item.get("can_execute_live") is True:
            reasons.append(f"{item_id}: can_execute_live is true")
        if outputs_outside_allowed(item.get("generated_outputs")):
            reasons.append(f"{item_id}: write outside allowed paths")
        if executed and item.get("risk_classification") == RISK_HIGH:
            reasons.append(f"{item_id}: HIGH risk executed")
        if executed and item.get("risk_classification") in {RISK_MEDIUM, RISK_REVIEW_ONLY}:
            reasons.append(f"{item_id}: MEDIUM/REVIEW_ONLY executed")
        if executed and str(item.get("action_type")) in PROHIBITED_ACTIONS:
            reasons.append(f"{item_id}: prohibited action executed")
        if executed and (item.get("requires_network_access") or item.get("requires_api_access") or item.get("requires_login")):
            reasons.append(f"{item_id}: network/API/login requirement on executed item")
        if executed and emergency_stop:
            reasons.append(f"{item_id}: executed while emergency_stop is true")
    return bool(reasons), reasons


def summarize_items(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    counts = {
        EXECUTED_DRAFT_ONLY: 0,
        EXECUTED_VALIDATION_ONLY: 0,
        BLOCKED_BY_RUNTIME_LOCK: 0,
        BLOCKED_BY_EMERGENCY_STOP: 0,
    }
    skipped = 0
    for item in items:
        status = item.get("runner_status")
        if status in counts:
            counts[status] += 1
        elif status in SKIPPED_STATUSES:
            skipped += 1
    return counts, skipped


def build_runner_report(
    inputs: Dict[str, Optional[Any]],
    input_statuses: Dict[str, str],
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    generated = generated_at or utc_now()
    gate, state = gate_from_lock(inputs.get("lock"))

    dry_run = inputs.get("dry_run")
    dry_items = dry_run.get("dry_run_items") if isinstance(dry_run, dict) and isinstance(dry_run.get("dry_run_items"), list) else []
    dry_items = [item for item in dry_items if isinstance(item, dict)]

    preflight_map = index_by_candidate(
        inputs["preflight"].get("preflight_items") if isinstance(inputs.get("preflight"), dict) else None,
        "preflight_status",
    )
    scope_map = index_by_candidate(
        inputs["scope"].get("scope_items") if isinstance(inputs.get("scope"), dict) else None,
        "scope_status",
    )
    guard_map = index_by_candidate(
        inputs["guard"].get("guard_checks") if isinstance(inputs.get("guard"), dict) else None,
        "guard_readiness_status",
    )
    registry_map = index_by_candidate(
        inputs["registry"].get("candidates") if isinstance(inputs.get("registry"), dict) else None,
        "registry_status",
    )

    items: List[Dict[str, Any]] = []
    for index, dry_item in enumerate(dry_items, start=1):
        candidate_id = str(dry_item.get("candidate_id") or "")
        items.append(
            build_runner_item(
                dry_item,
                index,
                preflight_map.get(candidate_id, ""),
                scope_map.get(candidate_id, ""),
                guard_map.get(candidate_id, ""),
                registry_map.get(candidate_id, ""),
                gate,
                state.get("live_apply_enabled", False),
            )
        )

    counts, skipped = summarize_items(items)
    breach, breach_reasons = runner_breach(items, state)

    if gate == BLOCKED_BY_EMERGENCY_STOP:
        runner_status = BLOCKED_BY_EMERGENCY_STOP
    elif gate == BLOCKED_BY_RUNTIME_LOCK:
        runner_status = BLOCKED_BY_RUNTIME_LOCK
    else:
        runner_status = "EXECUTED" if (counts[EXECUTED_DRAFT_ONLY] or counts[EXECUTED_VALIDATION_ONLY]) else "RAN_NO_ELIGIBLE"

    summary = {
        "candidate_count": len(items),
        "runner_status": runner_status,
        "executed_draft_only_count": counts[EXECUTED_DRAFT_ONLY],
        "executed_validation_only_count": counts[EXECUTED_VALIDATION_ONLY],
        "skipped_count": skipped,
        "blocked_by_runtime_lock_count": counts[BLOCKED_BY_RUNTIME_LOCK],
        "blocked_by_emergency_stop_count": counts[BLOCKED_BY_EMERGENCY_STOP],
        "runner_breach": breach,
        "runner_breach_reasons": breach_reasons,
    }

    status = "RUNNER_WARNING" if breach else runner_status
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": generated,
        "status": status,
        "runner_status": runner_status,
        "read_only": False,
        "live_apply": False,
        "live_apply_function": False,
        "network_access": False,
        "wordpress_login": False,
        "api_access": False,
        "productive_change": False,
        "secrets_output": False,
        "apply_status": APPLY_NOT_APPLIED,
        "can_execute_live": False,
        "runtime_lock_state": {
            "autonomy_enabled": bool(state.get("autonomy_enabled")),
            "draft_only_enabled": bool(state.get("draft_only_enabled")),
            "validation_only_enabled": bool(state.get("validation_only_enabled")),
            "live_apply_enabled": bool(state.get("live_apply_enabled")),
            "owner_disable_switch": bool(state.get("owner_disable_switch")),
            "emergency_stop": bool(state.get("emergency_stop")),
        },
        "allowed_write_roots": [str(path) for path in ALLOWED_WRITE_ROOTS],
        "allowed_actions": sorted(ALLOWED_ACTIONS),
        "prohibited_actions": sorted(PROHIBITED_ACTIONS),
        "input_statuses": input_statuses,
        "summary": summary,
        "runner_items": items,
        "outputs": {
            "report_json": str(REPORT_JSON),
            "report_md": str(REPORT_MD),
            "summary_md": str(SUMMARY_MD),
            "audit_jsonl": str(AUDIT_JSONL),
        },
    }


def generate_draft_files(report: Dict[str, Any]) -> None:
    """Write the dedicated draft files for executed items, aggregated by action.

    Only runs for executed items and only into allowed draft directories.
    """
    if report.get("runner_status") in {BLOCKED_BY_EMERGENCY_STOP, BLOCKED_BY_RUNTIME_LOCK}:
        return
    generated = report.get("generated_at_utc")
    grouped: Dict[str, List[str]] = {}
    for item in report.get("runner_items", []):
        if not isinstance(item, dict) or item.get("runner_status") not in EXECUTED_STATUSES:
            continue
        action_type = str(item.get("action_type"))
        if action_type in ACTION_DRAFT_FILES:
            grouped.setdefault(action_type, []).append(str(item.get("candidate_id")))
    for action_type, candidate_ids in grouped.items():
        path = ACTION_DRAFT_FILES[action_type]
        if action_type in ACTION_DRAFT_JSON:
            write_json_atomic(
                path,
                {
                    "schema_version": SCHEMA_VERSION,
                    "generated_at_utc": generated,
                    "action_type": action_type,
                    "candidate_ids": [redact_text(cid, max_len=160) for cid in candidate_ids],
                    "note": "autonomous local draft refresh only; no production write; apply_status=not_applied",
                    "apply_status": APPLY_NOT_APPLIED,
                    "live_apply": False,
                    "productive_change": False,
                },
            )
        else:
            lines = [
                f"# Autonomous Draft Refresh ({action_type})",
                "",
                f"- Generated (UTC): `{generated}`",
                f"- Action type: `{action_type}`",
                "- Note: autonomous local draft refresh only; no production write.",
                "- apply_status: `not_applied`, live_apply: `false`, productive_change: `false`",
                "",
                "## Candidates",
                "",
            ]
            for cid in candidate_ids:
                lines.append(f"- `{redact_text(cid, max_len=160)}`")
            lines.append("")
            write_text_atomic(path, "\n".join(lines))


def render_markdown(report: Dict[str, Any], *, title: str) -> str:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    lock_state = report.get("runtime_lock_state") if isinstance(report.get("runtime_lock_state"), dict) else {}
    lines = [
        f"# {title}",
        "",
        f"- Generated (UTC): `{report.get('generated_at_utc')}`",
        f"- Status: `{report.get('status')}`",
        f"- Runner status: `{report.get('runner_status')}`",
        f"- Candidates: `{summary.get('candidate_count')}`",
        f"- Executed draft-only: `{summary.get('executed_draft_only_count')}`",
        f"- Executed validation-only: `{summary.get('executed_validation_only_count')}`",
        f"- Skipped: `{summary.get('skipped_count')}`",
        f"- Blocked by runtime lock: `{summary.get('blocked_by_runtime_lock_count')}`",
        f"- Blocked by emergency stop: `{summary.get('blocked_by_emergency_stop_count')}`",
        f"- Runner breach: `{summary.get('runner_breach')}`",
        "",
        "## Runtime Lock State",
        "",
        f"- autonomy_enabled: `{lock_state.get('autonomy_enabled')}`",
        f"- draft_only_enabled: `{lock_state.get('draft_only_enabled')}`",
        f"- live_apply_enabled: `{lock_state.get('live_apply_enabled')}`",
        f"- emergency_stop: `{lock_state.get('emergency_stop')}`",
        "",
        "## Runner Items",
        "",
        "| Item | Candidate | Action | Status | Outputs | Live Apply | Apply Status |",
        "|---|---|---|---|---|---|---|",
    ]
    for item in report.get("runner_items", []):
        if not isinstance(item, dict):
            continue
        outputs = item.get("generated_outputs") if isinstance(item.get("generated_outputs"), list) else []
        lines.append(
            "| "
            f"`{redact_text(item.get('runner_item_id'), max_len=80)}` | "
            f"`{redact_text(item.get('candidate_id'), max_len=80)}` | "
            f"`{redact_text(item.get('action_type'), max_len=80)}` | "
            f"`{redact_text(item.get('runner_status'), max_len=80)}` | "
            f"{redact_text(str(len(outputs)), max_len=8)} | "
            f"`{redact_text(item.get('live_apply'), max_len=10)}` | "
            f"`{redact_text(item.get('apply_status'), max_len=40)}` |"
        )
    lines.extend(
        [
            "",
            "## Sicherheitsgrenzen",
            "",
            "- Keine Live-Aenderungen, keine Live-Apply-Funktion.",
            "- Keine WordPress-, .htaccess-, Cloudflare-, Nginx- oder DNS-Aenderung.",
            "- Kein WordPress-Login, keine API, kein Netzwerkzugriff, keine externen Schreibzugriffe.",
            "- Keine Secrets/Cookies/Auth speichern oder ausgeben.",
            "- `apply_status=not_applied`, `live_apply=false`, `can_execute_live=false`, `productive_change=false`.",
            "- Schreibzugriff nur unter drafts/seo, drafts/performance, drafts/owner, drafts/apply, "
            "drafts/validation, reports/latest, audit.",
            "",
        ]
    )
    return "\n".join(lines)


def audit_records(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    run_record = {
        "timestamp_utc": report.get("generated_at_utc"),
        "schema_version": SCHEMA_VERSION,
        "record_type": "run",
        "runner_status": report.get("runner_status"),
        "status": report.get("status"),
        "executed_draft_only_count": summary.get("executed_draft_only_count"),
        "executed_validation_only_count": summary.get("executed_validation_only_count"),
        "skipped_count": summary.get("skipped_count"),
        "blocked_by_runtime_lock_count": summary.get("blocked_by_runtime_lock_count"),
        "blocked_by_emergency_stop_count": summary.get("blocked_by_emergency_stop_count"),
        "runner_breach": summary.get("runner_breach"),
        "live_apply": False,
        "productive_change": False,
        "network_access": False,
    }
    records = [run_record]
    for item in report.get("runner_items", []):
        if not isinstance(item, dict) or item.get("runner_status") not in EXECUTED_STATUSES:
            continue
        records.append(
            {
                "timestamp_utc": report.get("generated_at_utc"),
                "schema_version": SCHEMA_VERSION,
                "record_type": "executed_item",
                "audit_event_id": item.get("audit_event_id"),
                "runner_item_id": item.get("runner_item_id"),
                "candidate_id": item.get("candidate_id"),
                "action_type": item.get("action_type"),
                "runner_status": item.get("runner_status"),
                "generated_outputs": item.get("generated_outputs"),
                "apply_status": APPLY_NOT_APPLIED,
                "live_apply": False,
                "productive_change": False,
            }
        )
    return records


def write_outputs(report: Dict[str, Any]) -> None:
    generate_draft_files(report)
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, render_markdown(report, title="Safe Draft Autonomy Runner Report"))
    write_text_atomic(SUMMARY_MD, render_markdown(report, title="Safe Draft Autonomy Runner Summary"))
    append_jsonl(AUDIT_JSONL, audit_records(report))


def _dry_item(**overrides: Any) -> Dict[str, Any]:
    base = {
        "candidate_id": "safe_apply_candidate:001",
        "candidate_type": "report_update_only",
        "title": "Report draft",
        "risk_classification": "LOW",
        "dry_run_status": DRY_RUN_READY_FOR_DRAFT_ONLY,
        "apply_status": "not_applied",
        "can_execute_now": False,
        "requires_network_access": False,
        "requires_api_access": False,
        "requires_login": False,
    }
    base.update(overrides)
    return base


def _ready_inputs(lock: Dict[str, Any], dry_items: List[Dict[str, Any]]) -> Dict[str, Optional[Any]]:
    def mk(items: List[Dict[str, Any]], key: str, value_fn) -> List[Dict[str, Any]]:
        return [{"candidate_id": it["candidate_id"], key: value_fn(it)} for it in items]

    return {
        "lock": lock,
        "dry_run": {"dry_run_items": dry_items},
        "preflight": {"preflight_items": mk(dry_items, "preflight_status", lambda it: PREFLIGHT_READY_DRAFT_ONLY)},
        "scope": {"scope_items": mk(dry_items, "scope_status", lambda it: SCOPE_ALLOWED_DRAFT_ONLY)},
        "guard": {"guard_checks": mk(dry_items, "guard_readiness_status", lambda it: GUARDS_READY_DRAFT_ONLY)},
        "registry": {"candidates": mk(dry_items, "registry_status", lambda it: REGISTERED_DRAFT_ONLY)},
        "owner_daily": None,
        "post_validation": None,
    }


def run_self_test() -> int:
    enabled_lock = {
        "autonomy_enabled": True,
        "draft_only_enabled": True,
        "validation_only_enabled": True,
        "live_apply_enabled": False,
        "owner_disable_switch": True,
        "emergency_stop": False,
    }
    stop_lock = {**enabled_lock, "emergency_stop": True, "autonomy_enabled": False, "draft_only_enabled": False}
    paused_lock = {**enabled_lock, "autonomy_enabled": False, "draft_only_enabled": False, "emergency_stop": False}

    # Scenario 1: emergency stop blocks everything, no breach.
    stop_report = build_runner_report(
        _ready_inputs(stop_lock, [_dry_item()]), {"autonomy_runtime_lock": "loaded"}, "2026-06-10T00:00:00Z"
    )
    if stop_report["runner_status"] != BLOCKED_BY_EMERGENCY_STOP:
        raise AssertionError("emergency stop did not block the runner")
    if stop_report["runner_items"][0]["runner_status"] != BLOCKED_BY_EMERGENCY_STOP:
        raise AssertionError("emergency stop item was not blocked")
    if stop_report["summary"]["runner_breach"]:
        raise AssertionError("emergency stop must not be a breach")
    if stop_report["runner_items"][0]["generated_outputs"]:
        raise AssertionError("blocked item must not generate outputs")

    # Scenario: runtime lock disabled blocks everything, no breach.
    paused_report = build_runner_report(
        _ready_inputs(paused_lock, [_dry_item()]), {"autonomy_runtime_lock": "loaded"}, "2026-06-10T00:01:00Z"
    )
    if paused_report["runner_status"] != BLOCKED_BY_RUNTIME_LOCK:
        raise AssertionError("disabled autonomy did not block the runner")
    if paused_report["summary"]["runner_breach"]:
        raise AssertionError("runtime-lock block must not be a breach")

    # Scenario 2: enable-draft-only -> draft-only candidate executes, no breach.
    ok_items = [
        _dry_item(),
        _dry_item(candidate_id="safe_apply_candidate:002", candidate_type="validation_only",
                  dry_run_status=DRY_RUN_READY_FOR_VALIDATION_ONLY),
        _dry_item(candidate_id="safe_apply_candidate:003", candidate_type="js_minify",
                  risk_classification="HIGH"),
        _dry_item(candidate_id="safe_apply_candidate:004", candidate_type="report_update_only",
                  risk_classification="MEDIUM"),
    ]
    ok_inputs = _ready_inputs(enabled_lock, ok_items)
    ok_report = build_runner_report(ok_inputs, {"autonomy_runtime_lock": "loaded"}, "2026-06-10T00:02:00Z")
    by_id = {it["candidate_id"]: it for it in ok_report["runner_items"]}
    if by_id["safe_apply_candidate:001"]["runner_status"] != EXECUTED_DRAFT_ONLY:
        raise AssertionError("ready draft candidate did not execute draft-only")
    if by_id["safe_apply_candidate:002"]["runner_status"] != EXECUTED_VALIDATION_ONLY:
        raise AssertionError("ready validation candidate did not execute validation-only")
    if by_id["safe_apply_candidate:003"]["runner_status"] != SKIPPED_PROHIBITED_ACTION:
        raise AssertionError("prohibited HIGH action was not skipped as prohibited")
    if by_id["safe_apply_candidate:004"]["runner_status"] != SKIPPED_MEDIUM_REVIEW_ONLY:
        raise AssertionError("MEDIUM candidate was not skipped")
    if ok_report["summary"]["runner_breach"]:
        raise AssertionError("clean draft-only run must not breach")
    for it in ok_report["runner_items"]:
        if it["apply_status"] != APPLY_NOT_APPLIED or it["live_apply"] or it["can_execute_live"] or it["productive_change"]:
            raise AssertionError("invariants violated on a runner item")

    # SKIPPED_MISSING_PREFLIGHT when preflight is not ready.
    miss_inputs = _ready_inputs(enabled_lock, [_dry_item(candidate_id="safe_apply_candidate:009")])
    miss_inputs["preflight"] = {"preflight_items": [{"candidate_id": "safe_apply_candidate:009", "preflight_status": "PREFLIGHT_BLOCKED_NOT_ALLOWED"}]}
    miss_report = build_runner_report(miss_inputs, {"autonomy_runtime_lock": "loaded"}, "2026-06-10T00:03:00Z")
    if miss_report["runner_items"][0]["runner_status"] != SKIPPED_MISSING_PREFLIGHT:
        raise AssertionError("missing preflight was not skipped correctly")

    # Breach: HIGH executed.
    b1, _ = runner_breach([{"runner_item_id": "x", "runner_status": EXECUTED_DRAFT_ONLY, "risk_classification": RISK_HIGH,
                            "apply_status": APPLY_NOT_APPLIED, "live_apply": False, "productive_change": False,
                            "can_execute_live": False, "generated_outputs": [], "action_type": "report_update_only"}],
                          {"emergency_stop": False})
    if not b1:
        raise AssertionError("HIGH executed did not breach")
    # Breach: MEDIUM executed.
    b2, _ = runner_breach([{"runner_item_id": "x", "runner_status": EXECUTED_DRAFT_ONLY, "risk_classification": RISK_MEDIUM,
                            "apply_status": APPLY_NOT_APPLIED, "live_apply": False, "productive_change": False,
                            "can_execute_live": False, "generated_outputs": [], "action_type": "report_update_only"}],
                          {"emergency_stop": False})
    if not b2:
        raise AssertionError("MEDIUM executed did not breach")
    # Breach: prohibited action executed.
    b3, _ = runner_breach([{"runner_item_id": "x", "runner_status": EXECUTED_DRAFT_ONLY, "risk_classification": RISK_LOW,
                            "apply_status": APPLY_NOT_APPLIED, "live_apply": False, "productive_change": False,
                            "can_execute_live": False, "generated_outputs": [], "action_type": "cloudflare_change"}],
                          {"emergency_stop": False})
    if not b3:
        raise AssertionError("prohibited action executed did not breach")
    # Breach: write outside allowed paths.
    b4, _ = runner_breach([{"runner_item_id": "x", "runner_status": EXECUTED_DRAFT_ONLY, "risk_classification": RISK_LOW,
                            "apply_status": APPLY_NOT_APPLIED, "live_apply": False, "productive_change": False,
                            "can_execute_live": False, "generated_outputs": ["/etc/nginx/site.conf"], "action_type": "report_update_only"}],
                          {"emergency_stop": False})
    if not b4:
        raise AssertionError("write outside allowed paths did not breach")
    # Breach: productive_change true.
    b5, _ = runner_breach([{"runner_item_id": "x", "runner_status": EXECUTED_DRAFT_ONLY, "risk_classification": RISK_LOW,
                            "apply_status": APPLY_NOT_APPLIED, "live_apply": False, "productive_change": True,
                            "can_execute_live": False, "generated_outputs": [], "action_type": "report_update_only"}],
                          {"emergency_stop": False})
    if not b5:
        raise AssertionError("productive_change did not breach")
    # Breach: live_apply true.
    b6, _ = runner_breach([{"runner_item_id": "x", "runner_status": EXECUTED_DRAFT_ONLY, "risk_classification": RISK_LOW,
                            "apply_status": APPLY_NOT_APPLIED, "live_apply": True, "productive_change": False,
                            "can_execute_live": False, "generated_outputs": [], "action_type": "report_update_only"}],
                          {"emergency_stop": False})
    if not b6:
        raise AssertionError("live_apply did not breach")
    # Breach: network/API/login on executed item.
    b7, _ = runner_breach([{"runner_item_id": "x", "runner_status": EXECUTED_DRAFT_ONLY, "risk_classification": RISK_LOW,
                            "apply_status": APPLY_NOT_APPLIED, "live_apply": False, "productive_change": False,
                            "can_execute_live": False, "generated_outputs": [], "action_type": "report_update_only",
                            "requires_login": True}],
                          {"emergency_stop": False})
    if not b7:
        raise AssertionError("network/API/login requirement did not breach")
    # Breach: apply_status != not_applied.
    b8, _ = runner_breach([{"runner_item_id": "x", "runner_status": EXECUTED_DRAFT_ONLY, "risk_classification": RISK_LOW,
                            "apply_status": "applied", "live_apply": False, "productive_change": False,
                            "can_execute_live": False, "generated_outputs": [], "action_type": "report_update_only"}],
                          {"emergency_stop": False})
    if not b8:
        raise AssertionError("apply_status != not_applied did not breach")
    # Breach: executed while emergency_stop true.
    b9, _ = runner_breach([{"runner_item_id": "x", "runner_status": EXECUTED_DRAFT_ONLY, "risk_classification": RISK_LOW,
                            "apply_status": APPLY_NOT_APPLIED, "live_apply": False, "productive_change": False,
                            "can_execute_live": False, "generated_outputs": [], "action_type": "report_update_only"}],
                          {"emergency_stop": True})
    if not b9:
        raise AssertionError("executed under emergency_stop did not breach")

    # Forbidden write path is rejected.
    try:
        assert_allowed_write(PROJECT_DIR / "config/should-not-write.json")
    except ValueError:
        pass
    else:
        raise AssertionError("forbidden write path (config) was not rejected")

    print("safe-draft-autonomy-runner self-tests: OK")
    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Safe draft-only autonomous runner (no live apply; gated by the owner runtime lock)."
    )
    parser.add_argument("--self-test", action="store_true", help="Run built-in safety tests and exit.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()
    inputs, statuses = load_inputs()
    report = build_runner_report(inputs, statuses)
    write_outputs(report)
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    print(
        "Safe Draft Autonomy Runner: "
        f"status={report.get('runner_status')}, "
        f"executed_draft={summary.get('executed_draft_only_count')}, "
        f"executed_validation={summary.get('executed_validation_only_count')}, "
        f"skipped={summary.get('skipped_count')}, "
        f"breach={summary.get('runner_breach')}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
