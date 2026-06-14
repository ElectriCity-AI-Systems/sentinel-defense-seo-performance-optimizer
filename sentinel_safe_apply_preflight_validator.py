#!/usr/bin/env python3
"""Sentinel Safe Apply Preflight Validator (Phase 3.4).

Validates whether a future safe-apply mechanism could ever even be *prepared*.
It only validates the preconditions (global guard availability and per-candidate
preflight status); it applies nothing and never executes.

Hard safety guarantees (enforced structurally):
- No live changes; no apply function exists in this module.
- Never edits WordPress files, .htaccess, Cloudflare rules, or Nginx config.
- No external writes, no network access, no WordPress login, no API calls.
- No secrets/cookies/auth values are stored or printed.
- All candidates stay apply_status=not_applied and can_execute_now=false.
- Writes are confined to drafts/apply, reports/latest, and audit.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


PROJECT_DIR = Path("/srv/sentinel-defense")

# Inputs are all optional; missing/invalid files must never crash the run.
INPUT_DRY_RUN_DRAFT = PROJECT_DIR / "drafts/apply/safe-apply-dry-run-plan.json"
INPUT_DRY_RUN_REPORT = PROJECT_DIR / "reports/latest/safe-apply-dry-run-plan-report.json"
INPUT_SCOPE_DRAFT = PROJECT_DIR / "drafts/apply/safe-apply-scope-allowlist.json"
INPUT_GUARD_DRAFT = PROJECT_DIR / "drafts/apply/safe-apply-guard-check.json"
INPUT_REGISTRY_DRAFT = PROJECT_DIR / "drafts/apply/safe-apply-candidate-registry.json"
INPUT_AUTONOMY_POLICY = PROJECT_DIR / "reports/latest/autonomy-policy-report.json"
INPUT_POST_VALIDATION = PROJECT_DIR / "reports/latest/post-manual-validation-report.json"
INPUT_MASTER = PROJECT_DIR / "reports/latest/sentinel-master-report.json"

PREFLIGHT_JSON = PROJECT_DIR / "drafts/apply/safe-apply-preflight-validation.json"
PREFLIGHT_MD = PROJECT_DIR / "drafts/apply/safe-apply-preflight-validation.md"
REPORT_JSON = PROJECT_DIR / "reports/latest/safe-apply-preflight-validation-report.json"
REPORT_MD = PROJECT_DIR / "reports/latest/safe-apply-preflight-validation-report.md"
AUDIT_JSONL = PROJECT_DIR / "audit/safe-apply-preflight-validation.jsonl"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "drafts/apply",
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "audit",
)

SCHEMA_VERSION = "safe-apply-preflight-validation-3.4"

APPLY_NOT_APPLIED = "not_applied"
RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"
RISK_REVIEW_ONLY = "REVIEW_ONLY"

# Dry-run status vocabulary consumed from Phase 3.3.
DRY_RUN_READY_FOR_DRAFT_ONLY = "DRY_RUN_READY_FOR_DRAFT_ONLY"
DRY_RUN_READY_FOR_VALIDATION_ONLY = "DRY_RUN_READY_FOR_VALIDATION_ONLY"
DRY_RUN_NOT_READY_MISSING_GUARDS = "DRY_RUN_NOT_READY_MISSING_GUARDS"
DRY_RUN_BLOCKED_HIGH_RISK = "DRY_RUN_BLOCKED_HIGH_RISK"
DRY_RUN_MONITOR_ONLY = "DRY_RUN_MONITOR_ONLY"

DRY_RUN_READY_STATUSES = {DRY_RUN_READY_FOR_DRAFT_ONLY, DRY_RUN_READY_FOR_VALIDATION_ONLY}

# Preflight status vocabulary (Phase 3.4).
PREFLIGHT_READY_DRAFT_ONLY = "PREFLIGHT_READY_DRAFT_ONLY"
PREFLIGHT_READY_VALIDATION_ONLY = "PREFLIGHT_READY_VALIDATION_ONLY"
PREFLIGHT_NOT_READY_MISSING_BACKUP = "PREFLIGHT_NOT_READY_MISSING_BACKUP"
PREFLIGHT_NOT_READY_MISSING_HEALTHCHECK = "PREFLIGHT_NOT_READY_MISSING_HEALTHCHECK"
PREFLIGHT_NOT_READY_MISSING_ROLLBACK = "PREFLIGHT_NOT_READY_MISSING_ROLLBACK"
PREFLIGHT_NOT_READY_MISSING_DISABLE_SWITCH = "PREFLIGHT_NOT_READY_MISSING_DISABLE_SWITCH"
PREFLIGHT_BLOCKED_HIGH_RISK = "PREFLIGHT_BLOCKED_HIGH_RISK"
PREFLIGHT_BLOCKED_NOT_ALLOWED = "PREFLIGHT_BLOCKED_NOT_ALLOWED"
PREFLIGHT_MONITOR_ONLY = "PREFLIGHT_MONITOR_ONLY"

PREFLIGHT_READY_STATUSES = {PREFLIGHT_READY_DRAFT_ONLY, PREFLIGHT_READY_VALIDATION_ONLY}
PREFLIGHT_NOT_READY_STATUSES = {
    PREFLIGHT_NOT_READY_MISSING_BACKUP,
    PREFLIGHT_NOT_READY_MISSING_HEALTHCHECK,
    PREFLIGHT_NOT_READY_MISSING_ROLLBACK,
    PREFLIGHT_NOT_READY_MISSING_DISABLE_SWITCH,
}
PREFLIGHT_BLOCKED_STATUSES = {PREFLIGHT_BLOCKED_HIGH_RISK, PREFLIGHT_BLOCKED_NOT_ALLOWED}

# Scope types that must never be considered for any future apply (live/prod).
PROHIBITED_SCOPE_TYPES = {
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

# Paths that are always prohibited inside any preflight allowance.
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

# Global preflight requirement keys (Phase 3.4 task #3).
GLOBAL_REQUIREMENT_KEYS = [
    "owner_disable_switch_available",
    "audit_available",
    "registry_available",
    "scope_allowlist_available",
    "guard_check_available",
    "dry_run_available",
    "post_validation_available",
    "backup_strategy_available",
    "rollback_strategy_available",
    "pre_healthcheck_available",
    "post_healthcheck_available",
    "max_scope_defined",
    "no_high_risk_ready",
    "no_medium_ready",
    "no_live_apply_function",
    "no_network_requirement",
    "all_apply_status_not_applied",
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


def redact_text(value: Any, default: str = "-", max_len: int = 900) -> str:
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


def parse_count(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return max(value, 0)
    if isinstance(value, float):
        return max(int(value), 0)
    if isinstance(value, str):
        try:
            return max(int(float(value.strip())), 0)
        except ValueError:
            return 0
    return 0


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def assert_allowed_write(path: Path) -> None:
    if not any(is_within(path, root) for root in ALLOWED_WRITE_ROOTS):
        raise ValueError(f"Refusing to write outside allowed preflight roots: {path}")


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


def load_inputs() -> Tuple[Dict[str, Optional[Any]], Dict[str, str]]:
    dry_run, dry_run_status = read_json_status(INPUT_DRY_RUN_DRAFT)
    if dry_run_status != "ok":
        dry_run, dry_run_status = read_json_status(INPUT_DRY_RUN_REPORT)
    scope, scope_status = read_json_status(INPUT_SCOPE_DRAFT)
    guard, guard_status = read_json_status(INPUT_GUARD_DRAFT)
    registry, registry_status = read_json_status(INPUT_REGISTRY_DRAFT)
    autonomy, autonomy_status = read_json_status(INPUT_AUTONOMY_POLICY)
    post_validation, post_validation_status = read_json_status(INPUT_POST_VALIDATION)
    inputs = {
        "dry_run": dry_run,
        "scope": scope,
        "guard": guard,
        "registry": registry,
        "autonomy": autonomy,
        "post_validation": post_validation,
    }
    statuses = {
        "safe_apply_dry_run_plan": dry_run_status,
        "safe_apply_scope_allowlist": scope_status,
        "safe_apply_guard_check": guard_status,
        "safe_apply_candidate_registry": registry_status,
        "autonomy_policy": autonomy_status,
        "post_manual_validation": post_validation_status,
        "sentinel_master": read_json_status(INPUT_MASTER)[1],
    }
    return inputs, statuses


def present(data: Optional[Any]) -> bool:
    return isinstance(data, dict)


def dry_run_items_from(dry_run: Optional[Any]) -> List[Dict[str, Any]]:
    if not isinstance(dry_run, dict) or not isinstance(dry_run.get("dry_run_items"), list):
        return []
    return [item for item in dry_run["dry_run_items"] if isinstance(item, dict)]


def path_contains_prohibited(paths: Any) -> bool:
    if not isinstance(paths, list):
        return False
    for path in paths:
        text = str(path).lower()
        for prohibited in ALWAYS_PROHIBITED_PATHS:
            token = prohibited.lower()
            if token and token in text:
                return True
    return False


def item_requires_network(item: Dict[str, Any]) -> bool:
    return bool(
        item.get("requires_network_access")
        or item.get("requires_api_access")
        or item.get("requires_login")
    )


def item_apply_ok(item: Dict[str, Any]) -> bool:
    return item.get("apply_status") == APPLY_NOT_APPLIED


def item_backup_ok(item: Dict[str, Any]) -> bool:
    backup = item.get("backup_requirements")
    if not isinstance(backup, list) or not backup:
        return False
    return not any("not_applicable" in str(entry).lower() for entry in backup)


def item_rollback_ok(item: Dict[str, Any]) -> bool:
    rollback = str(item.get("rollback_requirements") or "")
    if not rollback:
        return False
    return "blocked" not in rollback.lower() and "not_sufficient" not in rollback.lower()


def compute_global_requirements(
    inputs: Dict[str, Optional[Any]],
    items: List[Dict[str, Any]],
) -> Dict[str, bool]:
    dry_run = inputs.get("dry_run")
    scope = inputs.get("scope")
    guard = inputs.get("guard")
    registry = inputs.get("registry")
    post_validation = inputs.get("post_validation")

    guard_required = set()
    if present(guard) and isinstance(guard.get("required_guards"), list):
        guard_required = {str(value) for value in guard["required_guards"]}

    ready_items = [item for item in items if str(item.get("dry_run_status")) in DRY_RUN_READY_STATUSES]

    return {
        "owner_disable_switch_available": ("owner_disable_switch" in guard_required)
        or (bool(items) and all(bool(item.get("owner_disable_switch_required")) for item in items)),
        "audit_available": ("audit_log" in guard_required) or present(dry_run),
        "registry_available": present(registry),
        "scope_allowlist_available": present(scope),
        "guard_check_available": present(guard),
        "dry_run_available": present(dry_run) and bool(items),
        "post_validation_available": present(post_validation),
        "backup_strategy_available": ("backup_available" in guard_required)
        or (bool(ready_items) and all(item_backup_ok(item) for item in ready_items)),
        "rollback_strategy_available": ("rollback_plan" in guard_required)
        or (bool(ready_items) and all(item_rollback_ok(item) for item in ready_items)),
        "pre_healthcheck_available": "pre_healthcheck" in guard_required,
        "post_healthcheck_available": "post_healthcheck" in guard_required,
        "max_scope_defined": ("max_scope_defined" in guard_required) or present(scope),
        "no_high_risk_ready": not any(
            normalize_risk(item.get("risk_classification")) == RISK_HIGH for item in ready_items
        ),
        "no_medium_ready": not any(
            normalize_risk(item.get("risk_classification")) in {RISK_MEDIUM, RISK_REVIEW_ONLY}
            for item in ready_items
        ),
        "no_live_apply_function": (not present(dry_run)) or (dry_run.get("apply_function") is False),
        "no_network_requirement": not any(item_requires_network(item) for item in items),
        "all_apply_status_not_applied": all(item_apply_ok(item) for item in items) if items else True,
    }


def determine_preflight_status(
    item: Dict[str, Any],
    global_requirements: Dict[str, bool],
) -> Tuple[str, List[str], List[str], str]:
    """Return (preflight_status, missing_requirements, blocking_reasons, reason)."""
    risk = normalize_risk(item.get("risk_classification"))
    candidate_type = str(item.get("candidate_type") or "")
    dry_run_status = str(item.get("dry_run_status") or "")
    apply_status = item.get("apply_status")

    if apply_status != APPLY_NOT_APPLIED:
        return (
            PREFLIGHT_BLOCKED_NOT_ALLOWED,
            ["all_apply_status_not_applied"],
            ["apply_status is not not_applied"],
            "apply_status is not not_applied; preflight refuses readiness and flags review.",
        )
    if risk == RISK_HIGH or candidate_type in PROHIBITED_SCOPE_TYPES or dry_run_status == DRY_RUN_BLOCKED_HIGH_RISK:
        return (
            PREFLIGHT_BLOCKED_HIGH_RISK,
            [],
            ["HIGH risk or prohibited candidate_type"],
            "HIGH risk or prohibited candidate_type is permanently blocked from any future apply.",
        )
    if dry_run_status == DRY_RUN_MONITOR_ONLY:
        return (
            PREFLIGHT_MONITOR_ONLY,
            [],
            ["monitor-only candidate"],
            "Candidate is monitor-only; no future apply preparation is allowed.",
        )
    if dry_run_status not in DRY_RUN_READY_STATUSES:
        return (
            PREFLIGHT_BLOCKED_NOT_ALLOWED,
            ["dry_run_available"],
            ["dry-run scope was not allowed/ready"],
            "Dry-run did not allow this candidate; preflight keeps it not allowed.",
        )

    # Ready dry-run candidate: validate the future-apply preconditions.
    missing: List[str] = []
    if (not global_requirements.get("owner_disable_switch_available")) or (not item.get("owner_disable_switch_required")):
        missing.append("disable_switch")
    if not item_backup_ok(item):
        missing.append("backup")
    if not item_rollback_ok(item):
        missing.append("rollback")
    if not (global_requirements.get("pre_healthcheck_available") and global_requirements.get("post_healthcheck_available")):
        missing.append("healthcheck")

    if missing:
        missing_keys: List[str] = []
        if "disable_switch" in missing:
            missing_keys.append("owner_disable_switch_available")
        if "backup" in missing:
            missing_keys.append("backup_strategy_available")
        if "rollback" in missing:
            missing_keys.append("rollback_strategy_available")
        if "healthcheck" in missing:
            missing_keys.append("pre_healthcheck_available")
            missing_keys.append("post_healthcheck_available")
        # Emit a specific NOT_READY status by priority.
        if "disable_switch" in missing:
            status = PREFLIGHT_NOT_READY_MISSING_DISABLE_SWITCH
        elif "backup" in missing:
            status = PREFLIGHT_NOT_READY_MISSING_BACKUP
        elif "rollback" in missing:
            status = PREFLIGHT_NOT_READY_MISSING_ROLLBACK
        else:
            status = PREFLIGHT_NOT_READY_MISSING_HEALTHCHECK
        return (
            status,
            missing_keys,
            [f"missing preflight requirement: {key}" for key in missing_keys],
            "Ready dry-run candidate still misses one or more future-apply preconditions.",
        )

    if dry_run_status == DRY_RUN_READY_FOR_VALIDATION_ONLY:
        return (
            PREFLIGHT_READY_VALIDATION_ONLY,
            [],
            [],
            "LOW validation-only candidate satisfies the local preflight preconditions (validation-only).",
        )
    return (
        PREFLIGHT_READY_DRAFT_ONLY,
        [],
        [],
        "LOW draft-only candidate satisfies the local preflight preconditions (draft-only).",
    )


def build_preflight_item(
    item: Dict[str, Any],
    index: int,
    global_requirements: Dict[str, bool],
) -> Dict[str, Any]:
    raw_apply = item.get("apply_status")
    apply_status = raw_apply if raw_apply == APPLY_NOT_APPLIED else str(raw_apply or "")
    allowed_write_paths = item.get("allowed_write_paths") if isinstance(item.get("allowed_write_paths"), list) else []
    allowed_write_paths = [str(path) for path in allowed_write_paths]

    preflight_status, missing_requirements, blocking_reasons, reason = determine_preflight_status(
        item, global_requirements
    )
    can_consider = preflight_status in PREFLIGHT_READY_STATUSES

    return {
        "preflight_id": f"safe_apply_preflight:{index:03d}",
        "dry_run_id": redact_text(item.get("dry_run_id"), max_len=80),
        "candidate_id": redact_text(item.get("candidate_id"), max_len=160),
        "candidate_type": redact_text(item.get("candidate_type"), max_len=120),
        "title": redact_text(item.get("title"), max_len=320),
        "risk_classification": normalize_risk(item.get("risk_classification")),
        "dry_run_status": redact_text(item.get("dry_run_status"), max_len=80),
        "preflight_status": preflight_status,
        "missing_preflight_requirements": missing_requirements,
        "blocking_reasons": blocking_reasons,
        "allowed_write_paths": allowed_write_paths,
        "prohibited_write_paths": list(ALWAYS_PROHIBITED_PATHS),
        "owner_disable_switch_required": bool(item.get("owner_disable_switch_required")),
        # Carried through for breach detection; a preflight never needs these.
        "requires_network_access": bool(item.get("requires_network_access")),
        "requires_api_access": bool(item.get("requires_api_access")),
        "requires_login": bool(item.get("requires_login")),
        "live_apply_function_detected": False,
        "can_be_considered_for_future_apply": can_consider,
        "can_execute_now": False,
        "apply_status": APPLY_NOT_APPLIED if apply_status == APPLY_NOT_APPLIED else redact_text(apply_status, max_len=80),
        "reason": reason,
    }


def preflight_breach(items: List[Dict[str, Any]]) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    for item in items:
        preflight_id = item.get("preflight_id")
        ready = item.get("preflight_status") in PREFLIGHT_READY_STATUSES
        if item.get("can_execute_now"):
            reasons.append(f"{preflight_id}: can_execute_now is true")
        if item.get("apply_status") != APPLY_NOT_APPLIED:
            reasons.append(f"{preflight_id}: apply_status != not_applied")
        if item.get("live_apply_function_detected"):
            reasons.append(f"{preflight_id}: live apply function detected")
        if item.get("requires_network_access") or item.get("requires_api_access") or item.get("requires_login"):
            reasons.append(f"{preflight_id}: network/API/login requirement present")
        if path_contains_prohibited(item.get("allowed_write_paths")):
            reasons.append(f"{preflight_id}: prohibited path in allowed_write_paths")
        if (ready or item.get("can_be_considered_for_future_apply")) and item.get("risk_classification") == RISK_HIGH:
            reasons.append(f"{preflight_id}: HIGH risk ready/considered for apply")
        if (ready or item.get("can_be_considered_for_future_apply")) and item.get("risk_classification") in {RISK_MEDIUM, RISK_REVIEW_ONLY}:
            reasons.append(f"{preflight_id}: MEDIUM/REVIEW_ONLY ready/considered for apply")
    return bool(reasons), reasons


def summarize_items(items: List[Dict[str, Any]], global_missing: List[str]) -> Dict[str, Any]:
    counts = {
        PREFLIGHT_READY_DRAFT_ONLY: 0,
        PREFLIGHT_READY_VALIDATION_ONLY: 0,
        PREFLIGHT_MONITOR_ONLY: 0,
    }
    not_ready = 0
    blocked = 0
    for item in items:
        status = item.get("preflight_status")
        if status in counts:
            counts[status] += 1
        elif status in PREFLIGHT_NOT_READY_STATUSES:
            not_ready += 1
        elif status in PREFLIGHT_BLOCKED_STATUSES:
            blocked += 1
    breach, breach_reasons = preflight_breach(items)
    return {
        "candidate_count": len(items),
        "preflight_ready_draft_only_count": counts[PREFLIGHT_READY_DRAFT_ONLY],
        "preflight_ready_validation_only_count": counts[PREFLIGHT_READY_VALIDATION_ONLY],
        "preflight_not_ready_count": not_ready,
        "preflight_blocked_count": blocked,
        "preflight_monitor_only_count": counts[PREFLIGHT_MONITOR_ONLY],
        "preflight_breach": breach,
        "preflight_breach_reasons": breach_reasons,
        "global_missing_requirements": list(global_missing),
    }


def build_preflight_report(
    inputs: Dict[str, Optional[Any]],
    input_statuses: Dict[str, str],
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    generated = generated_at or utc_now()
    items_source = dry_run_items_from(inputs.get("dry_run"))
    global_requirements = compute_global_requirements(inputs, items_source)
    global_missing = [key for key in GLOBAL_REQUIREMENT_KEYS if not global_requirements.get(key)]

    items = [
        build_preflight_item(item, index + 1, global_requirements)
        for index, item in enumerate(items_source)
    ]
    summary = summarize_items(items, global_missing)
    considered = [item for item in items if item.get("can_be_considered_for_future_apply")]
    status = (
        "PREFLIGHT_WARNING"
        if summary["preflight_breach"]
        else ("NO_DRY_RUN_PLAN_AVAILABLE" if not items_source else "READY_FOR_REVIEW")
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": generated,
        "status": status,
        "read_only": True,
        "network_access": False,
        "wordpress_login": False,
        "api_access": False,
        "apply_function": False,
        "productive_change": False,
        "secrets_output": False,
        "all_candidates_remain_not_applied": all(item.get("apply_status") == APPLY_NOT_APPLIED for item in items),
        "all_can_execute_now_false": all(item.get("can_execute_now") is False for item in items),
        "allowed_write_roots": [str(path) for path in ALLOWED_WRITE_ROOTS],
        "always_prohibited_paths": list(ALWAYS_PROHIBITED_PATHS),
        "global_requirement_keys": list(GLOBAL_REQUIREMENT_KEYS),
        "global_requirements": global_requirements,
        "global_missing_requirements": global_missing,
        "input_statuses": input_statuses,
        "summary": summary,
        "preflight_items": items,
        "considered_for_future_apply": considered,
        "outputs": {
            "preflight_json": str(PREFLIGHT_JSON),
            "preflight_md": str(PREFLIGHT_MD),
            "report_json": str(REPORT_JSON),
            "report_md": str(REPORT_MD),
            "audit_jsonl": str(AUDIT_JSONL),
        },
    }


def render_markdown(report: Dict[str, Any], *, title: str) -> str:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    lines = [
        f"# {title}",
        "",
        f"- Generated (UTC): `{report.get('generated_at_utc')}`",
        f"- Status: `{report.get('status')}`",
        f"- Candidates: `{summary.get('candidate_count')}`",
        f"- Preflight ready draft-only: `{summary.get('preflight_ready_draft_only_count')}`",
        f"- Preflight ready validation-only: `{summary.get('preflight_ready_validation_only_count')}`",
        f"- Preflight not ready: `{summary.get('preflight_not_ready_count')}`",
        f"- Preflight blocked: `{summary.get('preflight_blocked_count')}`",
        f"- Preflight monitor-only: `{summary.get('preflight_monitor_only_count')}`",
        f"- Preflight breach: `{summary.get('preflight_breach')}`",
        "",
        "## Global Requirements",
        "",
        "| Requirement | Available |",
        "|---|---|",
    ]
    global_requirements = report.get("global_requirements") if isinstance(report.get("global_requirements"), dict) else {}
    for key in report.get("global_requirement_keys", []):
        lines.append(f"| `{redact_text(key, max_len=80)}` | `{global_requirements.get(key)}` |")
    lines.extend(
        [
            "",
            f"- Global missing requirements: `{report.get('global_missing_requirements')}`",
            "",
            "## Preflight Items",
            "",
            "| Preflight ID | Status | Consider Future Apply | Can Execute Now | Risk | Missing | Title |",
            "|---|---|---|---|---|---|---|",
        ]
    )
    for item in report.get("preflight_items", []):
        if not isinstance(item, dict):
            continue
        lines.append(
            "| "
            f"`{redact_text(item.get('preflight_id'), max_len=80)}` | "
            f"`{redact_text(item.get('preflight_status'), max_len=80)}` | "
            f"`{redact_text(item.get('can_be_considered_for_future_apply'), max_len=20)}` | "
            f"`{redact_text(item.get('can_execute_now'), max_len=20)}` | "
            f"`{redact_text(item.get('risk_classification'), max_len=60)}` | "
            f"{redact_text(', '.join(item.get('missing_preflight_requirements', [])) or '-', max_len=120)} | "
            f"{redact_text(item.get('title'), max_len=160)} |"
        )
    lines.extend(
        [
            "",
            "## Sicherheitsgrenzen",
            "",
            "- Keine Live-Aenderungen, keine Apply-Funktion, kein Apply-Mechanismus.",
            "- Keine WordPress-, .htaccess-, Cloudflare-, Nginx- oder DNS-Aenderung.",
            "- Kein WordPress-Login, keine API, kein Netzwerkzugriff, keine externen Schreibzugriffe.",
            "- Keine Secrets/Cookies/Auth speichern oder ausgeben.",
            "- Alle Kandidaten bleiben `apply_status=not_applied` und `can_execute_now=false`.",
            "- Schreibzugriff nur unter `drafts/apply`, `reports/latest`, `audit`.",
            "",
        ]
    )
    return "\n".join(lines)


def audit_record(report: Dict[str, Any]) -> Dict[str, Any]:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    return {
        "timestamp_utc": report.get("generated_at_utc"),
        "schema_version": SCHEMA_VERSION,
        "status": report.get("status"),
        "candidate_count": summary.get("candidate_count"),
        "preflight_ready_draft_only_count": summary.get("preflight_ready_draft_only_count"),
        "preflight_ready_validation_only_count": summary.get("preflight_ready_validation_only_count"),
        "preflight_not_ready_count": summary.get("preflight_not_ready_count"),
        "preflight_blocked_count": summary.get("preflight_blocked_count"),
        "preflight_monitor_only_count": summary.get("preflight_monitor_only_count"),
        "preflight_breach": summary.get("preflight_breach"),
        "global_missing_requirements": summary.get("global_missing_requirements"),
        "productive_change": False,
        "network_access": False,
        "apply_function": False,
    }


def write_outputs(report: Dict[str, Any]) -> None:
    write_json_atomic(PREFLIGHT_JSON, report)
    write_text_atomic(PREFLIGHT_MD, render_markdown(report, title="Safe Apply Preflight Validation"))
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, render_markdown(report, title="Safe Apply Preflight Validation Report"))
    append_jsonl(AUDIT_JSONL, [audit_record(report)])


def _dry_run_item(**overrides: Any) -> Dict[str, Any]:
    base = {
        "dry_run_id": "safe_apply_dry_run:001",
        "candidate_id": "safe_apply_candidate:001",
        "candidate_type": "report_update_only",
        "title": "Report draft",
        "risk_classification": "LOW",
        "dry_run_status": DRY_RUN_READY_FOR_DRAFT_ONLY,
        "apply_status": "not_applied",
        "owner_disable_switch_required": True,
        "requires_network_access": False,
        "requires_api_access": False,
        "requires_login": False,
        "can_execute_now": False,
        "allowed_write_paths": ["reports/latest", "drafts/apply", "audit"],
        "backup_requirements": ["prior_draft_snapshot_under_drafts_apply"],
        "rollback_requirements": "delete_or_regenerate_draft_and_report_only",
    }
    base.update(overrides)
    return base


def _full_guard() -> Dict[str, Any]:
    return {
        "required_guards": [
            "explicit_allowlist",
            "owner_disable_switch",
            "audit_log",
            "max_scope_defined",
            "pre_healthcheck",
            "post_healthcheck",
            "rollback_plan",
            "backup_available",
            "post_validation",
        ]
    }


def run_self_test() -> int:
    # 1. Missing dry-run plan never crashes and reports NO_DRY_RUN_PLAN_AVAILABLE.
    empty = build_preflight_report(
        {"dry_run": None}, {"safe_apply_dry_run_plan": "not_available"}, "2026-06-10T00:00:00Z"
    )
    if empty["status"] != "NO_DRY_RUN_PLAN_AVAILABLE":
        raise AssertionError("missing dry-run did not produce NO_DRY_RUN_PLAN_AVAILABLE")
    if empty["summary"]["preflight_breach"]:
        raise AssertionError("empty input must not report a breach")

    inputs = {
        "dry_run": {
            "apply_function": False,
            "dry_run_items": [
                _dry_run_item(),  # LOW ready draft -> ready draft-only
                _dry_run_item(
                    candidate_id="safe_apply_candidate:002",
                    candidate_type="validation_only",
                    dry_run_status=DRY_RUN_READY_FOR_VALIDATION_ONLY,
                    title="Validation",
                    rollback_requirements="delete_or_regenerate_validation_report_only",
                ),  # ready validation-only
                _dry_run_item(
                    candidate_id="safe_apply_candidate:003",
                    risk_classification="HIGH",
                    dry_run_status=DRY_RUN_BLOCKED_HIGH_RISK,
                    title="High",
                ),  # blocked high
                _dry_run_item(
                    candidate_id="safe_apply_candidate:004",
                    dry_run_status=DRY_RUN_MONITOR_ONLY,
                    title="Monitor",
                ),  # monitor-only
                _dry_run_item(
                    candidate_id="safe_apply_candidate:005",
                    dry_run_status=DRY_RUN_NOT_READY_MISSING_GUARDS,
                    title="Not allowed",
                ),  # blocked not allowed
                _dry_run_item(
                    candidate_id="safe_apply_candidate:006",
                    apply_status="applied",
                    title="Applied",
                ),  # apply_status breach
            ],
        },
        "scope": {"scope_items": []},
        "guard": _full_guard(),
        "registry": {"candidates": []},
        "autonomy": {"policy_only": True},
        "post_validation": {"status": "ok"},
    }
    report = build_preflight_report(inputs, {"safe_apply_dry_run_plan": "ok"}, "2026-06-10T00:01:00Z")
    by_id = {item["candidate_id"]: item for item in report["preflight_items"]}

    if by_id["safe_apply_candidate:001"]["preflight_status"] != PREFLIGHT_READY_DRAFT_ONLY:
        raise AssertionError("LOW ready draft was not preflight ready draft-only")
    if not by_id["safe_apply_candidate:001"]["can_be_considered_for_future_apply"]:
        raise AssertionError("ready draft must be considerable for future apply")
    if by_id["safe_apply_candidate:002"]["preflight_status"] != PREFLIGHT_READY_VALIDATION_ONLY:
        raise AssertionError("LOW ready validation was not preflight ready validation-only")
    if by_id["safe_apply_candidate:003"]["preflight_status"] != PREFLIGHT_BLOCKED_HIGH_RISK:
        raise AssertionError("HIGH candidate was not blocked")
    if by_id["safe_apply_candidate:004"]["preflight_status"] != PREFLIGHT_MONITOR_ONLY:
        raise AssertionError("monitor candidate did not stay monitor")
    if by_id["safe_apply_candidate:005"]["preflight_status"] != PREFLIGHT_BLOCKED_NOT_ALLOWED:
        raise AssertionError("not-allowed candidate was not blocked-not-allowed")
    if by_id["safe_apply_candidate:006"]["preflight_status"] in PREFLIGHT_READY_STATUSES:
        raise AssertionError("applied candidate became preflight ready")
    if not report["summary"]["preflight_breach"]:
        raise AssertionError("apply_status != not_applied did not raise preflight_breach")
    for item in report["preflight_items"]:
        if item["can_execute_now"] is not False:
            raise AssertionError("can_execute_now must always be false")

    # NOT_READY paths: missing healthcheck (guard without pre/post healthcheck).
    inputs_no_hc = {
        "dry_run": {"apply_function": False, "dry_run_items": [_dry_run_item()]},
        "scope": {"scope_items": []},
        "guard": {"required_guards": ["owner_disable_switch", "backup_available", "rollback_plan"]},
        "registry": {"candidates": []},
        "autonomy": {"policy_only": True},
        "post_validation": {"status": "ok"},
    }
    report_no_hc = build_preflight_report(inputs_no_hc, {"safe_apply_dry_run_plan": "ok"}, "2026-06-10T00:02:00Z")
    if report_no_hc["preflight_items"][0]["preflight_status"] != PREFLIGHT_NOT_READY_MISSING_HEALTHCHECK:
        raise AssertionError("missing healthcheck did not produce NOT_READY_MISSING_HEALTHCHECK")
    if "pre_healthcheck_available" not in report_no_hc["global_missing_requirements"]:
        raise AssertionError("missing healthcheck not reported in global_missing_requirements")

    # 2. can_execute_now=true -> breach.
    exec_breach, _ = preflight_breach(
        [{"preflight_id": "x", "preflight_status": PREFLIGHT_READY_DRAFT_ONLY, "risk_classification": RISK_LOW,
          "apply_status": APPLY_NOT_APPLIED, "can_execute_now": True, "allowed_write_paths": [],
          "can_be_considered_for_future_apply": True}]
    )
    if not exec_breach:
        raise AssertionError("can_execute_now=true did not raise preflight_breach")

    # 3. apply_status != not_applied -> breach.
    apply_breach, _ = preflight_breach(
        [{"preflight_id": "x", "preflight_status": PREFLIGHT_BLOCKED_NOT_ALLOWED, "risk_classification": RISK_LOW,
          "apply_status": "applied", "can_execute_now": False, "allowed_write_paths": [],
          "can_be_considered_for_future_apply": False}]
    )
    if not apply_breach:
        raise AssertionError("apply_status != not_applied did not raise preflight_breach")

    # 4. HIGH ready/considered -> breach.
    high_breach, _ = preflight_breach(
        [{"preflight_id": "x", "preflight_status": PREFLIGHT_READY_DRAFT_ONLY, "risk_classification": RISK_HIGH,
          "apply_status": APPLY_NOT_APPLIED, "can_execute_now": False, "allowed_write_paths": [],
          "can_be_considered_for_future_apply": True}]
    )
    if not high_breach:
        raise AssertionError("HIGH ready/considered did not raise preflight_breach")

    # 5. MEDIUM ready/considered -> breach.
    medium_breach, _ = preflight_breach(
        [{"preflight_id": "x", "preflight_status": PREFLIGHT_READY_VALIDATION_ONLY, "risk_classification": RISK_MEDIUM,
          "apply_status": APPLY_NOT_APPLIED, "can_execute_now": False, "allowed_write_paths": [],
          "can_be_considered_for_future_apply": True}]
    )
    if not medium_breach:
        raise AssertionError("MEDIUM ready/considered did not raise preflight_breach")

    # 6. Live apply function detected -> breach.
    func_breach, _ = preflight_breach(
        [{"preflight_id": "x", "preflight_status": PREFLIGHT_READY_DRAFT_ONLY, "risk_classification": RISK_LOW,
          "apply_status": APPLY_NOT_APPLIED, "can_execute_now": False, "live_apply_function_detected": True,
          "allowed_write_paths": [], "can_be_considered_for_future_apply": True}]
    )
    if not func_breach:
        raise AssertionError("live apply function detected did not raise preflight_breach")

    # 7. Network/API/login requirement -> breach.
    net_breach, _ = preflight_breach(
        [{"preflight_id": "x", "preflight_status": PREFLIGHT_READY_DRAFT_ONLY, "risk_classification": RISK_LOW,
          "apply_status": APPLY_NOT_APPLIED, "can_execute_now": False, "requires_api_access": True,
          "allowed_write_paths": [], "can_be_considered_for_future_apply": True}]
    )
    if not net_breach:
        raise AssertionError("network/API/login requirement did not raise preflight_breach")

    # 8. Prohibited path -> breach.
    path_breach, _ = preflight_breach(
        [{"preflight_id": "x", "preflight_status": PREFLIGHT_READY_DRAFT_ONLY, "risk_classification": RISK_LOW,
          "apply_status": APPLY_NOT_APPLIED, "can_execute_now": False,
          "allowed_write_paths": ["reports/latest", "/etc/nginx/x"], "can_be_considered_for_future_apply": True}]
    )
    if not path_breach:
        raise AssertionError("prohibited path did not raise preflight_breach")

    # 9. Forbidden write path is rejected.
    try:
        assert_allowed_write(PROJECT_DIR / "forbidden/safe-apply-preflight.json")
    except ValueError:
        pass
    else:
        raise AssertionError("forbidden write path was not rejected")

    print("safe-apply-preflight-validator self-tests: OK")
    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate Safe Apply preflight preconditions (read-only, no apply).")
    parser.add_argument("--self-test", action="store_true", help="Run in-memory preflight safety tests and exit.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()
    inputs, statuses = load_inputs()
    report = build_preflight_report(inputs, statuses)
    write_outputs(report)
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    print(
        "Safe Apply Preflight Validation written: "
        f"{PREFLIGHT_MD} "
        f"(ready_draft={summary.get('preflight_ready_draft_only_count')}, "
        f"not_ready={summary.get('preflight_not_ready_count')}, "
        f"blocked={summary.get('preflight_blocked_count')}, "
        f"breach={summary.get('preflight_breach')})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
