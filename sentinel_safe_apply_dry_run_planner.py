#!/usr/bin/env python3
"""Sentinel Safe Apply Dry-Run Planner (Phase 3.3).

Turns the Safe Apply Scope Allowlist (Phase 3.2) into a dry-run plan that
*simulates* how a future safe apply candidate would be prepared — without ever
applying anything live. It only emits dry-run plans, prechecks, postchecks and
rollback requirements.

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
INPUT_SCOPE_DRAFT = PROJECT_DIR / "drafts/apply/safe-apply-scope-allowlist.json"
INPUT_SCOPE_REPORT = PROJECT_DIR / "reports/latest/safe-apply-scope-allowlist-report.json"
INPUT_GUARD_DRAFT = PROJECT_DIR / "drafts/apply/safe-apply-guard-check.json"
INPUT_GUARD_REPORT = PROJECT_DIR / "reports/latest/safe-apply-guard-check-report.json"
INPUT_AUTONOMY_POLICY = PROJECT_DIR / "reports/latest/autonomy-policy-report.json"
INPUT_POST_VALIDATION = PROJECT_DIR / "reports/latest/post-manual-validation-report.json"
INPUT_MASTER = PROJECT_DIR / "reports/latest/sentinel-master-report.json"

PLAN_JSON = PROJECT_DIR / "drafts/apply/safe-apply-dry-run-plan.json"
PLAN_MD = PROJECT_DIR / "drafts/apply/safe-apply-dry-run-plan.md"
REPORT_JSON = PROJECT_DIR / "reports/latest/safe-apply-dry-run-plan-report.json"
REPORT_MD = PROJECT_DIR / "reports/latest/safe-apply-dry-run-plan-report.md"
AUDIT_JSONL = PROJECT_DIR / "audit/safe-apply-dry-run-plan.jsonl"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "drafts/apply",
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "audit",
)

SCHEMA_VERSION = "safe-apply-dry-run-plan-3.3"

APPLY_NOT_APPLIED = "not_applied"
RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"
RISK_REVIEW_ONLY = "REVIEW_ONLY"

# Scope status vocabulary consumed from Phase 3.2.
SCOPE_ALLOWED_DRAFT_ONLY = "SCOPE_ALLOWED_DRAFT_ONLY"
SCOPE_ALLOWED_VALIDATION_ONLY = "SCOPE_ALLOWED_VALIDATION_ONLY"
SCOPE_NOT_ALLOWED_MISSING_GUARDS = "SCOPE_NOT_ALLOWED_MISSING_GUARDS"
SCOPE_BLOCKED_HIGH_RISK = "SCOPE_BLOCKED_HIGH_RISK"
SCOPE_MONITOR_ONLY = "SCOPE_MONITOR_ONLY"

# Dry-run status vocabulary (Phase 3.3).
DRY_RUN_READY_FOR_DRAFT_ONLY = "DRY_RUN_READY_FOR_DRAFT_ONLY"
DRY_RUN_READY_FOR_VALIDATION_ONLY = "DRY_RUN_READY_FOR_VALIDATION_ONLY"
DRY_RUN_NOT_READY_MISSING_GUARDS = "DRY_RUN_NOT_READY_MISSING_GUARDS"
DRY_RUN_BLOCKED_HIGH_RISK = "DRY_RUN_BLOCKED_HIGH_RISK"
DRY_RUN_MONITOR_ONLY = "DRY_RUN_MONITOR_ONLY"

DRY_RUN_READY_STATUSES = {DRY_RUN_READY_FOR_DRAFT_ONLY, DRY_RUN_READY_FOR_VALIDATION_ONLY}

# Scope types that must never be planned for execution (live/production).
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

# Default local-only output path prefixes used when the scope item omits them.
DEFAULT_ALLOWED_OUTPUT_PATHS = [
    "reports/latest",
    "drafts/apply",
    "audit",
]

# Paths that are always prohibited inside any dry-run plan.
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

PRECHECK_KEYS = [
    "autonomy_policy_ok",
    "scope_allowlist_ok",
    "guard_check_ok",
    "no_high_risk",
    "apply_status_not_applied",
    "allowed_paths_only",
    "no_network_required",
    "no_live_write_required",
]

POSTCHECK_KEYS = [
    "generated_report_exists",
    "generated_draft_exists_if_expected",
    "json_valid_if_json_output",
    "audit_log_written",
    "no_productive_change",
    "post_manual_validation_recommended",
]

AUDIT_REQUIREMENTS = [
    "append_audit_safe_apply_dry_run_plan_jsonl",
    "record_scope_id_and_candidate_id",
    "record_no_productive_change",
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
        raise ValueError(f"Refusing to write outside allowed dry-run-planner roots: {path}")


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


def load_inputs() -> Tuple[Optional[Any], Optional[Any], Optional[Any], Optional[Any], Dict[str, str]]:
    scope, scope_status = read_json_status(INPUT_SCOPE_DRAFT)
    if scope_status != "ok":
        scope, scope_status = read_json_status(INPUT_SCOPE_REPORT)
    guard, guard_status = read_json_status(INPUT_GUARD_DRAFT)
    if guard_status != "ok":
        guard, guard_status = read_json_status(INPUT_GUARD_REPORT)
    autonomy, autonomy_status = read_json_status(INPUT_AUTONOMY_POLICY)
    post_validation, post_validation_status = read_json_status(INPUT_POST_VALIDATION)
    statuses = {
        "safe_apply_scope_allowlist": scope_status,
        "safe_apply_guard_check": guard_status,
        "autonomy_policy": autonomy_status,
        "post_manual_validation": post_validation_status,
        "sentinel_master": read_json_status(INPUT_MASTER)[1],
    }
    return scope, guard, autonomy, post_validation, statuses


def scope_items_from(scope: Optional[Any]) -> List[Dict[str, Any]]:
    if not isinstance(scope, dict) or not isinstance(scope.get("scope_items"), list):
        return []
    return [item for item in scope["scope_items"] if isinstance(item, dict)]


def breach_flag(data: Optional[Any], key: str) -> bool:
    if not isinstance(data, dict):
        return False
    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    return bool(summary.get(key, False)) or bool(data.get(key, False))


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


def planned_write_paths(scope_item: Dict[str, Any]) -> List[str]:
    """Use the scope item's local-only output paths, falling back to defaults."""
    outputs = scope_item.get("allowed_outputs")
    if isinstance(outputs, list) and outputs:
        paths = [str(path) for path in outputs]
    else:
        allowed = scope_item.get("allowed_paths")
        paths = [str(path) for path in allowed] if isinstance(allowed, list) and allowed else list(DEFAULT_ALLOWED_OUTPUT_PATHS)
    # Never let a prohibited path leak into a dry-run plan.
    return [path for path in paths if not path_contains_prohibited([path])]


def determine_dry_run_status(
    scope_status: str,
    risk: str,
    candidate_type: str,
    apply_status: str,
) -> Tuple[str, str]:
    if apply_status != APPLY_NOT_APPLIED:
        return (
            DRY_RUN_NOT_READY_MISSING_GUARDS,
            "apply_status is not not_applied; dry-run refuses readiness and flags review.",
        )
    if scope_status == SCOPE_BLOCKED_HIGH_RISK or risk == RISK_HIGH or candidate_type in PROHIBITED_SCOPE_TYPES:
        return (
            DRY_RUN_BLOCKED_HIGH_RISK,
            "HIGH risk or prohibited candidate_type; dry-run is permanently blocked.",
        )
    if scope_status == SCOPE_MONITOR_ONLY:
        return (
            DRY_RUN_MONITOR_ONLY,
            "Candidate is monitor-only; no dry-run preparation is allowed.",
        )
    if scope_status == SCOPE_ALLOWED_DRAFT_ONLY and risk == RISK_LOW:
        return (
            DRY_RUN_READY_FOR_DRAFT_ONLY,
            "LOW allowed draft-only scope can be dry-run prepared as a local draft only.",
        )
    if scope_status == SCOPE_ALLOWED_VALIDATION_ONLY and risk == RISK_LOW:
        return (
            DRY_RUN_READY_FOR_VALIDATION_ONLY,
            "LOW allowed validation-only scope can be dry-run prepared as a local validation only.",
        )
    return (
        DRY_RUN_NOT_READY_MISSING_GUARDS,
        "Scope is not allowed for dry-run; allowlist/risk requirements are not all met.",
    )


def rollback_requirements_for(dry_run_status: str) -> str:
    if dry_run_status == DRY_RUN_READY_FOR_DRAFT_ONLY:
        return "delete_or_regenerate_draft_and_report_only"
    if dry_run_status == DRY_RUN_READY_FOR_VALIDATION_ONLY:
        return "delete_or_regenerate_validation_report_only"
    return "dry_run_blocked_rollback_not_sufficient_without_future_owner_gated_apply"


def backup_requirements_for(dry_run_status: str) -> List[str]:
    if dry_run_status in DRY_RUN_READY_STATUSES:
        return [
            "prior_draft_snapshot_under_drafts_apply",
            "prior_report_snapshot_under_reports_latest",
        ]
    return ["not_applicable_dry_run_blocked"]


def build_prechecks(
    risk: str,
    candidate_type: str,
    apply_status: str,
    allowed_write_paths: List[str],
    *,
    autonomy_ok: bool,
    scope_ok: bool,
    guard_ok: bool,
) -> Dict[str, bool]:
    return {
        "autonomy_policy_ok": bool(autonomy_ok),
        "scope_allowlist_ok": bool(scope_ok),
        "guard_check_ok": bool(guard_ok),
        "no_high_risk": risk != RISK_HIGH,
        "apply_status_not_applied": apply_status == APPLY_NOT_APPLIED,
        "allowed_paths_only": not path_contains_prohibited(allowed_write_paths),
        # A dry-run plan never needs network or a live write.
        "no_network_required": True,
        "no_live_write_required": candidate_type not in PROHIBITED_SCOPE_TYPES,
    }


def build_postchecks() -> Dict[str, bool]:
    return {key: True for key in POSTCHECK_KEYS}


def build_dry_run_item(
    scope_item: Dict[str, Any],
    index: int,
    *,
    autonomy_ok: bool,
    scope_ok: bool,
    guard_ok: bool,
) -> Dict[str, Any]:
    candidate_id = redact_text(scope_item.get("candidate_id"), max_len=160)
    candidate_type = str(scope_item.get("candidate_type") or "")
    risk = normalize_risk(scope_item.get("risk_classification"))
    scope_status = str(scope_item.get("scope_status") or "")
    raw_apply = scope_item.get("apply_status")
    apply_status = raw_apply if raw_apply == APPLY_NOT_APPLIED else str(raw_apply or "")

    dry_run_status, reason = determine_dry_run_status(scope_status, risk, candidate_type, apply_status)
    ready = dry_run_status in DRY_RUN_READY_STATUSES

    if ready:
        allowed_write_paths = planned_write_paths(scope_item)
        if dry_run_status == DRY_RUN_READY_FOR_DRAFT_ONLY:
            planned_action_type = "prepare_local_draft_only"
        else:
            planned_action_type = "run_local_validation_only"
    else:
        allowed_write_paths = []
        planned_action_type = "none"

    prechecks = build_prechecks(
        risk,
        candidate_type,
        apply_status,
        allowed_write_paths,
        autonomy_ok=autonomy_ok,
        scope_ok=scope_ok,
        guard_ok=guard_ok,
    )

    return {
        "dry_run_id": f"safe_apply_dry_run:{index:03d}",
        "scope_id": redact_text(scope_item.get("scope_id"), max_len=80),
        "candidate_id": candidate_id,
        "candidate_type": redact_text(candidate_type, max_len=120) if candidate_type else "-",
        "title": redact_text(scope_item.get("title"), max_len=320),
        "risk_classification": risk,
        "scope_status": redact_text(scope_status, max_len=80) if scope_status else "-",
        "dry_run_status": dry_run_status,
        "planned_action_type": planned_action_type,
        "allowed_write_paths": allowed_write_paths,
        "prohibited_write_paths": list(ALWAYS_PROHIBITED_PATHS),
        "prechecks": prechecks,
        "postchecks": build_postchecks(),
        "rollback_requirements": rollback_requirements_for(dry_run_status),
        "backup_requirements": backup_requirements_for(dry_run_status),
        "audit_requirements": list(AUDIT_REQUIREMENTS),
        "owner_disable_switch_required": True,
        # A dry-run plan never needs network/API/login; tracked for breach detection.
        "requires_network_access": False,
        "requires_api_access": False,
        "requires_login": False,
        "can_execute_now": False,
        # The planner never applies: it records the candidate's apply_status,
        # which must stay not_applied. Any other value is a breach.
        "apply_status": APPLY_NOT_APPLIED if apply_status == APPLY_NOT_APPLIED else redact_text(apply_status, max_len=80),
        "reason": reason,
    }


def dry_run_breach(items: List[Dict[str, Any]]) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    for item in items:
        dry_run_id = item.get("dry_run_id")
        ready = item.get("dry_run_status") in DRY_RUN_READY_STATUSES
        if item.get("apply_status") != APPLY_NOT_APPLIED:
            reasons.append(f"{dry_run_id}: apply_status != not_applied")
        if item.get("can_execute_now"):
            reasons.append(f"{dry_run_id}: can_execute_now is true")
        if item.get("requires_network_access") or item.get("requires_api_access") or item.get("requires_login"):
            reasons.append(f"{dry_run_id}: network/API/login requirement present")
        if path_contains_prohibited(item.get("allowed_write_paths")):
            reasons.append(f"{dry_run_id}: prohibited path in allowed_write_paths")
        if ready and item.get("risk_classification") == RISK_HIGH:
            reasons.append(f"{dry_run_id}: HIGH risk in dry-run-ready scope")
        if ready and item.get("risk_classification") in {RISK_MEDIUM, RISK_REVIEW_ONLY}:
            reasons.append(f"{dry_run_id}: MEDIUM/REVIEW_ONLY risk in dry-run-ready scope")
        if ready and str(item.get("candidate_type")) in PROHIBITED_SCOPE_TYPES:
            reasons.append(f"{dry_run_id}: prohibited candidate_type in dry-run-ready scope")
    return bool(reasons), reasons


def summarize_items(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    counts = {
        DRY_RUN_READY_FOR_DRAFT_ONLY: 0,
        DRY_RUN_READY_FOR_VALIDATION_ONLY: 0,
        DRY_RUN_NOT_READY_MISSING_GUARDS: 0,
        DRY_RUN_BLOCKED_HIGH_RISK: 0,
        DRY_RUN_MONITOR_ONLY: 0,
    }
    for item in items:
        status = item.get("dry_run_status")
        if status in counts:
            counts[status] += 1
    breach, breach_reasons = dry_run_breach(items)
    return {
        "candidate_count": len(items),
        "dry_run_ready_draft_only_count": counts[DRY_RUN_READY_FOR_DRAFT_ONLY],
        "dry_run_ready_validation_only_count": counts[DRY_RUN_READY_FOR_VALIDATION_ONLY],
        "dry_run_not_ready_missing_guards_count": counts[DRY_RUN_NOT_READY_MISSING_GUARDS],
        "dry_run_blocked_high_risk_count": counts[DRY_RUN_BLOCKED_HIGH_RISK],
        "dry_run_monitor_only_count": counts[DRY_RUN_MONITOR_ONLY],
        "dry_run_breach": breach,
        "dry_run_breach_reasons": breach_reasons,
    }


def build_dry_run_report(
    scope: Optional[Any],
    guard: Optional[Any],
    autonomy: Optional[Any],
    input_statuses: Dict[str, str],
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    generated = generated_at or utc_now()
    scope_items = scope_items_from(scope)
    scope_ok = isinstance(scope, dict) and not breach_flag(scope, "scope_breach")
    guard_ok = isinstance(guard, dict) and not breach_flag(guard, "guard_breach")
    autonomy_ok = not (isinstance(autonomy, dict) and autonomy.get("policy_only") is False)

    items = [
        build_dry_run_item(
            scope_item,
            index + 1,
            autonomy_ok=autonomy_ok,
            scope_ok=scope_ok,
            guard_ok=guard_ok,
        )
        for index, scope_item in enumerate(scope_items)
    ]
    summary = summarize_items(items)
    ready_plans = [item for item in items if item.get("dry_run_status") in DRY_RUN_READY_STATUSES]
    status = (
        "DRY_RUN_WARNING"
        if summary["dry_run_breach"]
        else ("NO_SCOPE_ALLOWLIST_AVAILABLE" if not scope_items else "READY_FOR_REVIEW")
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
        "precheck_keys": list(PRECHECK_KEYS),
        "postcheck_keys": list(POSTCHECK_KEYS),
        "input_statuses": input_statuses,
        "summary": summary,
        "dry_run_items": items,
        "ready_dry_run_plans": ready_plans,
        "outputs": {
            "plan_json": str(PLAN_JSON),
            "plan_md": str(PLAN_MD),
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
        f"- Dry-run ready draft-only: `{summary.get('dry_run_ready_draft_only_count')}`",
        f"- Dry-run ready validation-only: `{summary.get('dry_run_ready_validation_only_count')}`",
        f"- Dry-run not ready (missing guards): `{summary.get('dry_run_not_ready_missing_guards_count')}`",
        f"- Dry-run blocked (high risk): `{summary.get('dry_run_blocked_high_risk_count')}`",
        f"- Dry-run monitor-only: `{summary.get('dry_run_monitor_only_count')}`",
        f"- Dry-run breach: `{summary.get('dry_run_breach')}`",
        "",
        "## Dry-Run Items",
        "",
        "| Dry-Run ID | Status | Planned Action | Can Execute Now | Risk | Rollback | Title |",
        "|---|---|---|---|---|---|---|",
    ]
    for item in report.get("dry_run_items", []):
        if not isinstance(item, dict):
            continue
        lines.append(
            "| "
            f"`{redact_text(item.get('dry_run_id'), max_len=80)}` | "
            f"`{redact_text(item.get('dry_run_status'), max_len=80)}` | "
            f"`{redact_text(item.get('planned_action_type'), max_len=80)}` | "
            f"`{redact_text(item.get('can_execute_now'), max_len=20)}` | "
            f"`{redact_text(item.get('risk_classification'), max_len=60)}` | "
            f"`{redact_text(item.get('rollback_requirements'), max_len=80)}` | "
            f"{redact_text(item.get('title'), max_len=160)} |"
        )
    lines.extend(["", "## Prechecks (required per ready plan)", ""])
    for key in report.get("precheck_keys", []):
        lines.append(f"- `{redact_text(key, max_len=80)}`")
    lines.extend(["", "## Postchecks (required per ready plan)", ""])
    for key in report.get("postcheck_keys", []):
        lines.append(f"- `{redact_text(key, max_len=80)}`")
    lines.extend(["", "## Always Prohibited Write Paths", ""])
    for path in report.get("always_prohibited_paths", []):
        lines.append(f"- `{redact_text(path, max_len=120)}`")
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
        "dry_run_ready_draft_only_count": summary.get("dry_run_ready_draft_only_count"),
        "dry_run_ready_validation_only_count": summary.get("dry_run_ready_validation_only_count"),
        "dry_run_not_ready_missing_guards_count": summary.get("dry_run_not_ready_missing_guards_count"),
        "dry_run_blocked_high_risk_count": summary.get("dry_run_blocked_high_risk_count"),
        "dry_run_monitor_only_count": summary.get("dry_run_monitor_only_count"),
        "dry_run_breach": summary.get("dry_run_breach"),
        "productive_change": False,
        "network_access": False,
        "apply_function": False,
    }


def write_outputs(report: Dict[str, Any]) -> None:
    write_json_atomic(PLAN_JSON, report)
    write_text_atomic(PLAN_MD, render_markdown(report, title="Safe Apply Dry-Run Plan"))
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, render_markdown(report, title="Safe Apply Dry-Run Plan Report"))
    append_jsonl(AUDIT_JSONL, [audit_record(report)])


def run_self_test() -> int:
    # 1. Missing scope allowlist never crashes and reports NO_SCOPE_ALLOWLIST_AVAILABLE.
    empty = build_dry_run_report(
        None, None, None, {"safe_apply_scope_allowlist": "not_available"}, "2026-06-10T00:00:00Z"
    )
    if empty["status"] != "NO_SCOPE_ALLOWLIST_AVAILABLE":
        raise AssertionError("missing scope did not produce NO_SCOPE_ALLOWLIST_AVAILABLE")
    if empty["summary"]["dry_run_breach"]:
        raise AssertionError("empty input must not report a breach")

    scope = {
        "summary": {"scope_breach": False},
        "scope_items": [
            {  # LOW allowed draft-only -> ready draft-only
                "scope_id": "safe_apply_scope:001",
                "candidate_id": "safe_apply_candidate:001",
                "candidate_type": "report_update_only",
                "title": "Report draft",
                "risk_classification": "LOW",
                "scope_status": SCOPE_ALLOWED_DRAFT_ONLY,
                "apply_status": "not_applied",
                "allowed_outputs": ["reports/latest", "drafts/apply", "audit"],
            },
            {  # LOW allowed validation-only -> ready validation-only
                "scope_id": "safe_apply_scope:002",
                "candidate_id": "safe_apply_candidate:002",
                "candidate_type": "validation_only",
                "title": "Validation check",
                "risk_classification": "LOW",
                "scope_status": SCOPE_ALLOWED_VALIDATION_ONLY,
                "apply_status": "not_applied",
                "allowed_outputs": ["drafts/validation", "reports/latest", "audit"],
            },
            {  # blocked high-risk -> blocked
                "scope_id": "safe_apply_scope:003",
                "candidate_id": "safe_apply_candidate:003",
                "candidate_type": "report_update_only",
                "title": "High risk",
                "risk_classification": "HIGH",
                "scope_status": SCOPE_BLOCKED_HIGH_RISK,
                "apply_status": "not_applied",
            },
            {  # monitor-only -> monitor
                "scope_id": "safe_apply_scope:004",
                "candidate_id": "safe_apply_candidate:004",
                "candidate_type": "report_update_only",
                "title": "Monitor",
                "risk_classification": "LOW",
                "scope_status": SCOPE_MONITOR_ONLY,
                "apply_status": "not_applied",
            },
            {  # not-allowed scope -> not ready
                "scope_id": "safe_apply_scope:005",
                "candidate_id": "safe_apply_candidate:005",
                "candidate_type": "report_update_only",
                "title": "Missing guards",
                "risk_classification": "LOW",
                "scope_status": SCOPE_NOT_ALLOWED_MISSING_GUARDS,
                "apply_status": "not_applied",
            },
            {  # apply_status != not_applied -> not ready AND breach
                "scope_id": "safe_apply_scope:006",
                "candidate_id": "safe_apply_candidate:006",
                "candidate_type": "report_update_only",
                "title": "Already applied",
                "risk_classification": "LOW",
                "scope_status": SCOPE_ALLOWED_DRAFT_ONLY,
                "apply_status": "applied",
            },
        ],
    }
    report = build_dry_run_report(scope, {"summary": {"guard_breach": False}}, {"policy_only": True}, {"safe_apply_scope_allowlist": "ok"}, "2026-06-10T00:01:00Z")
    by_id = {item["candidate_id"]: item for item in report["dry_run_items"]}

    if by_id["safe_apply_candidate:001"]["dry_run_status"] != DRY_RUN_READY_FOR_DRAFT_ONLY:
        raise AssertionError("LOW draft-only scope was not dry-run ready draft-only")
    if by_id["safe_apply_candidate:001"]["planned_action_type"] != "prepare_local_draft_only":
        raise AssertionError("ready draft plan has wrong planned_action_type")
    if by_id["safe_apply_candidate:001"]["rollback_requirements"] != "delete_or_regenerate_draft_and_report_only":
        raise AssertionError("draft rollback requirement wrong")
    if by_id["safe_apply_candidate:002"]["dry_run_status"] != DRY_RUN_READY_FOR_VALIDATION_ONLY:
        raise AssertionError("LOW validation-only scope was not dry-run ready validation-only")
    if by_id["safe_apply_candidate:002"]["rollback_requirements"] != "delete_or_regenerate_validation_report_only":
        raise AssertionError("validation rollback requirement wrong")
    if by_id["safe_apply_candidate:003"]["dry_run_status"] != DRY_RUN_BLOCKED_HIGH_RISK:
        raise AssertionError("HIGH scope was not blocked")
    if by_id["safe_apply_candidate:004"]["dry_run_status"] != DRY_RUN_MONITOR_ONLY:
        raise AssertionError("monitor-only scope did not stay monitor")
    if by_id["safe_apply_candidate:005"]["dry_run_status"] != DRY_RUN_NOT_READY_MISSING_GUARDS:
        raise AssertionError("not-allowed scope was not kept out of ready")
    if by_id["safe_apply_candidate:006"]["dry_run_status"] in DRY_RUN_READY_STATUSES:
        raise AssertionError("applied candidate became dry-run ready")
    if not report["summary"]["dry_run_breach"]:
        raise AssertionError("apply_status != not_applied did not raise dry_run_breach")
    if len(report["ready_dry_run_plans"]) != 2:
        raise AssertionError("ready_dry_run_plans did not contain exactly the two ready LOW scopes")
    for item in report["dry_run_items"]:
        if item["can_execute_now"] is not False:
            raise AssertionError("can_execute_now must always be false")
        if path_contains_prohibited(item["allowed_write_paths"]):
            raise AssertionError("dry-run item contains a prohibited write path")

    # 2. HIGH risk in dry-run ready -> breach.
    high_breach, _ = dry_run_breach(
        [{"dry_run_id": "x", "dry_run_status": DRY_RUN_READY_FOR_DRAFT_ONLY, "risk_classification": RISK_HIGH,
          "candidate_type": "report_update_only", "apply_status": APPLY_NOT_APPLIED, "can_execute_now": False,
          "allowed_write_paths": []}]
    )
    if not high_breach:
        raise AssertionError("HIGH in dry-run ready did not raise dry_run_breach")

    # 3. MEDIUM/REVIEW_ONLY in dry-run ready -> breach.
    medium_breach, _ = dry_run_breach(
        [{"dry_run_id": "x", "dry_run_status": DRY_RUN_READY_FOR_VALIDATION_ONLY, "risk_classification": RISK_REVIEW_ONLY,
          "candidate_type": "validation_only", "apply_status": APPLY_NOT_APPLIED, "can_execute_now": False,
          "allowed_write_paths": []}]
    )
    if not medium_breach:
        raise AssertionError("MEDIUM/REVIEW_ONLY in dry-run ready did not raise dry_run_breach")

    # 4. can_execute_now=true -> breach.
    exec_breach, _ = dry_run_breach(
        [{"dry_run_id": "x", "dry_run_status": DRY_RUN_READY_FOR_DRAFT_ONLY, "risk_classification": RISK_LOW,
          "candidate_type": "report_update_only", "apply_status": APPLY_NOT_APPLIED, "can_execute_now": True,
          "allowed_write_paths": []}]
    )
    if not exec_breach:
        raise AssertionError("can_execute_now=true did not raise dry_run_breach")

    # 5. Prohibited path in allowed_write_paths -> breach.
    path_breach, _ = dry_run_breach(
        [{"dry_run_id": "x", "dry_run_status": DRY_RUN_READY_FOR_DRAFT_ONLY, "risk_classification": RISK_LOW,
          "candidate_type": "report_update_only", "apply_status": APPLY_NOT_APPLIED, "can_execute_now": False,
          "allowed_write_paths": ["reports/latest", "wp-content/themes/x"]}]
    )
    if not path_breach:
        raise AssertionError("prohibited path in allowed_write_paths did not raise dry_run_breach")

    # 6. Network/API/login requirement -> breach.
    net_breach, _ = dry_run_breach(
        [{"dry_run_id": "x", "dry_run_status": DRY_RUN_READY_FOR_DRAFT_ONLY, "risk_classification": RISK_LOW,
          "candidate_type": "report_update_only", "apply_status": APPLY_NOT_APPLIED, "can_execute_now": False,
          "requires_network_access": True, "allowed_write_paths": []}]
    )
    if not net_breach:
        raise AssertionError("network requirement did not raise dry_run_breach")

    # 7. Forbidden write path is rejected.
    try:
        assert_allowed_write(PROJECT_DIR / "forbidden/safe-apply-dry-run.json")
    except ValueError:
        pass
    else:
        raise AssertionError("forbidden write path was not rejected")

    print("safe-apply-dry-run-planner self-tests: OK")
    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build the Safe Apply dry-run plan (read-only, no apply).")
    parser.add_argument("--self-test", action="store_true", help="Run in-memory dry-run safety tests and exit.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()
    scope, guard, autonomy, _post_validation, statuses = load_inputs()
    report = build_dry_run_report(scope, guard, autonomy, statuses)
    write_outputs(report)
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    print(
        "Safe Apply Dry-Run Plan written: "
        f"{PLAN_MD} "
        f"(ready_draft={summary.get('dry_run_ready_draft_only_count')}, "
        f"ready_validation={summary.get('dry_run_ready_validation_only_count')}, "
        f"blocked={summary.get('dry_run_blocked_high_risk_count')}, "
        f"breach={summary.get('dry_run_breach')})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
