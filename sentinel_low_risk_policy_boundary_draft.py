#!/usr/bin/env python3
"""LOW-RISK Policy Boundary Draft Pack (Phase 5.6).

Read-only module that drafts which SEO-&-performance actions could *theoretically*
become LOW-RISK later. It activates no autonomy, applies nothing, frees no timer
installation, and never changes the Master status. It only emits an owner-review
policy draft that classifies actions into risk categories.

This is NOT an apply mechanism, NOT an activation of LOW-RISK autonomy, NOT a WAF
rule, NOT a WordPress/Cloudflare/Nginx/.htaccess change, and NOT a systemd/crontab
installation. It is only a policy draft.
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

READINESS_GATE_JSON = PROJECT_DIR / "reports/latest/low-risk-autonomy-readiness-gate.json"
MANUAL_RECHECK_GATE_JSON = PROJECT_DIR / "reports/latest/manual-website-recheck-gate.json"
LOW_GROWTH_TIMELINE_JSON = PROJECT_DIR / "reports/latest/low-growth-readiness-timeline.json"
ROLLING_OBSERVER_JSON = PROJECT_DIR / "reports/latest/rolling-window-decay-observer.json"
MASTER_CRITICAL_CAUSE_JSON = PROJECT_DIR / "reports/latest/master-critical-cause-snapshot.json"
FINAL_OWNER_SNAPSHOT_JSON = PROJECT_DIR / "reports/latest/final-owner-decision-snapshot.json"
CANDIDATE_REGISTRY_JSON = PROJECT_DIR / "reports/latest/safe-apply-candidate-registry-report.json"
GUARD_CHECKER_JSON = PROJECT_DIR / "reports/latest/safe-apply-guard-check-report.json"
SCOPE_MANAGER_JSON = PROJECT_DIR / "reports/latest/safe-apply-scope-allowlist-report.json"
PREFLIGHT_VALIDATOR_JSON = PROJECT_DIR / "reports/latest/safe-apply-preflight-validation-report.json"
MASTER_JSON = PROJECT_DIR / "reports/latest/sentinel-master-report.json"
RUNTIME_LOCK_JSON = PROJECT_DIR / "config/autonomy-runtime-lock.json"

REPORT_JSON = PROJECT_DIR / "reports/latest/low-risk-policy-boundary-draft.json"
REPORT_MD = PROJECT_DIR / "reports/latest/low-risk-policy-boundary-draft.md"
OWNER_REVIEW_MD = PROJECT_DIR / "drafts/owner/low-risk-policy-boundary-owner-review.md"
SNAPSHOT_JSON = PROJECT_DIR / "snapshots/low-risk-policy-boundary-draft.json"
SNAPSHOT_MD = PROJECT_DIR / "snapshots/low-risk-policy-boundary-draft.md"
AUDIT_JSONL = PROJECT_DIR / "audit/low-risk-policy-boundary-draft.jsonl"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "drafts/owner",
    PROJECT_DIR / "snapshots",
    PROJECT_DIR / "audit",
)
ALLOWED_OUTPUT_PATHS = (REPORT_JSON, REPORT_MD, OWNER_REVIEW_MD, SNAPSHOT_JSON, SNAPSHOT_MD, AUDIT_JSONL)
FORBIDDEN_OUTPUT_SUFFIXES = (".sh", ".bash", ".zsh", ".service", ".timer", ".run", ".bin", ".py")
FORBIDDEN_INSTALL_PATH_TOKENS = (
    "/etc/systemd",
    "systemd/system",
    "/lib/systemd",
    "/usr/lib/systemd",
    "/etc/cron",
    "cron.d",
    "crontab",
)

SCHEMA_VERSION = "low-risk-policy-boundary-draft-5.6"
APPLY_NOT_APPLIED = "not_applied"

STATUS_LOCKED_BY_EMERGENCY_STOP = "LOW_RISK_POLICY_DRAFT_LOCKED_BY_EMERGENCY_STOP"
STATUS_READY_FOR_OWNER_REVIEW = "LOW_RISK_POLICY_DRAFT_READY_FOR_OWNER_REVIEW"
STATUS_PARTIAL_INPUTS = "LOW_RISK_POLICY_DRAFT_PARTIAL_INPUTS"
STATUS_BLOCKED_BY_BREACH = "LOW_RISK_POLICY_DRAFT_BLOCKED_BY_BREACH"
STATUS_BREACH = "LOW_RISK_POLICY_DRAFT_BREACH"

ACTION_BY_STATUS = {
    STATUS_LOCKED_BY_EMERGENCY_STOP: "Review policy boundaries only. Keep Emergency Stop active. Do not enable autonomy.",
    STATUS_READY_FOR_OWNER_REVIEW: "Owner may review LOW-RISK boundaries. Do not apply changes.",
    STATUS_BLOCKED_BY_BREACH: "Do not proceed. Resolve breach first.",
    STATUS_BREACH: "Do not proceed. Resolve breach first.",
    STATUS_PARTIAL_INPUTS: "Collect missing read-only readiness/safety inputs before reviewing boundaries.",
}

# Categories. CATEGORY_LABEL identifiers (review-only text, never executed).
CAT_DRAFT_ONLY = "LOW_RISK_DRAFT_ONLY"
CAT_REVIEW_ONLY = "LOW_RISK_REVIEW_ONLY"
CAT_POTENTIAL_FUTURE_APPLY = "LOW_RISK_POTENTIAL_FUTURE_APPLY"
CAT_MEDIUM = "MEDIUM_RISK_OWNER_APPROVAL_REQUIRED"
CAT_HIGH = "HIGH_RISK_NEVER_AUTO_APPLY"
CAT_FORBIDDEN = "FORBIDDEN"

# Mandatory preconditions every future LOW-RISK action must satisfy first.
REQUIRED_PRECONDITIONS = ["backup", "healthcheck", "rollback", "audit", "owner_policy_review"]

LOW_RISK_DRAFT_ONLY_ITEMS = [
    "Meta-Title-Draft",
    "Meta-Description-Draft",
    "OpenGraph-Draft",
    "Twitter-Card-Draft",
    "Internal-Link-Suggestion-Draft",
    "Image-alt-text-Suggestion-Draft",
    "Performance-Recommendation-Draft",
    "Report-Update",
    "Owner-Checklist",
]

LOW_RISK_REVIEW_ONLY_ITEMS = [
    "LOW-RISK boundary review summary (read-only)",
    "Owner policy review checklist (read-only)",
    "Draft-diff review for owner (read-only)",
]

LOW_RISK_POTENTIAL_FUTURE_APPLY_ITEMS = [
    "Local draft files under drafts/ only (future category, not active)",
    "No WordPress/Cloudflare/Nginx/systemd/crontab write action",
    "No network action",
    "No login action",
    "No API action",
]

MEDIUM_RISK_ITEMS = [
    "WordPress content changes",
    "Plugin options",
    "Cache-/Minify settings",
    "SEO plugin configuration",
    "Redirect suggestions",
    "Change internal link structure live",
    "Replace images live",
]

HIGH_RISK_ITEMS = [
    "Cloudflare WAF rules",
    "DNS",
    "Nginx",
    ".htaccess",
    "systemd",
    "crontab",
    "Database migrations",
    "Plugin deactivation",
    "Change theme files live",
    "Security rules",
    "Payment/account/login actions",
]

FORBIDDEN_ITEMS = [
    "Read/output secrets",
    "Store login credentials",
    "Test credentials",
    "Send external mail",
    "Use APIs without explicit approval",
    "Irreversible changes",
    "Anything without backup/healthcheck/rollback/audit",
]

SECRETISH_RE = re.compile(
    r"(?i)(api[_-]?key|token|secret|password|passwd|bearer|authorization|"
    r"cookie|set-cookie|credential|x-api-key|access[_-]?key|session)"
)
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|password|passwd|bearer|token|credential|session|"
    r"authorization|set-cookie|cookie|x-api-key|access[_-]?key)\b\s*[:=]\s*"
    r"[\"']?(?!false\b|true\b|null\b|none\b|not_applied\b|<redacted|-\b|0\b)"
    r"[A-Za-z0-9+/=_\-]{4,}"
)
LONG_HEX_RE = re.compile(r"\b[A-Fa-f0-9]{32,}\b")
FORBIDDEN_APPLY_COMMAND_RE = re.compile(
    r"(?i)\b(cloudflare\s+api|cfcli|wp\s+|wp-cli|nginx\s+reload|nginx\s+-s|"
    r"htaccess|\\.htaccess|apply-safe|consolidate-apply-safe|systemctl|crontab|"
    r"curl\s+.*(api|cloudflare|wp-json)|wget\s+.*(api|cloudflare|wp-json))\b"
)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def redact_text(value: Any, default: str = "-", max_len: int = 800) -> str:
    if value is None:
        return default
    text = str(value).replace("\r", " ").strip()
    text = SECRET_ASSIGNMENT_RE.sub("<redacted>", text)
    text = LONG_HEX_RE.sub("<redacted-hex>", text)
    if SECRETISH_RE.search(text):
        return "[redacted]"
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text or default


def detect_secret_like(value: Any) -> bool:
    text = "" if value is None else str(value)
    return bool(SECRET_ASSIGNMENT_RE.search(text) or LONG_HEX_RE.search(text))


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError):
        return False


def assert_allowed_write(path: Path) -> None:
    if path not in ALLOWED_OUTPUT_PATHS and not any(is_within(path, root) for root in ALLOWED_WRITE_ROOTS):
        raise ValueError(f"Refusing to write outside allowed low-risk-policy roots: {path}")
    if path.suffix.lower() in FORBIDDEN_OUTPUT_SUFFIXES:
        raise ValueError(f"Refusing to write executable/install artifact: {path}")
    path_text = str(path)
    if any(token in path_text for token in FORBIDDEN_INSTALL_PATH_TOKENS):
        raise ValueError(f"Refusing to write systemd/crontab path: {path}")


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


def read_optional_json(path: Path) -> Tuple[Optional[Any], str]:
    if ".env" in str(path).lower() or SECRETISH_RE.search(path.name):
        return None, "refused_secret_like_path"
    try:
        if not path.exists():
            return None, "not_available"
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return None, "read_error"
    try:
        return json.loads(raw), "ok"
    except (ValueError, json.JSONDecodeError):
        return None, "invalid_json"


def bool_from(data: Optional[Any], key: str, default: bool = False) -> bool:
    if not isinstance(data, dict):
        return default
    return bool(data.get(key, default))


def text_from(data: Optional[Any], key: str, default: str = "") -> str:
    if not isinstance(data, dict):
        return default
    return redact_text(data.get(key), default=default, max_len=500)


def any_breach_flag(data: Optional[Any]) -> bool:
    """Defensively detect any *_breach=true flag in an upstream report."""
    if not isinstance(data, dict):
        return False
    for key, value in data.items():
        if key.lower().endswith("breach") and bool(value):
            return True
    return False


def detect_breach(
    *,
    low_risk_autonomy_allowed_now: bool,
    policy_activation_allowed: bool,
    live_apply: bool,
    install_allowed_now: bool,
    can_install_timer_now: bool,
    apply_status: str,
    forbidden_apply_command_detected: bool,
    systemd_file_written: bool,
    crontab_file_written: bool,
    executable_install_script_generated: bool,
    secret_like_output: bool,
    output_path_breach: bool,
) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    if low_risk_autonomy_allowed_now:
        reasons.append("low_risk_autonomy_allowed_now=true")
    if policy_activation_allowed:
        reasons.append("policy_activation_allowed=true")
    if live_apply:
        reasons.append("live_apply=true")
    if install_allowed_now:
        reasons.append("install_allowed_now=true")
    if can_install_timer_now:
        reasons.append("can_install_timer_now=true")
    if apply_status != APPLY_NOT_APPLIED:
        reasons.append("apply_status != not_applied")
    if forbidden_apply_command_detected:
        reasons.append("Cloudflare/WordPress/Nginx/.htaccess apply command detected")
    if systemd_file_written:
        reasons.append("systemd_file_written=true")
    if crontab_file_written:
        reasons.append("crontab_file_written=true")
    if executable_install_script_generated:
        reasons.append("executable install script generated")
    if secret_like_output:
        reasons.append("secret-like output")
    if output_path_breach:
        reasons.append("writing outside allowed roots")
    return bool(reasons), sorted(set(reasons))


def determine_status(
    *,
    direct_breach: bool,
    upstream_breach: bool,
    emergency_stop_active: bool,
    partial_inputs: bool,
) -> Tuple[str, bool]:
    if direct_breach:
        return STATUS_BREACH, True
    if upstream_breach:
        return STATUS_BLOCKED_BY_BREACH, True
    if emergency_stop_active:
        return STATUS_LOCKED_BY_EMERGENCY_STOP, False
    if partial_inputs:
        return STATUS_PARTIAL_INPUTS, False
    return STATUS_READY_FOR_OWNER_REVIEW, False


def build_category(name: str, items: List[str], *, activatable: bool) -> Dict[str, Any]:
    return {
        "category": name,
        "activatable_now": False,
        "future_apply_possible": activatable,
        "required_preconditions": list(REQUIRED_PRECONDITIONS),
        "items": list(items),
        "count": len(items),
    }


def build_policy_categories() -> Dict[str, Dict[str, Any]]:
    return {
        CAT_DRAFT_ONLY: build_category(CAT_DRAFT_ONLY, LOW_RISK_DRAFT_ONLY_ITEMS, activatable=True),
        CAT_REVIEW_ONLY: build_category(CAT_REVIEW_ONLY, LOW_RISK_REVIEW_ONLY_ITEMS, activatable=False),
        CAT_POTENTIAL_FUTURE_APPLY: build_category(CAT_POTENTIAL_FUTURE_APPLY, LOW_RISK_POTENTIAL_FUTURE_APPLY_ITEMS, activatable=True),
        CAT_MEDIUM: build_category(CAT_MEDIUM, MEDIUM_RISK_ITEMS, activatable=False),
        CAT_HIGH: build_category(CAT_HIGH, HIGH_RISK_ITEMS, activatable=False),
        CAT_FORBIDDEN: build_category(CAT_FORBIDDEN, FORBIDDEN_ITEMS, activatable=False),
    }


def build_report(
    readiness_gate: Optional[Any],
    readiness_status_read: str,
    manual_recheck_gate: Optional[Any],
    manual_recheck_status_read: str,
    timeline: Optional[Any],
    timeline_status_read: str,
    observer: Optional[Any],
    observer_status_read: str,
    critical_cause: Optional[Any],
    critical_cause_status_read: str,
    final_owner_snapshot: Optional[Any],
    final_owner_status_read: str,
    candidate_registry: Optional[Any],
    candidate_registry_status_read: str,
    guard_checker: Optional[Any],
    guard_checker_status_read: str,
    scope_manager: Optional[Any],
    scope_manager_status_read: str,
    preflight_validator: Optional[Any],
    preflight_validator_status_read: str,
    master: Optional[Any],
    master_status_read: str,
    runtime_lock: Optional[Any],
    runtime_lock_status_read: str,
    *,
    generated_at: Optional[str] = None,
    forced_flags: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    generated = generated_at or utc_now()
    flags = forced_flags or {}

    low_risk_autonomy_allowed_now = bool(flags.get("low_risk_autonomy_allowed_now", False))
    policy_activation_allowed = bool(flags.get("policy_activation_allowed", False))
    live_apply = bool(flags.get("live_apply", False))
    install_allowed_now = bool(flags.get("install_allowed_now", False))
    can_install_timer_now = bool(flags.get("can_install_timer_now", False))
    apply_status = str(flags.get("apply_status", APPLY_NOT_APPLIED))
    forbidden_apply_command_detected = bool(flags.get("forbidden_apply_command_detected", False))
    systemd_file_written = bool(flags.get("systemd_file_written", False))
    crontab_file_written = bool(flags.get("crontab_file_written", False))
    executable_install_script_generated = bool(flags.get("executable_install_script_generated", False))
    secret_like_output = bool(flags.get("secret_like_output", False))
    output_path_breach = bool(flags.get("output_path_breach", False))

    direct_breach, direct_breach_reasons = detect_breach(
        low_risk_autonomy_allowed_now=low_risk_autonomy_allowed_now,
        policy_activation_allowed=policy_activation_allowed,
        live_apply=live_apply,
        install_allowed_now=install_allowed_now,
        can_install_timer_now=can_install_timer_now,
        apply_status=apply_status,
        forbidden_apply_command_detected=forbidden_apply_command_detected,
        systemd_file_written=systemd_file_written,
        crontab_file_written=crontab_file_written,
        executable_install_script_generated=executable_install_script_generated,
        secret_like_output=secret_like_output,
        output_path_breach=output_path_breach,
    )

    upstream_breach_reasons: List[str] = []
    for label, data in (
        ("low_risk_readiness_gate", readiness_gate),
        ("manual_website_recheck_gate", manual_recheck_gate),
        ("low_growth_timeline", timeline),
        ("rolling_window_observer", observer),
        ("master_critical_cause", critical_cause),
        ("final_owner_snapshot", final_owner_snapshot),
        ("safe_apply_candidate_registry", candidate_registry),
        ("safe_apply_guard_checker", guard_checker),
        ("safe_apply_scope_manager", scope_manager),
        ("safe_apply_preflight_validator", preflight_validator),
    ):
        if any_breach_flag(data):
            upstream_breach_reasons.append(f"{label}:breach=true")
    upstream_breach = bool(upstream_breach_reasons)

    emergency_stop_active = (
        bool_from(runtime_lock, "emergency_stop")
        or bool_from(readiness_gate, "emergency_stop_active")
        or bool_from(final_owner_snapshot, "emergency_stop_active")
        or bool_from(critical_cause, "emergency_stop_active")
        or bool_from(manual_recheck_gate, "emergency_stop_active")
    )

    # Required read-only inputs: readiness gate is the primary signal.
    partial_inputs = any(
        status != "ok"
        for status in (
            readiness_status_read,
            manual_recheck_status_read,
            timeline_status_read,
            observer_status_read,
            critical_cause_status_read,
            final_owner_status_read,
            master_status_read,
            runtime_lock_status_read,
        )
    )

    policy_status, policy_breach = determine_status(
        direct_breach=direct_breach,
        upstream_breach=upstream_breach,
        emergency_stop_active=emergency_stop_active,
        partial_inputs=partial_inputs,
    )
    breach_reasons = sorted(set(direct_breach_reasons + upstream_breach_reasons))
    recommended_owner_action = ACTION_BY_STATUS.get(policy_status, ACTION_BY_STATUS[STATUS_LOCKED_BY_EMERGENCY_STOP])

    categories = build_policy_categories()

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": generated,
        "policy_status": policy_status,
        "emergency_stop_active": emergency_stop_active,
        "low_risk_autonomy_allowed_now": False,
        "policy_activation_allowed": False,
        "owner_policy_review_required": True,
        "low_risk_draft_only_count": categories[CAT_DRAFT_ONLY]["count"],
        "low_risk_review_only_count": categories[CAT_REVIEW_ONLY]["count"],
        "low_risk_potential_future_apply_count": categories[CAT_POTENTIAL_FUTURE_APPLY]["count"],
        "medium_owner_approval_required_count": categories[CAT_MEDIUM]["count"],
        "high_never_auto_apply_count": categories[CAT_HIGH]["count"],
        "forbidden_count": categories[CAT_FORBIDDEN]["count"],
        "install_allowed_now": False,
        "can_install_timer_now": False,
        "live_apply": False,
        "apply_status": APPLY_NOT_APPLIED,
        "policy_breach": policy_breach,
        "recommended_owner_action": recommended_owner_action,
        "policy_breach_reasons": breach_reasons,
        "required_preconditions_for_any_low_risk_action": list(REQUIRED_PRECONDITIONS),
        "policy_categories": categories,
        "readiness_context": {
            "readiness_status": text_from(readiness_gate, "readiness_status", "NOT_AVAILABLE"),
            "low_risk_policy_draft_allowed": bool_from(readiness_gate, "low_risk_policy_draft_allowed"),
            "manual_recheck_recommended": bool_from(manual_recheck_gate, "manual_recheck_recommended"),
            "master_status": text_from(master, "overall_master_status", "UNKNOWN"),
        },
        "read_only": True,
        "network_access": False,
        "api_access": False,
        "cloudflare_mutations": False,
        "wordpress_mutations": False,
        "nginx_mutations": False,
        "htaccess_mutations": False,
        "systemd_file_written": systemd_file_written,
        "crontab_file_written": crontab_file_written,
        "executable_install_script_generated": executable_install_script_generated,
        "secrets_output": False,
        "master_status_not_auto_changed": True,
        "input_statuses": {
            "low_risk_readiness_gate": readiness_status_read,
            "manual_website_recheck_gate": manual_recheck_status_read,
            "low_growth_timeline": timeline_status_read,
            "rolling_window_observer": observer_status_read,
            "master_critical_cause_snapshot": critical_cause_status_read,
            "final_owner_snapshot": final_owner_status_read,
            "safe_apply_candidate_registry": candidate_registry_status_read,
            "safe_apply_guard_checker": guard_checker_status_read,
            "safe_apply_scope_manager": scope_manager_status_read,
            "safe_apply_preflight_validator": preflight_validator_status_read,
            "sentinel_master_json": master_status_read,
            "runtime_lock": runtime_lock_status_read,
        },
        "decision_template": {
            "blocked_by_breach": policy_status in {STATUS_BLOCKED_BY_BREACH, STATUS_BREACH},
            "locked_by_emergency_stop": policy_status == STATUS_LOCKED_BY_EMERGENCY_STOP,
            "ready_for_owner_review": policy_status == STATUS_READY_FOR_OWNER_REVIEW,
            "policy_activation_allowed": False,
        },
        "safe_owner_next_actions": [
            recommended_owner_action,
            "This is a policy draft only; it activates no autonomy and applies nothing.",
            "Every future LOW-RISK action requires backup, healthcheck, rollback, audit and owner policy review.",
            "Do not use this draft to change Master status automatically.",
        ],
        "do_not_apply_conditions": [
            "Do not activate LOW-RISK autonomy from this draft.",
            "Do not create WAF/Cloudflare rules from this draft.",
            "Do not change WordPress, Nginx, .htaccess, systemd, or crontab from this draft.",
            "Do not install timers from this draft.",
        ],
        "outputs": {
            "report_json": str(REPORT_JSON),
            "report_md": str(REPORT_MD),
            "owner_review_md": str(OWNER_REVIEW_MD),
            "snapshot_json": str(SNAPSHOT_JSON),
            "snapshot_md": str(SNAPSHOT_MD),
            "audit_jsonl": str(AUDIT_JSONL),
        },
    }


def render_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# LOW-RISK Policy Boundary Draft",
        "",
        "> Read-only owner-review draft. Classifies future SEO/perf actions by risk.",
        "> It activates no autonomy, applies nothing, and installs no timer.",
        "",
        "## Executive Summary",
        "",
        f"- Generated (UTC): `{report.get('generated_at_utc')}`",
        f"- Policy status: `{report.get('policy_status')}`",
        f"- Emergency stop active: `{report.get('emergency_stop_active')}`",
        f"- LOW-RISK autonomy allowed now: `{report.get('low_risk_autonomy_allowed_now')}`",
        f"- Policy activation allowed: `{report.get('policy_activation_allowed')}`",
        f"- Owner policy review required: `{report.get('owner_policy_review_required')}`",
        f"- LOW-RISK draft-only count: `{report.get('low_risk_draft_only_count')}`",
        f"- LOW-RISK review-only count: `{report.get('low_risk_review_only_count')}`",
        f"- LOW-RISK potential-future-apply count: `{report.get('low_risk_potential_future_apply_count')}`",
        f"- MEDIUM owner-approval-required count: `{report.get('medium_owner_approval_required_count')}`",
        f"- HIGH never-auto-apply count: `{report.get('high_never_auto_apply_count')}`",
        f"- FORBIDDEN count: `{report.get('forbidden_count')}`",
        f"- Install allowed now: `{report.get('install_allowed_now')}`",
        f"- Can install timer now: `{report.get('can_install_timer_now')}`",
        f"- Live apply: `{report.get('live_apply')}`",
        f"- Apply status: `{report.get('apply_status')}`",
        f"- Policy breach: `{report.get('policy_breach')}`",
        f"- Recommended owner action: {redact_text(report.get('recommended_owner_action'), max_len=900)}",
        "",
        "## Required Preconditions For Any Future LOW-RISK Action",
        "",
    ]
    for item in report.get("required_preconditions_for_any_low_risk_action", []):
        lines.append(f"- {redact_text(item, max_len=200)}")
    lines.extend(["", "## Policy Categories", ""])
    categories = report.get("policy_categories") if isinstance(report.get("policy_categories"), dict) else {}
    for name in (CAT_DRAFT_ONLY, CAT_REVIEW_ONLY, CAT_POTENTIAL_FUTURE_APPLY, CAT_MEDIUM, CAT_HIGH, CAT_FORBIDDEN):
        block = categories.get(name) if isinstance(categories.get(name), dict) else {}
        lines.append(f"### {name}")
        lines.append(f"- activatable_now: `{block.get('activatable_now')}`")
        lines.append(f"- future_apply_possible: `{block.get('future_apply_possible')}`")
        lines.append(f"- count: `{block.get('count')}`")
        for item in block.get("items", []):
            lines.append(f"  - {redact_text(item, max_len=300)}")
        lines.append("")
    breach_reasons = report.get("policy_breach_reasons") or []
    lines.append("## Breach Reasons")
    lines.append("")
    if breach_reasons:
        for reason in breach_reasons:
            lines.append(f"- {redact_text(reason, max_len=400)}")
    else:
        lines.append("- none")
    lines.extend(["", "## Owner Decision Template", ""])
    decision = report.get("decision_template") if isinstance(report.get("decision_template"), dict) else {}
    for key in ("blocked_by_breach", "locked_by_emergency_stop", "ready_for_owner_review", "policy_activation_allowed"):
        lines.append(f"- {key}: `{decision.get(key)}`")
    lines.extend(["", "## Safe Owner Next Actions", ""])
    for item in report.get("safe_owner_next_actions", []):
        lines.append(f"- {redact_text(item, max_len=800)}")
    lines.extend(["", "## Do Not Apply Conditions", ""])
    for item in report.get("do_not_apply_conditions", []):
        lines.append(f"- {redact_text(item, max_len=700)}")
    lines.append("")
    return "\n".join(lines)


def audit_record(report: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "timestamp_utc": report.get("generated_at_utc"),
        "schema_version": SCHEMA_VERSION,
        "policy_status": report.get("policy_status"),
        "emergency_stop_active": report.get("emergency_stop_active"),
        "low_risk_autonomy_allowed_now": False,
        "policy_activation_allowed": False,
        "owner_policy_review_required": report.get("owner_policy_review_required"),
        "low_risk_draft_only_count": report.get("low_risk_draft_only_count"),
        "high_never_auto_apply_count": report.get("high_never_auto_apply_count"),
        "forbidden_count": report.get("forbidden_count"),
        "policy_breach": report.get("policy_breach"),
        "install_allowed_now": False,
        "can_install_timer_now": False,
        "live_apply": False,
        "apply_status": APPLY_NOT_APPLIED,
        "network_access": False,
    }


def write_outputs(report: Dict[str, Any]) -> None:
    markdown = render_markdown(report)
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, markdown)
    write_text_atomic(OWNER_REVIEW_MD, markdown)
    write_json_atomic(SNAPSHOT_JSON, report)
    write_text_atomic(SNAPSHOT_MD, markdown)
    append_jsonl(AUDIT_JSONL, [audit_record(report)])


def build_current_report() -> Dict[str, Any]:
    readiness_gate, readiness_status = read_optional_json(READINESS_GATE_JSON)
    manual_recheck_gate, manual_recheck_status = read_optional_json(MANUAL_RECHECK_GATE_JSON)
    timeline, timeline_status = read_optional_json(LOW_GROWTH_TIMELINE_JSON)
    observer, observer_status = read_optional_json(ROLLING_OBSERVER_JSON)
    critical, critical_status = read_optional_json(MASTER_CRITICAL_CAUSE_JSON)
    final_owner, final_owner_status = read_optional_json(FINAL_OWNER_SNAPSHOT_JSON)
    candidate, candidate_status = read_optional_json(CANDIDATE_REGISTRY_JSON)
    guard, guard_status = read_optional_json(GUARD_CHECKER_JSON)
    scope, scope_status = read_optional_json(SCOPE_MANAGER_JSON)
    preflight, preflight_status = read_optional_json(PREFLIGHT_VALIDATOR_JSON)
    master, master_status = read_optional_json(MASTER_JSON)
    runtime_lock, runtime_lock_status = read_optional_json(RUNTIME_LOCK_JSON)
    return build_report(
        readiness_gate, readiness_status,
        manual_recheck_gate, manual_recheck_status,
        timeline, timeline_status,
        observer, observer_status,
        critical, critical_status,
        final_owner, final_owner_status,
        candidate, candidate_status,
        guard, guard_status,
        scope, scope_status,
        preflight, preflight_status,
        master, master_status,
        runtime_lock, runtime_lock_status,
    )


def _base_inputs(**overrides: Any) -> Dict[str, Any]:
    base = {
        "readiness_gate": {
            "readiness_status": "LOW_RISK_AUTONOMY_BLOCKED_BY_EMERGENCY_STOP",
            "low_risk_policy_draft_allowed": False,
            "emergency_stop_active": True,
            "readiness_breach": False,
        },
        "manual_recheck_gate": {"manual_recheck_recommended": False, "gate_breach": False, "emergency_stop_active": True},
        "timeline": {"snapshot_breach": False},
        "observer": {"snapshot_breach": False},
        "critical": {"snapshot_breach": False, "emergency_stop_active": True},
        "final_owner": {"snapshot_breach": False, "emergency_stop_active": True},
        "candidate": {"status": "READY_FOR_REVIEW"},
        "guard": {"status": "READY_FOR_REVIEW"},
        "scope": {"status": "READY_FOR_REVIEW"},
        "preflight": {"status": "READY_FOR_REVIEW"},
        "master": {"overall_master_status": "CRITICAL"},
        "runtime_lock": {"emergency_stop": True},
    }
    base.update(overrides)
    return base


def _report_from(inputs: Dict[str, Any], **kwargs: Any) -> Dict[str, Any]:
    return build_report(
        inputs["readiness_gate"], "ok",
        inputs["manual_recheck_gate"], "ok",
        inputs["timeline"], "ok",
        inputs["observer"], "ok",
        inputs["critical"], "ok",
        inputs["final_owner"], "ok",
        inputs["candidate"], "ok",
        inputs["guard"], "ok",
        inputs["scope"], "ok",
        inputs["preflight"], "ok",
        inputs["master"], "ok",
        inputs["runtime_lock"], "ok",
        **kwargs,
    )


def _no_estop_inputs(**overrides: Any) -> Dict[str, Any]:
    inputs = _base_inputs(
        readiness_gate={"readiness_status": "LOW_RISK_AUTONOMY_READY_FOR_POLICY_DRAFT_ONLY", "low_risk_policy_draft_allowed": True, "emergency_stop_active": False, "readiness_breach": False},
        manual_recheck_gate={"manual_recheck_recommended": True, "gate_breach": False, "emergency_stop_active": False},
        critical={"snapshot_breach": False, "emergency_stop_active": False},
        final_owner={"snapshot_breach": False, "emergency_stop_active": False},
        runtime_lock={"emergency_stop": False},
    )
    inputs.update(overrides)
    return inputs


def run_self_test() -> int:
    # Resting state: emergency stop active -> LOCKED_BY_EMERGENCY_STOP, no breach.
    rest = _report_from(_base_inputs())
    if rest["policy_status"] != STATUS_LOCKED_BY_EMERGENCY_STOP or rest["policy_breach"]:
        raise AssertionError("emergency stop should lock but not breach")
    if rest["low_risk_autonomy_allowed_now"] or rest["policy_activation_allowed"]:
        raise AssertionError("autonomy/activation must not be allowed")

    # Category counts must match the fixed policy content.
    if rest["low_risk_draft_only_count"] != len(LOW_RISK_DRAFT_ONLY_ITEMS):
        raise AssertionError("draft-only count mismatch")
    if rest["high_never_auto_apply_count"] != len(HIGH_RISK_ITEMS):
        raise AssertionError("high-risk count mismatch")
    if rest["forbidden_count"] != len(FORBIDDEN_ITEMS):
        raise AssertionError("forbidden count mismatch")
    for name, block in rest["policy_categories"].items():
        if block["activatable_now"]:
            raise AssertionError(f"category {name} must not be activatable now")
        if block["required_preconditions"] != REQUIRED_PRECONDITIONS:
            raise AssertionError(f"category {name} missing required preconditions")

    # Emergency stop cleared, no breaches -> READY_FOR_OWNER_REVIEW, no breach.
    ready = _report_from(_no_estop_inputs())
    if ready["policy_status"] != STATUS_READY_FOR_OWNER_REVIEW or ready["policy_breach"]:
        raise AssertionError("ready-for-owner-review path failed")
    if ready["policy_activation_allowed"] or ready["low_risk_autonomy_allowed_now"]:
        raise AssertionError("ready state must not allow activation/autonomy")

    # Upstream breach -> BLOCKED_BY_BREACH, breach=true.
    for block, field in (
        ("readiness_gate", "readiness_breach"),
        ("manual_recheck_gate", "gate_breach"),
        ("timeline", "snapshot_breach"),
        ("observer", "snapshot_breach"),
        ("critical", "snapshot_breach"),
        ("final_owner", "snapshot_breach"),
        ("candidate", "registry_breach"),
        ("guard", "guard_breach"),
        ("scope", "scope_breach"),
        ("preflight", "preflight_breach"),
    ):
        inputs = _base_inputs()
        inputs[block] = dict(inputs[block], **{field: True})
        bad = _report_from(inputs)
        if bad["policy_status"] != STATUS_BLOCKED_BY_BREACH or not bad["policy_breach"]:
            raise AssertionError(f"upstream breach {block}.{field} did not block-by-breach")

    # Direct breach flags -> BREACH (win over emergency stop).
    for flag in (
        "low_risk_autonomy_allowed_now",
        "policy_activation_allowed",
        "live_apply",
        "install_allowed_now",
        "can_install_timer_now",
        "forbidden_apply_command_detected",
        "systemd_file_written",
        "crontab_file_written",
        "executable_install_script_generated",
        "secret_like_output",
        "output_path_breach",
    ):
        bad = _report_from(_base_inputs(), forced_flags={flag: True})
        if not bad["policy_breach"] or bad["policy_status"] != STATUS_BREACH:
            raise AssertionError(f"direct breach flag {flag} did not produce BREACH")

    bad_apply = _report_from(_base_inputs(), forced_flags={"apply_status": "applied"})
    if not bad_apply["policy_breach"] or bad_apply["policy_status"] != STATUS_BREACH:
        raise AssertionError("apply_status != not_applied did not breach")

    # Hard-coded safe constants must stay safe even on breach.
    bad = _report_from(_base_inputs(), forced_flags={"live_apply": True})
    for must_be_false in ("low_risk_autonomy_allowed_now", "policy_activation_allowed", "install_allowed_now", "can_install_timer_now", "live_apply"):
        if bad[must_be_false]:
            raise AssertionError(f"{must_be_false} must always be False in report")
    if bad["apply_status"] != APPLY_NOT_APPLIED:
        raise AssertionError("apply_status must always be not_applied in report")

    # Partial inputs (missing readiness gate), emergency stop cleared -> PARTIAL_INPUTS, no breach.
    no_estop = _no_estop_inputs()
    partial = build_report(
        None, "not_available",
        no_estop["manual_recheck_gate"], "ok",
        no_estop["timeline"], "ok",
        no_estop["observer"], "ok",
        no_estop["critical"], "ok",
        no_estop["final_owner"], "ok",
        no_estop["candidate"], "ok",
        no_estop["guard"], "ok",
        no_estop["scope"], "ok",
        no_estop["preflight"], "ok",
        no_estop["master"], "ok",
        {"emergency_stop": False}, "ok",
    )
    if partial["policy_status"] != STATUS_PARTIAL_INPUTS or partial["policy_breach"]:
        raise AssertionError("partial inputs failed")

    # Missing inputs must not crash.
    crashless = build_report(
        None, "not_available", None, "not_available", None, "not_available",
        None, "not_available", None, "not_available", None, "not_available",
        None, "not_available", None, "not_available", None, "not_available",
        None, "not_available", None, "not_available", None, "not_available",
    )
    if not crashless["read_only"]:
        raise AssertionError("crashless run lost read_only")

    # Detector sanity.
    if not FORBIDDEN_APPLY_COMMAND_RE.search("cloudflare api update"):
        raise AssertionError("forbidden command detector failed")
    if not detect_secret_like("token=abc12345"):
        raise AssertionError("secret detector failed")
    for forbidden in (
        PROJECT_DIR / "reports/latest/bad.sh",
        PROJECT_DIR / "drafts/owner/bad.service",
        PROJECT_DIR / "snapshots/bad.timer",
        PROJECT_DIR / "audit/bad.py",
    ):
        try:
            assert_allowed_write(forbidden)
        except ValueError:
            pass
        else:
            raise AssertionError(f"forbidden artifact was not rejected: {forbidden}")
    try:
        assert_allowed_write(PROJECT_DIR / "config/low-risk-policy-boundary-draft.json")
    except ValueError:
        pass
    else:
        raise AssertionError("forbidden write root was not rejected")

    md = render_markdown(rest)
    for needed in (CAT_DRAFT_ONLY, CAT_REVIEW_ONLY, CAT_POTENTIAL_FUTURE_APPLY, CAT_MEDIUM, CAT_HIGH, CAT_FORBIDDEN):
        if needed not in md:
            raise AssertionError(f"markdown missing category: {needed}")
    print("low-risk-policy-boundary-draft self-tests: OK")
    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build LOW-RISK Policy Boundary Draft; read-only, no apply.")
    parser.add_argument("--self-test", action="store_true", help="Run in-memory safety tests and exit.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()
    report = build_current_report()
    write_outputs(report)
    print(
        "LOW-RISK Policy Boundary Draft: "
        f"status={report.get('policy_status')}, "
        f"owner_review_required={report.get('owner_policy_review_required')}, "
        f"activation_allowed={report.get('policy_activation_allowed')}, "
        f"breach={report.get('policy_breach')}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
