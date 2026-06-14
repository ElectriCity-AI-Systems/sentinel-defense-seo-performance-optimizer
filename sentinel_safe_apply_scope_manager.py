#!/usr/bin/env python3
"""Sentinel Safe Apply Scope & Allowlist Manager (Phase 3.2).

Turns the Safe Apply Candidate Registry (Phase 3.0) and the Safe Apply Guard
Check (Phase 3.1) into a strict scope/allowlist configuration that defines
*which candidate types would ever be permitted* for future controlled
autonomy. This is not an apply mechanism.

Hard safety guarantees (enforced structurally):
- No live changes; no apply function exists in this module.
- Never edits WordPress files, .htaccess, Cloudflare rules, or Nginx config.
- No external writes, no network access, no WordPress login, no API calls.
- No secrets/cookies/auth values are stored or printed.
- All candidates stay apply_status=not_applied.
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
INPUT_REGISTRY_DRAFT = PROJECT_DIR / "drafts/apply/safe-apply-candidate-registry.json"
INPUT_REGISTRY_REPORT = PROJECT_DIR / "reports/latest/safe-apply-candidate-registry-report.json"
INPUT_GUARD_DRAFT = PROJECT_DIR / "drafts/apply/safe-apply-guard-check.json"
INPUT_GUARD_REPORT = PROJECT_DIR / "reports/latest/safe-apply-guard-check-report.json"
INPUT_AUTONOMY_POLICY = PROJECT_DIR / "reports/latest/autonomy-policy-report.json"
INPUT_MASTER = PROJECT_DIR / "reports/latest/sentinel-master-report.json"

SCOPE_JSON = PROJECT_DIR / "drafts/apply/safe-apply-scope-allowlist.json"
SCOPE_MD = PROJECT_DIR / "drafts/apply/safe-apply-scope-allowlist.md"
REPORT_JSON = PROJECT_DIR / "reports/latest/safe-apply-scope-allowlist-report.json"
REPORT_MD = PROJECT_DIR / "reports/latest/safe-apply-scope-allowlist-report.md"
AUDIT_JSONL = PROJECT_DIR / "audit/safe-apply-scope-allowlist.jsonl"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "drafts/apply",
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "audit",
)

SCHEMA_VERSION = "safe-apply-scope-allowlist-3.2"

APPLY_NOT_APPLIED = "not_applied"
RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"
RISK_REVIEW_ONLY = "REVIEW_ONLY"

REGISTERED_DRAFT_ONLY = "REGISTERED_DRAFT_ONLY"
REGISTERED_VALIDATION_ONLY = "REGISTERED_VALIDATION_ONLY"
MONITOR_ONLY = "MONITOR_ONLY"

GUARDS_READY_DRAFT_ONLY = "GUARDS_READY_DRAFT_ONLY"
GUARDS_READY_VALIDATION_ONLY = "GUARDS_READY_VALIDATION_ONLY"
GUARDS_MONITOR_ONLY = "GUARDS_MONITOR_ONLY"
GUARDS_UNKNOWN = "GUARDS_UNKNOWN"

# Scope status vocabulary (Phase 3.2).
SCOPE_ALLOWED_DRAFT_ONLY = "SCOPE_ALLOWED_DRAFT_ONLY"
SCOPE_ALLOWED_VALIDATION_ONLY = "SCOPE_ALLOWED_VALIDATION_ONLY"
SCOPE_NOT_ALLOWED_MISSING_GUARDS = "SCOPE_NOT_ALLOWED_MISSING_GUARDS"
SCOPE_BLOCKED_HIGH_RISK = "SCOPE_BLOCKED_HIGH_RISK"
SCOPE_MONITOR_ONLY = "SCOPE_MONITOR_ONLY"

ALLOWED_SCOPE_STATUSES = {SCOPE_ALLOWED_DRAFT_ONLY, SCOPE_ALLOWED_VALIDATION_ONLY}

REGISTERED_OK = {REGISTERED_DRAFT_ONLY, REGISTERED_VALIDATION_ONLY}
GUARDS_READY = {GUARDS_READY_DRAFT_ONLY, GUARDS_READY_VALIDATION_ONLY}

REQUIRED_GUARDS = [
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

# Scope types that may ever appear in allowed_scope (local-only, draft/report).
ALLOWED_SCOPE_TYPES = [
    "report_update_only",
    "draft_refresh_only",
    "owner_summary_only",
    "validation_only",
    "seo_meta_draft_prepare",
    "seo_social_draft_prepare",
    "image_status_check",
    "width_height_check",
    "internal_link_suggestion_prepare",
]
ALLOWED_SCOPE_TYPE_SET = set(ALLOWED_SCOPE_TYPES)

# Scope types that must never be allowed (live/production-affecting).
PROHIBITED_SCOPE_TYPES = [
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
]
PROHIBITED_SCOPE_TYPE_SET = set(PROHIBITED_SCOPE_TYPES)

# Validation-flavoured scope types use the validation-only allowance.
VALIDATION_SCOPE_TYPES = {"validation_only", "image_status_check", "width_height_check"}

# Default allowed output path prefixes (relative to project; local-only).
DEFAULT_ALLOWED_OUTPUT_PATHS = [
    "reports/latest",
    "drafts/seo",
    "drafts/performance",
    "drafts/owner",
    "drafts/apply",
    "drafts/validation",
    "audit",
]

# Paths that are always prohibited inside any allowed scope.
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

# Per scope-type maximum allowed scope description (documentation only).
MAX_SCOPE_BY_TYPE = {
    "report_update_only": "Refresh local Sentinel report drafts only; no production writes.",
    "draft_refresh_only": "Regenerate local draft artifacts only; no production writes.",
    "owner_summary_only": "Rebuild local owner-facing summary drafts only; no production writes.",
    "validation_only": "Run local read-only validation checks only; no production writes.",
    "seo_meta_draft_prepare": "Prepare local SEO meta draft suggestions only; never edit Yoast/WordPress.",
    "seo_social_draft_prepare": "Prepare local SEO social draft suggestions only; never edit Yoast/WordPress.",
    "image_status_check": "Read-only local image status check; never modify media or files.",
    "width_height_check": "Read-only local width/height attribute check; never modify markup.",
    "internal_link_suggestion_prepare": "Prepare local internal-link suggestion drafts only; never edit live pages.",
}

# Per scope-type allowed output categories (subset of DEFAULT_ALLOWED_OUTPUT_PATHS).
ALLOWED_OUTPUTS_BY_TYPE = {
    "report_update_only": ["reports/latest", "drafts/apply", "audit"],
    "draft_refresh_only": ["drafts/apply", "reports/latest", "audit"],
    "owner_summary_only": ["drafts/owner", "reports/latest", "audit"],
    "validation_only": ["drafts/validation", "reports/latest", "audit"],
    "seo_meta_draft_prepare": ["drafts/seo", "reports/latest", "audit"],
    "seo_social_draft_prepare": ["drafts/seo", "reports/latest", "audit"],
    "image_status_check": ["drafts/performance", "reports/latest", "audit"],
    "width_height_check": ["drafts/performance", "reports/latest", "audit"],
    "internal_link_suggestion_prepare": ["drafts/seo", "reports/latest", "audit"],
}
DEFAULT_OUTPUTS = ["reports/latest", "drafts/apply", "audit"]

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
        raise ValueError(f"Refusing to write outside allowed scope-manager roots: {path}")


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


def load_inputs() -> Tuple[Optional[Any], Optional[Any], Dict[str, str]]:
    registry, registry_status = read_json_status(INPUT_REGISTRY_DRAFT)
    if registry_status != "ok":
        registry, registry_status = read_json_status(INPUT_REGISTRY_REPORT)
    guard, guard_status = read_json_status(INPUT_GUARD_DRAFT)
    if guard_status != "ok":
        guard, guard_status = read_json_status(INPUT_GUARD_REPORT)
    statuses = {
        "safe_apply_candidate_registry": registry_status,
        "safe_apply_guard_check": guard_status,
        "autonomy_policy": read_json_status(INPUT_AUTONOMY_POLICY)[1],
        "sentinel_master": read_json_status(INPUT_MASTER)[1],
    }
    return registry, guard, statuses


def candidates_from(registry: Optional[Any]) -> List[Dict[str, Any]]:
    if not isinstance(registry, dict) or not isinstance(registry.get("candidates"), list):
        return []
    return [item for item in registry["candidates"] if isinstance(item, dict)]


def guard_status_map_from(guard: Optional[Any]) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    if not isinstance(guard, dict) or not isinstance(guard.get("guard_checks"), list):
        return mapping
    for check in guard["guard_checks"]:
        if not isinstance(check, dict):
            continue
        candidate_id = str(check.get("candidate_id") or "")
        status = str(check.get("guard_readiness_status") or "")
        if candidate_id and status:
            mapping[candidate_id] = status
    return mapping


def normalize_required_guards(values: Any) -> List[str]:
    if isinstance(values, list):
        guards = [str(value) for value in values if str(value) in REQUIRED_GUARDS]
        if guards:
            return guards
    return list(REQUIRED_GUARDS)


def determine_scope_status(
    risk: str,
    candidate_type: str,
    registry_status: str,
    source_apply_status: str,
    guard_status: str,
) -> Tuple[str, str]:
    """Return (scope_status, reason) for one candidate.

    Only LOW / not_applied / draft-or-validation-only candidates whose registry
    and guard status both report ready may ever reach an allowed scope status.
    """
    if source_apply_status != APPLY_NOT_APPLIED:
        return (
            SCOPE_NOT_ALLOWED_MISSING_GUARDS,
            "apply_status is not not_applied; scope refuses to allow and flags review.",
        )
    if risk == RISK_HIGH or candidate_type in PROHIBITED_SCOPE_TYPE_SET:
        return (
            SCOPE_BLOCKED_HIGH_RISK,
            "HIGH risk or prohibited candidate_type is permanently blocked from scope.",
        )
    if guard_status == GUARDS_MONITOR_ONLY or registry_status == MONITOR_ONLY:
        return (
            SCOPE_MONITOR_ONLY,
            "Candidate is monitor-only; no future autonomous scope is allowed.",
        )
    if (
        risk == RISK_LOW
        and candidate_type in ALLOWED_SCOPE_TYPE_SET
        and registry_status in REGISTERED_OK
        and guard_status in GUARDS_READY
    ):
        validation = (
            guard_status == GUARDS_READY_VALIDATION_ONLY
            or registry_status == REGISTERED_VALIDATION_ONLY
            or candidate_type in VALIDATION_SCOPE_TYPES
        )
        if validation:
            return (
                SCOPE_ALLOWED_VALIDATION_ONLY,
                "LOW validation-only candidate with ready guards is allowed for local validation scope only.",
            )
        return (
            SCOPE_ALLOWED_DRAFT_ONLY,
            "LOW local-only draft candidate with ready guards is allowed for local draft scope only.",
        )
    return (
        SCOPE_NOT_ALLOWED_MISSING_GUARDS,
        "Candidate is not allowed; risk/registry/guard requirements for scope are not all met.",
    )


def build_scope_item(candidate: Dict[str, Any], guard_status_map: Dict[str, str], index: int) -> Dict[str, Any]:
    candidate_id = redact_text(candidate.get("candidate_id"), max_len=160)
    candidate_type = str(candidate.get("candidate_type") or "")
    risk = normalize_risk(candidate.get("risk_classification"))
    registry_status = str(candidate.get("registry_status") or "")
    raw_apply = candidate.get("apply_status")
    source_apply_status = raw_apply if raw_apply == APPLY_NOT_APPLIED else str(raw_apply or "")
    guard_status = guard_status_map.get(candidate_id, GUARDS_UNKNOWN)

    scope_status, reason = determine_scope_status(
        risk, candidate_type, registry_status, source_apply_status, guard_status
    )
    allowed = scope_status in ALLOWED_SCOPE_STATUSES

    if allowed and candidate_type in ALLOWED_SCOPE_TYPE_SET:
        allowed_scope_type = candidate_type
        max_scope = MAX_SCOPE_BY_TYPE.get(candidate_type, "Local draft/report scope only.")
        allowed_paths = list(DEFAULT_ALLOWED_OUTPUT_PATHS)
        allowed_outputs = ALLOWED_OUTPUTS_BY_TYPE.get(candidate_type, list(DEFAULT_OUTPUTS))
    else:
        allowed_scope_type = "none"
        max_scope = "none"
        allowed_paths = []
        allowed_outputs = []

    return {
        "scope_id": f"safe_apply_scope:{index:03d}",
        "candidate_id": candidate_id,
        "candidate_type": redact_text(candidate_type, max_len=120) if candidate_type else "-",
        "title": redact_text(candidate.get("title"), max_len=320),
        "risk_classification": risk,
        "registry_status": redact_text(registry_status, max_len=120) if registry_status else "-",
        "allowed_scope_type": allowed_scope_type,
        "max_scope": max_scope,
        "allowed_paths": allowed_paths,
        "prohibited_paths": list(ALWAYS_PROHIBITED_PATHS),
        "allowed_outputs": allowed_outputs,
        "required_guards": normalize_required_guards(candidate.get("required_guards")),
        "current_guard_status": guard_status,
        "scope_status": scope_status,
        # The manager never applies: it records the candidate's apply_status,
        # which must stay not_applied. Any other value is a breach.
        "apply_status": APPLY_NOT_APPLIED if source_apply_status == APPLY_NOT_APPLIED else redact_text(source_apply_status, max_len=80),
        "reason": reason,
    }


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


def scope_breach(items: List[Dict[str, Any]]) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    for item in items:
        scope_id = item.get("scope_id")
        allowed = item.get("scope_status") in ALLOWED_SCOPE_STATUSES
        if item.get("apply_status") != APPLY_NOT_APPLIED:
            reasons.append(f"{scope_id}: apply_status != not_applied")
        if allowed and item.get("risk_classification") == RISK_HIGH:
            reasons.append(f"{scope_id}: HIGH risk in allowed scope")
        if allowed and item.get("risk_classification") in {RISK_MEDIUM, RISK_REVIEW_ONLY}:
            reasons.append(f"{scope_id}: MEDIUM/REVIEW_ONLY risk in allowed scope")
        if allowed and str(item.get("candidate_type")) in PROHIBITED_SCOPE_TYPE_SET:
            reasons.append(f"{scope_id}: prohibited candidate_type in allowed scope")
        if path_contains_prohibited(item.get("allowed_paths")):
            reasons.append(f"{scope_id}: prohibited path in allowed_paths")
    return bool(reasons), reasons


def summarize_items(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    counts = {
        SCOPE_ALLOWED_DRAFT_ONLY: 0,
        SCOPE_ALLOWED_VALIDATION_ONLY: 0,
        SCOPE_NOT_ALLOWED_MISSING_GUARDS: 0,
        SCOPE_BLOCKED_HIGH_RISK: 0,
        SCOPE_MONITOR_ONLY: 0,
    }
    for item in items:
        status = item.get("scope_status")
        if status in counts:
            counts[status] += 1
    breach, breach_reasons = scope_breach(items)
    return {
        "candidate_count": len(items),
        "scope_allowed_draft_only_count": counts[SCOPE_ALLOWED_DRAFT_ONLY],
        "scope_allowed_validation_only_count": counts[SCOPE_ALLOWED_VALIDATION_ONLY],
        "scope_not_allowed_missing_guards_count": counts[SCOPE_NOT_ALLOWED_MISSING_GUARDS],
        "scope_blocked_high_risk_count": counts[SCOPE_BLOCKED_HIGH_RISK],
        "scope_monitor_only_count": counts[SCOPE_MONITOR_ONLY],
        "scope_breach": breach,
        "scope_breach_reasons": breach_reasons,
    }


def build_scope_report(
    registry: Optional[Any],
    guard: Optional[Any],
    input_statuses: Dict[str, str],
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    generated = generated_at or utc_now()
    candidates = candidates_from(registry)
    guard_status_map = guard_status_map_from(guard)
    items = [build_scope_item(candidate, guard_status_map, index + 1) for index, candidate in enumerate(candidates)]
    summary = summarize_items(items)
    allowed_scope = [item for item in items if item.get("scope_status") in ALLOWED_SCOPE_STATUSES]
    status = (
        "SCOPE_WARNING"
        if summary["scope_breach"]
        else ("NO_REGISTRY_AVAILABLE" if not candidates else "READY_FOR_REVIEW")
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
        "allowed_write_roots": [str(path) for path in ALLOWED_WRITE_ROOTS],
        "input_statuses": input_statuses,
        "allowed_scope_types": list(ALLOWED_SCOPE_TYPES),
        "prohibited_scope_types": list(PROHIBITED_SCOPE_TYPES),
        "default_allowed_output_paths": list(DEFAULT_ALLOWED_OUTPUT_PATHS),
        "always_prohibited_paths": list(ALWAYS_PROHIBITED_PATHS),
        "required_guards": list(REQUIRED_GUARDS),
        "summary": summary,
        "scope_items": items,
        "allowed_scope": allowed_scope,
        "outputs": {
            "scope_json": str(SCOPE_JSON),
            "scope_md": str(SCOPE_MD),
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
        f"- Scope allowed draft-only: `{summary.get('scope_allowed_draft_only_count')}`",
        f"- Scope allowed validation-only: `{summary.get('scope_allowed_validation_only_count')}`",
        f"- Scope not allowed (missing guards): `{summary.get('scope_not_allowed_missing_guards_count')}`",
        f"- Scope blocked (high risk): `{summary.get('scope_blocked_high_risk_count')}`",
        f"- Scope monitor-only: `{summary.get('scope_monitor_only_count')}`",
        f"- Scope breach: `{summary.get('scope_breach')}`",
        "",
        "## Scope Items",
        "",
        "| Scope ID | Status | Allowed Scope Type | Max Scope | Risk | Guard | Title |",
        "|---|---|---|---|---|---|---|",
    ]
    for item in report.get("scope_items", []):
        if not isinstance(item, dict):
            continue
        lines.append(
            "| "
            f"`{redact_text(item.get('scope_id'), max_len=80)}` | "
            f"`{redact_text(item.get('scope_status'), max_len=80)}` | "
            f"`{redact_text(item.get('allowed_scope_type'), max_len=80)}` | "
            f"{redact_text(item.get('max_scope'), max_len=120)} | "
            f"`{redact_text(item.get('risk_classification'), max_len=60)}` | "
            f"`{redact_text(item.get('current_guard_status'), max_len=80)}` | "
            f"{redact_text(item.get('title'), max_len=160)} |"
        )
    lines.extend(["", "## Allowed Scope Types", ""])
    for scope_type in report.get("allowed_scope_types", []):
        lines.append(f"- `{redact_text(scope_type, max_len=80)}`")
    lines.extend(["", "## Prohibited Scope Types", ""])
    for scope_type in report.get("prohibited_scope_types", []):
        lines.append(f"- `{redact_text(scope_type, max_len=80)}`")
    lines.extend(["", "## Always Prohibited Paths", ""])
    for path in report.get("always_prohibited_paths", []):
        lines.append(f"- `{redact_text(path, max_len=120)}`")
    lines.extend(
        [
            "",
            "## Sicherheitsgrenzen",
            "",
            "- Keine Live-Aenderungen, keine Apply-Funktion.",
            "- Keine WordPress-, .htaccess-, Cloudflare-, Nginx- oder DNS-Aenderung.",
            "- Kein WordPress-Login, keine API, kein Netzwerkzugriff, keine externen Schreibzugriffe.",
            "- Keine Secrets/Cookies/Auth speichern oder ausgeben.",
            "- Alle Kandidaten bleiben `apply_status=not_applied`.",
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
        "scope_allowed_draft_only_count": summary.get("scope_allowed_draft_only_count"),
        "scope_allowed_validation_only_count": summary.get("scope_allowed_validation_only_count"),
        "scope_not_allowed_missing_guards_count": summary.get("scope_not_allowed_missing_guards_count"),
        "scope_blocked_high_risk_count": summary.get("scope_blocked_high_risk_count"),
        "scope_monitor_only_count": summary.get("scope_monitor_only_count"),
        "scope_breach": summary.get("scope_breach"),
        "productive_change": False,
        "network_access": False,
        "apply_function": False,
    }


def write_outputs(report: Dict[str, Any]) -> None:
    write_json_atomic(SCOPE_JSON, report)
    write_text_atomic(SCOPE_MD, render_markdown(report, title="Safe Apply Scope Allowlist"))
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, render_markdown(report, title="Safe Apply Scope Allowlist Report"))
    append_jsonl(AUDIT_JSONL, [audit_record(report)])


def run_self_test() -> int:
    # 1. Missing registry/guard never crashes and reports NO_REGISTRY_AVAILABLE.
    empty = build_scope_report(
        None, None, {"safe_apply_candidate_registry": "not_available"}, "2026-06-10T00:00:00Z"
    )
    if empty["status"] != "NO_REGISTRY_AVAILABLE":
        raise AssertionError("missing registry did not produce NO_REGISTRY_AVAILABLE")
    if empty["summary"]["scope_breach"]:
        raise AssertionError("empty input must not report a breach")

    registry = {
        "candidates": [
            {  # happy path: LOW draft-only with ready guards -> allowed draft-only
                "candidate_id": "safe_apply_candidate:001",
                "candidate_type": "report_update_only",
                "title": "Report draft",
                "risk_classification": "LOW",
                "registry_status": REGISTERED_DRAFT_ONLY,
                "apply_status": "not_applied",
                "required_guards": list(REQUIRED_GUARDS),
            },
            {  # LOW validation-only with ready guards -> allowed validation-only
                "candidate_id": "safe_apply_candidate:002",
                "candidate_type": "validation_only",
                "title": "Validation check",
                "risk_classification": "LOW",
                "registry_status": REGISTERED_VALIDATION_ONLY,
                "apply_status": "not_applied",
            },
            {  # prohibited candidate_type -> blocked, never allowed
                "candidate_id": "safe_apply_candidate:003",
                "candidate_type": "cloudflare_change",
                "title": "Cloudflare change",
                "risk_classification": "LOW",
                "registry_status": REGISTERED_DRAFT_ONLY,
                "apply_status": "not_applied",
            },
            {  # MEDIUM -> not allowed (missing guards bucket)
                "candidate_id": "safe_apply_candidate:004",
                "candidate_type": "report_update_only",
                "title": "Medium risk draft",
                "risk_classification": "MEDIUM",
                "registry_status": REGISTERED_DRAFT_ONLY,
                "apply_status": "not_applied",
            },
            {  # monitor-only (non-HIGH) -> monitor scope, never allowed
                "candidate_id": "safe_apply_candidate:005",
                "candidate_type": "report_update_only",
                "title": "Monitor candidate",
                "risk_classification": "LOW",
                "registry_status": MONITOR_ONLY,
                "apply_status": "not_applied",
            },
            {  # apply_status != not_applied -> not allowed AND breach
                "candidate_id": "safe_apply_candidate:006",
                "candidate_type": "report_update_only",
                "title": "Already applied",
                "risk_classification": "LOW",
                "registry_status": REGISTERED_DRAFT_ONLY,
                "apply_status": "applied",
            },
        ]
    }
    guard = {
        "guard_checks": [
            {"candidate_id": "safe_apply_candidate:001", "guard_readiness_status": GUARDS_READY_DRAFT_ONLY},
            {"candidate_id": "safe_apply_candidate:002", "guard_readiness_status": GUARDS_READY_VALIDATION_ONLY},
            {"candidate_id": "safe_apply_candidate:003", "guard_readiness_status": "GUARDS_BLOCKED_NOT_ALLOWED"},
            {"candidate_id": "safe_apply_candidate:004", "guard_readiness_status": "GUARDS_MISSING_FOR_AUTONOMY"},
            {"candidate_id": "safe_apply_candidate:005", "guard_readiness_status": GUARDS_MONITOR_ONLY},
            {"candidate_id": "safe_apply_candidate:006", "guard_readiness_status": GUARDS_READY_DRAFT_ONLY},
        ]
    }
    report = build_scope_report(registry, guard, {"safe_apply_candidate_registry": "ok"}, "2026-06-10T00:01:00Z")
    by_id = {item["candidate_id"]: item for item in report["scope_items"]}

    if by_id["safe_apply_candidate:001"]["scope_status"] != SCOPE_ALLOWED_DRAFT_ONLY:
        raise AssertionError("LOW draft-only ready candidate was not allowed draft-only")
    if by_id["safe_apply_candidate:002"]["scope_status"] != SCOPE_ALLOWED_VALIDATION_ONLY:
        raise AssertionError("LOW validation-only ready candidate was not allowed validation-only")
    if by_id["safe_apply_candidate:003"]["scope_status"] != SCOPE_BLOCKED_HIGH_RISK:
        raise AssertionError("prohibited candidate_type was not blocked")
    if by_id["safe_apply_candidate:003"]["allowed_scope_type"] != "none":
        raise AssertionError("prohibited candidate_type leaked an allowed_scope_type")
    if by_id["safe_apply_candidate:004"]["scope_status"] != SCOPE_NOT_ALLOWED_MISSING_GUARDS:
        raise AssertionError("MEDIUM candidate was not kept out of allowed scope")
    if by_id["safe_apply_candidate:005"]["scope_status"] != SCOPE_MONITOR_ONLY:
        raise AssertionError("monitor-only candidate did not stay monitor-only")
    if by_id["safe_apply_candidate:006"]["scope_status"] in ALLOWED_SCOPE_STATUSES:
        raise AssertionError("applied candidate was allowed into scope")
    if not report["summary"]["scope_breach"]:
        raise AssertionError("apply_status != not_applied did not raise scope_breach")
    # The two allowed items only.
    if len(report["allowed_scope"]) != 2:
        raise AssertionError("allowed_scope did not contain exactly the two ready LOW candidates")
    # No allowed item may carry a prohibited output path.
    for item in report["allowed_scope"]:
        if path_contains_prohibited(item["allowed_paths"]):
            raise AssertionError("allowed item contains a prohibited path")

    # 2. HIGH risk in allowed scope -> breach.
    high_breach, _ = scope_breach(
        [{"scope_id": "x", "scope_status": SCOPE_ALLOWED_DRAFT_ONLY, "risk_classification": RISK_HIGH,
          "candidate_type": "report_update_only", "apply_status": APPLY_NOT_APPLIED, "allowed_paths": []}]
    )
    if not high_breach:
        raise AssertionError("HIGH in allowed scope did not raise scope_breach")

    # 3. MEDIUM/REVIEW_ONLY in allowed scope -> breach.
    medium_breach, _ = scope_breach(
        [{"scope_id": "x", "scope_status": SCOPE_ALLOWED_VALIDATION_ONLY, "risk_classification": RISK_REVIEW_ONLY,
          "candidate_type": "validation_only", "apply_status": APPLY_NOT_APPLIED, "allowed_paths": []}]
    )
    if not medium_breach:
        raise AssertionError("MEDIUM/REVIEW_ONLY in allowed scope did not raise scope_breach")

    # 4. Prohibited candidate_type in allowed scope -> breach.
    proh_type_breach, _ = scope_breach(
        [{"scope_id": "x", "scope_status": SCOPE_ALLOWED_DRAFT_ONLY, "risk_classification": RISK_LOW,
          "candidate_type": "cloudflare_change", "apply_status": APPLY_NOT_APPLIED, "allowed_paths": []}]
    )
    if not proh_type_breach:
        raise AssertionError("prohibited candidate_type in allowed scope did not raise scope_breach")

    # 5. Prohibited path in allowed_paths -> breach.
    proh_path_breach, _ = scope_breach(
        [{"scope_id": "x", "scope_status": SCOPE_ALLOWED_DRAFT_ONLY, "risk_classification": RISK_LOW,
          "candidate_type": "report_update_only", "apply_status": APPLY_NOT_APPLIED,
          "allowed_paths": ["reports/latest", "wp-content/plugins/evil"]}]
    )
    if not proh_path_breach:
        raise AssertionError("prohibited path in allowed_paths did not raise scope_breach")

    # 6. Forbidden write path is rejected.
    try:
        assert_allowed_write(PROJECT_DIR / "forbidden/safe-apply-scope.json")
    except ValueError:
        pass
    else:
        raise AssertionError("forbidden write path was not rejected")

    print("safe-apply-scope-manager self-tests: OK")
    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build the Safe Apply scope/allowlist configuration (read-only).")
    parser.add_argument("--self-test", action="store_true", help="Run in-memory scope safety tests and exit.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()
    registry, guard, statuses = load_inputs()
    report = build_scope_report(registry, guard, statuses)
    write_outputs(report)
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    print(
        "Safe Apply Scope Allowlist written: "
        f"{SCOPE_MD} "
        f"(draft_only={summary.get('scope_allowed_draft_only_count')}, "
        f"validation_only={summary.get('scope_allowed_validation_only_count')}, "
        f"blocked={summary.get('scope_blocked_high_risk_count')}, "
        f"breach={summary.get('scope_breach')})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
