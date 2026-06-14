#!/usr/bin/env python3
"""Sentinel Safe Apply Guard Requirements Checker (Phase 3.1).

Checks the Safe Apply Candidate Registry for guard readiness. This is not an
apply mechanism: it performs no network access, no WordPress login, no APIs,
and no production writes.
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

INPUT_REGISTRY_DRAFT = PROJECT_DIR / "drafts/apply/safe-apply-candidate-registry.json"
INPUT_REGISTRY_REPORT = PROJECT_DIR / "reports/latest/safe-apply-candidate-registry-report.json"
INPUT_AUTONOMY_POLICY = PROJECT_DIR / "reports/latest/autonomy-policy-report.json"
INPUT_POST_VALIDATION = PROJECT_DIR / "reports/latest/post-manual-validation-report.json"
INPUT_MASTER = PROJECT_DIR / "reports/latest/sentinel-master-report.json"

GUARD_JSON = PROJECT_DIR / "drafts/apply/safe-apply-guard-check.json"
GUARD_MD = PROJECT_DIR / "drafts/apply/safe-apply-guard-check.md"
REPORT_JSON = PROJECT_DIR / "reports/latest/safe-apply-guard-check-report.json"
REPORT_MD = PROJECT_DIR / "reports/latest/safe-apply-guard-check-report.md"
AUDIT_JSONL = PROJECT_DIR / "audit/safe-apply-guard-check.jsonl"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "drafts/apply",
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "audit",
)

SCHEMA_VERSION = "safe-apply-guard-check-3.1"

APPLY_NOT_APPLIED = "not_applied"
RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"
RISK_REVIEW_ONLY = "REVIEW_ONLY"

REGISTERED_DRAFT_ONLY = "REGISTERED_DRAFT_ONLY"
REGISTERED_VALIDATION_ONLY = "REGISTERED_VALIDATION_ONLY"
NOT_REGISTERED_MISSING_GUARDS = "NOT_REGISTERED_MISSING_GUARDS"
BLOCKED_NOT_ALLOWED = "BLOCKED_NOT_ALLOWED"
MONITOR_ONLY = "MONITOR_ONLY"

GUARDS_READY_DRAFT_ONLY = "GUARDS_READY_DRAFT_ONLY"
GUARDS_READY_VALIDATION_ONLY = "GUARDS_READY_VALIDATION_ONLY"
GUARDS_MISSING_FOR_AUTONOMY = "GUARDS_MISSING_FOR_AUTONOMY"
GUARDS_BLOCKED_NOT_ALLOWED = "GUARDS_BLOCKED_NOT_ALLOWED"
GUARDS_MONITOR_ONLY = "GUARDS_MONITOR_ONLY"

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

LOCAL_ONLY_TYPES = {
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

PROHIBITED_TYPES = {
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
}

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
        raise ValueError(f"Refusing to write outside allowed guard-check roots: {path}")


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
    if path.suffix.lower() != ".json":
        return None, "unsupported_suffix"
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


def read_json_status(path: Path) -> Tuple[Optional[Any], str]:
    try:
        if ".env" in str(path).lower() or SECRETISH_RE.search(path.name):
            return None, "refused_secret_like_path"
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


def normalize_guard_name(value: Any) -> str:
    name = str(value or "").strip()
    mapping = {
        "owner_disable_switch_required": "owner_disable_switch",
        "audit_log_required": "audit_log",
        "pre_healthcheck_required": "pre_healthcheck",
        "post_healthcheck_required": "post_healthcheck",
        "rollback_plan_required": "rollback_plan",
        "post_manual_validation_required": "post_validation",
        "post_validation_required": "post_validation",
        "explicit_allowlist_required": "explicit_allowlist",
        "max_scope_defined_required": "max_scope_defined",
        "backup_required": "backup_available",
        "backup_available_required": "backup_available",
    }
    return mapping.get(name, name)


def normalize_missing_guards(values: Any) -> List[str]:
    if not isinstance(values, list):
        return []
    normalized: List[str] = []
    for value in values:
        guard = normalize_guard_name(value)
        if guard in REQUIRED_GUARDS and guard not in normalized:
            normalized.append(guard)
    return normalized


def load_inputs() -> Tuple[Dict[str, Optional[Any]], Dict[str, str]]:
    registry, registry_status = read_json_status(INPUT_REGISTRY_DRAFT)
    if registry_status != "ok":
        registry, registry_status = read_json_status(INPUT_REGISTRY_REPORT)
    inputs = {
        "safe_apply_candidate_registry": registry,
        "autonomy_policy": read_json_status(INPUT_AUTONOMY_POLICY)[0],
        "post_manual_validation": read_json_status(INPUT_POST_VALIDATION)[0],
        "sentinel_master": read_json_status(INPUT_MASTER)[0],
    }
    statuses = {
        "safe_apply_candidate_registry": registry_status,
        "autonomy_policy": read_json_status(INPUT_AUTONOMY_POLICY)[1],
        "post_manual_validation": read_json_status(INPUT_POST_VALIDATION)[1],
        "sentinel_master": read_json_status(INPUT_MASTER)[1],
    }
    return inputs, statuses


def candidates_from(registry: Optional[Any]) -> List[Dict[str, Any]]:
    if not isinstance(registry, dict) or not isinstance(registry.get("candidates"), list):
        return []
    return [item for item in registry["candidates"] if isinstance(item, dict)]


def guard_status_for(candidate: Dict[str, Any], guards_missing: List[str]) -> Tuple[str, bool, str]:
    registry_status = str(candidate.get("registry_status") or "")
    risk = normalize_risk(candidate.get("risk_classification"))
    candidate_type = str(candidate.get("candidate_type") or "")
    apply_status = str(candidate.get("apply_status") or "")
    local_only = candidate_type in LOCAL_ONLY_TYPES
    if apply_status != APPLY_NOT_APPLIED:
        return GUARDS_MISSING_FOR_AUTONOMY, False, "apply_status is not not_applied; guard breach requires review."
    if registry_status == MONITOR_ONLY:
        return GUARDS_MONITOR_ONLY, False, "Candidate is monitor-only; no future autonomous apply is allowed."
    if registry_status == BLOCKED_NOT_ALLOWED or risk == RISK_HIGH or candidate_type in PROHIBITED_TYPES:
        return GUARDS_BLOCKED_NOT_ALLOWED, False, "Candidate is blocked or high-risk/prohibited."
    if registry_status == REGISTERED_DRAFT_ONLY and risk == RISK_LOW and local_only and not guards_missing:
        return GUARDS_READY_DRAFT_ONLY, True, "LOW local-only draft/report candidate has required local-only guards present."
    if registry_status == REGISTERED_VALIDATION_ONLY and risk == RISK_LOW and candidate_type == "validation_only" and not guards_missing:
        return GUARDS_READY_VALIDATION_ONLY, True, "LOW validation-only candidate has required local-only guards present."
    return GUARDS_MISSING_FOR_AUTONOMY, False, "Candidate is not ready for future autonomy; required guards or registry status are missing."


def check_candidate(candidate: Dict[str, Any], index: int) -> Dict[str, Any]:
    raw_missing = normalize_missing_guards(candidate.get("missing_guards"))
    guards_missing = [guard for guard in REQUIRED_GUARDS if guard in raw_missing]
    guards_present = {guard: guard not in guards_missing for guard in REQUIRED_GUARDS}
    guard_status, can_future, reason = guard_status_for(candidate, guards_missing)
    return {
        "guard_id": f"safe_apply_guard:{index:03d}",
        "candidate_id": redact_text(candidate.get("candidate_id"), max_len=160),
        "candidate_type": redact_text(candidate.get("candidate_type"), max_len=120),
        "title": redact_text(candidate.get("title"), max_len=320),
        "risk_classification": normalize_risk(candidate.get("risk_classification")),
        "registry_status": redact_text(candidate.get("registry_status"), max_len=120),
        "apply_status": redact_text(candidate.get("apply_status"), max_len=80),
        "guards_present": guards_present,
        "guards_missing": guards_missing,
        "guard_readiness_status": guard_status,
        "can_be_future_autonomous": can_future,
        "reason": reason,
    }


def guard_breach(checks: List[Dict[str, Any]]) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    for check in checks:
        if check.get("apply_status") != APPLY_NOT_APPLIED:
            reasons.append(f"{check.get('guard_id')}: apply_status != not_applied")
        if check.get("risk_classification") == RISK_HIGH and check.get("can_be_future_autonomous"):
            reasons.append(f"{check.get('guard_id')}: HIGH can_be_future_autonomous=true")
        if check.get("candidate_type") in PROHIBITED_TYPES and check.get("can_be_future_autonomous"):
            reasons.append(f"{check.get('guard_id')}: prohibited live-write candidate ready")
        if check.get("guard_readiness_status") in {GUARDS_READY_DRAFT_ONLY, GUARDS_READY_VALIDATION_ONLY}:
            if check.get("risk_classification") in {RISK_MEDIUM, RISK_REVIEW_ONLY, RISK_HIGH}:
                reasons.append(f"{check.get('guard_id')}: non-LOW candidate marked ready")
    return bool(reasons), reasons


def summarize_checks(checks: List[Dict[str, Any]]) -> Dict[str, Any]:
    counts = {
        GUARDS_READY_DRAFT_ONLY: 0,
        GUARDS_READY_VALIDATION_ONLY: 0,
        GUARDS_MISSING_FOR_AUTONOMY: 0,
        GUARDS_BLOCKED_NOT_ALLOWED: 0,
        GUARDS_MONITOR_ONLY: 0,
    }
    for check in checks:
        status = check.get("guard_readiness_status")
        if status in counts:
            counts[status] += 1
    breach, breach_reasons = guard_breach(checks)
    return {
        "candidate_count": len(checks),
        "guards_ready_draft_only_count": counts[GUARDS_READY_DRAFT_ONLY],
        "guards_ready_validation_only_count": counts[GUARDS_READY_VALIDATION_ONLY],
        "guards_missing_for_autonomy_count": counts[GUARDS_MISSING_FOR_AUTONOMY],
        "guards_blocked_not_allowed_count": counts[GUARDS_BLOCKED_NOT_ALLOWED],
        "guards_monitor_only_count": counts[GUARDS_MONITOR_ONLY],
        "guard_breach": breach,
        "guard_breach_reasons": breach_reasons,
    }


def build_guard_report(registry: Optional[Any], input_statuses: Dict[str, str], generated_at: Optional[str] = None) -> Dict[str, Any]:
    generated = generated_at or utc_now()
    candidates = candidates_from(registry)
    checks = [check_candidate(candidate, index + 1) for index, candidate in enumerate(candidates)]
    summary = summarize_checks(checks)
    status = "GUARD_WARNING" if summary["guard_breach"] else ("NO_REGISTRY_AVAILABLE" if not candidates else "READY_FOR_REVIEW")
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
        "allowed_write_roots": [str(path) for path in ALLOWED_WRITE_ROOTS],
        "input_statuses": input_statuses,
        "required_guards": list(REQUIRED_GUARDS),
        "summary": summary,
        "guard_checks": checks,
        "outputs": {
            "guard_json": str(GUARD_JSON),
            "guard_md": str(GUARD_MD),
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
        f"- Guards ready draft-only: `{summary.get('guards_ready_draft_only_count')}`",
        f"- Guards ready validation-only: `{summary.get('guards_ready_validation_only_count')}`",
        f"- Guards missing for autonomy: `{summary.get('guards_missing_for_autonomy_count')}`",
        f"- Guards blocked not allowed: `{summary.get('guards_blocked_not_allowed_count')}`",
        f"- Guards monitor-only: `{summary.get('guards_monitor_only_count')}`",
        f"- Guard breach: `{summary.get('guard_breach')}`",
        "",
        "## Guard Checks",
        "",
        "| Guard ID | Status | Future Auto | Type | Risk | Registry | Title |",
        "|---|---|---|---|---|---|---|",
    ]
    for check in report.get("guard_checks", []):
        if not isinstance(check, dict):
            continue
        lines.append(
            "| "
            f"`{redact_text(check.get('guard_id'), max_len=80)}` | "
            f"`{redact_text(check.get('guard_readiness_status'), max_len=80)}` | "
            f"`{redact_text(check.get('can_be_future_autonomous'), max_len=30)}` | "
            f"`{redact_text(check.get('candidate_type'), max_len=80)}` | "
            f"`{redact_text(check.get('risk_classification'), max_len=60)}` | "
            f"`{redact_text(check.get('registry_status'), max_len=80)}` | "
            f"{redact_text(check.get('title'), max_len=160)} |"
        )
    lines.extend(
        [
            "",
            "## Required Guards",
            "",
        ]
    )
    for guard in report.get("required_guards", []):
        lines.append(f"- `{redact_text(guard, max_len=120)}`")
    lines.extend(
        [
            "",
            "## Safety Boundaries",
            "",
            "- Keine Live-Aenderungen.",
            "- Kein WordPress-Login, keine API, kein Netzwerkzugriff.",
            "- Keine WordPress-, .htaccess-, Cloudflare-, Nginx- oder DNS-Aenderung.",
            "- Alle Kandidaten bleiben `apply_status=not_applied`.",
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
        "guards_ready_draft_only_count": summary.get("guards_ready_draft_only_count"),
        "guards_ready_validation_only_count": summary.get("guards_ready_validation_only_count"),
        "guards_missing_for_autonomy_count": summary.get("guards_missing_for_autonomy_count"),
        "guards_blocked_not_allowed_count": summary.get("guards_blocked_not_allowed_count"),
        "guards_monitor_only_count": summary.get("guards_monitor_only_count"),
        "guard_breach": summary.get("guard_breach"),
        "productive_change": False,
        "network_access": False,
        "apply_function": False,
    }


def write_outputs(report: Dict[str, Any]) -> None:
    write_json_atomic(GUARD_JSON, report)
    write_text_atomic(GUARD_MD, render_markdown(report, title="Safe Apply Guard Check"))
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, render_markdown(report, title="Safe Apply Guard Check Report"))
    append_jsonl(AUDIT_JSONL, [audit_record(report)])


def run_self_test() -> int:
    empty = build_guard_report(None, {"safe_apply_candidate_registry": "not_available"}, "2026-06-10T00:00:00Z")
    if empty["status"] != "NO_REGISTRY_AVAILABLE":
        raise AssertionError("missing registry did not produce NO_REGISTRY_AVAILABLE")
    sample = {
        "candidates": [
            {
                "candidate_id": "c1",
                "candidate_type": "report_update_only",
                "title": "Report draft",
                "risk_classification": "LOW",
                "registry_status": "REGISTERED_DRAFT_ONLY",
                "apply_status": "not_applied",
                "missing_guards": [],
            },
            {
                "candidate_id": "c2",
                "candidate_type": "wordpress_live_write",
                "title": "Live write",
                "risk_classification": "LOW",
                "registry_status": "NOT_REGISTERED_MISSING_GUARDS",
                "apply_status": "not_applied",
                "missing_guards": ["backup_available", "rollback_plan_required"],
            },
            {
                "candidate_id": "c3",
                "candidate_type": "report_update_only",
                "title": "Blocked high",
                "risk_classification": "HIGH",
                "registry_status": "BLOCKED_NOT_ALLOWED",
                "apply_status": "not_applied",
                "missing_guards": [],
            },
            {
                "candidate_id": "c4",
                "candidate_type": "report_update_only",
                "title": "Monitor",
                "risk_classification": "HIGH",
                "registry_status": "MONITOR_ONLY",
                "apply_status": "not_applied",
                "missing_guards": [],
            },
            {
                "candidate_id": "c5",
                "candidate_type": "report_update_only",
                "title": "Bad apply",
                "risk_classification": "LOW",
                "registry_status": "REGISTERED_DRAFT_ONLY",
                "apply_status": "applied",
                "missing_guards": [],
            },
            {
                "candidate_id": "c6",
                "candidate_type": "report_update_only",
                "title": "Bad high future",
                "risk_classification": "HIGH",
                "registry_status": "REGISTERED_DRAFT_ONLY",
                "apply_status": "not_applied",
                "missing_guards": [],
            },
        ]
    }
    report = build_guard_report(sample, {"safe_apply_candidate_registry": "ok"}, "2026-06-10T00:01:00Z")
    by_id = {check["candidate_id"]: check for check in report["guard_checks"]}
    if by_id["c1"]["guard_readiness_status"] != GUARDS_READY_DRAFT_ONLY:
        raise AssertionError("registered LOW draft candidate was not guard-ready")
    if by_id["c2"]["guard_readiness_status"] == GUARDS_READY_DRAFT_ONLY:
        raise AssertionError("live-write candidate without guards was marked ready")
    if by_id["c3"]["guard_readiness_status"] != GUARDS_BLOCKED_NOT_ALLOWED:
        raise AssertionError("blocked candidate did not stay blocked")
    if by_id["c4"]["guard_readiness_status"] != GUARDS_MONITOR_ONLY:
        raise AssertionError("monitor-only candidate did not stay monitor")
    if not report["summary"]["guard_breach"]:
        raise AssertionError("apply_status/HIGH future breach was not detected")
    try:
        assert_allowed_write(PROJECT_DIR / "forbidden/safe-apply-guard.json")
    except ValueError:
        pass
    else:
        raise AssertionError("forbidden write path was not rejected")
    print("safe-apply-guard-checker self-tests: OK")
    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check Safe Apply guard requirements.")
    parser.add_argument("--self-test", action="store_true", help="Run in-memory guard safety tests and exit.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()
    inputs, statuses = load_inputs()
    report = build_guard_report(inputs.get("safe_apply_candidate_registry"), statuses)
    write_outputs(report)
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    print(
        "Safe Apply Guard Check written: "
        f"{GUARD_MD} "
        f"(ready_draft={summary.get('guards_ready_draft_only_count')}, "
        f"missing={summary.get('guards_missing_for_autonomy_count')}, "
        f"blocked={summary.get('guards_blocked_not_allowed_count')})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
