#!/usr/bin/env python3
"""Sentinel Owner Daily Action Summary (Phase 2.8).

Aggregates existing local Sentinel reports into a short owner-facing daily
action summary and an autonomous-improvement readiness assessment. This module
never applies changes: no network access, no WordPress login, no APIs, and no
production writes.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


PROJECT_DIR = Path("/srv/sentinel-defense")

INPUTS = {
    "sentinel_master": PROJECT_DIR / "reports/latest/sentinel-master-report.json",
    "autonomy_policy": PROJECT_DIR / "reports/latest/autonomy-policy-report.json",
    "seo_safe_optimizer": PROJECT_DIR / "reports/latest/seo-safe-optimizer-report.json",
    "performance_safe_audit": PROJECT_DIR / "reports/latest/performance-safe-audit-report.json",
    "safe_improvement_roadmap_report": PROJECT_DIR / "reports/latest/safe-improvement-roadmap-report.json",
    "owner_approval_queue_report": PROJECT_DIR / "reports/latest/owner-approval-queue-report.json",
    "owner_approval_cli": PROJECT_DIR / "reports/latest/owner-approval-cli-report.json",
    "draft_execution_plan": PROJECT_DIR / "reports/latest/draft-execution-plan-report.json",
    "owner_review_pack": PROJECT_DIR / "reports/latest/owner-review-pack-report.json",
    "manual_apply_checklist": PROJECT_DIR / "reports/latest/manual-apply-checklist-report.json",
    "manual_completion_tracker": PROJECT_DIR / "reports/latest/manual-completion-tracker-report.json",
    "post_manual_validation": PROJECT_DIR / "reports/latest/post-manual-validation-report.json",
    "owner_approval_queue_draft": PROJECT_DIR / "drafts/approval/owner-approval-queue.json",
    "manual_apply_checklist_draft": PROJECT_DIR / "drafts/manual/manual-apply-checklist.json",
    "safe_improvement_roadmap_draft": PROJECT_DIR / "drafts/roadmap/safe-improvement-roadmap.json",
}

REPORT_JSON = PROJECT_DIR / "reports/latest/owner-daily-action-summary.json"
REPORT_MD = PROJECT_DIR / "reports/latest/owner-daily-action-summary.md"
OWNER_NEXT_ACTIONS_MD = PROJECT_DIR / "drafts/owner/owner-next-actions.md"
READINESS_MD = PROJECT_DIR / "drafts/owner/autonomous-improvement-readiness.md"
READINESS_JSON = PROJECT_DIR / "drafts/owner/autonomous-improvement-readiness.json"
AUDIT_JSONL = PROJECT_DIR / "audit/owner-daily-action-summary.jsonl"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "drafts/owner",
    PROJECT_DIR / "audit",
)

SCHEMA_VERSION = "owner-daily-action-summary-2.8"

APPLY_NOT_APPLIED = "not_applied"
RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"
RISK_REVIEW_ONLY = "REVIEW_ONLY"

OWNER_WARNING_REVIEW = "WARNING_REVIEW"
OWNER_REVIEW_NEEDED = "OWNER_REVIEW_NEEDED"
OWNER_READY_FOR_MANUAL_REVIEW = "READY_FOR_MANUAL_REVIEW"
OWNER_READY_FOR_NEXT_SAFE_CYCLE = "READY_FOR_NEXT_SAFE_CYCLE"
OWNER_NOT_AVAILABLE = "NOT_AVAILABLE"

READY_DRAFT_ONLY = "AUTONOMY_READY_DRAFT_ONLY"
READY_AFTER_APPROVAL = "AUTONOMY_READY_AFTER_OWNER_APPROVAL"
NOT_READY_MISSING_GUARDS = "AUTONOMY_NOT_READY_MISSING_GUARDS"
BLOCKED_HIGH_RISK = "AUTONOMY_BLOCKED_HIGH_RISK"
MONITOR_ONLY = "AUTONOMY_MONITOR_ONLY"

REQUIRED_GUARDS = {
    "explicit_allowlist": True,
    "backup_available": True,
    "pre_healthcheck_required": True,
    "post_healthcheck_required": True,
    "rollback_plan_required": True,
    "audit_log_required": True,
    "owner_disable_switch_required": True,
    "max_scope_defined": True,
    "post_manual_validation_required": True,
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


def sanitize_value(value: Any, *, max_len: int = 3000) -> Any:
    if isinstance(value, dict):
        safe: Dict[str, Any] = {}
        for key, child in value.items():
            key_text = str(key)
            if SECRETISH_RE.search(key_text):
                safe[key_text] = "[redacted]"
            else:
                safe[key_text] = sanitize_value(child, max_len=max_len)
        return safe
    if isinstance(value, list):
        return [sanitize_value(item, max_len=max_len) for item in value]
    if isinstance(value, str) or value is None:
        return redact_text(value, default="", max_len=max_len)
    if isinstance(value, (int, float, bool)):
        return value
    return redact_text(value, default="", max_len=max_len)


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
        raise ValueError(f"Refusing to write outside allowed owner summary roots: {path}")


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


def load_inputs() -> Tuple[Dict[str, Optional[Any]], Dict[str, str]]:
    data: Dict[str, Optional[Any]] = {}
    statuses: Dict[str, str] = {}
    for key, path in INPUTS.items():
        value, status = read_optional_json(path)
        data[key] = value
        statuses[key] = status
    return data, statuses


def normalize_risk(value: Any) -> str:
    risk = str(value or "").strip().upper()
    if risk in {RISK_LOW, RISK_MEDIUM, RISK_HIGH, RISK_REVIEW_ONLY}:
        return risk
    return RISK_REVIEW_ONLY


def list_from(data: Optional[Any], key: str) -> List[Dict[str, Any]]:
    if not isinstance(data, dict) or not isinstance(data.get(key), list):
        return []
    return [item for item in data[key] if isinstance(item, dict)]


def dict_from(data: Optional[Any], key: str) -> Dict[str, Any]:
    if not isinstance(data, dict) or not isinstance(data.get(key), dict):
        return {}
    return data[key]


def first_unchecked_item(tracker: Dict[str, Any], checklist: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    completion_items = list_from(tracker, "completion_items")
    for item in completion_items:
        if item.get("completion_status") == "unchecked":
            return item
    for item in list_from(checklist, "checklist_items"):
        completion_status = str(item.get("completion_status") or item.get("status_checkbox") or "unchecked")
        if completion_status == "unchecked":
            return item
    return None


def validation_safety_violation(validation: Dict[str, Any]) -> bool:
    safety = dict_from(validation, "safety_validation")
    return (
        bool(validation.get("safety_violation", False))
        or str(validation.get("status")) == "VALIDATION_WARNING"
        or str(safety.get("status")) == "WARNING"
        or parse_count(safety.get("warning_count")) > 0
        or bool(validation.get("productive_change", False))
        or bool(validation.get("network_access", False))
        or bool(validation.get("apply_function", False))
    )


def validation_ok(validation: Dict[str, Any]) -> bool:
    if not validation:
        return False
    safety = dict_from(validation, "safety_validation")
    return (
        not validation_safety_violation(validation)
        and str(safety.get("status", "OK")) == "OK"
        and str(validation.get("status", "")).upper()
        in {"READY_FOR_OWNER_VALIDATION", "OK", "READY_FOR_NEXT_SAFE_CYCLE"}
    )


def autonomy_breach(autonomy: Dict[str, Any], master: Dict[str, Any]) -> bool:
    master_autonomy = dict_from(master, "autonomy_policy")
    high_allowed = parse_count(autonomy.get("high_risk_allowed_now_count")) or parse_count(master_autonomy.get("high_risk_allowed_now_count"))
    apply_summary = autonomy.get("apply_status_summary")
    other_apply = 0
    if isinstance(apply_summary, dict):
        other_apply = parse_count(apply_summary.get("other_apply_status_count"))
    return (
        bool(autonomy.get("policy_breach", False))
        or bool(master_autonomy.get("policy_breach", False))
        or high_allowed > 0
        or other_apply > 0
        or bool(autonomy.get("productive_change", False))
    )


def build_owner_daily_summary(data: Dict[str, Optional[Any]], statuses: Dict[str, str], generated_at: str) -> Dict[str, Any]:
    master = data.get("sentinel_master") if isinstance(data.get("sentinel_master"), dict) else {}
    autonomy = data.get("autonomy_policy") if isinstance(data.get("autonomy_policy"), dict) else {}
    seo = data.get("seo_safe_optimizer") if isinstance(data.get("seo_safe_optimizer"), dict) else {}
    performance = data.get("performance_safe_audit") if isinstance(data.get("performance_safe_audit"), dict) else {}
    roadmap = data.get("safe_improvement_roadmap_report") if isinstance(data.get("safe_improvement_roadmap_report"), dict) else {}
    queue = data.get("owner_approval_queue_report") if isinstance(data.get("owner_approval_queue_report"), dict) else {}
    cli = data.get("owner_approval_cli") if isinstance(data.get("owner_approval_cli"), dict) else {}
    checklist = data.get("manual_apply_checklist_draft") if isinstance(data.get("manual_apply_checklist_draft"), dict) else {}
    tracker = data.get("manual_completion_tracker") if isinstance(data.get("manual_completion_tracker"), dict) else {}
    validation = data.get("post_manual_validation") if isinstance(data.get("post_manual_validation"), dict) else {}

    items_count = parse_count(tracker.get("checklist_items_count")) or parse_count(checklist.get("checklist_items_count"))
    completed = parse_count(tracker.get("completed_count"))
    in_progress = parse_count(tracker.get("in_progress_count"))
    skipped = parse_count(tracker.get("skipped_count"))
    needs_review = parse_count(tracker.get("needs_review_count"))
    unchecked = parse_count(tracker.get("unchecked_count"))
    if not tracker and checklist:
        unchecked = items_count
    blocked_high = (
        parse_count(dict_from(queue, "summary").get("blocked_high_risk_count"))
        or parse_count(dict_from(roadmap, "summary").get("blocked_high_count"))
        or parse_count(master.get("approval_queue", {}).get("blocked_high_risk_count") if isinstance(master.get("approval_queue"), dict) else 0)
    )

    safety_violation = validation_safety_violation(validation)
    completion_breach = bool(tracker.get("completion_breach", False)) or bool(tracker.get("productive_change", False))
    auto_breach = autonomy_breach(autonomy, master)

    if safety_violation or completion_breach or auto_breach:
        owner_status = OWNER_WARNING_REVIEW
    elif needs_review > 0:
        owner_status = OWNER_REVIEW_NEEDED
    elif unchecked > 0 and not safety_violation:
        owner_status = OWNER_READY_FOR_MANUAL_REVIEW
    elif items_count > 0 and completed >= items_count and validation_ok(validation):
        owner_status = OWNER_READY_FOR_NEXT_SAFE_CYCLE
    elif not tracker and not checklist:
        owner_status = OWNER_NOT_AVAILABLE
    else:
        owner_status = OWNER_READY_FOR_MANUAL_REVIEW

    first_unchecked = first_unchecked_item(tracker, checklist)
    first_unchecked_id = redact_text(first_unchecked.get("checklist_id") if first_unchecked else None, default="")
    if owner_status == OWNER_WARNING_REVIEW:
        recommended = "Stop and review safety warning before any owner action."
    elif needs_review > 0:
        recommended = "Review items marked needs_review first."
    elif unchecked > 0:
        recommended = (
            f"Start with first unchecked LOW checklist item: {first_unchecked_id}."
            if first_unchecked_id
            else "Start with first unchecked LOW checklist item."
        )
    elif in_progress > 0:
        recommended = "Finish in-progress item or mark it needs_review."
    elif completed > 0:
        recommended = "Run post-manual-validation after completed manual work."
    elif items_count > 0 and completed >= items_count and validation_ok(validation):
        recommended = "Prepare next safe cycle."
    elif blocked_high > 0:
        recommended = "Keep blocked high-risk items blocked; no action."
    else:
        recommended = "Run manual completion tracker list and review available checklist items."

    today_actions = [recommended]
    if blocked_high > 0:
        today_actions.append("Keep blocked high-risk items blocked; do not convert them to apply candidates.")
    if statuses.get("post_manual_validation") != "ok":
        today_actions.append("Run sentinel_post_manual_validation.py after any manual owner change.")

    seo_risk_raw = seo.get("highest_risk") or seo.get("risk_classification")
    if isinstance(seo_risk_raw, dict):
        seo_risk_raw = seo_risk_raw.get("highest_risk") or seo_risk_raw.get("policy") or "UNKNOWN"
    seo_summary = {
        "status": redact_text(seo.get("status"), default="NOT_AVAILABLE"),
        "highest_risk": redact_text(seo_risk_raw, default="UNKNOWN"),
        "drafts_available": bool(seo.get("improved_drafts_summary") or seo.get("draft_outputs")),
    }
    performance_summary = {
        "status": redact_text(performance.get("status"), default="NOT_AVAILABLE"),
        "highest_risk": redact_text(performance.get("highest_risk"), default="UNKNOWN"),
        "ai_radio_nowplaying_cache_status": redact_text(performance.get("ai_radio_nowplaying_cache_status"), default="UNKNOWN"),
        "origin_5xx_status": redact_text(performance.get("origin_5xx_status"), default="UNKNOWN"),
    }
    validation_summary = {
        "status": redact_text(validation.get("status"), default="NOT_AVAILABLE"),
        "seo_validation_status": redact_text(dict_from(validation, "seo_validation").get("status"), default="NOT_AVAILABLE"),
        "performance_validation_status": redact_text(dict_from(validation, "performance_validation").get("status"), default="NOT_AVAILABLE"),
        "safety_validation_status": redact_text(dict_from(validation, "safety_validation").get("status"), default="NOT_AVAILABLE"),
        "safety_violation": safety_violation,
    }
    autonomy_summary = {
        "status": redact_text(autonomy.get("status"), default="NOT_AVAILABLE"),
        "current_autonomy_level": redact_text(autonomy.get("current_autonomy_level"), default="UNKNOWN"),
        "policy_only": bool(autonomy.get("policy_only", True)),
        "autonomy_breach": auto_breach,
        "last_owner_action": redact_text(cli.get("last_owner_action"), default=""),
    }

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": generated_at,
        "overall_owner_status": owner_status,
        "today_safe_next_actions": today_actions,
        "open_manual_items": unchecked + in_progress + needs_review,
        "completed_manual_items": completed,
        "in_progress_manual_items": in_progress,
        "needs_review_items": needs_review,
        "skipped_items": skipped,
        "unchecked_items": unchecked,
        "blocked_high_risk_items": blocked_high,
        "seo_status_summary": seo_summary,
        "performance_status_summary": performance_summary,
        "validation_status_summary": validation_summary,
        "autonomy_status_summary": autonomy_summary,
        "recommended_next_owner_action": recommended,
        "safety_violation": safety_violation,
        "completion_breach": completion_breach,
        "autonomy_breach": auto_breach,
        "input_statuses": statuses,
        "read_only": True,
        "network_access": False,
        "wordpress_login": False,
        "api_access": False,
        "apply_function": False,
        "productive_change": False,
        "secrets_output": False,
    }


def source_items(data: Dict[str, Optional[Any]]) -> List[Dict[str, Any]]:
    collected: List[Dict[str, Any]] = []
    source_specs = (
        ("owner_approval_queue", data.get("owner_approval_queue_report"), "queue_items"),
        ("owner_approval_queue_draft", data.get("owner_approval_queue_draft"), "queue_items"),
        ("safe_improvement_roadmap", data.get("safe_improvement_roadmap_report"), "roadmap_items"),
        ("safe_improvement_roadmap_draft", data.get("safe_improvement_roadmap_draft"), "roadmap_items"),
        ("draft_execution_planner", data.get("draft_execution_plan"), "execution_items"),
        ("owner_review_pack", data.get("owner_review_pack"), "review_items"),
        ("manual_apply_checklist", data.get("manual_apply_checklist"), "checklist_items"),
    )
    seen = set()
    for source, payload, key in source_specs:
        for item in list_from(payload, key):
            source_id = (
                item.get("queue_id")
                or item.get("roadmap_id")
                or item.get("execution_id")
                or item.get("item_id")
                or item.get("checklist_id")
                or item.get("title")
                or f"{source}:{len(collected)}"
            )
            dedupe_key = str(source_id)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            copied = dict(item)
            copied["_summary_source"] = source
            copied["_source_id"] = str(source_id)
            collected.append(copied)
    return collected


def infer_impact_area(item: Dict[str, Any]) -> str:
    raw = " ".join(
        redact_text(item.get(key), default="", max_len=300)
        for key in ("impact_area", "section", "draft_type", "title", "source")
    ).lower()
    if "seo" in raw or "title" in raw or "meta" in raw or "opengraph" in raw or "twitter" in raw:
        return "SEO"
    if "performance" in raw or "image" in raw or "lazy" in raw or "cache" in raw or "webp" in raw:
        return "Performance"
    if "5xx" in raw or "origin" in raw or "radio" in raw or "sourcemap" in raw:
        return "Stability"
    if "content" in raw or "outline" in raw or "blog" in raw or "link" in raw:
        return "Content"
    return "Technical"


def is_forbidden_live_area(item: Dict[str, Any]) -> bool:
    text = " ".join(
        redact_text(item.get(key), default="", max_len=400)
        for key in ("title", "section", "source", "reason", "suggested_next_step", "draft_type")
    ).lower()
    blocked_terms = (
        "cloudflare",
        "nginx",
        ".htaccess",
        "htaccess",
        "dns",
        "service worker",
        "js minify",
        "javascript minify",
        "player code",
        "waf",
    )
    return any(term in text for term in blocked_terms)


def is_monitor_only(item: Dict[str, Any]) -> bool:
    text = " ".join(
        redact_text(item.get(key), default="", max_len=400)
        for key in ("title", "section", "source", "group", "queue_status", "reason", "suggested_next_step")
    ).lower()
    return (
        str(item.get("queue_status")) == "monitor_only"
        or str(item.get("group")) == "MONITOR_ONLY"
        or "monitor_only" in text
        or "ai-radio" in text
        or "microcache" in text
        or "origin 5xx" in text
        or "diagnostic_only" in text
    )


def is_draft_generation_candidate(item: Dict[str, Any]) -> bool:
    source = str(item.get("_summary_source", ""))
    text = " ".join(
        redact_text(item.get(key), default="", max_len=400)
        for key in ("title", "section", "draft_type", "queue_status", "group", "allowed_next_action")
    ).lower()
    return (
        source in {"draft_execution_planner", "owner_review_pack", "manual_apply_checklist"}
        or str(item.get("queue_status")) == "approved_for_draft_only"
        or str(item.get("group")) == "NEXT_SAFE_DRAFTS"
        or "draft" in text
        or "report" in text
        or "summary" in text
        or "check" in text
    )


def missing_guards_for(status: str) -> List[str]:
    if status in {READY_DRAFT_ONLY, MONITOR_ONLY, BLOCKED_HIGH_RISK}:
        return []
    return list(REQUIRED_GUARDS.keys())


def readiness_for_item(item: Dict[str, Any], index: int) -> Dict[str, Any]:
    risk = normalize_risk(item.get("risk_classification"))
    source_id = redact_text(item.get("_source_id"), default=f"candidate-{index}", max_len=220)
    title = redact_text(item.get("title") or item.get("section") or source_id, max_len=320)
    current_status = redact_text(
        item.get("queue_status") or item.get("status") or item.get("group") or item.get("allowed_next_action"),
        default="not_available",
        max_len=220,
    )
    apply_status = APPLY_NOT_APPLIED

    if is_monitor_only(item):
        readiness = MONITOR_ONLY
        possible_action = "Monitor and report only."
        reason = "This item is diagnostic/monitor-only; no autonomous production mutation is appropriate."
    elif risk == RISK_HIGH or is_forbidden_live_area(item):
        readiness = BLOCKED_HIGH_RISK
        possible_action = "Do not automate; keep blocked or diagnostic-only."
        reason = "High-risk or forbidden production area remains blocked."
    elif risk != RISK_LOW:
        readiness = NOT_READY_MISSING_GUARDS
        possible_action = "No autonomous action; owner review and guard design required."
        reason = "MEDIUM/REVIEW_ONLY items are not autonomous-ready."
    elif str(item.get("queue_status")) == "pending_owner_review":
        readiness = READY_AFTER_APPROVAL
        possible_action = "Generate owner-reviewed draft after explicit approval; no live apply."
        reason = "LOW item is pending owner review before any further autonomous workflow."
    elif is_draft_generation_candidate(item):
        readiness = READY_DRAFT_ONLY
        possible_action = "Generate or refresh drafts, reports, summaries, and manual checklists only."
        reason = "LOW draft/report action can be automated without production writes."
    else:
        readiness = NOT_READY_MISSING_GUARDS
        possible_action = "No live autonomous action until guard registry exists."
        reason = "No explicit allowlist/backup/healthcheck/rollback registry exists yet."

    missing_guards = missing_guards_for(readiness)
    return {
        "readiness_id": f"readiness:{index:03d}",
        "source": redact_text(item.get("_summary_source"), max_len=180),
        "source_id": source_id,
        "title": title,
        "impact_area": infer_impact_area(item),
        "risk_classification": risk,
        "current_status": current_status,
        "possible_future_autonomous_action": possible_action,
        "required_guards": dict(REQUIRED_GUARDS),
        "missing_guards": missing_guards,
        "readiness_status": readiness,
        "reason": reason,
        "apply_status": apply_status,
    }


def build_autonomy_readiness(data: Dict[str, Optional[Any]], generated_at: str) -> Dict[str, Any]:
    candidates = [readiness_for_item(item, idx + 1) for idx, item in enumerate(source_items(data))]
    counts = {
        READY_DRAFT_ONLY: 0,
        READY_AFTER_APPROVAL: 0,
        NOT_READY_MISSING_GUARDS: 0,
        BLOCKED_HIGH_RISK: 0,
        MONITOR_ONLY: 0,
    }
    missing_guard_summary: Dict[str, int] = {key: 0 for key in REQUIRED_GUARDS}
    for candidate in candidates:
        status = candidate.get("readiness_status")
        if status in counts:
            counts[status] += 1
        for guard in candidate.get("missing_guards", []):
            missing_guard_summary[guard] = missing_guard_summary.get(guard, 0) + 1

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": generated_at,
        "status": "READY_FOR_REVIEW",
        "read_only": True,
        "network_access": False,
        "apply_function": False,
        "productive_change": False,
        "autonomy_ready_draft_only_count": counts[READY_DRAFT_ONLY],
        "ready_after_owner_approval_count": counts[READY_AFTER_APPROVAL],
        "not_ready_missing_guards_count": counts[NOT_READY_MISSING_GUARDS],
        "blocked_high_risk_count": counts[BLOCKED_HIGH_RISK],
        "monitor_only_count": counts[MONITOR_ONLY],
        "missing_guard_summary": missing_guard_summary,
        "next_safe_autonomy_build_step": "Build Safe Apply Candidate Registry, not live apply.",
        "required_guards": dict(REQUIRED_GUARDS),
        "readiness_candidates": candidates,
        "groups": {
            READY_DRAFT_ONLY: [c for c in candidates if c.get("readiness_status") == READY_DRAFT_ONLY],
            READY_AFTER_APPROVAL: [c for c in candidates if c.get("readiness_status") == READY_AFTER_APPROVAL],
            NOT_READY_MISSING_GUARDS: [c for c in candidates if c.get("readiness_status") == NOT_READY_MISSING_GUARDS],
            BLOCKED_HIGH_RISK: [c for c in candidates if c.get("readiness_status") == BLOCKED_HIGH_RISK],
            MONITOR_ONLY: [c for c in candidates if c.get("readiness_status") == MONITOR_ONLY],
        },
    }


def build_report(generated_at: Optional[str] = None) -> Dict[str, Any]:
    generated = generated_at or utc_now()
    data, statuses = load_inputs()
    return build_report_from_data(data, statuses, generated)[0]


def render_owner_report(report: Dict[str, Any]) -> str:
    summary = dict_from(report, "owner_daily_action_summary")
    readiness = dict_from(report, "autonomous_improvement_readiness")
    lines = [
        "# Owner Daily Action Summary",
        "",
        f"- Generated (UTC): `{report.get('generated_at_utc')}`",
        f"- Owner status: `{summary.get('overall_owner_status')}`",
        f"- Recommended next owner action: {redact_text(summary.get('recommended_next_owner_action'))}",
        "",
        "## Manual Progress",
        "",
        f"- Open manual items: `{summary.get('open_manual_items')}`",
        f"- Completed: `{summary.get('completed_manual_items')}`",
        f"- In progress: `{summary.get('in_progress_manual_items')}`",
        f"- Needs review: `{summary.get('needs_review_items')}`",
        f"- Skipped: `{summary.get('skipped_items')}`",
        f"- Blocked high-risk items: `{summary.get('blocked_high_risk_items')}`",
        "",
        "## Today Safe Next Actions",
        "",
    ]
    for action in summary.get("today_safe_next_actions", []):
        lines.append(f"- {redact_text(action)}")
    lines.extend(
        [
            "",
            "## Status Summaries",
            "",
            f"- SEO: `{dict_from(summary, 'seo_status_summary').get('status')}` / highest risk `{dict_from(summary, 'seo_status_summary').get('highest_risk')}`",
            f"- Performance: `{dict_from(summary, 'performance_status_summary').get('status')}` / cache `{dict_from(summary, 'performance_status_summary').get('ai_radio_nowplaying_cache_status')}`",
            f"- Validation: `{dict_from(summary, 'validation_status_summary').get('status')}` / safety `{dict_from(summary, 'validation_status_summary').get('safety_validation_status')}`",
            f"- Autonomy: `{dict_from(summary, 'autonomy_status_summary').get('current_autonomy_level')}` / breach `{dict_from(summary, 'autonomy_status_summary').get('autonomy_breach')}`",
            "",
            "## Autonomous Improvement Readiness",
            "",
            f"- Draft-only ready: `{readiness.get('autonomy_ready_draft_only_count')}`",
            f"- Ready after owner approval: `{readiness.get('ready_after_owner_approval_count')}`",
            f"- Not ready, missing guards: `{readiness.get('not_ready_missing_guards_count')}`",
            f"- Blocked high-risk: `{readiness.get('blocked_high_risk_count')}`",
            f"- Monitor-only: `{readiness.get('monitor_only_count')}`",
            f"- Next safe autonomy build step: {redact_text(readiness.get('next_safe_autonomy_build_step'))}",
            "",
            "## Safety Boundaries",
            "",
            "- Keine Live-Aenderungen.",
            "- Keine WordPress-, .htaccess-, Cloudflare- oder Nginx-Aenderung.",
            "- Kein Netzwerkzugriff, kein Login, keine API.",
            "- Alle Kandidaten bleiben `apply_status=not_applied`.",
            "",
        ]
    )
    return "\n".join(lines)


def render_owner_next_actions(report: Dict[str, Any]) -> str:
    summary = dict_from(report, "owner_daily_action_summary")
    lines = [
        "# Owner Next Actions",
        "",
        f"- Owner status: `{summary.get('overall_owner_status')}`",
        f"- Recommended next owner action: {redact_text(summary.get('recommended_next_owner_action'))}",
        "",
        "## Checklist Counts",
        "",
        f"- Open manual items: `{summary.get('open_manual_items')}`",
        f"- Completed: `{summary.get('completed_manual_items')}`",
        f"- In progress: `{summary.get('in_progress_manual_items')}`",
        f"- Needs review: `{summary.get('needs_review_items')}`",
        f"- Skipped: `{summary.get('skipped_items')}`",
        f"- Blocked high-risk items: `{summary.get('blocked_high_risk_items')}`",
        "",
        "## Safe Actions Today",
        "",
    ]
    for action in summary.get("today_safe_next_actions", []):
        lines.append(f"- {redact_text(action)}")
    lines.append("")
    return "\n".join(lines)


def render_readiness(readiness: Dict[str, Any]) -> str:
    lines = [
        "# Autonomous Improvement Readiness",
        "",
        f"- Generated (UTC): `{readiness.get('generated_at_utc')}`",
        f"- Draft-only ready: `{readiness.get('autonomy_ready_draft_only_count')}`",
        f"- Ready after owner approval: `{readiness.get('ready_after_owner_approval_count')}`",
        f"- Not ready, missing guards: `{readiness.get('not_ready_missing_guards_count')}`",
        f"- Blocked high-risk: `{readiness.get('blocked_high_risk_count')}`",
        f"- Monitor-only: `{readiness.get('monitor_only_count')}`",
        f"- Next safe autonomy build step: {redact_text(readiness.get('next_safe_autonomy_build_step'))}",
        "",
        "## Missing Guard Summary",
        "",
    ]
    for guard, count in dict_from(readiness, "missing_guard_summary").items():
        lines.append(f"- `{guard}`: `{count}`")
    lines.extend(
        [
            "",
            "## Candidates",
            "",
            "| Readiness ID | Status | Risk | Impact | Title |",
            "|---|---|---|---|---|",
        ]
    )
    for candidate in readiness.get("readiness_candidates", []):
        if not isinstance(candidate, dict):
            continue
        lines.append(
            "| "
            f"`{redact_text(candidate.get('readiness_id'), max_len=80)}` | "
            f"`{redact_text(candidate.get('readiness_status'), max_len=80)}` | "
            f"`{redact_text(candidate.get('risk_classification'), max_len=80)}` | "
            f"`{redact_text(candidate.get('impact_area'), max_len=80)}` | "
            f"{redact_text(candidate.get('title'), max_len=160)} |"
        )
    lines.extend(
        [
            "",
            "## Boundary",
            "",
            "- Dies ist kein Apply-Plan.",
            "- Naechster Baustein ist eine Safe Apply Candidate Registry, nicht Live-Apply.",
            "",
        ]
    )
    return "\n".join(lines)


def audit_record(report: Dict[str, Any]) -> Dict[str, Any]:
    summary = dict_from(report, "owner_daily_action_summary")
    readiness = dict_from(report, "autonomous_improvement_readiness")
    return {
        "timestamp_utc": report.get("generated_at_utc"),
        "schema_version": SCHEMA_VERSION,
        "overall_owner_status": summary.get("overall_owner_status"),
        "recommended_next_owner_action": summary.get("recommended_next_owner_action"),
        "open_manual_items": summary.get("open_manual_items"),
        "completed_manual_items": summary.get("completed_manual_items"),
        "needs_review_items": summary.get("needs_review_items"),
        "blocked_high_risk_items": summary.get("blocked_high_risk_items"),
        "autonomy_ready_draft_only_count": readiness.get("autonomy_ready_draft_only_count"),
        "ready_after_owner_approval_count": readiness.get("ready_after_owner_approval_count"),
        "not_ready_missing_guards_count": readiness.get("not_ready_missing_guards_count"),
        "blocked_high_risk_count": readiness.get("blocked_high_risk_count"),
        "monitor_only_count": readiness.get("monitor_only_count"),
        "productive_change": False,
        "network_access": False,
        "apply_function": False,
    }


def write_outputs(report: Dict[str, Any]) -> None:
    readiness = build_autonomy_readiness(load_inputs()[0], report.get("generated_at_utc") or utc_now())
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, render_owner_report(report))
    write_text_atomic(OWNER_NEXT_ACTIONS_MD, render_owner_next_actions(report))
    write_json_atomic(READINESS_JSON, readiness)
    write_text_atomic(READINESS_MD, render_readiness(readiness))
    append_jsonl(AUDIT_JSONL, [audit_record(report)])


def build_report_from_data(
    data: Dict[str, Optional[Any]],
    statuses: Dict[str, str],
    generated_at: str,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    owner_summary = build_owner_daily_summary(data, statuses, generated_at)
    readiness = build_autonomy_readiness(data, generated_at)
    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": generated_at,
        "status": owner_summary.get("overall_owner_status"),
        "overall_owner_status": owner_summary.get("overall_owner_status"),
        "today_safe_next_actions": owner_summary.get("today_safe_next_actions"),
        "open_manual_items": owner_summary.get("open_manual_items"),
        "completed_manual_items": owner_summary.get("completed_manual_items"),
        "in_progress_manual_items": owner_summary.get("in_progress_manual_items"),
        "needs_review_items": owner_summary.get("needs_review_items"),
        "skipped_items": owner_summary.get("skipped_items"),
        "blocked_high_risk_items": owner_summary.get("blocked_high_risk_items"),
        "seo_status_summary": owner_summary.get("seo_status_summary"),
        "performance_status_summary": owner_summary.get("performance_status_summary"),
        "validation_status_summary": owner_summary.get("validation_status_summary"),
        "autonomy_status_summary": owner_summary.get("autonomy_status_summary"),
        "recommended_next_owner_action": owner_summary.get("recommended_next_owner_action"),
        "autonomy_ready_draft_only_count": readiness.get("autonomy_ready_draft_only_count"),
        "ready_after_owner_approval_count": readiness.get("ready_after_owner_approval_count"),
        "not_ready_missing_guards_count": readiness.get("not_ready_missing_guards_count"),
        "blocked_high_risk_count": readiness.get("blocked_high_risk_count"),
        "monitor_only_count": readiness.get("monitor_only_count"),
        "missing_guard_summary": readiness.get("missing_guard_summary"),
        "next_safe_autonomy_build_step": readiness.get("next_safe_autonomy_build_step"),
        "owner_daily_action_summary": owner_summary,
        "autonomous_improvement_readiness": {
            key: readiness.get(key)
            for key in (
                "status",
                "autonomy_ready_draft_only_count",
                "ready_after_owner_approval_count",
                "not_ready_missing_guards_count",
                "blocked_high_risk_count",
                "monitor_only_count",
                "missing_guard_summary",
                "next_safe_autonomy_build_step",
            )
        },
        "readiness_candidates": readiness.get("readiness_candidates", []),
        "input_statuses": statuses,
        "outputs": {
            "report_json": str(REPORT_JSON),
            "report_md": str(REPORT_MD),
            "owner_next_actions_md": str(OWNER_NEXT_ACTIONS_MD),
            "readiness_md": str(READINESS_MD),
            "readiness_json": str(READINESS_JSON),
            "audit_jsonl": str(AUDIT_JSONL),
        },
        "read_only": True,
        "network_access": False,
        "wordpress_login": False,
        "api_access": False,
        "apply_function": False,
        "productive_change": False,
        "secrets_output": False,
        "allowed_write_roots": [str(path) for path in ALLOWED_WRITE_ROOTS],
    }
    return report, readiness


def run_self_test() -> int:
    generated = "2026-06-10T00:00:00Z"
    empty_report, empty_ready = build_report_from_data({}, {}, generated)
    if empty_report["status"] != OWNER_NOT_AVAILABLE:
        raise AssertionError("missing reports did not produce NOT_AVAILABLE")

    safety_data = {
        "post_manual_validation": {
            "status": "VALIDATION_WARNING",
            "safety_validation": {"status": "WARNING", "warning_count": 1},
        }
    }
    safety_report, _ = build_report_from_data(safety_data, {"post_manual_validation": "ok"}, generated)
    if safety_report["status"] != OWNER_WARNING_REVIEW:
        raise AssertionError("safety violation did not produce WARNING_REVIEW")

    completion_data = {
        "manual_completion_tracker": {
            "completion_breach": True,
            "checklist_items_count": 1,
        }
    }
    completion_report, _ = build_report_from_data(completion_data, {"manual_completion_tracker": "ok"}, generated)
    if completion_report["status"] != OWNER_WARNING_REVIEW:
        raise AssertionError("completion breach did not produce WARNING_REVIEW")

    unchecked_data = {
        "manual_completion_tracker": {
            "completion_breach": False,
            "checklist_items_count": 2,
            "unchecked_count": 2,
        },
        "post_manual_validation": {"status": "READY_FOR_OWNER_VALIDATION", "safety_validation": {"status": "OK"}},
    }
    unchecked_report, _ = build_report_from_data(unchecked_data, {"manual_completion_tracker": "ok"}, generated)
    if unchecked_report["status"] != OWNER_READY_FOR_MANUAL_REVIEW:
        raise AssertionError("unchecked items did not produce READY_FOR_MANUAL_REVIEW")

    readiness_data = {
        "owner_approval_queue_report": {
            "queue_items": [
                {
                    "queue_id": "low:draft",
                    "title": "SEO report draft",
                    "risk_classification": "LOW",
                    "queue_status": "approved_for_draft_only",
                    "apply_status": "not_applied",
                },
                {
                    "queue_id": "high:cloudflare",
                    "title": "Cloudflare WAF change",
                    "risk_classification": "HIGH",
                    "queue_status": "blocked_high_risk",
                    "apply_status": "not_applied",
                },
                {
                    "queue_id": "medium:lazy",
                    "title": "Lazy Loading live change",
                    "risk_classification": "MEDIUM",
                    "queue_status": "pending_owner_review",
                    "apply_status": "not_applied",
                },
            ]
        }
    }
    _, readiness = build_report_from_data(readiness_data, {"owner_approval_queue_report": "ok"}, generated)
    candidates = readiness["readiness_candidates"]
    statuses = {candidate["source_id"]: candidate["readiness_status"] for candidate in candidates}
    if statuses.get("low:draft") != READY_DRAFT_ONLY:
        raise AssertionError("LOW draft did not become AUTONOMY_READY_DRAFT_ONLY")
    if statuses.get("high:cloudflare") != BLOCKED_HIGH_RISK:
        raise AssertionError("HIGH risk did not become AUTONOMY_BLOCKED_HIGH_RISK")
    if statuses.get("medium:lazy") == READY_DRAFT_ONLY:
        raise AssertionError("MEDIUM item was marked draft-only ready")
    if any(candidate.get("apply_status") != APPLY_NOT_APPLIED for candidate in candidates):
        raise AssertionError("readiness candidate apply_status changed")

    try:
        assert_allowed_write(PROJECT_DIR / "forbidden/owner-summary.json")
    except ValueError:
        pass
    else:
        raise AssertionError("forbidden write path was not rejected")

    print("owner-daily-action-summary self-tests: OK")
    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build owner daily action summary and autonomy readiness.")
    parser.add_argument("--self-test", action="store_true", help="Run in-memory safety tests and exit.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()
    generated = utc_now()
    data, statuses = load_inputs()
    report, readiness = build_report_from_data(data, statuses, generated)
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, render_owner_report(report))
    write_text_atomic(OWNER_NEXT_ACTIONS_MD, render_owner_next_actions(report))
    write_json_atomic(READINESS_JSON, readiness)
    write_text_atomic(READINESS_MD, render_readiness(readiness))
    append_jsonl(AUDIT_JSONL, [audit_record(report)])
    summary = dict_from(report, "owner_daily_action_summary")
    print(
        "Owner daily action summary written: "
        f"{REPORT_MD} ({summary.get('overall_owner_status')})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
