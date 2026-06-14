#!/usr/bin/env python3
"""Sentinel Owner Approval Queue (Phase 2.0).

Reads the Safe Improvement Roadmap and produces a controlled owner approval
queue. It applies nothing live and accepts no real approvals — it only builds
the queue (auto-setting draft-only status for unambiguous safe LOW drafts).

Hard safety guarantees (enforced structurally):
  * No live changes; no WordPress/.htaccess/Cloudflare/Nginx edits.
  * No external/network access — local files only (no network imports).
  * No secrets/cookies/authorization values are stored or emitted.
  * No apply function; every queue item stays apply_status=not_applied.
  * Writes only ever under:
        /srv/sentinel-defense/reports/latest
        /srv/sentinel-defense/drafts/approval
        /srv/sentinel-defense/audit
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

# --- Output targets ---------------------------------------------------------
QUEUE_DRAFT_JSON = PROJECT_DIR / "drafts/approval/owner-approval-queue.json"
QUEUE_DRAFT_MD = PROJECT_DIR / "drafts/approval/owner-approval-queue.md"
REPORT_JSON = PROJECT_DIR / "reports/latest/owner-approval-queue-report.json"
REPORT_MD = PROJECT_DIR / "reports/latest/owner-approval-queue-report.md"
AUDIT_JSONL = PROJECT_DIR / "audit/owner-approval-queue.jsonl"
RECONCILE_AUDIT_JSONL = PROJECT_DIR / "audit/owner-approval-reconcile.jsonl"

# --- Optional inputs (must never crash when missing) ------------------------
INPUT_ROADMAP_DRAFT = PROJECT_DIR / "drafts/roadmap/safe-improvement-roadmap.json"
INPUT_ROADMAP_REPORT = PROJECT_DIR / "reports/latest/safe-improvement-roadmap-report.json"
INPUT_AUTONOMY_POLICY = PROJECT_DIR / "reports/latest/autonomy-policy-report.json"

# --- Allowed write roots (the only paths this module may ever write) --------
ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "drafts/approval",
    PROJECT_DIR / "audit",
)

SCHEMA_VERSION = "owner-approval-queue-2.0"

SECRETISH_RE = re.compile(
    r"(?i)(api[_-]?key|token|secret|password|passwd|bearer|authorization|"
    r"cookie|set-cookie|credential|x-api-key|access[_-]?key|session)"
)

# Risk classes.
RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"
RISK_REVIEW_ONLY = "REVIEW_ONLY"

# Roadmap groups (inputs).
GROUP_NEXT_SAFE_DRAFTS = "NEXT_SAFE_DRAFTS"
GROUP_OWNER_REVIEW_REQUIRED = "OWNER_REVIEW_REQUIRED"
GROUP_BLOCKED_HIGH_RISK = "BLOCKED_HIGH_RISK"
GROUP_MONITOR_ONLY = "MONITOR_ONLY"

# Queue statuses.
QUEUE_PENDING_OWNER_REVIEW = "pending_owner_review"
QUEUE_APPROVED_FOR_DRAFT_ONLY = "approved_for_draft_only"
QUEUE_APPROVED_FOR_MANUAL_APPLY = "approved_for_manual_apply"  # never auto-set
QUEUE_REJECTED = "rejected"  # never auto-set
QUEUE_MONITOR_ONLY = "monitor_only"
QUEUE_BLOCKED_HIGH_RISK = "blocked_high_risk"
QUEUE_STALE_REMOVED = "stale_removed_from_roadmap"

ALL_QUEUE_STATUSES = (
    QUEUE_PENDING_OWNER_REVIEW,
    QUEUE_APPROVED_FOR_DRAFT_ONLY,
    QUEUE_APPROVED_FOR_MANUAL_APPLY,
    QUEUE_REJECTED,
    QUEUE_MONITOR_ONLY,
    QUEUE_BLOCKED_HIGH_RISK,
    QUEUE_STALE_REMOVED,
)

# Owner-decision fields preserved across a roadmap regeneration.
OWNER_PRESERVE_FIELDS = (
    "owner_note",
    "owner_note_updated_at_utc",
    "owner_note_history",
    "last_owner_action",
    "last_owner_action_at_utc",
    "last_owner_action_utc",
    "decision_history",
)

# Next action allowed for each queue status (advisory; never an apply).
ALLOWED_NEXT_ACTION = {
    QUEUE_PENDING_OWNER_REVIEW: "await_owner_decision",
    QUEUE_APPROVED_FOR_DRAFT_ONLY: "produce_or_keep_draft_only",
    QUEUE_APPROVED_FOR_MANUAL_APPLY: "manual_owner_apply",
    QUEUE_REJECTED: "no_action",
    QUEUE_MONITOR_ONLY: "observe_only",
    QUEUE_BLOCKED_HIGH_RISK: "no_action_blocked",
    QUEUE_STALE_REMOVED: "observe_only",
}

OWNER_APPROVAL_REQUIRED_BY_STATUS = {
    QUEUE_PENDING_OWNER_REVIEW: True,
    QUEUE_APPROVED_FOR_DRAFT_ONLY: False,  # draft-only is allowed at LEVEL_1
    QUEUE_APPROVED_FOR_MANUAL_APPLY: True,
    QUEUE_REJECTED: False,
    QUEUE_MONITOR_ONLY: False,
    QUEUE_STALE_REMOVED: False,
    QUEUE_BLOCKED_HIGH_RISK: True,
}


# ===========================================================================
# Safety helpers
# ===========================================================================
def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def redact_text(value: Any, default: str = "-", max_len: int = 300) -> str:
    if value is None:
        return default
    text = str(value).replace("\n", " ").replace("\r", " ").strip()
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


def assert_allowed_write(path: Path) -> None:
    if not any(is_within(path, root) for root in ALLOWED_WRITE_ROOTS):
        raise ValueError(
            f"Refusing to write outside allowed approval queue roots: {path}"
        )


def write_text_atomic(path: Path, content: str) -> None:
    assert_allowed_write(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)


def write_json_atomic(path: Path, data: Any) -> None:
    write_text_atomic(
        path, json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    )


def append_jsonl_atomic(path: Path, records: List[Dict[str, Any]]) -> None:
    assert_allowed_write(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = "".join(
        json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n" for rec in records
    )
    with path.open("a", encoding="utf-8") as handle:
        handle.write(lines)


def read_optional_json(path: Path) -> Tuple[Optional[Any], str]:
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


def normalize_risk(value: Any) -> str:
    risk = str(value or "").strip().upper()
    if risk in (RISK_LOW, RISK_MEDIUM, RISK_HIGH, RISK_REVIEW_ONLY):
        return risk
    return RISK_HIGH  # unknown -> conservative


# ===========================================================================
# Queue construction
# ===========================================================================
def decide_queue_status(group: str, risk: str, autonomy_class: str) -> str:
    """Map a roadmap item to a queue status. Conservative by construction.

    Auto-approval is limited to draft-only for unambiguous safe LOW drafts.
    Never auto-sets approved_for_manual_apply or rejected.
    """
    # HIGH is always blocked, regardless of group.
    if risk == RISK_HIGH:
        return QUEUE_BLOCKED_HIGH_RISK
    if group == GROUP_BLOCKED_HIGH_RISK:
        return QUEUE_BLOCKED_HIGH_RISK
    if group == GROUP_MONITOR_ONLY:
        return QUEUE_MONITOR_ONLY
    if group == GROUP_OWNER_REVIEW_REQUIRED:
        return QUEUE_PENDING_OWNER_REVIEW
    if group == GROUP_NEXT_SAFE_DRAFTS:
        # Unambiguous safe LOW draft -> auto draft-only (still never applied).
        if risk == RISK_LOW and autonomy_class == "LEVEL_1_DRAFT_ONLY":
            return QUEUE_APPROVED_FOR_DRAFT_ONLY
        return QUEUE_PENDING_OWNER_REVIEW
    # MEDIUM / REVIEW_ONLY without a recognized group -> owner review.
    if risk in (RISK_MEDIUM, RISK_REVIEW_ONLY):
        return QUEUE_PENDING_OWNER_REVIEW
    # LOW fallback -> draft-only at most.
    if risk == RISK_LOW:
        return QUEUE_APPROVED_FOR_DRAFT_ONLY
    return QUEUE_PENDING_OWNER_REVIEW


def make_queue_item(roadmap_item: Dict[str, Any], created_at: str) -> Dict[str, Any]:
    roadmap_id = str(roadmap_item.get("roadmap_id", "unknown"))
    group = str(roadmap_item.get("group", "")).strip()
    risk = normalize_risk(roadmap_item.get("risk_classification"))
    autonomy_class = str(roadmap_item.get("autonomy_policy_class", "")).strip()
    # Hard safety: HIGH stays blocked from autonomy.
    if risk == RISK_HIGH:
        autonomy_class = "BLOCKED_NOT_PERMITTED"

    queue_status = decide_queue_status(group, risk, autonomy_class)

    if queue_status == QUEUE_BLOCKED_HIGH_RISK:
        reason = "HIGH-risk item; blocked from any autonomy/apply. Owner+technical review only."
    elif queue_status == QUEUE_MONITOR_ONLY:
        reason = "Monitor/diagnostic only; no change is proposed or applied."
    elif queue_status == QUEUE_APPROVED_FOR_DRAFT_ONLY:
        reason = "Unambiguous safe LOW draft; draft generation allowed, never applied."
    else:  # pending_owner_review
        reason = "Requires explicit owner review before any future manual change."

    return {
        "queue_id": f"approval:{roadmap_id}",
        "roadmap_id": roadmap_id,
        "source": redact_text(roadmap_item.get("source"), default="-", max_len=80),
        "title": redact_text(roadmap_item.get("title"), default="-", max_len=160),
        "impact_area": redact_text(roadmap_item.get("impact_area"), default="-", max_len=40),
        "risk_classification": risk,
        "autonomy_policy_class": autonomy_class,
        "queue_status": queue_status,
        "allowed_next_action": ALLOWED_NEXT_ACTION.get(queue_status, "no_action"),
        # Phase 2.0 never applies anything.
        "apply_status": "not_applied",
        "owner_approval_required": OWNER_APPROVAL_REQUIRED_BY_STATUS.get(queue_status, True),
        "reason": reason,
        "created_at_utc": created_at,
    }


def detect_queue_breach(items: List[Dict[str, Any]]) -> Tuple[bool, List[str]]:
    """A queue breach exists if a HIGH item is not blocked, or any item is
    not in apply_status=not_applied. Used by the Master to escalate."""
    problems: List[str] = []
    for item in items:
        if item.get("risk_classification") == RISK_HIGH and item.get("queue_status") != QUEUE_BLOCKED_HIGH_RISK:
            problems.append(f"HIGH not blocked: {item.get('queue_id')}")
        if item.get("apply_status") != "not_applied":
            problems.append(f"apply_status not not_applied: {item.get('queue_id')}")
    return (len(problems) > 0), problems


def fallback_key(item: Dict[str, Any]) -> Tuple[str, str, str]:
    return (
        str(item.get("source", "")).strip(),
        str(item.get("title", "")).strip(),
        str(item.get("impact_area", "")).strip(),
    )


def reconcile_status(existing_status: str, risk: str) -> Tuple[str, bool]:
    """Decide which queue_status survives a regeneration, enforcing safety.

    Returns (status, security_override). Security overrides:
      * HIGH -> always blocked_high_risk.
      * approved_for_manual_apply -> never preserved automatically.
      * MEDIUM/REVIEW_ONLY -> never approved_for_draft_only.
    Otherwise the owner's prior status is preserved.
    """
    if risk == RISK_HIGH:
        return QUEUE_BLOCKED_HIGH_RISK, (existing_status != QUEUE_BLOCKED_HIGH_RISK)
    if existing_status == QUEUE_APPROVED_FOR_MANUAL_APPLY:
        return QUEUE_PENDING_OWNER_REVIEW, True
    if risk in (RISK_MEDIUM, RISK_REVIEW_ONLY) and existing_status == QUEUE_APPROVED_FOR_DRAFT_ONLY:
        return QUEUE_PENDING_OWNER_REVIEW, True
    if existing_status in ALL_QUEUE_STATUSES:
        return existing_status, False
    # Unknown/missing prior status -> caller keeps the freshly computed default.
    return "", False


def reconcile_item(new_item: Dict[str, Any], existing_item: Dict[str, Any]) -> Tuple[Dict[str, Any], bool, bool]:
    """Merge owner decisions from existing_item into new_item, safely.

    Returns (merged_item, preserved_decision, security_override).
    apply_status is always forced to not_applied.
    """
    risk = normalize_risk(new_item.get("risk_classification"))
    new_default_status = new_item.get("queue_status")
    existing_status = str(existing_item.get("queue_status", ""))

    merged = dict(new_item)
    # Keep a stable queue_id from the existing item when matched.
    if existing_item.get("queue_id"):
        merged["queue_id"] = existing_item["queue_id"]

    # Preserve owner-decision metadata fields verbatim (already redacted on write).
    for field in OWNER_PRESERVE_FIELDS:
        if field in existing_item:
            merged[field] = existing_item[field]

    preserved_status, override = reconcile_status(existing_status, risk)
    if preserved_status:
        merged["queue_status"] = preserved_status
    else:
        merged["queue_status"] = new_default_status

    # Re-derive dependent fields from the effective status; force not_applied.
    merged["allowed_next_action"] = ALLOWED_NEXT_ACTION.get(merged["queue_status"], "no_action")
    merged["owner_approval_required"] = OWNER_APPROVAL_REQUIRED_BY_STATUS.get(merged["queue_status"], True)
    merged["apply_status"] = "not_applied"
    merged["reconciled"] = True

    owner_had_decision = (
        any(existing_item.get(f) for f in OWNER_PRESERVE_FIELDS)
        or (existing_status and existing_status != new_default_status)
    )
    preserved = bool(owner_had_decision)
    return merged, preserved, override


def make_stale_item(existing_item: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
    """Keep an item that is no longer in the roadmap, marked stale.

    Returns (stale_item, security_override). HIGH stale stays blocked.
    apply_status is always not_applied.
    """
    risk = normalize_risk(existing_item.get("risk_classification"))
    stale = dict(existing_item)
    prior_status = str(existing_item.get("queue_status", ""))
    override = False
    if risk == RISK_HIGH:
        new_status = QUEUE_BLOCKED_HIGH_RISK
        override = (prior_status != QUEUE_BLOCKED_HIGH_RISK)
    else:
        new_status = QUEUE_STALE_REMOVED
    stale["queue_status"] = new_status
    stale["allowed_next_action"] = ALLOWED_NEXT_ACTION.get(new_status, "observe_only")
    stale["owner_approval_required"] = OWNER_APPROVAL_REQUIRED_BY_STATUS.get(new_status, False)
    stale["apply_status"] = "not_applied"
    stale["stale"] = True
    stale["reconciled"] = True
    stale["reason"] = "Item no longer present in current roadmap; preserved as stale, never applied."
    return stale, override


def reconcile_queue(new_items: List[Dict[str, Any]], existing_items: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """Merge prior owner decisions into freshly built queue items and keep
    stale items. Returns (merged_items, reconcile_stats)."""
    existing_by_roadmap: Dict[str, Dict[str, Any]] = {}
    existing_by_fallback: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    for item in existing_items:
        if not isinstance(item, dict):
            continue
        rid = item.get("roadmap_id")
        if rid:
            existing_by_roadmap.setdefault(str(rid), item)
        existing_by_fallback.setdefault(fallback_key(item), item)

    used_existing_ids = set()
    merged_items: List[Dict[str, Any]] = []
    preserved_count = 0
    override_count = 0

    for new_item in new_items:
        rid = str(new_item.get("roadmap_id", ""))
        match = existing_by_roadmap.get(rid)
        if match is None:
            match = existing_by_fallback.get(fallback_key(new_item))
        if match is not None and id(match) not in used_existing_ids:
            used_existing_ids.add(id(match))
            merged, preserved, override = reconcile_item(new_item, match)
            merged_items.append(merged)
            preserved_count += 1 if preserved else 0
            override_count += 1 if override else 0
        else:
            merged_items.append(new_item)

    # Stale: existing items not matched to any roadmap item.
    stale_count = 0
    for item in existing_items:
        if not isinstance(item, dict):
            continue
        if id(item) in used_existing_ids:
            continue
        stale_item, override = make_stale_item(item)
        merged_items.append(stale_item)
        stale_count += 1
        override_count += 1 if override else 0

    stats = {
        "old_items_count": len([i for i in existing_items if isinstance(i, dict)]),
        "new_roadmap_items_count": len(new_items),
        "reconciled_items_count": len(merged_items),
        "preserved_decisions_count": preserved_count,
        "stale_items_count": stale_count,
        "security_overrides_count": override_count,
    }
    return merged_items, stats


def build_queue() -> Dict[str, Any]:
    created_at = utc_now()
    roadmap_data, roadmap_status = read_optional_json(INPUT_ROADMAP_DRAFT)
    if not isinstance(roadmap_data, dict):
        # Fall back to the report copy if the draft is unavailable.
        roadmap_data, roadmap_status_report = read_optional_json(INPUT_ROADMAP_REPORT)
        roadmap_source_status = (
            f"draft:{roadmap_status},report:{roadmap_status_report}"
        )
    else:
        roadmap_source_status = f"draft:{roadmap_status}"

    autonomy_data, autonomy_status = read_optional_json(INPUT_AUTONOMY_POLICY)

    roadmap_items = []
    if isinstance(roadmap_data, dict) and isinstance(roadmap_data.get("roadmap_items"), list):
        roadmap_items = [i for i in roadmap_data["roadmap_items"] if isinstance(i, dict)]

    new_items = [make_queue_item(item, created_at) for item in roadmap_items]

    # Reconcile: preserve prior owner decisions (Phase 2.2). Existing queue is
    # the owner-maintained draft, if present.
    existing_data, existing_status = read_optional_json(QUEUE_DRAFT_JSON)
    existing_items = []
    if isinstance(existing_data, dict) and isinstance(existing_data.get("queue_items"), list):
        existing_items = [i for i in existing_data["queue_items"] if isinstance(i, dict)]

    queue_items, reconcile_stats = reconcile_queue(new_items, existing_items)
    reconcile_stats["apply_status_summary"] = (
        "all_not_applied"
        if all(i.get("apply_status") == "not_applied" for i in queue_items)
        else "VIOLATION"
    )

    status_counts = {s: 0 for s in ALL_QUEUE_STATUSES}
    for item in queue_items:
        status_counts[item["queue_status"]] = status_counts.get(item["queue_status"], 0) + 1

    breach, breach_problems = detect_queue_breach(queue_items)

    pending_items = [i for i in queue_items if i["queue_status"] == QUEUE_PENDING_OWNER_REVIEW]
    top_pending_items = [
        {"queue_id": i["queue_id"], "title": i["title"], "impact_area": i["impact_area"], "risk_classification": i["risk_classification"]}
        for i in pending_items[:5]
    ]

    context = {
        "current_autonomy_level": redact_text(autonomy_data.get("current_autonomy_level"), default="-") if isinstance(autonomy_data, dict) else "-",
        "autonomy_policy_only": bool(autonomy_data.get("policy_only")) if isinstance(autonomy_data, dict) else None,
        "autonomy_report_status": autonomy_status,
    }

    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": created_at,
        "read_only": True,
        "productive_change": False,
        "secrets_output": False,
        "network_access": False,
        "apply_function": False,
        "accepts_real_approvals": False,
        "status": "READY_FOR_REVIEW" if queue_items else "NOT_AVAILABLE",
        "roadmap_source_status": roadmap_source_status,
        "allowed_write_roots": [str(r) for r in ALLOWED_WRITE_ROOTS],
        "forbidden_mutations": {
            "wordpress": False,
            "htaccess": False,
            "cloudflare": False,
            "nginx": False,
            "external_write": False,
        },
        "context": context,
        "reconcile_enabled": True,
        "reconcile": reconcile_stats,
        "preserved_decisions_count": reconcile_stats["preserved_decisions_count"],
        "stale_items_count": reconcile_stats["stale_items_count"],
        "security_overrides_count": reconcile_stats["security_overrides_count"],
        "queue_items_count": len(queue_items),
        "queue_items": queue_items,
        "status_counts": status_counts,
        "queue_breach": breach,
        "queue_breach_problems": breach_problems,
        "top_pending_items": top_pending_items,
        "summary": {
            "queue_item_count": len(queue_items),
            "pending_owner_review_count": status_counts[QUEUE_PENDING_OWNER_REVIEW],
            "approved_for_draft_only_count": status_counts[QUEUE_APPROVED_FOR_DRAFT_ONLY],
            "approved_for_manual_apply_count": status_counts[QUEUE_APPROVED_FOR_MANUAL_APPLY],
            "rejected_count": status_counts[QUEUE_REJECTED],
            "monitor_only_count": status_counts[QUEUE_MONITOR_ONLY],
            "blocked_high_risk_count": status_counts[QUEUE_BLOCKED_HIGH_RISK],
            "stale_removed_count": status_counts.get(QUEUE_STALE_REMOVED, 0),
            "preserved_decisions_count": reconcile_stats["preserved_decisions_count"],
            "stale_items_count": reconcile_stats["stale_items_count"],
            "security_overrides_count": reconcile_stats["security_overrides_count"],
            "all_not_applied": all(i["apply_status"] == "not_applied" for i in queue_items),
        },
        "outputs": {
            "draft_json": str(QUEUE_DRAFT_JSON),
            "draft_md": str(QUEUE_DRAFT_MD),
            "report_json": str(REPORT_JSON),
            "report_md": str(REPORT_MD),
            "audit_jsonl": str(AUDIT_JSONL),
            "reconcile_audit_jsonl": str(RECONCILE_AUDIT_JSONL),
        },
    }
    return report


def build_reconcile_audit_record(report: Dict[str, Any]) -> Dict[str, Any]:
    stats = report.get("reconcile", {})
    return {
        "timestamp_utc": report["generated_at_utc"],
        "schema_version": SCHEMA_VERSION,
        "event": "owner_approval_queue_reconcile",
        "old_items_count": stats.get("old_items_count", 0),
        "new_roadmap_items_count": stats.get("new_roadmap_items_count", 0),
        "reconciled_items_count": stats.get("reconciled_items_count", 0),
        "preserved_decisions_count": stats.get("preserved_decisions_count", 0),
        "stale_items_count": stats.get("stale_items_count", 0),
        "security_overrides_count": stats.get("security_overrides_count", 0),
        "apply_status_summary": stats.get("apply_status_summary", "all_not_applied"),
        "queue_breach": bool(report.get("queue_breach", False)),
    }


def build_audit_records(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    generated = report["generated_at_utc"]
    records = []
    for item in report.get("queue_items", []):
        records.append({
            "timestamp_utc": generated,
            "schema_version": SCHEMA_VERSION,
            "queue_id": item.get("queue_id", "unknown"),
            "roadmap_id": item.get("roadmap_id", "unknown"),
            "queue_status": item.get("queue_status", "unknown"),
            "risk_classification": item.get("risk_classification", "unknown"),
            "autonomy_policy_class": item.get("autonomy_policy_class", "unknown"),
            "allowed_next_action": item.get("allowed_next_action", "no_action"),
            "owner_approval_required": item.get("owner_approval_required", True),
            "apply_status": item.get("apply_status", "not_applied"),
            "stale": bool(item.get("stale", False)),
        })
    return records


def render_markdown(report: Dict[str, Any]) -> str:
    summary = report.get("summary", {})
    lines: List[str] = []
    lines.append("# Owner Approval Queue (Phase 2.0 — review only)")
    lines.append("")
    lines.append(f"- Generated (UTC): `{report['generated_at_utc']}`")
    lines.append(f"- Status: **{report['status']}**")
    lines.append(
        f"- Items: {summary.get('queue_item_count')} "
        f"(pending_owner_review={summary.get('pending_owner_review_count')}, "
        f"approved_for_draft_only={summary.get('approved_for_draft_only_count')}, "
        f"monitor_only={summary.get('monitor_only_count')}, "
        f"blocked_high_risk={summary.get('blocked_high_risk_count')})"
    )
    lines.append(f"- all_not_applied: {summary.get('all_not_applied')} · queue_breach: {report.get('queue_breach')}")
    lines.append(
        f"- Reconcile: enabled={report.get('reconcile_enabled')}, "
        f"preserved_decisions={report.get('preserved_decisions_count')}, "
        f"stale_items={report.get('stale_items_count')}, "
        f"security_overrides={report.get('security_overrides_count')}"
    )
    lines.append("- Mode: queue/review-only; nothing is applied (apply_status=not_applied). No apply function; no real approvals accepted.")
    lines.append("")

    ctx = report.get("context", {})
    lines.append("## Context")
    lines.append("")
    lines.append(f"- Autonomy level: `{ctx.get('current_autonomy_level')}` · policy_only: `{ctx.get('autonomy_policy_only')}`")
    lines.append(f"- Roadmap source: `{report.get('roadmap_source_status')}`")
    lines.append("")

    lines.append("## Top Pending Owner Review")
    lines.append("")
    top = report.get("top_pending_items", [])
    if top:
        for entry in top:
            lines.append(f"- `{entry['queue_id']}` [{entry['impact_area']}/{entry['risk_classification']}]: {entry['title']}")
    else:
        lines.append("- (none)")
    lines.append("")

    lines.append("## Queue Items")
    lines.append("")
    lines.append("| queue_id | roadmap_id | impact | risk | queue_status | next_action | apply_status |")
    lines.append("|---|---|---|---|---|---|---|")
    for i in report.get("queue_items", []):
        stale_mark = " (stale)" if i.get("stale") else ""
        lines.append(
            f"| `{i.get('queue_id')}` | `{i.get('roadmap_id')}` | {i.get('impact_area')} | "
            f"{i.get('risk_classification')} | `{i.get('queue_status')}`{stale_mark} | "
            f"{i.get('allowed_next_action')} | {i.get('apply_status')} |"
        )
    lines.append("")

    lines.append("## Safety")
    lines.append("")
    lines.append("- Queue/review-only; nothing applied (apply_status=not_applied). No apply function.")
    lines.append("- No real approvals are accepted; only draft-only status is auto-set for unambiguous safe LOW drafts.")
    lines.append("- HIGH is always blocked_high_risk; MEDIUM/REVIEW_ONLY is pending_owner_review; LOW is at most approved_for_draft_only.")
    lines.append("- No WordPress/.htaccess/Cloudflare/Nginx/external change; no network access.")
    lines.append("- No secrets/cookies/authorization values are stored or emitted.")
    lines.append(
        "- Writes restricted to: " + ", ".join(f"`{r}`" for r in report["allowed_write_roots"]) + "."
    )
    lines.append("")
    return "\n".join(lines)


# ===========================================================================
# Self-tests
# ===========================================================================
def run_self_tests() -> int:
    global INPUT_ROADMAP_DRAFT, INPUT_ROADMAP_REPORT, QUEUE_DRAFT_JSON
    # Write-path guard.
    for ok in (QUEUE_DRAFT_JSON, REPORT_JSON, AUDIT_JSONL):
        assert_allowed_write(ok)
    for forbidden in (
        Path("/etc/nginx/q.conf"),
        Path("/var/www/.htaccess"),
        Path("/srv/sentinel-defense/sentinel_master.py"),
        Path("/srv/sentinel-defense/drafts/roadmap/x.json"),
        Path("/srv/sentinel-defense/drafts/seo/y.json"),
    ):
        try:
            assert_allowed_write(forbidden)
        except ValueError:
            pass
        else:
            raise AssertionError(f"forbidden write path not rejected: {forbidden}")

    # Status mapping rules.
    assert decide_queue_status(GROUP_BLOCKED_HIGH_RISK, RISK_HIGH, "BLOCKED_NOT_PERMITTED") == QUEUE_BLOCKED_HIGH_RISK
    assert decide_queue_status(GROUP_MONITOR_ONLY, RISK_HIGH, "BLOCKED_NOT_PERMITTED") == QUEUE_BLOCKED_HIGH_RISK  # HIGH overrides monitor
    assert decide_queue_status(GROUP_MONITOR_ONLY, RISK_MEDIUM, "OWNER_APPROVAL_REQUIRED") == QUEUE_MONITOR_ONLY
    assert decide_queue_status(GROUP_OWNER_REVIEW_REQUIRED, RISK_MEDIUM, "OWNER_APPROVAL_REQUIRED") == QUEUE_PENDING_OWNER_REVIEW
    assert decide_queue_status(GROUP_OWNER_REVIEW_REQUIRED, RISK_REVIEW_ONLY, "OWNER_APPROVAL_REQUIRED") == QUEUE_PENDING_OWNER_REVIEW
    assert decide_queue_status(GROUP_NEXT_SAFE_DRAFTS, RISK_LOW, "LEVEL_1_DRAFT_ONLY") == QUEUE_APPROVED_FOR_DRAFT_ONLY
    # A NEXT_SAFE_DRAFTS item that is not a clean LOW/LEVEL_1 -> pending.
    assert decide_queue_status(GROUP_NEXT_SAFE_DRAFTS, RISK_MEDIUM, "OWNER_APPROVAL_REQUIRED") == QUEUE_PENDING_OWNER_REVIEW

    # make_queue_item: HIGH blocked, MEDIUM pending, LOW draft-only; all not_applied.
    high = make_queue_item({"roadmap_id": "perf:x", "group": GROUP_MONITOR_ONLY, "risk_classification": "HIGH", "autonomy_policy_class": "BLOCKED_NOT_PERMITTED"}, "T")
    assert high["queue_status"] == QUEUE_BLOCKED_HIGH_RISK
    assert high["autonomy_policy_class"] == "BLOCKED_NOT_PERMITTED"
    assert high["apply_status"] == "not_applied"
    med = make_queue_item({"roadmap_id": "seo:s", "group": GROUP_OWNER_REVIEW_REQUIRED, "risk_classification": "MEDIUM", "autonomy_policy_class": "OWNER_APPROVAL_REQUIRED"}, "T")
    assert med["queue_status"] == QUEUE_PENDING_OWNER_REVIEW
    assert med["owner_approval_required"] is True
    assert med["apply_status"] == "not_applied"
    low = make_queue_item({"roadmap_id": "seo:title", "group": GROUP_NEXT_SAFE_DRAFTS, "risk_classification": "LOW", "autonomy_policy_class": "LEVEL_1_DRAFT_ONLY"}, "T")
    assert low["queue_status"] == QUEUE_APPROVED_FOR_DRAFT_ONLY
    assert low["apply_status"] == "not_applied"
    # LOW never reaches manual-apply automatically.
    assert low["queue_status"] != QUEUE_APPROVED_FOR_MANUAL_APPLY

    # Breach detection.
    ok_items = [high, med, low]
    breach, problems = detect_queue_breach(ok_items)
    assert breach is False and problems == []
    bad_high = dict(high)
    bad_high["queue_status"] = QUEUE_MONITOR_ONLY  # HIGH not blocked -> breach
    breach2, problems2 = detect_queue_breach([bad_high])
    assert breach2 is True and problems2

    # Secret redaction.
    secret = make_queue_item({"roadmap_id": "x", "group": GROUP_NEXT_SAFE_DRAFTS, "risk_classification": "LOW", "autonomy_policy_class": "LEVEL_1_DRAFT_ONLY", "title": "Bearer abc123 token", "source": "src"}, "T")
    assert secret["title"] == "[redacted]"

    # Full build does not crash and stays read-only.
    report = build_queue()
    assert report["productive_change"] is False
    assert report["apply_function"] is False
    assert report["accepts_real_approvals"] is False
    assert report["summary"]["all_not_applied"] is True
    for item in report["queue_items"]:
        assert item["apply_status"] == "not_applied"
        if item["risk_classification"] == RISK_HIGH:
            assert item["queue_status"] == QUEUE_BLOCKED_HIGH_RISK
    audit_records = build_audit_records(report)
    assert len(audit_records) == len(report["queue_items"])
    assert all(r["apply_status"] == "not_applied" for r in audit_records)
    md = render_markdown(report)
    assert "Owner Approval Queue" in md

    # --- Reconcile logic (Phase 2.2) -----------------------------------
    # New items freshly built from a synthetic roadmap.
    roadmap = [
        {"roadmap_id": "seo:title", "group": GROUP_NEXT_SAFE_DRAFTS, "risk_classification": "LOW", "autonomy_policy_class": "LEVEL_1_DRAFT_ONLY", "source": "seo", "title": "Title", "impact_area": "SEO"},
        {"roadmap_id": "perf:embeds", "group": GROUP_OWNER_REVIEW_REQUIRED, "risk_classification": "MEDIUM", "autonomy_policy_class": "OWNER_APPROVAL_REQUIRED", "source": "perf", "title": "Embeds", "impact_area": "Performance"},
        {"roadmap_id": "perf:microcache", "group": GROUP_MONITOR_ONLY, "risk_classification": "HIGH", "autonomy_policy_class": "BLOCKED_NOT_PERMITTED", "source": "perf", "title": "Microcache", "impact_area": "Stability"},
        {"roadmap_id": "seo:schema", "group": GROUP_OWNER_REVIEW_REQUIRED, "risk_classification": "REVIEW_ONLY", "autonomy_policy_class": "OWNER_APPROVAL_REQUIRED", "source": "seo", "title": "Schema", "impact_area": "SEO"},
    ]
    new_items = [make_queue_item(r, "T") for r in roadmap]

    # Existing owner-edited queue (incl. a manipulated HIGH and a stale item).
    existing = [
        {"queue_id": "approval:seo:title", "roadmap_id": "seo:title", "source": "seo", "title": "Title",
         "impact_area": "SEO", "risk_classification": "LOW", "queue_status": QUEUE_APPROVED_FOR_DRAFT_ONLY,
         "apply_status": "not_applied", "owner_note": "looks good", "last_owner_action": "approve-draft-only"},
        {"queue_id": "approval:perf:embeds", "roadmap_id": "perf:embeds", "source": "perf", "title": "Embeds",
         "impact_area": "Performance", "risk_classification": "MEDIUM", "queue_status": QUEUE_PENDING_OWNER_REVIEW,
         "apply_status": "not_applied", "owner_note": "needs review"},
        {"queue_id": "approval:perf:microcache", "roadmap_id": "perf:microcache", "source": "perf", "title": "Microcache",
         "impact_area": "Stability", "risk_classification": "HIGH", "queue_status": QUEUE_APPROVED_FOR_DRAFT_ONLY,  # manipulated!
         "apply_status": "not_applied"},
        {"queue_id": "approval:seo:schema", "roadmap_id": "seo:schema", "source": "seo", "title": "Schema",
         "impact_area": "SEO", "risk_classification": "REVIEW_ONLY", "queue_status": QUEUE_APPROVED_FOR_DRAFT_ONLY,  # manipulated!
         "apply_status": "not_applied"},
        {"queue_id": "approval:old:gone", "roadmap_id": "old:gone", "source": "seo", "title": "Removed item",
         "impact_area": "SEO", "risk_classification": "LOW", "queue_status": QUEUE_APPROVED_FOR_DRAFT_ONLY,
         "apply_status": "not_applied", "owner_note": "kept around"},
    ]

    merged, stats = reconcile_queue(new_items, existing)
    by_id = {m["queue_id"]: m for m in merged}

    # LOW decision + owner_note preserved.
    assert by_id["approval:seo:title"]["queue_status"] == QUEUE_APPROVED_FOR_DRAFT_ONLY
    assert by_id["approval:seo:title"]["owner_note"] == "looks good"
    # MEDIUM stays pending_owner_review.
    assert by_id["approval:perf:embeds"]["queue_status"] == QUEUE_PENDING_OWNER_REVIEW
    assert by_id["approval:perf:embeds"]["owner_note"] == "needs review"
    # HIGH manipulated -> security override to blocked_high_risk.
    assert by_id["approval:perf:microcache"]["queue_status"] == QUEUE_BLOCKED_HIGH_RISK
    # MEDIUM/REVIEW_ONLY manipulated draft-only -> override to pending_owner_review.
    assert by_id["approval:seo:schema"]["queue_status"] == QUEUE_PENDING_OWNER_REVIEW
    # Stale item kept and marked stale.
    stale = by_id["approval:old:gone"]
    assert stale.get("stale") is True
    assert stale["queue_status"] == QUEUE_STALE_REMOVED
    assert stale["owner_note"] == "kept around"
    # apply_status everywhere not_applied; manual-apply never present.
    assert all(m["apply_status"] == "not_applied" for m in merged)
    assert not any(m["queue_status"] == QUEUE_APPROVED_FOR_MANUAL_APPLY for m in merged)
    # Stats are coherent.
    assert stats["old_items_count"] == 5
    assert stats["new_roadmap_items_count"] == 4
    assert stats["stale_items_count"] == 1
    assert stats["security_overrides_count"] >= 2  # HIGH + schema (+ maybe)
    assert stats["preserved_decisions_count"] >= 2  # title + embeds

    # Fallback matching by (source,title,impact_area) when roadmap_id changed.
    new_renamed = [make_queue_item({"roadmap_id": "seo:title-v2", "group": GROUP_NEXT_SAFE_DRAFTS, "risk_classification": "LOW", "autonomy_policy_class": "LEVEL_1_DRAFT_ONLY", "source": "seo", "title": "Title", "impact_area": "SEO"}, "T")]
    existing_renamed = [{"queue_id": "approval:seo:title", "roadmap_id": "seo:title", "source": "seo", "title": "Title", "impact_area": "SEO", "risk_classification": "LOW", "queue_status": QUEUE_REJECTED, "apply_status": "not_applied", "owner_note": "no"}]
    merged2, _ = reconcile_queue(new_renamed, existing_renamed)
    assert merged2[0]["queue_status"] == QUEUE_REJECTED  # preserved via fallback
    assert merged2[0]["queue_id"] == "approval:seo:title"  # stable queue_id
    assert merged2[0]["owner_note"] == "no"

    # Missing roadmap AND no prior queue must not crash (empty queue).
    saved_draft, saved_report, saved_queue = INPUT_ROADMAP_DRAFT, INPUT_ROADMAP_REPORT, QUEUE_DRAFT_JSON
    try:
        INPUT_ROADMAP_DRAFT = PROJECT_DIR / "drafts/roadmap/__no_such__.json"
        INPUT_ROADMAP_REPORT = PROJECT_DIR / "reports/latest/__no_such__.json"
        QUEUE_DRAFT_JSON = PROJECT_DIR / "drafts/approval/__no_such_queue__.json"
        empty = build_queue()
        assert empty["status"] == "NOT_AVAILABLE"
        assert empty["queue_items"] == []
        assert empty["summary"]["all_not_applied"] is True
        assert empty["reconcile_enabled"] is True
        assert empty["stale_items_count"] == 0
    finally:
        INPUT_ROADMAP_DRAFT, INPUT_ROADMAP_REPORT, QUEUE_DRAFT_JSON = saved_draft, saved_report, saved_queue

    print("owner-approval-queue self-tests: OK")
    return 0


# ===========================================================================
# CLI
# ===========================================================================
def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sentinel Owner Approval Queue (read-only; no real approvals)."
    )
    parser.add_argument("--self-test", action="store_true", help="Run built-in safety/unit tests.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_tests()

    report = build_queue()
    md = render_markdown(report)
    write_json_atomic(QUEUE_DRAFT_JSON, report)
    write_text_atomic(QUEUE_DRAFT_MD, md)
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, md)
    append_jsonl_atomic(AUDIT_JSONL, build_audit_records(report))
    append_jsonl_atomic(RECONCILE_AUDIT_JSONL, [build_reconcile_audit_record(report)])
    print(f"Owner approval queue draft (JSON):  {QUEUE_DRAFT_JSON}")
    print(f"Owner approval queue draft (MD):    {QUEUE_DRAFT_MD}")
    print(f"Owner approval queue report (JSON): {REPORT_JSON}")
    print(f"Owner approval queue report (MD):   {REPORT_MD}")
    print(f"Owner approval queue audit (JSONL): {AUDIT_JSONL}")
    print(f"Owner approval reconcile audit:     {RECONCILE_AUDIT_JSONL}")
    s = report["summary"]
    print(
        f"status={report['status']} items={s['queue_item_count']} "
        f"pending={s['pending_owner_review_count']} draft_only={s['approved_for_draft_only_count']} "
        f"monitor={s['monitor_only_count']} blocked_high={s['blocked_high_risk_count']} "
        f"| reconcile: preserved={report['preserved_decisions_count']} "
        f"stale={report['stale_items_count']} overrides={report['security_overrides_count']} "
        "(read-only, no apply function)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
