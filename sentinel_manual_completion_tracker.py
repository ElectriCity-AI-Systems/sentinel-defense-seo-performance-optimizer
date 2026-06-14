#!/usr/bin/env python3
"""Sentinel Manual Completion Tracker (Phase 2.7).

Tracks owner-reported progress for Manual Apply Checklist items. This module
does not apply anything live: no WordPress login, no API calls, no network
access, and no production writes. It only writes tracker metadata under
drafts/manual, reports/latest, and audit.
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


PROJECT_DIR = Path("/srv/sentinel-defense")

INPUT_CHECKLIST_JSON = PROJECT_DIR / "drafts/manual/manual-apply-checklist.json"
INPUT_POST_VALIDATION_JSON = PROJECT_DIR / "reports/latest/post-manual-validation-report.json"

CHECKLIST_JSON = PROJECT_DIR / "drafts/manual/manual-apply-checklist.json"
CHECKLIST_MD = PROJECT_DIR / "drafts/manual/manual-apply-checklist.md"
REPORT_JSON = PROJECT_DIR / "reports/latest/manual-completion-tracker-report.json"
REPORT_MD = PROJECT_DIR / "reports/latest/manual-completion-tracker-report.md"
AUDIT_JSONL = PROJECT_DIR / "audit/manual-completion-tracker.jsonl"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "drafts/manual",
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "audit",
)

SCHEMA_VERSION = "manual-completion-tracker-2.7"

APPLY_NOT_APPLIED = "not_applied"
RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"
RISK_REVIEW_ONLY = "REVIEW_ONLY"

COMPLETION_UNCHECKED = "unchecked"
COMPLETION_IN_PROGRESS = "in_progress"
COMPLETION_COMPLETED = "completed"
COMPLETION_SKIPPED = "skipped"
COMPLETION_NEEDS_REVIEW = "needs_review"
VALID_COMPLETION_STATUSES = {
    COMPLETION_UNCHECKED,
    COMPLETION_IN_PROGRESS,
    COMPLETION_COMPLETED,
    COMPLETION_SKIPPED,
    COMPLETION_NEEDS_REVIEW,
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


class TrackerError(Exception):
    """Expected CLI validation error. These errors write no output."""


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def redact_text(value: Any, default: str = "-", max_len: int = 800) -> str:
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


def sanitize_value(value: Any, *, max_len: int = 2600) -> Any:
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


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def assert_allowed_write(path: Path) -> None:
    if not any(is_within(path, root) for root in ALLOWED_WRITE_ROOTS):
        raise ValueError(f"Refusing to write outside allowed completion tracker roots: {path}")


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


def normalize_risk(value: Any) -> str:
    risk = str(value or "").strip().upper()
    if risk in {RISK_LOW, RISK_MEDIUM, RISK_HIGH, RISK_REVIEW_ONLY}:
        return risk
    return RISK_REVIEW_ONLY


def normalize_completion(value: Any) -> str:
    status = str(value or "").strip().lower()
    if status in VALID_COMPLETION_STATUSES:
        return status
    return COMPLETION_UNCHECKED


def checklist_items_from(data: Optional[Any]) -> List[Dict[str, Any]]:
    if not isinstance(data, dict) or not isinstance(data.get("checklist_items"), list):
        return []
    return [item for item in data["checklist_items"] if isinstance(item, dict)]


def apply_status_summary(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    not_applied_count = 0
    other_count = 0
    other_ids: List[str] = []
    for item in items:
        if item.get("apply_status") == APPLY_NOT_APPLIED:
            not_applied_count += 1
        else:
            other_count += 1
            other_ids.append(redact_text(item.get("checklist_id"), max_len=160))
    return {
        "all_not_applied": other_count == 0,
        "not_applied_count": not_applied_count,
        "other_apply_status_count": other_count,
        "other_apply_status_item_ids": other_ids,
    }


def completion_counts(items: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {
        COMPLETION_COMPLETED: 0,
        COMPLETION_IN_PROGRESS: 0,
        COMPLETION_SKIPPED: 0,
        COMPLETION_NEEDS_REVIEW: 0,
        COMPLETION_UNCHECKED: 0,
    }
    for item in items:
        counts[normalize_completion(item.get("completion_status"))] += 1
    return counts


def find_item(items: List[Dict[str, Any]], checklist_id: str) -> Optional[Dict[str, Any]]:
    for item in items:
        if item.get("checklist_id") == checklist_id:
            return item
    return None


def completion_breach(items: List[Dict[str, Any]], productive_change: bool) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    summary = apply_status_summary(items)
    if summary["other_apply_status_count"] > 0:
        reasons.append("apply_status != not_applied")
    if productive_change:
        reasons.append("productive_change=true")
    high_medium_completed = [
        redact_text(item.get("checklist_id"), max_len=160)
        for item in items
        if normalize_completion(item.get("completion_status")) == COMPLETION_COMPLETED
        and normalize_risk(item.get("risk_classification")) in {RISK_HIGH, RISK_MEDIUM}
    ]
    if high_medium_completed:
        reasons.append("HIGH/MEDIUM item marked completed")
    return bool(reasons), reasons


def build_last_action(command: str, checklist_id: Optional[str], note: Optional[str], timestamp: str) -> Dict[str, Any]:
    return {
        "timestamp_utc": timestamp,
        "command": command,
        "checklist_id": redact_text(checklist_id, default="", max_len=180) if checklist_id else None,
        "note": redact_text(note, default="", max_len=1000) if note else "",
    }


def previous_last_action() -> Optional[Dict[str, Any]]:
    data, status = read_optional_json(REPORT_JSON)
    if status != "ok" or not isinstance(data, dict):
        return None
    action = data.get("last_owner_completion_action")
    return action if isinstance(action, dict) else None


def build_report(
    checklist_data: Optional[Any],
    checklist_status: str,
    post_validation_data: Optional[Any],
    post_validation_status: str,
    *,
    last_action: Optional[Dict[str, Any]],
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    generated = generated_at or utc_now()
    items = checklist_items_from(checklist_data)
    counts = completion_counts(items)
    apply_summary = apply_status_summary(items)
    productive_change = bool(checklist_data.get("productive_change", False)) if isinstance(checklist_data, dict) else False
    breach, breach_reasons = completion_breach(items, productive_change)
    status = "COMPLETION_WARNING" if breach else ("NO_CHECKLIST_AVAILABLE" if checklist_status != "ok" else "OK")
    post_status = (
        post_validation_data.get("status")
        if isinstance(post_validation_data, dict)
        else "NOT_AVAILABLE"
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
        "productive_change": productive_change,
        "secrets_output": False,
        "allowed_write_roots": [str(path) for path in ALLOWED_WRITE_ROOTS],
        "input_statuses": {
            "manual_apply_checklist": checklist_status,
            "post_manual_validation_report": post_validation_status,
        },
        "post_manual_validation_status": post_status,
        "checklist_items_count": len(items),
        "completed_count": counts[COMPLETION_COMPLETED],
        "in_progress_count": counts[COMPLETION_IN_PROGRESS],
        "skipped_count": counts[COMPLETION_SKIPPED],
        "needs_review_count": counts[COMPLETION_NEEDS_REVIEW],
        "unchecked_count": counts[COMPLETION_UNCHECKED],
        "apply_status_summary": apply_summary,
        "completion_breach": breach,
        "completion_breach_reasons": breach_reasons,
        "high_medium_completed_count": sum(
            1
            for item in items
            if normalize_completion(item.get("completion_status")) == COMPLETION_COMPLETED
            and normalize_risk(item.get("risk_classification")) in {RISK_HIGH, RISK_MEDIUM}
        ),
        "last_owner_completion_action": last_action,
        "completion_items": [
            {
                "checklist_id": redact_text(item.get("checklist_id"), max_len=180),
                "section": redact_text(item.get("section"), max_len=220),
                "risk_classification": normalize_risk(item.get("risk_classification")),
                "apply_status": redact_text(item.get("apply_status"), max_len=80),
                "completion_status": normalize_completion(item.get("completion_status")),
                "owner_notes_count": len(item.get("owner_notes", [])) if isinstance(item.get("owner_notes"), list) else 0,
            }
            for item in items
        ],
        "outputs": {
            "checklist_json": str(CHECKLIST_JSON),
            "checklist_md": str(CHECKLIST_MD),
            "report_json": str(REPORT_JSON),
            "report_md": str(REPORT_MD),
            "audit_jsonl": str(AUDIT_JSONL),
        },
    }


def update_item_status(
    checklist_data: Dict[str, Any],
    checklist_id: str,
    new_status: Optional[str],
    note: str,
    command: str,
    timestamp: str,
) -> Dict[str, Any]:
    updated = copy.deepcopy(checklist_data)
    items = checklist_items_from(updated)
    target = find_item(items, checklist_id)
    if target is None:
        raise TrackerError(f"checklist_id not found: {redact_text(checklist_id, max_len=180)}")

    original_apply_status = target.get("apply_status")
    risk = normalize_risk(target.get("risk_classification"))
    if new_status == COMPLETION_COMPLETED and risk in {RISK_HIGH, RISK_MEDIUM}:
        raise TrackerError("HIGH/MEDIUM checklist items cannot be marked completed")
    if original_apply_status != APPLY_NOT_APPLIED:
        raise TrackerError("Refusing to update completion for item whose apply_status is not not_applied")

    for item in items:
        if "completion_status" not in item:
            item["completion_status"] = COMPLETION_UNCHECKED
        else:
            item["completion_status"] = normalize_completion(item.get("completion_status"))

    if new_status is not None:
        target["completion_status"] = new_status
    target["completion_updated_at_utc"] = timestamp
    target["completion_updated_by"] = "owner_reported_manual_tracker"
    notes = target.get("owner_notes")
    if not isinstance(notes, list):
        notes = []
    notes.append(
        {
            "timestamp_utc": timestamp,
            "command": command,
            "completion_status": target.get("completion_status"),
            "note": redact_text(note, default="", max_len=1000),
        }
    )
    target["owner_notes"] = notes[-20:]

    if target.get("apply_status") != original_apply_status:
        raise TrackerError("Internal safety error: apply_status changed")

    updated["completion_tracker_schema_version"] = SCHEMA_VERSION
    updated["completion_updated_at_utc"] = timestamp
    updated["last_owner_completion_action"] = build_last_action(command, checklist_id, note, timestamp)
    counts = completion_counts(items)
    updated["completion_status_summary"] = {
        "completed_count": counts[COMPLETION_COMPLETED],
        "in_progress_count": counts[COMPLETION_IN_PROGRESS],
        "skipped_count": counts[COMPLETION_SKIPPED],
        "needs_review_count": counts[COMPLETION_NEEDS_REVIEW],
        "unchecked_count": counts[COMPLETION_UNCHECKED],
    }
    updated["apply_status_summary"] = apply_status_summary(items)
    return updated


def render_payload(value: Any) -> str:
    if value is None:
        return "-"
    safe = sanitize_value(value)
    if isinstance(safe, (dict, list)):
        return json.dumps(safe, ensure_ascii=False, indent=2, sort_keys=True)
    return str(safe)


def render_checklist_markdown(checklist_data: Dict[str, Any], tracker_report: Dict[str, Any]) -> str:
    items = checklist_items_from(checklist_data)
    lines = [
        "# Manual Apply Checklist",
        "",
        f"- Tracker generated (UTC): `{tracker_report.get('generated_at_utc')}`",
        f"- Completion tracker status: `{tracker_report.get('status')}`",
        f"- Items: `{tracker_report.get('checklist_items_count')}`",
        f"- Completed: `{tracker_report.get('completed_count')}`",
        f"- In progress: `{tracker_report.get('in_progress_count')}`",
        f"- Needs review: `{tracker_report.get('needs_review_count')}`",
        f"- Skipped: `{tracker_report.get('skipped_count')}`",
        f"- Unchecked: `{tracker_report.get('unchecked_count')}`",
        f"- Completion breach: `{tracker_report.get('completion_breach')}`",
        "",
        "| Checklist ID | Section | Risk | Apply Status | Completion |",
        "|---|---|---|---|---|",
    ]
    for item in items:
        lines.append(
            "| "
            f"`{redact_text(item.get('checklist_id'), max_len=160)}` | "
            f"{redact_text(item.get('section'), max_len=180)} | "
            f"`{normalize_risk(item.get('risk_classification'))}` | "
            f"`{redact_text(item.get('apply_status'), max_len=80)}` | "
            f"`{normalize_completion(item.get('completion_status'))}` |"
        )
    lines.extend(["", "## Item Details", ""])
    for item in items:
        lines.extend(
            [
                f"### {redact_text(item.get('checklist_id'), max_len=180)}",
                "",
                f"- Section: `{redact_text(item.get('section'), max_len=220)}`",
                f"- Completion status: `{normalize_completion(item.get('completion_status'))}`",
                f"- Apply status: `{redact_text(item.get('apply_status'), max_len=80)}`",
                f"- Risk: `{normalize_risk(item.get('risk_classification'))}`",
                f"- Manual action: {redact_text(item.get('manual_action'), max_len=500)}",
                "",
                "**Manual steps:**",
                "",
            ]
        )
        steps = item.get("manual_apply_steps") if isinstance(item.get("manual_apply_steps"), list) else []
        for step in steps:
            lines.append(f"- {redact_text(step, max_len=500)}")
        lines.extend(["", "**Post-check:**", ""])
        post_checks = item.get("post_check") if isinstance(item.get("post_check"), list) else []
        for check in post_checks:
            lines.append(f"- {redact_text(check, max_len=500)}")
        lines.extend(
            [
                "",
                f"**Rollback note:** {redact_text(item.get('rollback_note'), max_len=500)}",
                "",
            ]
        )
        owner_notes = item.get("owner_notes") if isinstance(item.get("owner_notes"), list) else []
        if owner_notes:
            lines.extend(["**Owner notes:**", ""])
            for note in owner_notes[-5:]:
                if isinstance(note, dict):
                    lines.append(
                        "- "
                        f"`{redact_text(note.get('timestamp_utc'), max_len=80)}` "
                        f"`{redact_text(note.get('command'), max_len=80)}` "
                        f"{redact_text(note.get('note'), max_len=500)}"
                    )
            lines.append("")
    lines.extend(
        [
            "## Safety Boundaries",
            "",
            "- Keine Live-Aenderungen.",
            "- Kein WordPress-Login, keine API, kein Netzwerkzugriff.",
            "- apply_status bleibt `not_applied`.",
            "- Completion bedeutet nur Owner-gemeldeten manuellen Fortschritt.",
            "",
        ]
    )
    return "\n".join(lines)


def render_report_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# Manual Completion Tracker Report",
        "",
        f"- Generated (UTC): `{report.get('generated_at_utc')}`",
        f"- Status: `{report.get('status')}`",
        f"- Checklist items: `{report.get('checklist_items_count')}`",
        f"- Completed: `{report.get('completed_count')}`",
        f"- In progress: `{report.get('in_progress_count')}`",
        f"- Skipped: `{report.get('skipped_count')}`",
        f"- Needs review: `{report.get('needs_review_count')}`",
        f"- Unchecked: `{report.get('unchecked_count')}`",
        f"- Completion breach: `{report.get('completion_breach')}`",
        "",
    ]
    action = report.get("last_owner_completion_action")
    if isinstance(action, dict):
        lines.extend(
            [
                "## Last Owner Completion Action",
                "",
                f"- Command: `{redact_text(action.get('command'), max_len=120)}`",
                f"- Checklist ID: `{redact_text(action.get('checklist_id'), default='', max_len=180)}`",
                f"- Timestamp: `{redact_text(action.get('timestamp_utc'), max_len=80)}`",
                f"- Note: {redact_text(action.get('note'), default='', max_len=500)}",
                "",
            ]
        )
    lines.extend(
        [
            "## Completion Items",
            "",
            "| Checklist ID | Section | Completion | Risk | Apply Status | Notes |",
            "|---|---|---|---|---|---|",
        ]
    )
    for item in report.get("completion_items", []):
        if not isinstance(item, dict):
            continue
        lines.append(
            "| "
            f"`{redact_text(item.get('checklist_id'), max_len=160)}` | "
            f"{redact_text(item.get('section'), max_len=180)} | "
            f"`{redact_text(item.get('completion_status'), max_len=80)}` | "
            f"`{redact_text(item.get('risk_classification'), max_len=80)}` | "
            f"`{redact_text(item.get('apply_status'), max_len=80)}` | "
            f"`{item.get('owner_notes_count', 0)}` |"
        )
    lines.extend(
        [
            "",
            "## Safety Boundaries",
            "",
            "- Keine Live-Aenderungen.",
            "- Keine WordPress-, .htaccess-, Cloudflare- oder Nginx-Aenderung.",
            "- Kein Netzwerkzugriff, kein Login, keine API.",
            "- Completion-Status ist Owner-Tracking; `apply_status` bleibt `not_applied`.",
            "",
        ]
    )
    return "\n".join(lines)


def audit_record(report: Dict[str, Any], command: str, checklist_id: Optional[str]) -> Dict[str, Any]:
    return {
        "timestamp_utc": report.get("generated_at_utc"),
        "schema_version": SCHEMA_VERSION,
        "command": command,
        "checklist_id": redact_text(checklist_id, default="", max_len=180) if checklist_id else None,
        "status": report.get("status"),
        "completion_breach": report.get("completion_breach"),
        "completed_count": report.get("completed_count"),
        "in_progress_count": report.get("in_progress_count"),
        "skipped_count": report.get("skipped_count"),
        "needs_review_count": report.get("needs_review_count"),
        "unchecked_count": report.get("unchecked_count"),
        "productive_change": report.get("productive_change"),
        "network_access": False,
        "apply_function": False,
    }


def write_tracker_outputs(
    checklist_data: Dict[str, Any],
    report: Dict[str, Any],
    *,
    write_checklist: bool,
    command: str,
    checklist_id: Optional[str],
) -> None:
    if write_checklist:
        write_json_atomic(CHECKLIST_JSON, checklist_data)
        write_text_atomic(CHECKLIST_MD, render_checklist_markdown(checklist_data, report))
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, render_report_markdown(report))
    append_jsonl(AUDIT_JSONL, [audit_record(report, command, checklist_id)])


def print_list(report: Dict[str, Any]) -> None:
    print("Checklist items:")
    for item in report.get("completion_items", []):
        if not isinstance(item, dict):
            continue
        print(
            f"- {item.get('checklist_id')} | "
            f"completion={item.get('completion_status')} | "
            f"risk={item.get('risk_classification')} | "
            f"apply_status={item.get('apply_status')} | "
            f"section={item.get('section')}"
        )
    print(
        "Summary: "
        f"completed={report.get('completed_count')} "
        f"in_progress={report.get('in_progress_count')} "
        f"needs_review={report.get('needs_review_count')} "
        f"skipped={report.get('skipped_count')} "
        f"unchecked={report.get('unchecked_count')}"
    )


def print_show(item: Dict[str, Any]) -> None:
    print(f"Checklist ID: {redact_text(item.get('checklist_id'), max_len=180)}")
    print(f"Section: {redact_text(item.get('section'), max_len=220)}")
    print(f"Risk: {normalize_risk(item.get('risk_classification'))}")
    print(f"Apply status: {redact_text(item.get('apply_status'), max_len=80)}")
    print(f"Completion status: {normalize_completion(item.get('completion_status'))}")
    print(f"Manual action: {redact_text(item.get('manual_action'), max_len=500)}")
    print("Manual steps:")
    for step in item.get("manual_apply_steps", []) if isinstance(item.get("manual_apply_steps"), list) else []:
        print(f"- {redact_text(step, max_len=500)}")
    print("Pre-check:")
    for check in item.get("pre_check", []) if isinstance(item.get("pre_check"), list) else []:
        print(f"- {redact_text(check, max_len=500)}")
    print("Post-check:")
    for check in item.get("post_check", []) if isinstance(item.get("post_check"), list) else []:
        print(f"- {redact_text(check, max_len=500)}")
    print(f"Rollback note: {redact_text(item.get('rollback_note'), max_len=500)}")
    print("Copy-paste payload:")
    print(render_payload(item.get("copy_paste_payload")))


def command_to_completion(command: str) -> Optional[str]:
    return {
        "mark-in-progress": COMPLETION_IN_PROGRESS,
        "mark-completed": COMPLETION_COMPLETED,
        "mark-skipped": COMPLETION_SKIPPED,
        "mark-needs-review": COMPLETION_NEEDS_REVIEW,
        "comment": None,
    }[command]


def run_command(args: argparse.Namespace) -> int:
    checklist_data, checklist_status = read_optional_json(INPUT_CHECKLIST_JSON)
    post_validation_data, post_validation_status = read_optional_json(INPUT_POST_VALIDATION_JSON)
    command = args.command or "list"
    timestamp = utc_now()

    if command in {"mark-in-progress", "mark-completed", "mark-skipped", "mark-needs-review", "comment"}:
        if checklist_status != "ok" or not isinstance(checklist_data, dict):
            raise TrackerError("Manual Apply Checklist is not available; no writes performed")
        checklist_id = args.checklist_id
        note = args.note
        original_apply_statuses = [
            (item.get("checklist_id"), item.get("apply_status"))
            for item in checklist_items_from(checklist_data)
        ]
        updated = update_item_status(
            checklist_data,
            checklist_id,
            command_to_completion(command),
            note,
            command,
            timestamp,
        )
        new_apply_statuses = [
            (item.get("checklist_id"), item.get("apply_status"))
            for item in checklist_items_from(updated)
        ]
        if original_apply_statuses != new_apply_statuses:
            raise TrackerError("Internal safety error: apply_status changed")
        report = build_report(
            updated,
            "ok",
            post_validation_data,
            post_validation_status,
            last_action=updated.get("last_owner_completion_action"),
            generated_at=timestamp,
        )
        write_tracker_outputs(updated, report, write_checklist=True, command=command, checklist_id=checklist_id)
        print(f"{command}: {redact_text(checklist_id, max_len=180)} -> OK; apply_status remains not_applied")
        return 0

    if command == "show":
        if checklist_status != "ok" or not isinstance(checklist_data, dict):
            raise TrackerError("Manual Apply Checklist is not available")
        item = find_item(checklist_items_from(checklist_data), args.checklist_id)
        if item is None:
            raise TrackerError(f"checklist_id not found: {redact_text(args.checklist_id, max_len=180)}")
        report = build_report(
            checklist_data,
            checklist_status,
            post_validation_data,
            post_validation_status,
            last_action=previous_last_action(),
            generated_at=timestamp,
        )
        write_tracker_outputs(checklist_data, report, write_checklist=False, command=command, checklist_id=args.checklist_id)
        print_show(item)
        return 0

    if command == "list":
        report = build_report(
            checklist_data,
            checklist_status,
            post_validation_data,
            post_validation_status,
            last_action=previous_last_action(),
            generated_at=timestamp,
        )
        if isinstance(checklist_data, dict):
            write_tracker_outputs(checklist_data, report, write_checklist=False, command=command, checklist_id=None)
        else:
            write_json_atomic(REPORT_JSON, report)
            write_text_atomic(REPORT_MD, render_report_markdown(report))
        print_list(report)
        return 0

    raise TrackerError(f"unsupported command: {redact_text(command)}")


def run_self_test() -> int:
    sample = {
        "productive_change": False,
        "checklist_items": [
            {
                "checklist_id": "manual_check:low",
                "risk_classification": "LOW",
                "apply_status": APPLY_NOT_APPLIED,
                "section": "SEO Title",
                "manual_action": "Review title",
            },
            {
                "checklist_id": "manual_check:high",
                "risk_classification": "HIGH",
                "apply_status": APPLY_NOT_APPLIED,
                "section": "Risk test",
                "manual_action": "Do not complete",
            },
        ],
    }
    updated = update_item_status(sample, "manual_check:low", COMPLETION_IN_PROGRESS, "starting review", "mark-in-progress", "2026-06-10T00:00:00Z")
    item = find_item(checklist_items_from(updated), "manual_check:low")
    if not item or item.get("completion_status") != COMPLETION_IN_PROGRESS:
        raise AssertionError("mark-in-progress failed")
    updated = update_item_status(updated, "manual_check:low", COMPLETION_COMPLETED, "manual owner done", "mark-completed", "2026-06-10T00:01:00Z")
    item = find_item(checklist_items_from(updated), "manual_check:low")
    if not item or item.get("completion_status") != COMPLETION_COMPLETED:
        raise AssertionError("mark-completed failed")
    updated = update_item_status(updated, "manual_check:low", COMPLETION_SKIPPED, "skip for now", "mark-skipped", "2026-06-10T00:02:00Z")
    updated = update_item_status(updated, "manual_check:low", COMPLETION_NEEDS_REVIEW, "needs owner review", "mark-needs-review", "2026-06-10T00:03:00Z")
    updated = update_item_status(updated, "manual_check:low", None, "token=abc123 should redact", "comment", "2026-06-10T00:04:00Z")
    item = find_item(checklist_items_from(updated), "manual_check:low")
    if not item or item.get("apply_status") != APPLY_NOT_APPLIED:
        raise AssertionError("apply_status changed")
    if item["owner_notes"][-1]["note"] != "[redacted]":
        raise AssertionError("owner note redaction failed")
    try:
        update_item_status(updated, "manual_check:high", COMPLETION_COMPLETED, "bad", "mark-completed", "2026-06-10T00:05:00Z")
    except TrackerError:
        pass
    else:
        raise AssertionError("HIGH completion was not blocked")
    try:
        update_item_status(updated, "missing", COMPLETION_IN_PROGRESS, "bad", "mark-in-progress", "2026-06-10T00:06:00Z")
    except TrackerError:
        pass
    else:
        raise AssertionError("missing checklist_id was not blocked")
    report = build_report(updated, "ok", {}, "not_available", last_action=None, generated_at="2026-06-10T00:07:00Z")
    if report["completion_breach"]:
        raise AssertionError("normal completion state produced breach")
    bad = copy.deepcopy(updated)
    high_item = find_item(checklist_items_from(bad), "manual_check:high")
    if high_item:
        high_item["completion_status"] = COMPLETION_COMPLETED
    bad_report = build_report(bad, "ok", {}, "not_available", last_action=None, generated_at="2026-06-10T00:08:00Z")
    if not bad_report["completion_breach"]:
        raise AssertionError("HIGH completed did not produce breach")
    try:
        assert_allowed_write(PROJECT_DIR / "forbidden/manual-completion.json")
    except ValueError:
        pass
    else:
        raise AssertionError("forbidden write path was not rejected")
    print("manual-completion-tracker self-tests: OK")
    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Track owner-reported manual checklist completion.")
    parser.add_argument("--self-test", action="store_true", help="Run in-memory safety tests and exit.")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("list", help="List checklist items and completion status.")

    show = subparsers.add_parser("show", help="Show one checklist item.")
    show.add_argument("--checklist-id", required=True)

    for command in ("mark-in-progress", "mark-completed", "mark-skipped", "mark-needs-review", "comment"):
        sub = subparsers.add_parser(command, help=f"{command} for one checklist item.")
        sub.add_argument("--checklist-id", required=True)
        sub.add_argument("--note", required=True)

    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()
    try:
        return run_command(args)
    except TrackerError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
