#!/usr/bin/env python3
"""Sentinel Manual Evidence Review Completion Tracker (Phase 4.7).

Tracks owner-reported review progress for the Manual Evidence Review
Dashboard. This module is intentionally documentation/state only:

- no installation
- no active timer
- no apply mechanism
- no systemctl, crontab, network, API, login, or production writes
- install_allowed_now, can_install_timer_now, can_execute_live, and live_apply
  remain false
- apply_status remains not_applied
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

DASHBOARD_JSON = PROJECT_DIR / "reports/latest/manual-evidence-review-dashboard.json"
MASTER_JSON = PROJECT_DIR / "reports/latest/sentinel-master-report.json"
FINAL_SAFETY_JSON = PROJECT_DIR / "reports/latest/safe-draft-autonomy-final-safety-report.json"

REVIEW_SOURCE_PATHS = {
    "evidence_dashboard": [
        PROJECT_DIR / "reports/latest/manual-evidence-review-dashboard.json",
        PROJECT_DIR / "drafts/owner/manual-evidence-review-dashboard.md",
    ],
    "next_owner_actions": [
        PROJECT_DIR / "drafts/owner/manual-evidence-review-next-owner-actions.md",
    ],
    "manual_timer_install_packet": [
        PROJECT_DIR / "drafts/owner/owner-manual-timer-install-packet.md",
    ],
    "manual_timer_install_final_checklist": [
        PROJECT_DIR / "drafts/owner/owner-manual-timer-install-final-checklist.md",
    ],
    "timer_install_review_only": [
        PROJECT_DIR / "drafts/apply/owner-manual-timer-install-review-only.md",
    ],
    "final_safety_report": [
        PROJECT_DIR / "reports/latest/safe-draft-autonomy-final-safety-report.json",
    ],
    "master_report_autonomy_section": [
        PROJECT_DIR / "reports/latest/sentinel-master-report.json",
        PROJECT_DIR / "reports/latest/sentinel-master-report.md",
    ],
    "emergency_stop_state": [
        PROJECT_DIR / "reports/latest/manual-evidence-review-dashboard.json",
        PROJECT_DIR / "reports/latest/safe-draft-autonomy-final-safety-report.json",
        PROJECT_DIR / "config/autonomy-runtime-lock.json",
    ],
    "do_not_proceed_conditions": [
        PROJECT_DIR / "drafts/owner/manual-evidence-review-dashboard.md",
        PROJECT_DIR / "drafts/owner/owner-manual-timer-install-packet.md",
    ],
    "rollback_instructions": [
        PROJECT_DIR / "drafts/owner/owner-manual-timer-install-packet.md",
        PROJECT_DIR / "drafts/owner/owner-manual-timer-install-final-checklist.md",
        PROJECT_DIR / "drafts/apply/owner-manual-timer-install-review-only.md",
    ],
}

REVIEW_ITEM_TITLES = {
    "evidence_dashboard": "Manual Evidence Review Dashboard",
    "next_owner_actions": "Manual Evidence Review Next Owner Actions",
    "manual_timer_install_packet": "Owner Manual Timer Install Packet",
    "manual_timer_install_final_checklist": "Owner Manual Timer Install Final Checklist",
    "timer_install_review_only": "Timer Install Review Only Document",
    "final_safety_report": "Safe Draft Autonomy Final Safety Report",
    "master_report_autonomy_section": "Sentinel Master Autonomy Section",
    "emergency_stop_state": "Emergency Stop State",
    "do_not_proceed_conditions": "Do Not Proceed Conditions",
    "rollback_instructions": "Rollback Instructions",
}

STATE_JSON = PROJECT_DIR / "state/manual-evidence-review-completion.json"
REPORT_JSON = PROJECT_DIR / "reports/latest/manual-evidence-review-completion-tracker.json"
REPORT_MD = PROJECT_DIR / "reports/latest/manual-evidence-review-completion-tracker.md"
DRAFT_MD = PROJECT_DIR / "drafts/owner/manual-evidence-review-completion-tracker.md"
AUDIT_JSONL = PROJECT_DIR / "audit/manual-evidence-review-completion-tracker.jsonl"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "drafts/owner",
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "audit",
    PROJECT_DIR / "state",
)
ALLOWED_OUTPUT_PATHS = (STATE_JSON, REPORT_JSON, REPORT_MD, DRAFT_MD, AUDIT_JSONL)
FORBIDDEN_OUTPUT_SUFFIXES = (".sh", ".bash", ".zsh", ".service", ".timer", ".run", ".bin")
FORBIDDEN_INSTALL_PATH_TOKENS = (
    "/etc/systemd",
    "systemd/system",
    "/lib/systemd",
    "/usr/lib/systemd",
    "/etc/cron",
    "cron.d",
    "crontab",
)

SCHEMA_VERSION = "manual-evidence-review-completion-tracker-4.7"
APPLY_NOT_APPLIED = "not_applied"

STATUS_UNCHECKED = "unchecked"
STATUS_REVIEWED = "reviewed"
STATUS_NEEDS_WORK = "needs_work"
STATUS_BLOCKED = "blocked"
STATUS_SKIPPED = "skipped"
VALID_REVIEW_STATUSES = {
    STATUS_UNCHECKED,
    STATUS_REVIEWED,
    STATUS_NEEDS_WORK,
    STATUS_BLOCKED,
    STATUS_SKIPPED,
}

TRACKER_READY = "REVIEW_TRACKER_READY"
TRACKER_IN_PROGRESS = "REVIEW_TRACKER_IN_PROGRESS"
TRACKER_BLOCKED_ITEMS = "REVIEW_TRACKER_BLOCKED_ITEMS"
TRACKER_COMPLETE_LOCKED = "REVIEW_TRACKER_COMPLETE_LOCKED"
TRACKER_BREACH = "REVIEW_TRACKER_BREACH"

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


class TrackerError(Exception):
    """Expected CLI validation error. These errors do not write state."""


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def detect_secret_like(value: Any) -> bool:
    text = "" if value is None else str(value)
    return bool(SECRET_ASSIGNMENT_RE.search(text) or LONG_HEX_RE.search(text))


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
    except (ValueError, OSError):
        return False


def assert_allowed_write(path: Path) -> None:
    if path not in ALLOWED_OUTPUT_PATHS and not any(is_within(path, root) for root in ALLOWED_WRITE_ROOTS):
        raise ValueError(f"Refusing to write outside allowed tracker roots: {path}")
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


def source_status(paths: List[Path]) -> Dict[str, Any]:
    available = [str(path) for path in paths if path.exists()]
    missing = [str(path) for path in paths if not path.exists()]
    return {
        "available": bool(available),
        "available_paths": available,
        "missing_paths": missing,
    }


def normalize_status(value: Any) -> str:
    status = str(value or "").strip().lower()
    if status in VALID_REVIEW_STATUSES:
        return status
    return STATUS_UNCHECKED


def safe_bool(data: Optional[Any], key: str, default: bool = False) -> bool:
    if not isinstance(data, dict):
        return default
    return bool(data.get(key, default))


def parse_count(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def load_state() -> Tuple[Dict[str, Any], str]:
    data, status = read_optional_json(STATE_JSON)
    if status == "ok" and isinstance(data, dict):
        return data, "ok"
    return {
        "schema_version": SCHEMA_VERSION,
        "review_items": [],
        "last_owner_review_action": None,
    }, status


def item_template(item_id: str) -> Dict[str, Any]:
    status = source_status(REVIEW_SOURCE_PATHS[item_id])
    return {
        "item_id": item_id,
        "title": REVIEW_ITEM_TITLES[item_id],
        "review_status": STATUS_UNCHECKED,
        "required": True,
        "source_available": status["available"],
        "source_paths": status["available_paths"],
        "missing_source_paths": status["missing_paths"],
        "apply_status": APPLY_NOT_APPLIED,
        "owner_notes": [],
    }


def merge_review_items(state: Dict[str, Any]) -> List[Dict[str, Any]]:
    existing: Dict[str, Dict[str, Any]] = {}
    for item in state.get("review_items", []):
        if isinstance(item, dict) and str(item.get("item_id", "")) in REVIEW_ITEM_TITLES:
            existing[str(item["item_id"])] = item

    merged: List[Dict[str, Any]] = []
    for item_id in REVIEW_ITEM_TITLES:
        base = item_template(item_id)
        old = existing.get(item_id, {})
        base["review_status"] = normalize_status(old.get("review_status"))
        base["review_updated_at_utc"] = redact_text(old.get("review_updated_at_utc"), default="", max_len=80)
        base["review_updated_by"] = redact_text(old.get("review_updated_by"), default="", max_len=120)
        notes = old.get("owner_notes")
        base["owner_notes"] = sanitize_notes(notes if isinstance(notes, list) else [])
        base["apply_status"] = APPLY_NOT_APPLIED
        merged.append(base)
    return merged


def sanitize_notes(notes: List[Any]) -> List[Dict[str, Any]]:
    safe: List[Dict[str, Any]] = []
    for note in notes[-20:]:
        if not isinstance(note, dict):
            continue
        safe.append(
            {
                "timestamp_utc": redact_text(note.get("timestamp_utc"), default="", max_len=80),
                "command": redact_text(note.get("command"), default="", max_len=80),
                "review_status": normalize_status(note.get("review_status")),
                "note": redact_text(note.get("note"), default="", max_len=1000),
            }
        )
    return safe


def find_item(items: List[Dict[str, Any]], item_id: str) -> Optional[Dict[str, Any]]:
    for item in items:
        if item.get("item_id") == item_id:
            return item
    return None


def count_statuses(items: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {status: 0 for status in VALID_REVIEW_STATUSES}
    for item in items:
        counts[normalize_status(item.get("review_status"))] += 1
    return counts


def completion_percent(items: List[Dict[str, Any]]) -> float:
    required = [item for item in items if item.get("required", True)]
    if not required:
        return 0.0
    reviewed = sum(1 for item in required if normalize_status(item.get("review_status")) == STATUS_REVIEWED)
    return round((reviewed / len(required)) * 100, 2)


def all_required_reviewed(items: List[Dict[str, Any]]) -> bool:
    required = [item for item in items if item.get("required", True)]
    return bool(required) and all(normalize_status(item.get("review_status")) == STATUS_REVIEWED for item in required)


def build_last_action(command: str, item_id: Optional[str], note: Optional[str], timestamp: str) -> Dict[str, Any]:
    return {
        "timestamp_utc": timestamp,
        "command": command,
        "item_id": redact_text(item_id, default="", max_len=180) if item_id else None,
        "note": redact_text(note, default="", max_len=1000) if note else "",
    }


def previous_last_action() -> Optional[Dict[str, Any]]:
    data, status = read_optional_json(REPORT_JSON)
    if status != "ok" or not isinstance(data, dict):
        return None
    action = data.get("last_owner_review_action")
    return action if isinstance(action, dict) else None


def detect_tracker_breach(
    items: List[Dict[str, Any]],
    dashboard_data: Optional[Any],
    master_data: Optional[Any],
    final_safety_data: Optional[Any],
    *,
    install_allowed_now: bool,
    can_install_timer_now: bool,
    live_apply: bool,
    can_execute_live: bool,
    systemd_file_written: bool,
    crontab_file_written: bool,
    executable_install_script_generated: bool,
    output_path_breach: bool,
    secret_like_state: bool,
) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    if install_allowed_now:
        reasons.append("install_allowed_now=true")
    if can_install_timer_now:
        reasons.append("can_install_timer_now=true")
    if live_apply:
        reasons.append("live_apply=true")
    if can_execute_live:
        reasons.append("can_execute_live=true")
    for item in items:
        if item.get("apply_status") != APPLY_NOT_APPLIED:
            reasons.append("apply_status != not_applied")
            break
    if systemd_file_written:
        reasons.append("systemd file written")
    if crontab_file_written:
        reasons.append("crontab file written")
    if executable_install_script_generated:
        reasons.append("executable install script generated")
    if output_path_breach:
        reasons.append("writing outside allowed roots")
    if secret_like_state:
        reasons.append("secret-like value in notes/output")

    for source, data in (
        ("dashboard", dashboard_data),
        ("master", master_data),
        ("final_safety", final_safety_data),
    ):
        if not isinstance(data, dict):
            continue
        if bool(data.get("live_apply", False)) or bool(data.get("live_apply_allowed", False)):
            reasons.append(f"{source}: live_apply=true")
        if bool(data.get("can_execute_live", False)):
            reasons.append(f"{source}: can_execute_live=true")
        if bool(data.get("systemd_file_written", False)):
            reasons.append(f"{source}: systemd_file_written=true")
        if bool(data.get("crontab_file_written", False)):
            reasons.append(f"{source}: crontab_file_written=true")
        apply_status = data.get("apply_status")
        if apply_status not in (None, "", APPLY_NOT_APPLIED):
            reasons.append(f"{source}: apply_status != not_applied")
    return bool(reasons), sorted(set(reasons))


def build_report(
    state: Dict[str, Any],
    state_status: str,
    dashboard_data: Optional[Any],
    dashboard_status: str,
    master_data: Optional[Any],
    master_status: str,
    final_safety_data: Optional[Any],
    final_safety_status: str,
    *,
    last_action: Optional[Dict[str, Any]],
    generated_at: Optional[str] = None,
    forced_flags: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    generated = generated_at or utc_now()
    state_apply_status_breach = any(
        isinstance(item, dict)
        and str(item.get("item_id", "")) in REVIEW_ITEM_TITLES
        and item.get("apply_status") not in (None, "", APPLY_NOT_APPLIED)
        for item in state.get("review_items", [])
        if isinstance(state.get("review_items"), list)
    )
    items = merge_review_items(state)
    counts = count_statuses(items)

    emergency_stop_active = (
        safe_bool(dashboard_data, "emergency_stop_active")
        or safe_bool(final_safety_data, "emergency_stop_active")
        or safe_bool(master_data.get("manual_evidence_review_dashboard") if isinstance(master_data, dict) else None, "emergency_stop_active")
    )

    flags = forced_flags or {}
    install_allowed_now = bool(flags.get("install_allowed_now", False))
    can_install_timer_now = bool(flags.get("can_install_timer_now", False))
    live_apply = bool(flags.get("live_apply", False))
    can_execute_live = bool(flags.get("can_execute_live", False))
    systemd_file_written = bool(flags.get("systemd_file_written", False))
    crontab_file_written = bool(flags.get("crontab_file_written", False))
    executable_install_script_generated = bool(flags.get("executable_install_script_generated", False))
    output_path_breach = bool(flags.get("output_path_breach", False))
    secret_like_state = bool(flags.get("secret_like_state", False)) or detect_secret_like(json.dumps(state, ensure_ascii=False))

    breach, breach_reasons = detect_tracker_breach(
        items,
        dashboard_data,
        master_data,
        final_safety_data,
        install_allowed_now=install_allowed_now,
        can_install_timer_now=can_install_timer_now,
        live_apply=live_apply,
        can_execute_live=can_execute_live,
        systemd_file_written=systemd_file_written,
        crontab_file_written=crontab_file_written,
        executable_install_script_generated=executable_install_script_generated,
        output_path_breach=output_path_breach,
        secret_like_state=secret_like_state,
    )
    if state_apply_status_breach:
        breach = True
        breach_reasons = sorted(set(breach_reasons + ["state: apply_status != not_applied"]))

    if breach:
        tracker_status = TRACKER_BREACH
    elif counts[STATUS_BLOCKED] or counts[STATUS_NEEDS_WORK]:
        tracker_status = TRACKER_BLOCKED_ITEMS
    elif all_required_reviewed(items) and emergency_stop_active:
        tracker_status = TRACKER_COMPLETE_LOCKED
    elif all_required_reviewed(items):
        tracker_status = TRACKER_READY
    else:
        tracker_status = TRACKER_IN_PROGRESS

    next_owner_action = "Review unchecked evidence items manually; no install and no live apply."
    if breach:
        next_owner_action = "Stop and review tracker safety breach before any further owner decision."
    elif counts[STATUS_BLOCKED] or counts[STATUS_NEEDS_WORK]:
        next_owner_action = "Review blocked or needs-work evidence items first."
    elif all_required_reviewed(items) and emergency_stop_active:
        next_owner_action = "All required evidence reviewed; keep Emergency Stop active and do not install."
    elif all_required_reviewed(items):
        next_owner_action = "All required evidence reviewed; keep this as review-only status, no install."

    total_items = len(items)
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": generated,
        "tracker_status": tracker_status,
        "read_only": True,
        "network_access": False,
        "wordpress_login": False,
        "api_access": False,
        "apply_function": False,
        "live_apply": live_apply,
        "can_execute_live": can_execute_live,
        "install_allowed_now": install_allowed_now,
        "can_install_timer_now": can_install_timer_now,
        "timer_installation_status": "not_installed",
        "systemd_file_written": systemd_file_written,
        "crontab_file_written": crontab_file_written,
        "executable_install_script_generated": executable_install_script_generated,
        "apply_status": APPLY_NOT_APPLIED,
        "secrets_output": False,
        "allowed_write_roots": [str(path) for path in ALLOWED_WRITE_ROOTS],
        "input_statuses": {
            "state": state_status,
            "manual_evidence_review_dashboard": dashboard_status,
            "sentinel_master": master_status,
            "final_safety": final_safety_status,
        },
        "total_items": total_items,
        "reviewed_count": counts[STATUS_REVIEWED],
        "unchecked_count": counts[STATUS_UNCHECKED],
        "needs_work_count": counts[STATUS_NEEDS_WORK],
        "blocked_count": counts[STATUS_BLOCKED],
        "skipped_count": counts[STATUS_SKIPPED],
        "completion_percent": completion_percent(items),
        "all_required_reviewed": all_required_reviewed(items),
        "emergency_stop_active": emergency_stop_active,
        "tracker_breach": breach,
        "tracker_breach_reasons": breach_reasons,
        "next_owner_action": next_owner_action,
        "last_owner_review_action": last_action,
        "review_items": [
            {
                "item_id": redact_text(item.get("item_id"), max_len=180),
                "title": redact_text(item.get("title"), max_len=220),
                "review_status": normalize_status(item.get("review_status")),
                "required": bool(item.get("required", True)),
                "source_available": bool(item.get("source_available", False)),
                "source_paths": [redact_text(path, max_len=300) for path in item.get("source_paths", [])],
                "missing_source_paths": [redact_text(path, max_len=300) for path in item.get("missing_source_paths", [])],
                "apply_status": APPLY_NOT_APPLIED,
                "owner_notes_count": len(item.get("owner_notes", [])) if isinstance(item.get("owner_notes"), list) else 0,
            }
            for item in items
        ],
        "outputs": {
            "state_json": str(STATE_JSON),
            "report_json": str(REPORT_JSON),
            "report_md": str(REPORT_MD),
            "draft_md": str(DRAFT_MD),
            "audit_jsonl": str(AUDIT_JSONL),
        },
    }


def update_state_item(
    state: Dict[str, Any],
    item_id: str,
    new_status: Optional[str],
    note: str,
    command: str,
    timestamp: str,
) -> Dict[str, Any]:
    if detect_secret_like(note):
        raise TrackerError("Secret-like note rejected; no state written")
    updated = copy.deepcopy(state)
    items = merge_review_items(updated)
    target = find_item(items, item_id)
    if target is None:
        raise TrackerError(f"item_id not found: {redact_text(item_id, max_len=180)}")
    original_apply_statuses = [(item.get("item_id"), item.get("apply_status")) for item in items]

    if new_status is not None:
        target["review_status"] = new_status
    target["review_updated_at_utc"] = timestamp
    target["review_updated_by"] = "owner_reported_manual_evidence_review_tracker"
    notes = target.get("owner_notes") if isinstance(target.get("owner_notes"), list) else []
    notes.append(
        {
            "timestamp_utc": timestamp,
            "command": command,
            "review_status": target.get("review_status"),
            "note": redact_text(note, default="", max_len=1000),
        }
    )
    target["owner_notes"] = notes[-20:]
    updated["schema_version"] = SCHEMA_VERSION
    updated["updated_at_utc"] = timestamp
    updated["review_items"] = items
    updated["last_owner_review_action"] = build_last_action(command, item_id, note, timestamp)

    new_apply_statuses = [(item.get("item_id"), item.get("apply_status")) for item in items]
    if original_apply_statuses != new_apply_statuses:
        raise TrackerError("Internal safety error: apply_status changed")
    return updated


def render_state_markdown(state: Dict[str, Any], report: Dict[str, Any]) -> str:
    items = merge_review_items(state)
    lines = [
        "# Manual Evidence Review Completion Tracker",
        "",
        f"- Generated (UTC): `{report.get('generated_at_utc')}`",
        f"- Tracker status: `{report.get('tracker_status')}`",
        f"- Reviewed: `{report.get('reviewed_count')}` / `{report.get('total_items')}`",
        f"- Unchecked: `{report.get('unchecked_count')}`",
        f"- Needs work: `{report.get('needs_work_count')}`",
        f"- Blocked: `{report.get('blocked_count')}`",
        f"- Skipped: `{report.get('skipped_count')}`",
        f"- Completion percent: `{report.get('completion_percent')}`",
        f"- Emergency stop active: `{report.get('emergency_stop_active')}`",
        f"- Install allowed now: `{report.get('install_allowed_now')}`",
        f"- Can install timer now: `{report.get('can_install_timer_now')}`",
        f"- Live apply: `{report.get('live_apply')}`",
        f"- Tracker breach: `{report.get('tracker_breach')}`",
        "",
        "## Review Items",
        "",
        "| Item ID | Title | Review Status | Source | Notes |",
        "|---|---|---|---|---|",
    ]
    for item in items:
        lines.append(
            "| "
            f"`{redact_text(item.get('item_id'), max_len=160)}` | "
            f"{redact_text(item.get('title'), max_len=220)} | "
            f"`{normalize_status(item.get('review_status'))}` | "
            f"`{'available' if item.get('source_available') else 'missing'}` | "
            f"`{len(item.get('owner_notes', [])) if isinstance(item.get('owner_notes'), list) else 0}` |"
        )
    lines.extend(["", "## Item Details", ""])
    for item in items:
        lines.extend(
            [
                f"### {redact_text(item.get('item_id'), max_len=180)}",
                "",
                f"- Title: `{redact_text(item.get('title'), max_len=220)}`",
                f"- Review status: `{normalize_status(item.get('review_status'))}`",
                f"- Required: `{bool(item.get('required', True))}`",
                f"- Apply status: `{APPLY_NOT_APPLIED}`",
                f"- Source available: `{bool(item.get('source_available', False))}`",
                "",
                "**Available source paths:**",
                "",
            ]
        )
        for path in item.get("source_paths", []):
            lines.append(f"- `{redact_text(path, max_len=300)}`")
        if not item.get("source_paths"):
            lines.append("- `none`")
        lines.extend(["", "**Owner notes:**", ""])
        notes = item.get("owner_notes") if isinstance(item.get("owner_notes"), list) else []
        if notes:
            for note in notes[-5:]:
                lines.append(
                    "- "
                    f"`{redact_text(note.get('timestamp_utc'), max_len=80)}` "
                    f"`{redact_text(note.get('command'), max_len=80)}` "
                    f"{redact_text(note.get('note'), default='', max_len=500)}"
                )
        else:
            lines.append("- `none`")
        lines.append("")
    lines.extend(
        [
            "## Safety Boundaries",
            "",
            "- Keine Installation.",
            "- Kein aktiver Timer.",
            "- Kein Apply-Mechanismus.",
            "- Kein systemctl, keine crontab, keine systemd-Datei.",
            "- Keine WordPress-, Cloudflare-, Nginx- oder .htaccess-Aenderung.",
            "- `apply_status` bleibt `not_applied`.",
            "",
        ]
    )
    return "\n".join(lines)


def render_report_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# Manual Evidence Review Completion Tracker Report",
        "",
        f"- Generated (UTC): `{report.get('generated_at_utc')}`",
        f"- Tracker status: `{report.get('tracker_status')}`",
        f"- Total items: `{report.get('total_items')}`",
        f"- Reviewed: `{report.get('reviewed_count')}`",
        f"- Unchecked: `{report.get('unchecked_count')}`",
        f"- Needs work: `{report.get('needs_work_count')}`",
        f"- Blocked: `{report.get('blocked_count')}`",
        f"- Skipped: `{report.get('skipped_count')}`",
        f"- Completion percent: `{report.get('completion_percent')}`",
        f"- All required reviewed: `{report.get('all_required_reviewed')}`",
        f"- Emergency stop active: `{report.get('emergency_stop_active')}`",
        f"- Install allowed now: `{report.get('install_allowed_now')}`",
        f"- Can install timer now: `{report.get('can_install_timer_now')}`",
        f"- Live apply: `{report.get('live_apply')}`",
        f"- Tracker breach: `{report.get('tracker_breach')}`",
        f"- Next owner action: {redact_text(report.get('next_owner_action'), max_len=500)}",
        "",
    ]
    if report.get("tracker_breach_reasons"):
        lines.extend(["## Breach Reasons", ""])
        for reason in report.get("tracker_breach_reasons", []):
            lines.append(f"- {redact_text(reason, max_len=300)}")
        lines.append("")
    action = report.get("last_owner_review_action")
    if isinstance(action, dict):
        lines.extend(
            [
                "## Last Owner Review Action",
                "",
                f"- Command: `{redact_text(action.get('command'), max_len=120)}`",
                f"- Item ID: `{redact_text(action.get('item_id'), default='', max_len=180)}`",
                f"- Timestamp: `{redact_text(action.get('timestamp_utc'), max_len=80)}`",
                f"- Note: {redact_text(action.get('note'), default='', max_len=500)}",
                "",
            ]
        )
    lines.extend(
        [
            "## Review Items",
            "",
            "| Item ID | Title | Status | Source | Notes |",
            "|---|---|---|---|---|",
        ]
    )
    for item in report.get("review_items", []):
        if not isinstance(item, dict):
            continue
        lines.append(
            "| "
            f"`{redact_text(item.get('item_id'), max_len=160)}` | "
            f"{redact_text(item.get('title'), max_len=220)} | "
            f"`{redact_text(item.get('review_status'), max_len=80)}` | "
            f"`{'available' if item.get('source_available') else 'missing'}` | "
            f"`{parse_count(item.get('owner_notes_count'))}` |"
        )
    lines.extend(
        [
            "",
            "## Safety Boundaries",
            "",
            "- Review-Tracking only; keine Live-Aenderungen.",
            "- Keine Installation, kein aktiver Timer, kein Apply.",
            "- Keine systemd-/crontab-Dateien und kein `systemctl`.",
            "- Keine Netzwerkzugriffe, API, Login oder Secrets.",
            "",
        ]
    )
    return "\n".join(lines)


def audit_record(report: Dict[str, Any], command: str, item_id: Optional[str]) -> Dict[str, Any]:
    return {
        "timestamp_utc": report.get("generated_at_utc"),
        "schema_version": SCHEMA_VERSION,
        "command": command,
        "item_id": redact_text(item_id, default="", max_len=180) if item_id else None,
        "tracker_status": report.get("tracker_status"),
        "tracker_breach": report.get("tracker_breach"),
        "reviewed_count": report.get("reviewed_count"),
        "unchecked_count": report.get("unchecked_count"),
        "needs_work_count": report.get("needs_work_count"),
        "blocked_count": report.get("blocked_count"),
        "skipped_count": report.get("skipped_count"),
        "install_allowed_now": False,
        "can_install_timer_now": False,
        "live_apply": False,
        "can_execute_live": False,
        "apply_status": APPLY_NOT_APPLIED,
        "network_access": False,
        "apply_function": False,
    }


def write_tracker_outputs(state: Dict[str, Any], report: Dict[str, Any], *, command: str, item_id: Optional[str]) -> None:
    write_json_atomic(STATE_JSON, state)
    write_json_atomic(REPORT_JSON, report)
    markdown = render_report_markdown(report)
    write_text_atomic(REPORT_MD, markdown)
    write_text_atomic(DRAFT_MD, render_state_markdown(state, report))
    append_jsonl(AUDIT_JSONL, [audit_record(report, command, item_id)])


def build_current_report(state: Dict[str, Any], state_status: str, last_action: Optional[Dict[str, Any]], timestamp: str) -> Dict[str, Any]:
    dashboard_data, dashboard_status = read_optional_json(DASHBOARD_JSON)
    master_data, master_status = read_optional_json(MASTER_JSON)
    final_safety_data, final_safety_status = read_optional_json(FINAL_SAFETY_JSON)
    return build_report(
        state,
        state_status,
        dashboard_data,
        dashboard_status,
        master_data,
        master_status,
        final_safety_data,
        final_safety_status,
        last_action=last_action,
        generated_at=timestamp,
    )


def print_list(report: Dict[str, Any]) -> None:
    print("Manual evidence review items:")
    for item in report.get("review_items", []):
        if not isinstance(item, dict):
            continue
        print(
            f"- {item.get('item_id')} | "
            f"status={item.get('review_status')} | "
            f"source={'available' if item.get('source_available') else 'missing'} | "
            f"title={item.get('title')}"
        )
    print(
        "Summary: "
        f"reviewed={report.get('reviewed_count')}/{report.get('total_items')} "
        f"unchecked={report.get('unchecked_count')} "
        f"needs_work={report.get('needs_work_count')} "
        f"blocked={report.get('blocked_count')} "
        f"skipped={report.get('skipped_count')} "
        f"breach={report.get('tracker_breach')}"
    )


def print_show(item: Dict[str, Any]) -> None:
    print(f"Item ID: {redact_text(item.get('item_id'), max_len=180)}")
    print(f"Title: {redact_text(item.get('title'), max_len=220)}")
    print(f"Review status: {normalize_status(item.get('review_status'))}")
    print(f"Required: {bool(item.get('required', True))}")
    print(f"Apply status: {APPLY_NOT_APPLIED}")
    print(f"Source available: {bool(item.get('source_available', False))}")
    print("Source paths:")
    for path in item.get("source_paths", []):
        print(f"- {redact_text(path, max_len=300)}")
    notes = item.get("owner_notes") if isinstance(item.get("owner_notes"), list) else []
    if notes:
        print("Owner notes:")
        for note in notes[-5:]:
            print(
                "- "
                f"{redact_text(note.get('timestamp_utc'), max_len=80)} "
                f"{redact_text(note.get('command'), max_len=80)} "
                f"{redact_text(note.get('note'), default='', max_len=500)}"
            )


def command_to_status(command: str) -> Optional[str]:
    return {
        "mark-reviewed": STATUS_REVIEWED,
        "mark-needs-work": STATUS_NEEDS_WORK,
        "mark-blocked": STATUS_BLOCKED,
        "mark-skipped": STATUS_SKIPPED,
        "reset-item": STATUS_UNCHECKED,
        "comment": None,
    }[command]


def run_command(args: argparse.Namespace) -> int:
    state, state_status = load_state()
    command = args.command or "list"
    timestamp = utc_now()

    if command in {"mark-reviewed", "mark-needs-work", "mark-blocked", "mark-skipped", "reset-item", "comment"}:
        updated = update_state_item(
            state,
            args.item_id,
            command_to_status(command),
            args.note,
            command,
            timestamp,
        )
        report = build_current_report(updated, "ok", updated.get("last_owner_review_action"), timestamp)
        write_tracker_outputs(updated, report, command=command, item_id=args.item_id)
        print(f"{command}: {redact_text(args.item_id, max_len=180)} -> OK; apply_status remains not_applied")
        return 0

    if command == "show":
        items = merge_review_items(state)
        item = find_item(items, args.item_id)
        if item is None:
            raise TrackerError(f"item_id not found: {redact_text(args.item_id, max_len=180)}")
        report = build_current_report(state, state_status, previous_last_action(), timestamp)
        state_for_write = copy.deepcopy(state)
        state_for_write["review_items"] = items
        write_tracker_outputs(state_for_write, report, command=command, item_id=args.item_id)
        print_show(item)
        return 0

    if command == "list":
        items = merge_review_items(state)
        state_for_write = copy.deepcopy(state)
        state_for_write["schema_version"] = SCHEMA_VERSION
        state_for_write["review_items"] = items
        state_for_write.setdefault("last_owner_review_action", previous_last_action())
        report = build_current_report(state_for_write, state_status, state_for_write.get("last_owner_review_action"), timestamp)
        write_tracker_outputs(state_for_write, report, command=command, item_id=None)
        print_list(report)
        return 0

    raise TrackerError(f"unsupported command: {redact_text(command)}")


def run_self_test() -> int:
    sample_state = {
        "schema_version": SCHEMA_VERSION,
        "review_items": [
            {"item_id": "evidence_dashboard", "review_status": STATUS_UNCHECKED, "apply_status": APPLY_NOT_APPLIED, "owner_notes": []}
        ],
    }
    updated = update_state_item(
        sample_state,
        "evidence_dashboard",
        STATUS_REVIEWED,
        "owner reviewed dashboard",
        "mark-reviewed",
        "2026-06-11T00:00:00Z",
    )
    item = find_item(merge_review_items(updated), "evidence_dashboard")
    if not item or item.get("review_status") != STATUS_REVIEWED:
        raise AssertionError("mark-reviewed failed")
    updated = update_state_item(updated, "emergency_stop_state", None, "emergency stop intentionally active", "comment", "2026-06-11T00:01:00Z")
    item = find_item(merge_review_items(updated), "emergency_stop_state")
    if not item or item.get("owner_notes", [])[-1]["note"] != "emergency stop intentionally active":
        raise AssertionError("comment failed")
    for command, expected in (
        ("mark-needs-work", STATUS_NEEDS_WORK),
        ("mark-blocked", STATUS_BLOCKED),
        ("mark-skipped", STATUS_SKIPPED),
        ("reset-item", STATUS_UNCHECKED),
    ):
        updated = update_state_item(updated, "evidence_dashboard", command_to_status(command), f"{command} note", command, "2026-06-11T00:02:00Z")
        item = find_item(merge_review_items(updated), "evidence_dashboard")
        if not item or item.get("review_status") != expected:
            raise AssertionError(f"{command} failed")
    try:
        update_state_item(updated, "evidence_dashboard", STATUS_REVIEWED, "token=abc12345", "mark-reviewed", "2026-06-11T00:03:00Z")
    except TrackerError:
        pass
    else:
        raise AssertionError("secret-like note was not rejected")
    try:
        update_state_item(updated, "missing_item", STATUS_REVIEWED, "ok", "mark-reviewed", "2026-06-11T00:04:00Z")
    except TrackerError:
        pass
    else:
        raise AssertionError("missing item was not rejected")

    all_reviewed = {
        "review_items": [
            {"item_id": item_id, "review_status": STATUS_REVIEWED, "apply_status": APPLY_NOT_APPLIED, "owner_notes": []}
            for item_id in REVIEW_ITEM_TITLES
        ]
    }
    locked_report = build_report(
        all_reviewed,
        "ok",
        {"emergency_stop_active": True},
        "ok",
        {},
        "ok",
        {},
        "ok",
        last_action=None,
        generated_at="2026-06-11T00:05:00Z",
    )
    if locked_report["tracker_status"] != TRACKER_COMPLETE_LOCKED or locked_report["tracker_breach"]:
        raise AssertionError("locked complete status failed")

    blocked_report = build_report(
        {"review_items": [{"item_id": "evidence_dashboard", "review_status": STATUS_BLOCKED, "apply_status": APPLY_NOT_APPLIED}]},
        "ok",
        {},
        "ok",
        {},
        "ok",
        {},
        "ok",
        last_action=None,
        generated_at="2026-06-11T00:06:00Z",
    )
    if blocked_report["tracker_status"] != TRACKER_BLOCKED_ITEMS:
        raise AssertionError("blocked status failed")

    for key in ("install_allowed_now", "can_install_timer_now", "live_apply", "can_execute_live", "systemd_file_written", "crontab_file_written", "executable_install_script_generated", "output_path_breach", "secret_like_state"):
        report = build_report(
            sample_state,
            "ok",
            {},
            "ok",
            {},
            "ok",
            {},
            "ok",
            last_action=None,
            generated_at="2026-06-11T00:07:00Z",
            forced_flags={key: True},
        )
        if not report["tracker_breach"]:
            raise AssertionError(f"{key} did not produce breach")
    bad_apply = {"review_items": [{"item_id": "evidence_dashboard", "review_status": STATUS_REVIEWED, "apply_status": "applied"}]}
    report = build_report(bad_apply, "ok", {}, "ok", {}, "ok", {}, "ok", last_action=None, generated_at="2026-06-11T00:08:00Z")
    if not report["tracker_breach"]:
        raise AssertionError("apply_status != not_applied did not produce breach")
    try:
        assert_allowed_write(PROJECT_DIR / "forbidden/manual-evidence-review-completion.json")
    except ValueError:
        pass
    else:
        raise AssertionError("forbidden write path was not rejected")
    for forbidden in (PROJECT_DIR / "drafts/owner/bad.sh", PROJECT_DIR / "reports/latest/bad.service"):
        try:
            assert_allowed_write(forbidden)
        except ValueError:
            pass
        else:
            raise AssertionError(f"forbidden artifact was not rejected: {forbidden}")
    print("manual-evidence-review-completion-tracker self-tests: OK")
    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Track manual owner evidence review completion.")
    parser.add_argument("--self-test", action="store_true", help="Run in-memory safety tests and exit.")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("list", help="List review items and statuses.")

    show = subparsers.add_parser("show", help="Show one review item.")
    show.add_argument("item_id")

    for command in ("mark-reviewed", "mark-needs-work", "mark-blocked", "mark-skipped", "comment", "reset-item"):
        sub = subparsers.add_parser(command, help=f"{command} for one review item.")
        sub.add_argument("item_id")
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
