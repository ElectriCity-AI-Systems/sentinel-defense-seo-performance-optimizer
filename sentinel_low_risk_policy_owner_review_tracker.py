#!/usr/bin/env python3
"""LOW-RISK Policy Owner Review Tracker (Phase 5.7).

Read-only owner-review tracker for the LOW-RISK Policy Boundary Draft. It records
ONLY whether the owner has reviewed each policy boundary; it activates nothing,
applies nothing, and installs nothing.

- no installation, no active timer, no apply mechanism
- no systemctl, crontab, network, API, login, or production writes
- low_risk_autonomy_allowed_now, policy_activation_allowed, install_allowed_now,
  can_install_timer_now and live_apply remain false
- apply_status remains not_applied
- HIGH/FORBIDDEN boundaries may be reviewed but are never activatable
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

POLICY_BOUNDARY_JSON = PROJECT_DIR / "reports/latest/low-risk-policy-boundary-draft.json"
READINESS_GATE_JSON = PROJECT_DIR / "reports/latest/low-risk-autonomy-readiness-gate.json"
MASTER_JSON = PROJECT_DIR / "reports/latest/sentinel-master-report.json"
RUNTIME_LOCK_JSON = PROJECT_DIR / "config/autonomy-runtime-lock.json"

# Review items: each boundary the owner must consciously review.
REVIEW_ITEM_TITLES = {
    "low_risk_draft_only": "LOW_RISK_DRAFT_ONLY boundary",
    "low_risk_review_only": "LOW_RISK_REVIEW_ONLY boundary",
    "low_risk_potential_future_apply": "LOW_RISK_POTENTIAL_FUTURE_APPLY boundary (future only)",
    "medium_owner_approval_required": "MEDIUM_RISK_OWNER_APPROVAL_REQUIRED boundary",
    "high_never_auto_apply": "HIGH_RISK_NEVER_AUTO_APPLY boundary (never activatable)",
    "forbidden": "FORBIDDEN boundary (never activatable)",
    "required_safety_prerequisites": "Required safety prerequisites (backup/healthcheck/rollback/audit/owner-review)",
    "emergency_stop_and_no_activation": "Emergency Stop active and no activation allowed",
}
# Boundaries that may be reviewed but must never become activatable.
NEVER_ACTIVATABLE_ITEMS = {"high_never_auto_apply", "forbidden"}

REVIEW_SOURCE_PATHS = {item_id: [POLICY_BOUNDARY_JSON, READINESS_GATE_JSON] for item_id in REVIEW_ITEM_TITLES}

STATE_JSON = PROJECT_DIR / "state/low-risk-policy-owner-review.json"
REPORT_JSON = PROJECT_DIR / "reports/latest/low-risk-policy-owner-review-tracker.json"
REPORT_MD = PROJECT_DIR / "reports/latest/low-risk-policy-owner-review-tracker.md"
CHECKLIST_MD = PROJECT_DIR / "drafts/owner/low-risk-policy-owner-review-checklist.md"
SNAPSHOT_JSON = PROJECT_DIR / "snapshots/low-risk-policy-owner-review-tracker.json"
SNAPSHOT_MD = PROJECT_DIR / "snapshots/low-risk-policy-owner-review-tracker.md"
AUDIT_JSONL = PROJECT_DIR / "audit/low-risk-policy-owner-review-tracker.jsonl"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "drafts/owner",
    PROJECT_DIR / "snapshots",
    PROJECT_DIR / "audit",
    PROJECT_DIR / "state",
)
ALLOWED_OUTPUT_PATHS = (STATE_JSON, REPORT_JSON, REPORT_MD, CHECKLIST_MD, SNAPSHOT_JSON, SNAPSHOT_MD, AUDIT_JSONL)
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

SCHEMA_VERSION = "low-risk-policy-owner-review-tracker-5.7"
APPLY_NOT_APPLIED = "not_applied"

STATUS_UNCHECKED = "unchecked"
STATUS_REVIEWED = "reviewed"
STATUS_NEEDS_WORK = "needs_work"
VALID_REVIEW_STATUSES = {STATUS_UNCHECKED, STATUS_REVIEWED, STATUS_NEEDS_WORK}

TRACKER_NOT_STARTED = "LOW_RISK_POLICY_OWNER_REVIEW_NOT_STARTED"
TRACKER_IN_PROGRESS = "LOW_RISK_POLICY_OWNER_REVIEW_IN_PROGRESS"
TRACKER_COMPLETE_LOCKED = "LOW_RISK_POLICY_OWNER_REVIEW_COMPLETE_LOCKED"
TRACKER_BLOCKED_BY_BREACH = "LOW_RISK_POLICY_OWNER_REVIEW_BLOCKED_BY_BREACH"
TRACKER_BREACH = "LOW_RISK_POLICY_OWNER_REVIEW_BREACH"

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


class TrackerError(Exception):
    """Expected CLI validation error. These errors do not write state."""


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


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
    return {"available": bool(available), "available_paths": available, "missing_paths": missing}


def normalize_status(value: Any) -> str:
    status = str(value or "").strip().lower()
    return status if status in VALID_REVIEW_STATUSES else STATUS_UNCHECKED


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
    return {"schema_version": SCHEMA_VERSION, "review_items": [], "last_owner_review_action": None}, status


def item_template(item_id: str) -> Dict[str, Any]:
    status = source_status(REVIEW_SOURCE_PATHS[item_id])
    return {
        "item_id": item_id,
        "title": REVIEW_ITEM_TITLES[item_id],
        "review_status": STATUS_UNCHECKED,
        "required": True,
        "activatable_now": False,
        "never_activatable": item_id in NEVER_ACTIVATABLE_ITEMS,
        "source_available": status["available"],
        "source_paths": status["available_paths"],
        "missing_source_paths": status["missing_paths"],
        "apply_status": APPLY_NOT_APPLIED,
        "owner_notes": [],
    }


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


def merge_review_items(state: Dict[str, Any]) -> List[Dict[str, Any]]:
    existing: Dict[str, Dict[str, Any]] = {}
    for item in state.get("review_items", []) if isinstance(state.get("review_items"), list) else []:
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
        base["activatable_now"] = False
        merged.append(base)
    return merged


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


def detect_breach(
    items: List[Dict[str, Any]],
    policy_data: Optional[Any],
    readiness_data: Optional[Any],
    *,
    forced_flags: Dict[str, Any],
    secret_like_state: bool,
) -> Tuple[bool, List[str], bool]:
    """Return (direct_breach_or_state, reasons, upstream_breach)."""
    reasons: List[str] = []
    flags = forced_flags
    if bool(flags.get("low_risk_autonomy_allowed_now", False)):
        reasons.append("low_risk_autonomy_allowed_now=true")
    if bool(flags.get("policy_activation_allowed", False)):
        reasons.append("policy_activation_allowed=true")
    if bool(flags.get("live_apply", False)):
        reasons.append("live_apply=true")
    if bool(flags.get("install_allowed_now", False)):
        reasons.append("install_allowed_now=true")
    if bool(flags.get("can_install_timer_now", False)):
        reasons.append("can_install_timer_now=true")
    if bool(flags.get("forbidden_apply_command_detected", False)):
        reasons.append("Cloudflare/WordPress/Nginx/.htaccess apply command detected")
    if bool(flags.get("systemd_file_written", False)):
        reasons.append("systemd_file_written=true")
    if bool(flags.get("crontab_file_written", False)):
        reasons.append("crontab_file_written=true")
    if bool(flags.get("executable_install_script_generated", False)):
        reasons.append("executable install script generated")
    if bool(flags.get("output_path_breach", False)):
        reasons.append("writing outside allowed roots")
    if secret_like_state:
        reasons.append("secret-like value in notes/output")
    for item in items:
        if item.get("apply_status") != APPLY_NOT_APPLIED:
            reasons.append("state: apply_status != not_applied")
            break
        if item.get("activatable_now"):
            reasons.append("state: activatable_now=true")
            break

    upstream_reasons: List[str] = []
    for label, data in (("policy_boundary_draft", policy_data), ("readiness_gate", readiness_data)):
        if isinstance(data, dict):
            for key, value in data.items():
                if key.lower().endswith("breach") and bool(value):
                    upstream_reasons.append(f"{label}:{key}=true")
    reasons.extend(upstream_reasons)
    return bool([r for r in reasons if r not in upstream_reasons]), sorted(set(reasons)), bool(upstream_reasons)


def build_report(
    state: Dict[str, Any],
    state_status: str,
    policy_data: Optional[Any],
    policy_status_read: str,
    readiness_data: Optional[Any],
    readiness_status_read: str,
    master_data: Optional[Any],
    master_status_read: str,
    runtime_lock: Optional[Any],
    runtime_lock_status_read: str,
    *,
    last_action: Optional[Dict[str, Any]],
    generated_at: Optional[str] = None,
    forced_flags: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    generated = generated_at or utc_now()
    raw_items = state.get("review_items", []) if isinstance(state.get("review_items"), list) else []
    state_apply_status_breach = any(
        isinstance(item, dict)
        and str(item.get("item_id", "")) in REVIEW_ITEM_TITLES
        and item.get("apply_status") not in (None, "", APPLY_NOT_APPLIED)
        for item in raw_items
    )
    state_activatable_breach = any(
        isinstance(item, dict) and bool(item.get("activatable_now", False)) for item in raw_items
    )
    items = merge_review_items(state)
    counts = count_statuses(items)

    emergency_stop_active = (
        safe_bool(runtime_lock, "emergency_stop")
        or safe_bool(policy_data, "emergency_stop_active")
        or safe_bool(readiness_data, "emergency_stop_active")
    )

    flags = forced_flags or {}
    secret_like_state = bool(flags.get("secret_like_state", False)) or detect_secret_like(json.dumps(state, ensure_ascii=False))

    direct_breach, breach_reasons, upstream_breach = detect_breach(
        items, policy_data, readiness_data, forced_flags=flags, secret_like_state=secret_like_state
    )
    if state_apply_status_breach:
        direct_breach = True
        breach_reasons = sorted(set(breach_reasons + ["state: apply_status != not_applied"]))
    if state_activatable_breach:
        direct_breach = True
        breach_reasons = sorted(set(breach_reasons + ["state: activatable_now=true"]))

    if direct_breach:
        tracker_status = TRACKER_BREACH
        tracker_breach = True
    elif upstream_breach:
        tracker_status = TRACKER_BLOCKED_BY_BREACH
        tracker_breach = True
    elif all_required_reviewed(items) and emergency_stop_active:
        tracker_status = TRACKER_COMPLETE_LOCKED
        tracker_breach = False
    elif counts[STATUS_REVIEWED] == 0 and counts[STATUS_NEEDS_WORK] == 0:
        tracker_status = TRACKER_NOT_STARTED
        tracker_breach = False
    else:
        tracker_status = TRACKER_IN_PROGRESS
        tracker_breach = False

    if tracker_status == TRACKER_COMPLETE_LOCKED:
        next_owner_action = "Policy review complete. Keep Emergency Stop active. Do not enable LOW-RISK autonomy."
    elif tracker_status == TRACKER_NOT_STARTED:
        next_owner_action = "Begin reviewing LOW-RISK policy boundaries. Do not activate autonomy."
    elif tracker_status == TRACKER_IN_PROGRESS:
        next_owner_action = "Continue reviewing LOW-RISK policy boundaries. Do not activate autonomy."
    else:
        next_owner_action = "Do not proceed. Resolve breach first."

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": generated,
        "tracker_status": tracker_status,
        "read_only": True,
        "network_access": False,
        "api_access": False,
        "wordpress_login": False,
        "low_risk_autonomy_allowed_now": False,
        "policy_activation_allowed": False,
        "live_apply": False,
        "install_allowed_now": False,
        "can_install_timer_now": False,
        "timer_installation_status": "not_installed",
        "systemd_file_written": bool(flags.get("systemd_file_written", False)),
        "crontab_file_written": bool(flags.get("crontab_file_written", False)),
        "executable_install_script_generated": bool(flags.get("executable_install_script_generated", False)),
        "apply_status": APPLY_NOT_APPLIED,
        "secrets_output": False,
        "owner_policy_review_required": True,
        "total_items": len(items),
        "total_required": sum(1 for item in items if item.get("required", True)),
        "reviewed_count": counts[STATUS_REVIEWED],
        "unchecked_count": counts[STATUS_UNCHECKED],
        "needs_work_count": counts[STATUS_NEEDS_WORK],
        "completion_percent": completion_percent(items),
        "all_required_reviewed": all_required_reviewed(items),
        "emergency_stop_active": emergency_stop_active,
        "tracker_breach": tracker_breach,
        "tracker_breach_reasons": breach_reasons,
        "next_owner_action": next_owner_action,
        "recommended_owner_action": next_owner_action,
        "last_owner_review_action": last_action,
        "input_statuses": {
            "state": state_status,
            "low_risk_policy_boundary_draft": policy_status_read,
            "low_risk_autonomy_readiness_gate": readiness_status_read,
            "sentinel_master_json": master_status_read,
            "runtime_lock": runtime_lock_status_read,
        },
        "review_items": [
            {
                "item_id": redact_text(item.get("item_id"), max_len=180),
                "title": redact_text(item.get("title"), max_len=220),
                "review_status": normalize_status(item.get("review_status")),
                "required": bool(item.get("required", True)),
                "activatable_now": False,
                "never_activatable": bool(item.get("never_activatable", False)),
                "source_available": bool(item.get("source_available", False)),
                "apply_status": APPLY_NOT_APPLIED,
                "owner_notes_count": len(item.get("owner_notes", [])) if isinstance(item.get("owner_notes"), list) else 0,
            }
            for item in items
        ],
        "outputs": {
            "state_json": str(STATE_JSON),
            "report_json": str(REPORT_JSON),
            "report_md": str(REPORT_MD),
            "checklist_md": str(CHECKLIST_MD),
            "snapshot_json": str(SNAPSHOT_JSON),
            "snapshot_md": str(SNAPSHOT_MD),
            "audit_jsonl": str(AUDIT_JSONL),
        },
    }


def update_state_item(
    state: Dict[str, Any], item_id: str, new_status: Optional[str], note: str, command: str, timestamp: str
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
    target["review_updated_by"] = "owner_reported_low_risk_policy_review_tracker"
    notes = target.get("owner_notes") if isinstance(target.get("owner_notes"), list) else []
    notes.append({"timestamp_utc": timestamp, "command": command, "review_status": target.get("review_status"), "note": redact_text(note, default="", max_len=1000)})
    target["owner_notes"] = notes[-20:]
    target["apply_status"] = APPLY_NOT_APPLIED
    target["activatable_now"] = False
    updated["schema_version"] = SCHEMA_VERSION
    updated["updated_at_utc"] = timestamp
    updated["review_items"] = items
    updated["last_owner_review_action"] = build_last_action(command, item_id, note, timestamp)
    new_apply_statuses = [(item.get("item_id"), item.get("apply_status")) for item in items]
    if original_apply_statuses != new_apply_statuses:
        raise TrackerError("Internal safety error: apply_status changed")
    return updated


def render_checklist_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# LOW-RISK Policy Owner Review Checklist",
        "",
        "> Review-only. Marking an item reviewed records owner attestation only.",
        "> It activates no autonomy, applies nothing, and installs nothing.",
        "",
        f"- Generated (UTC): `{report.get('generated_at_utc')}`",
        f"- Tracker status: `{report.get('tracker_status')}`",
        f"- Reviewed: `{report.get('reviewed_count')}` / `{report.get('total_required')}`",
        f"- Completion percent: `{report.get('completion_percent')}`",
        f"- Emergency stop active: `{report.get('emergency_stop_active')}`",
        f"- Tracker breach: `{report.get('tracker_breach')}`",
        "",
        "## Review Items",
        "",
        "| Item ID | Title | Status | Never activatable |",
        "|---|---|---|---|",
    ]
    for item in report.get("review_items", []):
        lines.append(
            "| "
            f"`{redact_text(item.get('item_id'), max_len=160)}` | "
            f"{redact_text(item.get('title'), max_len=220)} | "
            f"`{redact_text(item.get('review_status'), max_len=40)}` | "
            f"`{bool(item.get('never_activatable'))}` |"
        )
    lines.extend(["", "## Owner Commands (manual, review-only)", ""])
    for item in report.get("review_items", []):
        item_id = item.get("item_id")
        lines.append(f"- `python3 sentinel_low_risk_policy_owner_review_tracker.py mark-reviewed {item_id} --note \"reviewed\"`")
    lines.extend(
        [
            "",
            "## Safety Boundaries",
            "",
            "- No activation, no apply, no installation.",
            "- HIGH/FORBIDDEN boundaries may be reviewed but never become activatable.",
            "- `apply_status` stays `not_applied`; Emergency Stop stays active.",
            "",
        ]
    )
    return "\n".join(lines)


def render_report_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# LOW-RISK Policy Owner Review Tracker",
        "",
        f"- Generated (UTC): `{report.get('generated_at_utc')}`",
        f"- Tracker status: `{report.get('tracker_status')}`",
        f"- Total required: `{report.get('total_required')}`",
        f"- Reviewed: `{report.get('reviewed_count')}`",
        f"- Unchecked: `{report.get('unchecked_count')}`",
        f"- Needs work: `{report.get('needs_work_count')}`",
        f"- Completion percent: `{report.get('completion_percent')}`",
        f"- All required reviewed: `{report.get('all_required_reviewed')}`",
        f"- Emergency stop active: `{report.get('emergency_stop_active')}`",
        f"- LOW-RISK autonomy allowed now: `{report.get('low_risk_autonomy_allowed_now')}`",
        f"- Policy activation allowed: `{report.get('policy_activation_allowed')}`",
        f"- Install allowed now: `{report.get('install_allowed_now')}`",
        f"- Live apply: `{report.get('live_apply')}`",
        f"- Apply status: `{report.get('apply_status')}`",
        f"- Tracker breach: `{report.get('tracker_breach')}`",
        f"- Next owner action: {redact_text(report.get('next_owner_action'), max_len=500)}",
        "",
    ]
    if report.get("tracker_breach_reasons"):
        lines.extend(["## Breach Reasons", ""])
        for reason in report.get("tracker_breach_reasons", []):
            lines.append(f"- {redact_text(reason, max_len=300)}")
        lines.append("")
    lines.extend(["## Review Items", "", "| Item ID | Title | Status | Never activatable | Notes |", "|---|---|---|---|---|"])
    for item in report.get("review_items", []):
        lines.append(
            "| "
            f"`{redact_text(item.get('item_id'), max_len=160)}` | "
            f"{redact_text(item.get('title'), max_len=220)} | "
            f"`{redact_text(item.get('review_status'), max_len=40)}` | "
            f"`{bool(item.get('never_activatable'))}` | "
            f"`{parse_count(item.get('owner_notes_count'))}` |"
        )
    lines.extend(
        [
            "",
            "## Safety Boundaries",
            "",
            "- Review-tracking only; no live changes, no activation, no apply, no install.",
            "- No systemd/crontab files and no systemctl.",
            "- No network, API, login or secrets.",
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
        "low_risk_autonomy_allowed_now": False,
        "policy_activation_allowed": False,
        "install_allowed_now": False,
        "can_install_timer_now": False,
        "live_apply": False,
        "apply_status": APPLY_NOT_APPLIED,
        "network_access": False,
    }


def write_tracker_outputs(state: Dict[str, Any], report: Dict[str, Any], *, command: str, item_id: Optional[str]) -> None:
    write_json_atomic(STATE_JSON, state)
    write_json_atomic(REPORT_JSON, report)
    report_md = render_report_markdown(report)
    write_text_atomic(REPORT_MD, report_md)
    write_text_atomic(CHECKLIST_MD, render_checklist_markdown(report))
    write_json_atomic(SNAPSHOT_JSON, report)
    write_text_atomic(SNAPSHOT_MD, report_md)
    append_jsonl(AUDIT_JSONL, [audit_record(report, command, item_id)])


def build_current_report(state: Dict[str, Any], state_status: str, last_action: Optional[Dict[str, Any]], timestamp: str) -> Dict[str, Any]:
    policy_data, policy_status = read_optional_json(POLICY_BOUNDARY_JSON)
    readiness_data, readiness_status = read_optional_json(READINESS_GATE_JSON)
    master_data, master_status = read_optional_json(MASTER_JSON)
    runtime_lock, runtime_lock_status = read_optional_json(RUNTIME_LOCK_JSON)
    return build_report(
        state, state_status, policy_data, policy_status, readiness_data, readiness_status,
        master_data, master_status, runtime_lock, runtime_lock_status,
        last_action=last_action, generated_at=timestamp,
    )


def previous_last_action() -> Optional[Dict[str, Any]]:
    data, status = read_optional_json(REPORT_JSON)
    if status != "ok" or not isinstance(data, dict):
        return None
    action = data.get("last_owner_review_action")
    return action if isinstance(action, dict) else None


def print_list(report: Dict[str, Any]) -> None:
    print("LOW-RISK policy owner review items:")
    for item in report.get("review_items", []):
        print(
            f"- {item.get('item_id')} | status={item.get('review_status')} | "
            f"never_activatable={item.get('never_activatable')} | title={item.get('title')}"
        )
    print(
        "Summary: "
        f"status={report.get('tracker_status')} "
        f"reviewed={report.get('reviewed_count')}/{report.get('total_required')} "
        f"unchecked={report.get('unchecked_count')} needs_work={report.get('needs_work_count')} "
        f"breach={report.get('tracker_breach')}"
    )


def print_show(item: Dict[str, Any]) -> None:
    print(f"Item ID: {redact_text(item.get('item_id'), max_len=180)}")
    print(f"Title: {redact_text(item.get('title'), max_len=220)}")
    print(f"Review status: {normalize_status(item.get('review_status'))}")
    print(f"Required: {bool(item.get('required', True))}")
    print(f"Never activatable: {bool(item.get('never_activatable', False))}")
    print(f"Activatable now: False")
    print(f"Apply status: {APPLY_NOT_APPLIED}")
    notes = item.get("owner_notes") if isinstance(item.get("owner_notes"), list) else []
    if notes:
        print("Owner notes:")
        for note in notes[-5:]:
            print(f"- {redact_text(note.get('timestamp_utc'), max_len=80)} {redact_text(note.get('command'), max_len=80)} {redact_text(note.get('note'), default='', max_len=500)}")


def command_to_status(command: str) -> Optional[str]:
    return {"mark-reviewed": STATUS_REVIEWED, "mark-needs-work": STATUS_NEEDS_WORK, "reset": STATUS_UNCHECKED}[command]


def run_command(args: argparse.Namespace) -> int:
    state, state_status = load_state()
    command = args.command or "list"
    timestamp = utc_now()

    if command in {"mark-reviewed", "mark-needs-work", "reset"}:
        note = getattr(args, "note", None) or f"{command}"
        updated = update_state_item(state, args.item_id, command_to_status(command), note, command, timestamp)
        report = build_current_report(updated, "ok", updated.get("last_owner_review_action"), timestamp)
        write_tracker_outputs(updated, report, command=command, item_id=args.item_id)
        print(f"{command}: {redact_text(args.item_id, max_len=180)} -> OK; apply_status remains not_applied, no activation")
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
    sample_state = {"schema_version": SCHEMA_VERSION, "review_items": []}
    policy = {"emergency_stop_active": True, "policy_breach": False}
    readiness = {"emergency_stop_active": True, "readiness_breach": False}
    lock = {"emergency_stop": True}

    # Fresh state -> NOT_STARTED, no breach, nothing reviewed.
    fresh = build_report(sample_state, "ok", policy, "ok", readiness, "ok", {}, "ok", lock, "ok", last_action=None, generated_at="2026-06-12T00:00:00Z")
    if fresh["tracker_status"] != TRACKER_NOT_STARTED or fresh["tracker_breach"]:
        raise AssertionError("fresh state should be NOT_STARTED")
    if fresh["reviewed_count"] != 0:
        raise AssertionError("fresh state must not auto-review items")

    # mark-reviewed one item -> IN_PROGRESS.
    updated = update_state_item(sample_state, "low_risk_draft_only", STATUS_REVIEWED, "reviewed draft-only", "mark-reviewed", "2026-06-12T00:01:00Z")
    prog = build_report(updated, "ok", policy, "ok", readiness, "ok", {}, "ok", lock, "ok", last_action=None, generated_at="2026-06-12T00:02:00Z")
    if prog["tracker_status"] != TRACKER_IN_PROGRESS or prog["reviewed_count"] != 1:
        raise AssertionError("in-progress failed")

    # All reviewed + emergency stop -> COMPLETE_LOCKED.
    all_state = {"review_items": [{"item_id": iid, "review_status": STATUS_REVIEWED, "apply_status": APPLY_NOT_APPLIED, "owner_notes": []} for iid in REVIEW_ITEM_TITLES]}
    locked = build_report(all_state, "ok", policy, "ok", readiness, "ok", {}, "ok", lock, "ok", last_action=None, generated_at="2026-06-12T00:03:00Z")
    if locked["tracker_status"] != TRACKER_COMPLETE_LOCKED or locked["tracker_breach"]:
        raise AssertionError("complete-locked failed")
    if locked["low_risk_autonomy_allowed_now"] or locked["policy_activation_allowed"]:
        raise AssertionError("complete-locked must not allow activation")

    # HIGH/FORBIDDEN may be reviewed but never activatable.
    for item in locked["review_items"]:
        if item["activatable_now"]:
            raise AssertionError("no item may be activatable")
        if item["item_id"] in NEVER_ACTIVATABLE_ITEMS and not item["never_activatable"]:
            raise AssertionError("HIGH/FORBIDDEN must be never_activatable")

    # mark-needs-work / reset transitions.
    nw = update_state_item(all_state, "forbidden", STATUS_NEEDS_WORK, "needs work", "mark-needs-work", "2026-06-12T00:04:00Z")
    if find_item(merge_review_items(nw), "forbidden")["review_status"] != STATUS_NEEDS_WORK:
        raise AssertionError("mark-needs-work failed")
    rs = update_state_item(nw, "forbidden", STATUS_UNCHECKED, "reset", "reset", "2026-06-12T00:05:00Z")
    if find_item(merge_review_items(rs), "forbidden")["review_status"] != STATUS_UNCHECKED:
        raise AssertionError("reset failed")

    # Invalid item id rejected.
    try:
        update_state_item(sample_state, "does_not_exist", STATUS_REVIEWED, "x", "mark-reviewed", "2026-06-12T00:06:00Z")
    except TrackerError:
        pass
    else:
        raise AssertionError("invalid item_id not rejected")

    # Secret-like note rejected.
    try:
        update_state_item(sample_state, "low_risk_draft_only", STATUS_REVIEWED, "token=abc12345", "mark-reviewed", "2026-06-12T00:07:00Z")
    except TrackerError:
        pass
    else:
        raise AssertionError("secret-like note not rejected")

    # Direct breach flags -> BREACH.
    for flag in ("low_risk_autonomy_allowed_now", "policy_activation_allowed", "live_apply", "install_allowed_now", "can_install_timer_now", "forbidden_apply_command_detected", "systemd_file_written", "crontab_file_written", "executable_install_script_generated", "output_path_breach", "secret_like_state"):
        bad = build_report(sample_state, "ok", policy, "ok", readiness, "ok", {}, "ok", lock, "ok", last_action=None, generated_at="2026-06-12T00:08:00Z", forced_flags={flag: True})
        if not bad["tracker_breach"] or bad["tracker_status"] != TRACKER_BREACH:
            raise AssertionError(f"flag {flag} did not breach")

    # Upstream breach -> BLOCKED_BY_BREACH.
    up = build_report(sample_state, "ok", {"policy_breach": True, "emergency_stop_active": True}, "ok", readiness, "ok", {}, "ok", lock, "ok", last_action=None, generated_at="2026-06-12T00:09:00Z")
    if up["tracker_status"] != TRACKER_BLOCKED_BY_BREACH or not up["tracker_breach"]:
        raise AssertionError("upstream breach failed")

    # apply_status in state -> breach.
    bad_apply = {"review_items": [{"item_id": "low_risk_draft_only", "review_status": STATUS_REVIEWED, "apply_status": "applied"}]}
    rep = build_report(bad_apply, "ok", policy, "ok", readiness, "ok", {}, "ok", lock, "ok", last_action=None, generated_at="2026-06-12T00:10:00Z")
    if not rep["tracker_breach"]:
        raise AssertionError("state apply_status breach failed")

    # Forbidden write paths.
    for forbidden in (PROJECT_DIR / "drafts/owner/bad.sh", PROJECT_DIR / "state/bad.service", PROJECT_DIR / "config/x.json"):
        try:
            assert_allowed_write(forbidden)
        except ValueError:
            pass
        else:
            raise AssertionError(f"forbidden path not rejected: {forbidden}")
    # Missing inputs must not crash.
    crashless = build_report({}, "not_available", None, "not_available", None, "not_available", None, "not_available", None, "not_available", last_action=None, generated_at="2026-06-12T00:11:00Z")
    if not crashless["read_only"]:
        raise AssertionError("crashless run lost read_only")
    print("low-risk-policy-owner-review-tracker self-tests: OK")
    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Track LOW-RISK policy owner review; read-only, no activation.")
    parser.add_argument("--self-test", action="store_true", help="Run in-memory safety tests and exit.")
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("list", help="List review items and statuses.")
    show = subparsers.add_parser("show", help="Show one review item.")
    show.add_argument("item_id")
    for command in ("mark-reviewed", "mark-needs-work"):
        sub = subparsers.add_parser(command, help=f"{command} for one review item.")
        sub.add_argument("item_id")
        sub.add_argument("--note", required=True)
    reset = subparsers.add_parser("reset", help="Reset one review item to unchecked.")
    reset.add_argument("item_id")
    reset.add_argument("--note", required=False, default="reset")
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
