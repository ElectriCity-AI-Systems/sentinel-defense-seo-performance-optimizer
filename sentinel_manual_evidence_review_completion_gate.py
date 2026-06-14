#!/usr/bin/env python3
"""Sentinel Manual Evidence Review Completion Gate (Phase 4.8).

Evaluates the Manual Evidence Review Completion Tracker and produces an owner
decision template. This is not an installation, not an active timer, and not an
apply mechanism.

Hard safety guarantees:
- no live changes
- no systemd/crontab writes
- no network, API, login, WordPress, Cloudflare, Nginx, or .htaccess work
- install_allowed_now, can_install_timer_now, can_execute_live, and live_apply
  remain false
- apply_status remains not_applied
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

TRACKER_JSON = PROJECT_DIR / "reports/latest/manual-evidence-review-completion-tracker.json"
STATE_JSON = PROJECT_DIR / "state/manual-evidence-review-completion.json"
DASHBOARD_JSON = PROJECT_DIR / "reports/latest/manual-evidence-review-dashboard.json"
FINAL_SAFETY_JSON = PROJECT_DIR / "reports/latest/safe-draft-autonomy-final-safety-report.json"
MASTER_JSON = PROJECT_DIR / "reports/latest/sentinel-master-report.json"
RUNTIME_LOCK_JSON = PROJECT_DIR / "config/autonomy-runtime-lock.json"

REPORT_JSON = PROJECT_DIR / "reports/latest/manual-evidence-review-completion-gate.json"
REPORT_MD = PROJECT_DIR / "reports/latest/manual-evidence-review-completion-gate.md"
DRAFT_GATE_MD = PROJECT_DIR / "drafts/owner/manual-evidence-review-completion-gate.md"
NEXT_OWNER_ACTION_MD = PROJECT_DIR / "drafts/owner/manual-evidence-review-gate-next-owner-action.md"
AUDIT_JSONL = PROJECT_DIR / "audit/manual-evidence-review-completion-gate.jsonl"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "drafts/owner",
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "audit",
)
ALLOWED_OUTPUT_PATHS = (REPORT_JSON, REPORT_MD, DRAFT_GATE_MD, NEXT_OWNER_ACTION_MD, AUDIT_JSONL)
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

SCHEMA_VERSION = "manual-evidence-review-completion-gate-4.8"
APPLY_NOT_APPLIED = "not_applied"

GATE_IN_PROGRESS = "COMPLETION_GATE_IN_PROGRESS"
GATE_READY_BUT_LOCKED = "COMPLETION_GATE_READY_BUT_LOCKED"
GATE_BLOCKED_ITEMS = "COMPLETION_GATE_BLOCKED_ITEMS"
GATE_NEEDS_WORK = "COMPLETION_GATE_NEEDS_WORK"
GATE_NOT_READY_MISSING_INPUTS = "COMPLETION_GATE_NOT_READY_MISSING_INPUTS"
GATE_BREACH = "COMPLETION_GATE_BREACH"

STATUS_UNCHECKED = "unchecked"
STATUS_REVIEWED = "reviewed"
STATUS_NEEDS_WORK = "needs_work"
STATUS_BLOCKED = "blocked"
STATUS_SKIPPED = "skipped"

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


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError):
        return False


def assert_allowed_write(path: Path) -> None:
    if path not in ALLOWED_OUTPUT_PATHS and not any(is_within(path, root) for root in ALLOWED_WRITE_ROOTS):
        raise ValueError(f"Refusing to write outside allowed gate roots: {path}")
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


def parse_count(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def safe_float(value: Any) -> float:
    try:
        return round(float(value), 2)
    except (TypeError, ValueError):
        return 0.0


def bool_from(data: Optional[Any], key: str, default: bool = False) -> bool:
    if not isinstance(data, dict):
        return default
    return bool(data.get(key, default))


def text_from(data: Optional[Any], key: str, default: str = "") -> str:
    if not isinstance(data, dict):
        return default
    return redact_text(data.get(key), default=default, max_len=500)


def review_items_from_state(state_data: Optional[Any]) -> List[Dict[str, Any]]:
    if not isinstance(state_data, dict) or not isinstance(state_data.get("review_items"), list):
        return []
    return [item for item in state_data["review_items"] if isinstance(item, dict)]


def review_items_from_tracker(tracker_data: Optional[Any]) -> List[Dict[str, Any]]:
    if not isinstance(tracker_data, dict) or not isinstance(tracker_data.get("review_items"), list):
        return []
    return [item for item in tracker_data["review_items"] if isinstance(item, dict)]


def items_by_status(state_data: Optional[Any], tracker_data: Optional[Any], status: str) -> List[Dict[str, Any]]:
    state_items = review_items_from_state(state_data)
    source_items = state_items if state_items else review_items_from_tracker(tracker_data)
    result: List[Dict[str, Any]] = []
    for item in source_items:
        review_status = str(item.get("review_status", "")).strip().lower()
        if review_status == status:
            result.append(
                {
                    "item_id": redact_text(item.get("item_id"), max_len=180),
                    "title": redact_text(item.get("title"), max_len=240),
                    "review_status": status,
                    "source_available": bool(item.get("source_available", False)),
                }
            )
    return result


def gate_counts(tracker_data: Optional[Any], state_data: Optional[Any]) -> Dict[str, Any]:
    if isinstance(tracker_data, dict):
        total = parse_count(tracker_data.get("total_items"))
        reviewed = parse_count(tracker_data.get("reviewed_count"))
        unchecked = parse_count(tracker_data.get("unchecked_count"))
        needs_work = parse_count(tracker_data.get("needs_work_count"))
        blocked = parse_count(tracker_data.get("blocked_count"))
        skipped = parse_count(tracker_data.get("skipped_count"))
        percent = safe_float(tracker_data.get("completion_percent"))
        all_reviewed = bool(tracker_data.get("all_required_reviewed", False))
    else:
        items = review_items_from_state(state_data)
        total = len(items)
        reviewed = sum(1 for item in items if item.get("review_status") == STATUS_REVIEWED)
        unchecked = sum(1 for item in items if item.get("review_status") == STATUS_UNCHECKED)
        needs_work = sum(1 for item in items if item.get("review_status") == STATUS_NEEDS_WORK)
        blocked = sum(1 for item in items if item.get("review_status") == STATUS_BLOCKED)
        skipped = sum(1 for item in items if item.get("review_status") == STATUS_SKIPPED)
        percent = round((reviewed / total) * 100, 2) if total else 0.0
        all_reviewed = total > 0 and reviewed == total
    return {
        "total_items": total,
        "reviewed_count": reviewed,
        "unchecked_count": unchecked,
        "needs_work_count": needs_work,
        "blocked_count": blocked,
        "skipped_count": skipped,
        "completion_percent": percent,
        "all_required_reviewed": all_reviewed,
    }


def detect_breach(
    tracker_data: Optional[Any],
    dashboard_data: Optional[Any],
    final_safety_data: Optional[Any],
    master_data: Optional[Any],
    runtime_lock_data: Optional[Any],
    *,
    install_allowed_now: bool,
    can_install_timer_now: bool,
    can_execute_live: bool,
    live_apply: bool,
    apply_status: str,
    systemd_file_written: bool,
    crontab_file_written: bool,
    executable_install_script_generated: bool,
    output_path_breach: bool,
    secret_like_output: bool,
) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    if install_allowed_now:
        reasons.append("install_allowed_now=true")
    if can_install_timer_now:
        reasons.append("can_install_timer_now=true")
    if can_execute_live:
        reasons.append("can_execute_live=true")
    if live_apply:
        reasons.append("live_apply=true")
    if apply_status != APPLY_NOT_APPLIED:
        reasons.append("apply_status != not_applied")
    if bool_from(tracker_data, "tracker_breach"):
        reasons.append("upstream tracker_breach=true")
    if bool_from(dashboard_data, "dashboard_breach"):
        reasons.append("upstream dashboard_breach=true")
    if bool_from(final_safety_data, "final_safety_breach"):
        reasons.append("upstream final_safety_breach=true")
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
    for source, data in (
        ("master", master_data),
        ("runtime_lock", runtime_lock_data),
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
        upstream_apply_status = data.get("apply_status")
        if upstream_apply_status not in (None, "", APPLY_NOT_APPLIED):
            reasons.append(f"{source}: apply_status != not_applied")
    return bool(reasons), sorted(set(reasons))


def decide_gate_status(
    counts: Dict[str, Any],
    *,
    input_missing: bool,
    breach: bool,
    emergency_stop_active: bool,
) -> Tuple[str, str, str]:
    if breach:
        return (
            GATE_BREACH,
            "Safety-Verletzung erkannt; Gate blockiert.",
            "Stop and review completion gate breach before any owner decision.",
        )
    if input_missing:
        return (
            GATE_NOT_READY_MISSING_INPUTS,
            "Ein oder mehrere wichtige Inputs fehlen; Gate bleibt review-only.",
            "Generate missing tracker/dashboard/final-safety inputs; do not install.",
        )
    if counts["needs_work_count"] > 0:
        return (
            GATE_NEEDS_WORK,
            "Mindestens ein Evidence-Review-Item benoetigt Nacharbeit.",
            "Work through needs_work items first; do not install.",
        )
    if counts["blocked_count"] > 0:
        return (
            GATE_BLOCKED_ITEMS,
            "Mindestens ein Evidence-Review-Item ist blockiert.",
            "Resolve blocked evidence items first; do not install.",
        )
    if counts["reviewed_count"] < counts["total_items"] or not counts["all_required_reviewed"]:
        return (
            GATE_IN_PROGRESS,
            "Owner Evidence Review ist noch nicht vollstaendig.",
            "Continue manual evidence review; no install and no live apply.",
        )
    if counts["all_required_reviewed"]:
        lock_note = "Emergency Stop ist aktiv." if emergency_stop_active else "Emergency Stop ist nicht aktiv, aber dieses Gate erlaubt trotzdem keine Installation."
        return (
            GATE_READY_BUT_LOCKED,
            f"Alle required Items sind reviewed. {lock_note}",
            "Review completed; installation remains a separate manual owner decision outside this module.",
        )
    return (
        GATE_IN_PROGRESS,
        "Owner Evidence Review ist noch nicht vollstaendig.",
        "Continue manual evidence review; no install and no live apply.",
    )


def build_report(
    tracker_data: Optional[Any],
    tracker_status: str,
    state_data: Optional[Any],
    state_status: str,
    dashboard_data: Optional[Any],
    dashboard_status: str,
    final_safety_data: Optional[Any],
    final_safety_status: str,
    master_data: Optional[Any],
    master_status: str,
    runtime_lock_data: Optional[Any],
    runtime_lock_status: str,
    *,
    generated_at: Optional[str] = None,
    forced_flags: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    generated = generated_at or utc_now()
    counts = gate_counts(tracker_data, state_data)
    flags = forced_flags or {}

    install_allowed_now = bool(flags.get("install_allowed_now", False))
    can_install_timer_now = bool(flags.get("can_install_timer_now", False))
    can_execute_live = bool(flags.get("can_execute_live", False))
    live_apply = bool(flags.get("live_apply", False))
    apply_status = str(flags.get("apply_status", APPLY_NOT_APPLIED))
    systemd_file_written = bool(flags.get("systemd_file_written", False))
    crontab_file_written = bool(flags.get("crontab_file_written", False))
    executable_install_script_generated = bool(flags.get("executable_install_script_generated", False))
    output_path_breach = bool(flags.get("output_path_breach", False))
    secret_like_output = bool(flags.get("secret_like_output", False))

    emergency_stop_active = (
        bool_from(tracker_data, "emergency_stop_active")
        or bool_from(dashboard_data, "emergency_stop_active")
        or bool_from(final_safety_data, "emergency_stop_active")
        or bool_from(runtime_lock_data, "emergency_stop")
        or bool_from(runtime_lock_data, "emergency_stop_active")
    )

    breach, breach_reasons = detect_breach(
        tracker_data,
        dashboard_data,
        final_safety_data,
        master_data,
        runtime_lock_data,
        install_allowed_now=install_allowed_now,
        can_install_timer_now=can_install_timer_now,
        can_execute_live=can_execute_live,
        live_apply=live_apply,
        apply_status=apply_status,
        systemd_file_written=systemd_file_written,
        crontab_file_written=crontab_file_written,
        executable_install_script_generated=executable_install_script_generated,
        output_path_breach=output_path_breach,
        secret_like_output=secret_like_output,
    )

    input_missing = tracker_status != "ok" or dashboard_status != "ok" or final_safety_status != "ok"
    gate_status, reason, next_owner_action = decide_gate_status(
        counts,
        input_missing=input_missing,
        breach=breach,
        emergency_stop_active=emergency_stop_active,
    )

    unchecked_items = items_by_status(state_data, tracker_data, STATUS_UNCHECKED)
    needs_work_items = items_by_status(state_data, tracker_data, STATUS_NEEDS_WORK)
    blocked_items = items_by_status(state_data, tracker_data, STATUS_BLOCKED)

    if gate_status == GATE_IN_PROGRESS and unchecked_items:
        decision_focus = "unchecked_items"
    elif gate_status == GATE_NEEDS_WORK:
        decision_focus = "needs_work_items"
    elif gate_status == GATE_BLOCKED_ITEMS:
        decision_focus = "blocked_items"
    elif gate_status == GATE_READY_BUT_LOCKED:
        decision_focus = "ready_but_locked"
    elif gate_status == GATE_BREACH:
        decision_focus = "safety_breach"
    else:
        decision_focus = "missing_inputs"

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": generated,
        "gate_status": gate_status,
        "read_only": True,
        "network_access": False,
        "wordpress_login": False,
        "api_access": False,
        "apply_function": False,
        "install_allowed_now": install_allowed_now,
        "can_install_timer_now": can_install_timer_now,
        "can_execute_live": can_execute_live,
        "live_apply": live_apply,
        "apply_status": apply_status,
        "timer_installation_status": "not_installed",
        "systemd_file_written": systemd_file_written,
        "crontab_file_written": crontab_file_written,
        "executable_install_script_generated": executable_install_script_generated,
        "secrets_output": False,
        "allowed_write_roots": [str(path) for path in ALLOWED_WRITE_ROOTS],
        "input_statuses": {
            "completion_tracker": tracker_status,
            "completion_state": state_status,
            "manual_evidence_dashboard": dashboard_status,
            "final_safety": final_safety_status,
            "sentinel_master": master_status,
            "runtime_lock": runtime_lock_status,
        },
        "total_items": counts["total_items"],
        "reviewed_count": counts["reviewed_count"],
        "unchecked_count": counts["unchecked_count"],
        "needs_work_count": counts["needs_work_count"],
        "blocked_count": counts["blocked_count"],
        "skipped_count": counts["skipped_count"],
        "completion_percent": counts["completion_percent"],
        "all_required_reviewed": counts["all_required_reviewed"],
        "emergency_stop_active": emergency_stop_active,
        "gate_breach": breach,
        "gate_breach_reasons": breach_reasons,
        "next_owner_action": next_owner_action,
        "reason": reason,
        "decision_focus": decision_focus,
        "unchecked_items": unchecked_items,
        "needs_work_items": needs_work_items,
        "blocked_items": blocked_items,
        "reviewed_items": items_by_status(state_data, tracker_data, STATUS_REVIEWED),
        "owner_decision_template": build_owner_decision_template(
            gate_status,
            unchecked_items,
            needs_work_items,
            blocked_items,
            emergency_stop_active,
        ),
        "outputs": {
            "report_json": str(REPORT_JSON),
            "report_md": str(REPORT_MD),
            "draft_gate_md": str(DRAFT_GATE_MD),
            "next_owner_action_md": str(NEXT_OWNER_ACTION_MD),
            "audit_jsonl": str(AUDIT_JSONL),
        },
    }


def build_owner_decision_template(
    gate_status: str,
    unchecked_items: List[Dict[str, Any]],
    needs_work_items: List[Dict[str, Any]],
    blocked_items: List[Dict[str, Any]],
    emergency_stop_active: bool,
) -> Dict[str, Any]:
    if gate_status == GATE_IN_PROGRESS:
        return {
            "status": gate_status,
            "title": "Evidence Review In Progress",
            "items_to_review_next": unchecked_items,
            "recommendation": "Weiter manuell pruefen; nichts installieren.",
        }
    if gate_status == GATE_NEEDS_WORK:
        return {
            "status": gate_status,
            "title": "Evidence Review Needs Work",
            "items_needing_work": needs_work_items,
            "recommendation": "Erst Nacharbeit abschliessen; nichts installieren.",
        }
    if gate_status == GATE_BLOCKED_ITEMS:
        return {
            "status": gate_status,
            "title": "Evidence Review Blocked",
            "blocked_items": blocked_items,
            "recommendation": "Blocker klaeren; nichts installieren.",
        }
    if gate_status == GATE_READY_BUT_LOCKED:
        return {
            "status": gate_status,
            "title": "Evidence Review Complete",
            "emergency_stop_active": emergency_stop_active,
            "recommendation": "Review ist vollstaendig. Installation bleibt eine separate manuelle Owner-Entscheidung ausserhalb dieses Moduls; keine automatische Installation.",
        }
    if gate_status == GATE_BREACH:
        return {
            "status": gate_status,
            "title": "Safety Breach",
            "recommendation": "Stoppen und Safety-Breach pruefen; nichts installieren.",
        }
    return {
        "status": gate_status,
        "title": "Missing Inputs",
        "recommendation": "Fehlende Inputs erzeugen; nichts installieren.",
    }


def render_item_table(items: List[Dict[str, Any]]) -> List[str]:
    lines = ["| Item ID | Title | Status |", "|---|---|---|"]
    if not items:
        lines.append("| - | - | - |")
        return lines
    for item in items:
        lines.append(
            "| "
            f"`{redact_text(item.get('item_id'), max_len=160)}` | "
            f"{redact_text(item.get('title'), max_len=220)} | "
            f"`{redact_text(item.get('review_status'), max_len=80)}` |"
        )
    return lines


def render_report_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# Manual Evidence Review Completion Gate",
        "",
        f"- Generated (UTC): `{report.get('generated_at_utc')}`",
        f"- Gate status: `{report.get('gate_status')}`",
        f"- Reason: {redact_text(report.get('reason'), max_len=600)}",
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
        f"- Can execute live: `{report.get('can_execute_live')}`",
        f"- Live apply: `{report.get('live_apply')}`",
        f"- Apply status: `{report.get('apply_status')}`",
        f"- Gate breach: `{report.get('gate_breach')}`",
        f"- Next owner action: {redact_text(report.get('next_owner_action'), max_len=600)}",
        "",
    ]
    if report.get("gate_breach_reasons"):
        lines.extend(["## Breach Reasons", ""])
        for reason in report.get("gate_breach_reasons", []):
            lines.append(f"- {redact_text(reason, max_len=300)}")
        lines.append("")
    lines.extend(["## Owner Decision Template", ""])
    template = report.get("owner_decision_template") if isinstance(report.get("owner_decision_template"), dict) else {}
    lines.extend(
        [
            f"- Title: `{redact_text(template.get('title'), max_len=240)}`",
            f"- Recommendation: {redact_text(template.get('recommendation'), max_len=700)}",
            "",
        ]
    )
    lines.extend(["## Unchecked Items", ""])
    lines.extend(render_item_table(report.get("unchecked_items", []) if isinstance(report.get("unchecked_items"), list) else []))
    lines.extend(["", "## Needs Work Items", ""])
    lines.extend(render_item_table(report.get("needs_work_items", []) if isinstance(report.get("needs_work_items"), list) else []))
    lines.extend(["", "## Blocked Items", ""])
    lines.extend(render_item_table(report.get("blocked_items", []) if isinstance(report.get("blocked_items"), list) else []))
    lines.extend(
        [
            "",
            "## Safety Boundaries",
            "",
            "- Keine Installation.",
            "- Kein aktiver Timer.",
            "- Kein Apply-Mechanismus.",
            "- Keine systemd-Datei, keine crontab, kein Shell-Skript.",
            "- Keine WordPress-, Cloudflare-, Nginx- oder .htaccess-Aenderung.",
            "- `install_allowed_now=false`, `can_install_timer_now=false`, `live_apply=false`.",
            "",
        ]
    )
    return "\n".join(lines)


def render_next_owner_action(report: Dict[str, Any]) -> str:
    lines = [
        "# Manual Evidence Review Gate - Next Owner Action",
        "",
        f"- Gate status: `{report.get('gate_status')}`",
        f"- Next owner action: {redact_text(report.get('next_owner_action'), max_len=700)}",
        f"- Install allowed now: `{report.get('install_allowed_now')}`",
        f"- Can install timer now: `{report.get('can_install_timer_now')}`",
        f"- Live apply: `{report.get('live_apply')}`",
        f"- Gate breach: `{report.get('gate_breach')}`",
        "",
        "## Decision Guidance",
        "",
        redact_text((report.get("owner_decision_template") or {}).get("recommendation"), max_len=900),
        "",
        "## Do Not Proceed",
        "",
        "- Keine Installation durch dieses Modul.",
        "- Keine systemd-/crontab-/Shell-Artefakte erzeugen.",
        "- Keine Live-Aenderungen ausfuehren.",
        "",
    ]
    return "\n".join(lines)


def audit_record(report: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "timestamp_utc": report.get("generated_at_utc"),
        "schema_version": SCHEMA_VERSION,
        "gate_status": report.get("gate_status"),
        "gate_breach": report.get("gate_breach"),
        "total_items": report.get("total_items"),
        "reviewed_count": report.get("reviewed_count"),
        "unchecked_count": report.get("unchecked_count"),
        "needs_work_count": report.get("needs_work_count"),
        "blocked_count": report.get("blocked_count"),
        "install_allowed_now": False,
        "can_install_timer_now": False,
        "can_execute_live": False,
        "live_apply": False,
        "apply_status": APPLY_NOT_APPLIED,
        "network_access": False,
        "apply_function": False,
    }


def write_outputs(report: Dict[str, Any]) -> None:
    write_json_atomic(REPORT_JSON, report)
    markdown = render_report_markdown(report)
    write_text_atomic(REPORT_MD, markdown)
    write_text_atomic(DRAFT_GATE_MD, markdown)
    write_text_atomic(NEXT_OWNER_ACTION_MD, render_next_owner_action(report))
    append_jsonl(AUDIT_JSONL, [audit_record(report)])


def build_current_report() -> Dict[str, Any]:
    tracker_data, tracker_status = read_optional_json(TRACKER_JSON)
    state_data, state_status = read_optional_json(STATE_JSON)
    dashboard_data, dashboard_status = read_optional_json(DASHBOARD_JSON)
    final_safety_data, final_safety_status = read_optional_json(FINAL_SAFETY_JSON)
    master_data, master_status = read_optional_json(MASTER_JSON)
    runtime_lock_data, runtime_lock_status = read_optional_json(RUNTIME_LOCK_JSON)
    return build_report(
        tracker_data,
        tracker_status,
        state_data,
        state_status,
        dashboard_data,
        dashboard_status,
        final_safety_data,
        final_safety_status,
        master_data,
        master_status,
        runtime_lock_data,
        runtime_lock_status,
    )


def run_self_test() -> int:
    base_tracker = {
        "total_items": 10,
        "reviewed_count": 1,
        "unchecked_count": 9,
        "needs_work_count": 0,
        "blocked_count": 0,
        "skipped_count": 0,
        "completion_percent": 10.0,
        "all_required_reviewed": False,
        "emergency_stop_active": True,
        "tracker_breach": False,
        "apply_status": APPLY_NOT_APPLIED,
        "review_items": [
            {"item_id": "evidence_dashboard", "title": "Dashboard", "review_status": STATUS_REVIEWED, "source_available": True},
            {"item_id": "next_owner_actions", "title": "Next", "review_status": STATUS_UNCHECKED, "source_available": True},
        ],
    }
    state = {
        "review_items": [
            {"item_id": "evidence_dashboard", "title": "Dashboard", "review_status": STATUS_REVIEWED, "source_available": True},
            {"item_id": "next_owner_actions", "title": "Next", "review_status": STATUS_UNCHECKED, "source_available": True},
        ]
    }
    dashboard = {"emergency_stop_active": True, "dashboard_breach": False, "apply_status": APPLY_NOT_APPLIED}
    final = {"emergency_stop_active": True, "final_safety_breach": False, "apply_status": APPLY_NOT_APPLIED}
    report = build_report(base_tracker, "ok", state, "ok", dashboard, "ok", final, "ok", {}, "ok", {}, "ok", generated_at="2026-06-11T00:00:00Z")
    if report["gate_status"] != GATE_IN_PROGRESS or report["gate_breach"]:
        raise AssertionError("in-progress gate status failed")

    needs_work = dict(base_tracker, needs_work_count=1, unchecked_count=8, review_items=[{"item_id": "x", "title": "X", "review_status": STATUS_NEEDS_WORK}])
    needs_report = build_report(needs_work, "ok", {"review_items": needs_work["review_items"]}, "ok", dashboard, "ok", final, "ok", {}, "ok", {}, "ok", generated_at="2026-06-11T00:01:00Z")
    if needs_report["gate_status"] != GATE_NEEDS_WORK:
        raise AssertionError("needs-work gate status failed")

    blocked = dict(base_tracker, blocked_count=1, unchecked_count=8, review_items=[{"item_id": "x", "title": "X", "review_status": STATUS_BLOCKED}])
    blocked_report = build_report(blocked, "ok", {"review_items": blocked["review_items"]}, "ok", dashboard, "ok", final, "ok", {}, "ok", {}, "ok", generated_at="2026-06-11T00:02:00Z")
    if blocked_report["gate_status"] != GATE_BLOCKED_ITEMS:
        raise AssertionError("blocked gate status failed")

    ready = dict(base_tracker, reviewed_count=10, unchecked_count=0, completion_percent=100.0, all_required_reviewed=True, review_items=[{"item_id": "x", "title": "X", "review_status": STATUS_REVIEWED}])
    ready_report = build_report(ready, "ok", {"review_items": ready["review_items"]}, "ok", dashboard, "ok", final, "ok", {}, "ok", {}, "ok", generated_at="2026-06-11T00:03:00Z")
    if ready_report["gate_status"] != GATE_READY_BUT_LOCKED or ready_report["gate_breach"]:
        raise AssertionError("ready locked gate status failed")

    missing_report = build_report(None, "not_available", {}, "not_available", dashboard, "ok", final, "ok", {}, "ok", {}, "ok", generated_at="2026-06-11T00:04:00Z")
    if missing_report["gate_status"] != GATE_NOT_READY_MISSING_INPUTS or missing_report["gate_breach"]:
        raise AssertionError("missing inputs gate status failed")

    for key in (
        "install_allowed_now",
        "can_install_timer_now",
        "can_execute_live",
        "live_apply",
        "systemd_file_written",
        "crontab_file_written",
        "executable_install_script_generated",
        "secret_like_output",
        "output_path_breach",
    ):
        bad = build_report(base_tracker, "ok", state, "ok", dashboard, "ok", final, "ok", {}, "ok", {}, "ok", generated_at="2026-06-11T00:05:00Z", forced_flags={key: True})
        if not bad["gate_breach"]:
            raise AssertionError(f"{key} did not produce breach")
    bad = build_report(base_tracker, "ok", state, "ok", dashboard, "ok", final, "ok", {}, "ok", {}, "ok", generated_at="2026-06-11T00:06:00Z", forced_flags={"apply_status": "applied"})
    if not bad["gate_breach"]:
        raise AssertionError("apply_status != not_applied did not produce breach")
    for source_name, source_data in (
        ("tracker_breach", dict(base_tracker, tracker_breach=True)),
        ("dashboard_breach", dict(dashboard, dashboard_breach=True)),
        ("final_safety_breach", dict(final, final_safety_breach=True)),
    ):
        bad = build_report(
            source_data if source_name == "tracker_breach" else base_tracker,
            "ok",
            state,
            "ok",
            source_data if source_name == "dashboard_breach" else dashboard,
            "ok",
            source_data if source_name == "final_safety_breach" else final,
            "ok",
            {},
            "ok",
            {},
            "ok",
            generated_at="2026-06-11T00:07:00Z",
        )
        if not bad["gate_breach"]:
            raise AssertionError(f"{source_name} did not produce breach")
    for forbidden in (PROJECT_DIR / "drafts/owner/bad.sh", PROJECT_DIR / "reports/latest/bad.service", PROJECT_DIR / "audit/bad.timer"):
        try:
            assert_allowed_write(forbidden)
        except ValueError:
            pass
        else:
            raise AssertionError(f"forbidden artifact was not rejected: {forbidden}")
    try:
        assert_allowed_write(PROJECT_DIR / "state/manual-evidence-review-completion-gate.json")
    except ValueError:
        pass
    else:
        raise AssertionError("forbidden write root was not rejected")
    if not detect_secret_like("token=abc12345"):
        raise AssertionError("secret-like detector failed")
    print("manual-evidence-review-completion-gate self-tests: OK")
    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build Manual Evidence Review Completion Gate; no install, no live apply.")
    parser.add_argument("--self-test", action="store_true", help="Run in-memory safety tests and exit.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()
    report = build_current_report()
    write_outputs(report)
    print(
        "Manual Evidence Review Completion Gate: "
        f"status={report.get('gate_status')}, "
        f"reviewed={report.get('reviewed_count')}/{report.get('total_items')}, "
        f"emergency_stop={report.get('emergency_stop_active')}, "
        f"install_allowed={report.get('install_allowed_now')}, "
        f"can_install={report.get('can_install_timer_now')}, "
        f"breach={report.get('gate_breach')}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
