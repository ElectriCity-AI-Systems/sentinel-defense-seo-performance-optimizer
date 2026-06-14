#!/usr/bin/env python3
"""Sentinel Owner Evidence Review Console (Phase 4.9).

Builds a local owner-facing review console for open Manual Evidence Review
items. This module is review-only:

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
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


PROJECT_DIR = Path("/srv/sentinel-defense")

TRACKER_JSON = PROJECT_DIR / "reports/latest/manual-evidence-review-completion-tracker.json"
STATE_JSON = PROJECT_DIR / "state/manual-evidence-review-completion.json"
GATE_JSON = PROJECT_DIR / "reports/latest/manual-evidence-review-completion-gate.json"
DASHBOARD_JSON = PROJECT_DIR / "reports/latest/manual-evidence-review-dashboard.json"
FINAL_SAFETY_JSON = PROJECT_DIR / "reports/latest/safe-draft-autonomy-final-safety-report.json"
MASTER_JSON = PROJECT_DIR / "reports/latest/sentinel-master-report.json"

REPORT_JSON = PROJECT_DIR / "reports/latest/owner-evidence-review-console.json"
REPORT_MD = PROJECT_DIR / "reports/latest/owner-evidence-review-console.md"
DRAFT_CONSOLE_MD = PROJECT_DIR / "drafts/owner/owner-evidence-review-console.md"
OPEN_ITEMS_MD = PROJECT_DIR / "drafts/owner/owner-evidence-review-open-items.md"
AUDIT_JSONL = PROJECT_DIR / "audit/owner-evidence-review-console.jsonl"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "drafts/owner",
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "audit",
)
ALLOWED_OUTPUT_PATHS = (REPORT_JSON, REPORT_MD, DRAFT_CONSOLE_MD, OPEN_ITEMS_MD, AUDIT_JSONL)
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

SCHEMA_VERSION = "owner-evidence-review-console-4.9"
APPLY_NOT_APPLIED = "not_applied"

STATUS_UNCHECKED = "unchecked"
STATUS_REVIEWED = "reviewed"
STATUS_NEEDS_WORK = "needs_work"
STATUS_BLOCKED = "blocked"
STATUS_SKIPPED = "skipped"

CONSOLE_READY = "REVIEW_CONSOLE_READY"
CONSOLE_IN_PROGRESS = "REVIEW_CONSOLE_IN_PROGRESS"
CONSOLE_COMPLETE_LOCKED = "REVIEW_CONSOLE_COMPLETE_LOCKED"
CONSOLE_BLOCKED_GATE_BREACH = "REVIEW_CONSOLE_BLOCKED_BY_GATE_BREACH"
CONSOLE_PARTIAL_INPUTS = "REVIEW_CONSOLE_PARTIAL_INPUTS"
CONSOLE_BREACH = "REVIEW_CONSOLE_BREACH"

REVIEW_SOURCES = {
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
        PROJECT_DIR / "reports/latest/sentinel-master-report.md",
        PROJECT_DIR / "reports/latest/sentinel-master-report.json",
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

REVIEW_GUIDANCE = {
    "evidence_dashboard": {
        "title": "Manual Evidence Review Dashboard",
        "review_goal": "Dashboard-Safety pruefen.",
        "what_to_check": "Pruefen, ob dashboard emergency_stop=true, breaches=0, install_allowed=false, can_install_timer_now=false und live_apply=false zeigt.",
        "safe_expected_result": "Dashboard ist review-only, Emergency Stop ist sichtbar, keine Installation ist erlaubt.",
        "do_not_proceed_if": "dashboard_breach=true, install_allowed_now=true, can_install_timer_now=true oder live_apply=true.",
    },
    "next_owner_actions": {
        "title": "Manual Evidence Review Next Owner Actions",
        "review_goal": "Naechste Owner-Schritte auf Review-only-Sicherheit pruefen.",
        "what_to_check": "Pruefen, ob die naechsten Schritte kein Installieren, kein Live-Apply und kein systemctl verlangen.",
        "safe_expected_result": "Next Actions bleiben manuelle Review-Schritte.",
        "do_not_proceed_if": "Ein Schritt Installation, systemctl, Live-Apply oder produktive Aenderungen verlangt.",
    },
    "manual_timer_install_packet": {
        "title": "Owner Manual Timer Install Packet",
        "review_goal": "Packet als Dokumentationspaket pruefen.",
        "what_to_check": "Pruefen, ob das Packet nur Review-only ist und keine ausfuehrbare Installationsdatei erzeugt.",
        "safe_expected_result": "Nur Markdown/JSON-Dokumentation; keine Shell-, systemd- oder crontab-Artefakte.",
        "do_not_proceed_if": "Das Packet eine ausfuehrbare Installationsdatei oder automatische Kopierschritte erzeugt.",
    },
    "manual_timer_install_final_checklist": {
        "title": "Owner Manual Timer Install Final Checklist",
        "review_goal": "Finale Checkliste pruefen.",
        "what_to_check": "Pruefen, ob Emergency Stop, Rollback, Verifier und Do-Not-Proceed-Bedingungen enthalten sind.",
        "safe_expected_result": "Checkliste ist manuell, vollstaendig und nicht ausfuehrbar.",
        "do_not_proceed_if": "Rollback, Emergency Stop oder Verifier fehlen.",
    },
    "timer_install_review_only": {
        "title": "Timer Install Review Only Document",
        "review_goal": "Review-only-Charakter der Timer-Kommandos pruefen.",
        "what_to_check": "Pruefen, ob systemd/systemctl nur als Review-Text erscheint.",
        "safe_expected_result": "Keine ausfuehrbare Datei, keine automatische Installation.",
        "do_not_proceed_if": "Kommandos als ausfuehrbares Skript oder Auto-Apply-Artefakt erzeugt wurden.",
    },
    "final_safety_report": {
        "title": "Safe Draft Autonomy Final Safety Report",
        "review_goal": "Finalen Safety-Status pruefen.",
        "what_to_check": "Pruefen, ob SAFE_BUT_LOCKED_BY_EMERGENCY_STOP und breaches=0 gilt.",
        "safe_expected_result": "Final Safety meldet keine Breaches und bleibt durch Emergency Stop gesperrt.",
        "do_not_proceed_if": "final_safety_breach=true oder Live-/Install-Flags true sind.",
    },
    "master_report_autonomy_section": {
        "title": "Sentinel Master Autonomy Section",
        "review_goal": "Master-Autonomy-Zusammenfassung pruefen.",
        "what_to_check": "Pruefen, ob alle Autonomy-Breaches false sind und keine Installation erlaubt wird.",
        "safe_expected_result": "Master zeigt Review-/Draft-only Status ohne Safety-Breach.",
        "do_not_proceed_if": "Ein Autonomy-Breach, Live-Apply oder install_allowed_now=true sichtbar ist.",
    },
    "emergency_stop_state": {
        "title": "Emergency Stop State",
        "review_goal": "Emergency Stop bewusst bestaetigen.",
        "what_to_check": "Pruefen, ob Emergency Stop bewusst aktiv ist und Installationsfreigaben blockiert.",
        "safe_expected_result": "Emergency Stop ist aktiv oder bewusst dokumentiert; Installation bleibt gesperrt.",
        "do_not_proceed_if": "Emergency Stop unklar ist oder trotz Stop eine Installation erlaubt wird.",
    },
    "do_not_proceed_conditions": {
        "title": "Do Not Proceed Conditions",
        "review_goal": "Stop-Bedingungen pruefen.",
        "what_to_check": "Pruefen, ob klare Stop-Bedingungen fuer Breach, Emergency Stop, Live-Apply und Installationsrisiken vorhanden sind.",
        "safe_expected_result": "Stop-Bedingungen sind sichtbar und konservativ.",
        "do_not_proceed_if": "Stop-Bedingungen fehlen oder produktive Aenderungen erlauben.",
    },
    "rollback_instructions": {
        "title": "Rollback Instructions",
        "review_goal": "Rollback-Dokumentation pruefen.",
        "what_to_check": "Pruefen, ob Rollback vollstaendig beschrieben, aber nicht automatisch ausfuehrbar ist.",
        "safe_expected_result": "Rollback ist manuell pruefbar und kein Bot-Apply.",
        "do_not_proceed_if": "Rollback unvollstaendig oder als automatisches Skript umgesetzt ist.",
    },
}

FORBIDDEN_COMMAND_RE = re.compile(
    r"(?i)\b(systemctl|curl|wget|wp|ssh|git\s+push|nginx\s+reload|cloudflare\s+api|cfcli|"
    r"apply-safe|consolidate-apply-safe|install|enable-timer|crontab)\b"
)
ALLOWED_COMMAND_RE = re.compile(
    r'^python3 sentinel_manual_evidence_review_completion_tracker\.py '
    r'(mark-reviewed|mark-needs-work|mark-blocked) [a-z0-9_:-]+ --note "[^"]*"$'
)
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
        raise ValueError(f"Refusing to write outside allowed console roots: {path}")
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


def bool_from(data: Optional[Any], key: str, default: bool = False) -> bool:
    if not isinstance(data, dict):
        return default
    return bool(data.get(key, default))


def first_existing_source(item_id: str) -> str:
    for path in REVIEW_SOURCES.get(item_id, []):
        if path.exists():
            return str(path)
    paths = REVIEW_SOURCES.get(item_id, [])
    return str(paths[0]) if paths else "not_available"


def source_exists(item_id: str) -> bool:
    return any(path.exists() for path in REVIEW_SOURCES.get(item_id, []))


def item_id_order() -> List[str]:
    return list(REVIEW_GUIDANCE.keys())


def items_from_state_or_tracker(state_data: Optional[Any], tracker_data: Optional[Any]) -> List[Dict[str, Any]]:
    source: List[Dict[str, Any]] = []
    if isinstance(state_data, dict) and isinstance(state_data.get("review_items"), list):
        source = [item for item in state_data["review_items"] if isinstance(item, dict)]
    elif isinstance(tracker_data, dict) and isinstance(tracker_data.get("review_items"), list):
        source = [item for item in tracker_data["review_items"] if isinstance(item, dict)]
    by_id = {str(item.get("item_id")): item for item in source if str(item.get("item_id")) in REVIEW_GUIDANCE}
    items: List[Dict[str, Any]] = []
    for item_id in item_id_order():
        raw = by_id.get(item_id, {})
        status = str(raw.get("review_status", STATUS_UNCHECKED)).strip().lower() or STATUS_UNCHECKED
        if status not in {STATUS_UNCHECKED, STATUS_REVIEWED, STATUS_NEEDS_WORK, STATUS_BLOCKED, STATUS_SKIPPED}:
            status = STATUS_UNCHECKED
        guidance = REVIEW_GUIDANCE[item_id]
        items.append(
            {
                "item_id": item_id,
                "title": redact_text(raw.get("title") or guidance["title"], max_len=240),
                "current_status": status,
                "source_file": first_existing_source(item_id),
                "source_available": source_exists(item_id),
                "review_goal": guidance["review_goal"],
                "what_to_check": guidance["what_to_check"],
                "safe_expected_result": guidance["safe_expected_result"],
                "do_not_proceed_if": guidance["do_not_proceed_if"],
                "suggested_command_to_mark_reviewed": suggested_command("mark-reviewed", item_id),
                "suggested_command_to_mark_needs_work": suggested_command("mark-needs-work", item_id),
                "suggested_command_to_mark_blocked": suggested_command("mark-blocked", item_id),
                "apply_status": APPLY_NOT_APPLIED,
            }
        )
    return sorted(items, key=item_sort_key)


def item_sort_key(item: Dict[str, Any]) -> Tuple[int, int]:
    status = item.get("current_status")
    priority = {
        STATUS_NEEDS_WORK: 0,
        STATUS_BLOCKED: 1,
        STATUS_UNCHECKED: 2,
        STATUS_SKIPPED: 3,
        STATUS_REVIEWED: 4,
    }.get(str(status), 2)
    try:
        order = item_id_order().index(str(item.get("item_id")))
    except ValueError:
        order = 999
    return priority, order


def suggested_command(command: str, item_id: str) -> str:
    notes = {
        "mark-reviewed": "owner reviewed this evidence item",
        "mark-needs-work": "owner found follow-up work for this evidence item",
        "mark-blocked": "owner found this evidence item blocked",
    }
    return (
        "python3 sentinel_manual_evidence_review_completion_tracker.py "
        f"{command} {item_id} --note \"{notes[command]}\""
    )


def command_is_safe(command: str) -> bool:
    return bool(ALLOWED_COMMAND_RE.match(command)) and not FORBIDDEN_COMMAND_RE.search(command)


def commands_are_safe(items: List[Dict[str, Any]]) -> Tuple[bool, List[str]]:
    bad: List[str] = []
    for item in items:
        for key in (
            "suggested_command_to_mark_reviewed",
            "suggested_command_to_mark_needs_work",
            "suggested_command_to_mark_blocked",
        ):
            command = str(item.get(key, ""))
            if not command_is_safe(command):
                bad.append(f"{item.get('item_id')}:{key}")
    return not bad, bad


def counts_from_items(items: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {
        STATUS_REVIEWED: 0,
        STATUS_UNCHECKED: 0,
        STATUS_NEEDS_WORK: 0,
        STATUS_BLOCKED: 0,
        STATUS_SKIPPED: 0,
    }
    for item in items:
        status = str(item.get("current_status"))
        if status in counts:
            counts[status] += 1
    return counts


def detect_breach(
    gate_data: Optional[Any],
    dashboard_data: Optional[Any],
    final_safety_data: Optional[Any],
    master_data: Optional[Any],
    items: List[Dict[str, Any]],
    *,
    install_allowed_now: bool,
    can_install_timer_now: bool,
    can_execute_live: bool,
    live_apply: bool,
    apply_status: str,
    executable_install_script_generated: bool,
    systemd_file_written: bool,
    crontab_file_written: bool,
    output_path_breach: bool,
    secret_like_output: bool,
) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    commands_safe, bad_commands = commands_are_safe(items)
    if not commands_safe:
        reasons.append("unsafe suggested command: " + ", ".join(bad_commands[:6]))
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
    if bool_from(gate_data, "gate_breach"):
        reasons.append("upstream gate_breach=true")
    if executable_install_script_generated:
        reasons.append("executable install script generated")
    if systemd_file_written:
        reasons.append("systemd_file_written=true")
    if crontab_file_written:
        reasons.append("crontab_file_written=true")
    if secret_like_output:
        reasons.append("secret-like output")
    if output_path_breach:
        reasons.append("writing outside allowed roots")
    for source, data in (("dashboard", dashboard_data), ("final_safety", final_safety_data), ("master", master_data)):
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


def decide_console_status(
    *,
    gate_breach: bool,
    breach: bool,
    inputs_missing: bool,
    reviewed_count: int,
    total_items: int,
    all_required_reviewed: bool,
    emergency_stop_active: bool,
) -> str:
    if breach and gate_breach:
        return CONSOLE_BLOCKED_GATE_BREACH
    if breach:
        return CONSOLE_BREACH
    if inputs_missing:
        return CONSOLE_PARTIAL_INPUTS
    if reviewed_count < total_items:
        return CONSOLE_IN_PROGRESS
    if all_required_reviewed and emergency_stop_active:
        return CONSOLE_COMPLETE_LOCKED
    if all_required_reviewed:
        return CONSOLE_READY
    return CONSOLE_IN_PROGRESS


def build_report(
    tracker_data: Optional[Any],
    tracker_status: str,
    state_data: Optional[Any],
    state_status: str,
    gate_data: Optional[Any],
    gate_status: str,
    dashboard_data: Optional[Any],
    dashboard_status: str,
    final_safety_data: Optional[Any],
    final_safety_status: str,
    master_data: Optional[Any],
    master_status: str,
    *,
    generated_at: Optional[str] = None,
    forced_flags: Optional[Dict[str, Any]] = None,
    forced_items: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    generated = generated_at or utc_now()
    items = forced_items if forced_items is not None else items_from_state_or_tracker(state_data, tracker_data)
    counts = counts_from_items(items)
    total_items = len(items)
    reviewed_count = counts[STATUS_REVIEWED]
    open_items_count = counts[STATUS_UNCHECKED] + counts[STATUS_NEEDS_WORK] + counts[STATUS_BLOCKED]

    flags = forced_flags or {}
    install_allowed_now = bool(flags.get("install_allowed_now", False))
    can_install_timer_now = bool(flags.get("can_install_timer_now", False))
    can_execute_live = bool(flags.get("can_execute_live", False))
    live_apply = bool(flags.get("live_apply", False))
    apply_status = str(flags.get("apply_status", APPLY_NOT_APPLIED))
    executable_install_script_generated = bool(flags.get("executable_install_script_generated", False))
    systemd_file_written = bool(flags.get("systemd_file_written", False))
    crontab_file_written = bool(flags.get("crontab_file_written", False))
    output_path_breach = bool(flags.get("output_path_breach", False))
    secret_like_output = bool(flags.get("secret_like_output", False)) or detect_secret_like(json.dumps(items, ensure_ascii=False))

    emergency_stop_active = (
        bool_from(gate_data, "emergency_stop_active")
        or bool_from(tracker_data, "emergency_stop_active")
        or bool_from(dashboard_data, "emergency_stop_active")
        or bool_from(final_safety_data, "emergency_stop_active")
    )
    all_required_reviewed = bool_from(gate_data, "all_required_reviewed") or (total_items > 0 and reviewed_count == total_items)
    gate_breach = bool_from(gate_data, "gate_breach")

    breach, breach_reasons = detect_breach(
        gate_data,
        dashboard_data,
        final_safety_data,
        master_data,
        items,
        install_allowed_now=install_allowed_now,
        can_install_timer_now=can_install_timer_now,
        can_execute_live=can_execute_live,
        live_apply=live_apply,
        apply_status=apply_status,
        executable_install_script_generated=executable_install_script_generated,
        systemd_file_written=systemd_file_written,
        crontab_file_written=crontab_file_written,
        output_path_breach=output_path_breach,
        secret_like_output=secret_like_output,
    )

    inputs_missing = tracker_status != "ok" or gate_status != "ok"
    console_status = decide_console_status(
        gate_breach=gate_breach,
        breach=breach,
        inputs_missing=inputs_missing,
        reviewed_count=reviewed_count,
        total_items=total_items,
        all_required_reviewed=all_required_reviewed,
        emergency_stop_active=emergency_stop_active,
    )

    open_items = [item for item in items if item.get("current_status") in {STATUS_UNCHECKED, STATUS_NEEDS_WORK, STATUS_BLOCKED}]
    next_item = open_items[0]["item_id"] if open_items else ""
    if breach:
        next_owner_action = "Stop and review console breach; do not install."
    elif open_items:
        next_owner_action = f"Review next open item `{next_item}` using tracker-only commands; do not install."
    elif all_required_reviewed and emergency_stop_active:
        next_owner_action = "All evidence reviewed; keep Emergency Stop active and do not install."
    else:
        next_owner_action = "All evidence reviewed; keep review-only status, no install."

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": generated,
        "console_status": console_status,
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
            "completion_gate": gate_status,
            "manual_evidence_dashboard": dashboard_status,
            "final_safety": final_safety_status,
            "sentinel_master": master_status,
        },
        "total_items": total_items,
        "reviewed_count": reviewed_count,
        "unchecked_count": counts[STATUS_UNCHECKED],
        "needs_work_count": counts[STATUS_NEEDS_WORK],
        "blocked_count": counts[STATUS_BLOCKED],
        "skipped_count": counts[STATUS_SKIPPED],
        "open_items_count": open_items_count,
        "emergency_stop_active": emergency_stop_active,
        "console_breach": breach,
        "console_breach_reasons": breach_reasons,
        "next_recommended_item": next_item,
        "next_owner_action": next_owner_action,
        "review_items": items,
        "open_items": open_items,
        "outputs": {
            "report_json": str(REPORT_JSON),
            "report_md": str(REPORT_MD),
            "draft_console_md": str(DRAFT_CONSOLE_MD),
            "open_items_md": str(OPEN_ITEMS_MD),
            "audit_jsonl": str(AUDIT_JSONL),
        },
    }


def render_item_table(items: List[Dict[str, Any]]) -> List[str]:
    lines = ["| Item ID | Status | Source | Review Goal |", "|---|---|---|---|"]
    if not items:
        lines.append("| - | - | - | - |")
        return lines
    for item in items:
        lines.append(
            "| "
            f"`{redact_text(item.get('item_id'), max_len=160)}` | "
            f"`{redact_text(item.get('current_status'), max_len=80)}` | "
            f"`{redact_text(item.get('source_file'), max_len=300)}` | "
            f"{redact_text(item.get('review_goal'), max_len=300)} |"
        )
    return lines


def render_report_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# Owner Evidence Review Console",
        "",
        f"- Generated (UTC): `{report.get('generated_at_utc')}`",
        f"- Console status: `{report.get('console_status')}`",
        f"- Total items: `{report.get('total_items')}`",
        f"- Reviewed: `{report.get('reviewed_count')}`",
        f"- Unchecked: `{report.get('unchecked_count')}`",
        f"- Needs work: `{report.get('needs_work_count')}`",
        f"- Blocked: `{report.get('blocked_count')}`",
        f"- Skipped: `{report.get('skipped_count')}`",
        f"- Open items: `{report.get('open_items_count')}`",
        f"- Emergency stop active: `{report.get('emergency_stop_active')}`",
        f"- Install allowed now: `{report.get('install_allowed_now')}`",
        f"- Can install timer now: `{report.get('can_install_timer_now')}`",
        f"- Can execute live: `{report.get('can_execute_live')}`",
        f"- Live apply: `{report.get('live_apply')}`",
        f"- Apply status: `{report.get('apply_status')}`",
        f"- Console breach: `{report.get('console_breach')}`",
        f"- Next recommended item: `{report.get('next_recommended_item')}`",
        f"- Next owner action: {redact_text(report.get('next_owner_action'), max_len=700)}",
        "",
    ]
    if report.get("console_breach_reasons"):
        lines.extend(["## Breach Reasons", ""])
        for reason in report.get("console_breach_reasons", []):
            lines.append(f"- {redact_text(reason, max_len=400)}")
        lines.append("")
    lines.extend(["## Open Items First", ""])
    lines.extend(render_item_table(report.get("open_items", []) if isinstance(report.get("open_items"), list) else []))
    lines.extend(["", "## All Review Items", ""])
    lines.extend(render_item_table(report.get("review_items", []) if isinstance(report.get("review_items"), list) else []))
    lines.extend(["", "## Item Instructions", ""])
    for item in report.get("review_items", []):
        if not isinstance(item, dict):
            continue
        lines.extend(
            [
                f"### {redact_text(item.get('item_id'), max_len=180)}",
                "",
                f"- Title: `{redact_text(item.get('title'), max_len=240)}`",
                f"- Current status: `{redact_text(item.get('current_status'), max_len=80)}`",
                f"- Source file: `{redact_text(item.get('source_file'), max_len=300)}`",
                f"- Review goal: {redact_text(item.get('review_goal'), max_len=500)}",
                f"- What to check: {redact_text(item.get('what_to_check'), max_len=800)}",
                f"- Safe expected result: {redact_text(item.get('safe_expected_result'), max_len=800)}",
                f"- Do not proceed if: {redact_text(item.get('do_not_proceed_if'), max_len=800)}",
                "",
                "**Suggested tracker-only commands:**",
                "",
                "```bash",
                redact_text(item.get("suggested_command_to_mark_reviewed"), max_len=500),
                redact_text(item.get("suggested_command_to_mark_needs_work"), max_len=500),
                redact_text(item.get("suggested_command_to_mark_blocked"), max_len=500),
                "```",
                "",
            ]
        )
    lines.extend(
        [
            "## Safety Boundaries",
            "",
            "- Suggested commands are tracker-only.",
            "- Keine Installation, kein aktiver Timer, kein Apply.",
            "- Kein `systemctl`, kein `curl`, kein `wp`, kein `nginx reload`, keine Cloudflare API.",
            "- Keine systemd-Datei, keine crontab, kein Shell-Skript.",
            "- `install_allowed_now=false`, `can_install_timer_now=false`, `live_apply=false`.",
            "",
        ]
    )
    return "\n".join(lines)


def render_open_items_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# Owner Evidence Review - Open Items",
        "",
        f"- Console status: `{report.get('console_status')}`",
        f"- Open items: `{report.get('open_items_count')}`",
        f"- Next recommended item: `{report.get('next_recommended_item')}`",
        f"- Next owner action: {redact_text(report.get('next_owner_action'), max_len=700)}",
        "",
    ]
    for item in report.get("open_items", []):
        if not isinstance(item, dict):
            continue
        lines.extend(
            [
                f"## {redact_text(item.get('item_id'), max_len=180)}",
                "",
                f"- Source file: `{redact_text(item.get('source_file'), max_len=300)}`",
                f"- Review goal: {redact_text(item.get('review_goal'), max_len=500)}",
                f"- What to check: {redact_text(item.get('what_to_check'), max_len=800)}",
                "",
                "```bash",
                redact_text(item.get("suggested_command_to_mark_reviewed"), max_len=500),
                "```",
                "",
            ]
        )
    return "\n".join(lines)


def audit_record(report: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "timestamp_utc": report.get("generated_at_utc"),
        "schema_version": SCHEMA_VERSION,
        "console_status": report.get("console_status"),
        "console_breach": report.get("console_breach"),
        "total_items": report.get("total_items"),
        "reviewed_count": report.get("reviewed_count"),
        "open_items_count": report.get("open_items_count"),
        "next_recommended_item": report.get("next_recommended_item"),
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
    write_text_atomic(DRAFT_CONSOLE_MD, markdown)
    write_text_atomic(OPEN_ITEMS_MD, render_open_items_markdown(report))
    append_jsonl(AUDIT_JSONL, [audit_record(report)])


def build_current_report() -> Dict[str, Any]:
    tracker_data, tracker_status = read_optional_json(TRACKER_JSON)
    state_data, state_status = read_optional_json(STATE_JSON)
    gate_data, gate_status = read_optional_json(GATE_JSON)
    dashboard_data, dashboard_status = read_optional_json(DASHBOARD_JSON)
    final_safety_data, final_safety_status = read_optional_json(FINAL_SAFETY_JSON)
    master_data, master_status = read_optional_json(MASTER_JSON)
    return build_report(
        tracker_data,
        tracker_status,
        state_data,
        state_status,
        gate_data,
        gate_status,
        dashboard_data,
        dashboard_status,
        final_safety_data,
        final_safety_status,
        master_data,
        master_status,
    )


def run_self_test() -> int:
    tracker = {
        "reviewed_count": 1,
        "total_items": 10,
        "unchecked_count": 9,
        "needs_work_count": 0,
        "blocked_count": 0,
        "skipped_count": 0,
        "emergency_stop_active": True,
        "review_items": [
            {"item_id": "evidence_dashboard", "title": "Dashboard", "review_status": STATUS_REVIEWED},
            {"item_id": "next_owner_actions", "title": "Next", "review_status": STATUS_UNCHECKED},
        ],
    }
    state = {"review_items": tracker["review_items"]}
    gate = {"gate_breach": False, "all_required_reviewed": False, "emergency_stop_active": True}
    report = build_report(tracker, "ok", state, "ok", gate, "ok", {}, "ok", {}, "ok", {}, "ok", generated_at="2026-06-11T00:00:00Z")
    if report["console_status"] != CONSOLE_IN_PROGRESS or report["console_breach"]:
        raise AssertionError("in-progress console status failed")
    if report["next_recommended_item"] != "next_owner_actions":
        raise AssertionError("next recommended item failed")
    for item in report["review_items"]:
        for key in ("suggested_command_to_mark_reviewed", "suggested_command_to_mark_needs_work", "suggested_command_to_mark_blocked"):
            if not command_is_safe(item[key]):
                raise AssertionError(f"safe command rejected: {item[key]}")

    ready_tracker = dict(tracker, reviewed_count=10, total_items=10, unchecked_count=0, review_items=[{"item_id": item_id, "review_status": STATUS_REVIEWED} for item_id in REVIEW_GUIDANCE])
    ready_report = build_report(ready_tracker, "ok", {"review_items": ready_tracker["review_items"]}, "ok", {"gate_breach": False, "all_required_reviewed": True, "emergency_stop_active": True}, "ok", {}, "ok", {}, "ok", {}, "ok", generated_at="2026-06-11T00:01:00Z")
    if ready_report["console_status"] != CONSOLE_COMPLETE_LOCKED:
        raise AssertionError("complete locked console status failed")

    partial_report = build_report(None, "not_available", {}, "not_available", gate, "ok", {}, "ok", {}, "ok", {}, "ok", generated_at="2026-06-11T00:02:00Z")
    if partial_report["console_status"] != CONSOLE_PARTIAL_INPUTS or partial_report["console_breach"]:
        raise AssertionError("partial inputs status failed")

    gate_breach_report = build_report(tracker, "ok", state, "ok", {"gate_breach": True}, "ok", {}, "ok", {}, "ok", {}, "ok", generated_at="2026-06-11T00:03:00Z")
    if gate_breach_report["console_status"] != CONSOLE_BLOCKED_GATE_BREACH or not gate_breach_report["console_breach"]:
        raise AssertionError("gate breach did not block console")

    bad_items = [dict(report["review_items"][0])]
    bad_items[0]["suggested_command_to_mark_reviewed"] = "systemctl start sentinel.service"
    if not build_report(tracker, "ok", state, "ok", gate, "ok", {}, "ok", {}, "ok", {}, "ok", forced_items=bad_items)["console_breach"]:
        raise AssertionError("systemctl command did not breach")
    for bad_command in ("curl https://example.com", "wget https://example.com", "wp option update x y", "nginx reload", "cloudflare api update"):
        bad_items = [dict(report["review_items"][0])]
        bad_items[0]["suggested_command_to_mark_reviewed"] = bad_command
        if not build_report(tracker, "ok", state, "ok", gate, "ok", {}, "ok", {}, "ok", {}, "ok", forced_items=bad_items)["console_breach"]:
            raise AssertionError(f"{bad_command} did not breach")
    for key in ("install_allowed_now", "can_install_timer_now", "can_execute_live", "live_apply", "executable_install_script_generated", "systemd_file_written", "crontab_file_written", "secret_like_output", "output_path_breach"):
        bad = build_report(tracker, "ok", state, "ok", gate, "ok", {}, "ok", {}, "ok", {}, "ok", generated_at="2026-06-11T00:04:00Z", forced_flags={key: True})
        if not bad["console_breach"]:
            raise AssertionError(f"{key} did not breach")
    bad = build_report(tracker, "ok", state, "ok", gate, "ok", {}, "ok", {}, "ok", {}, "ok", forced_flags={"apply_status": "applied"})
    if not bad["console_breach"]:
        raise AssertionError("apply_status != not_applied did not breach")
    for forbidden in (PROJECT_DIR / "drafts/owner/bad.sh", PROJECT_DIR / "reports/latest/bad.service", PROJECT_DIR / "audit/bad.timer"):
        try:
            assert_allowed_write(forbidden)
        except ValueError:
            pass
        else:
            raise AssertionError(f"forbidden artifact was not rejected: {forbidden}")
    try:
        assert_allowed_write(PROJECT_DIR / "state/owner-evidence-review-console.json")
    except ValueError:
        pass
    else:
        raise AssertionError("forbidden write root was not rejected")
    if not detect_secret_like("token=abc12345"):
        raise AssertionError("secret detector failed")
    print("owner-evidence-review-console self-tests: OK")
    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build Owner Evidence Review Console; no install, no live apply.")
    parser.add_argument("--self-test", action="store_true", help="Run in-memory safety tests and exit.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()
    report = build_current_report()
    write_outputs(report)
    print(
        "Owner Evidence Review Console: "
        f"status={report.get('console_status')}, "
        f"open={report.get('open_items_count')}, "
        f"next={report.get('next_recommended_item')}, "
        f"install_allowed={report.get('install_allowed_now')}, "
        f"can_install={report.get('can_install_timer_now')}, "
        f"breach={report.get('console_breach')}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
