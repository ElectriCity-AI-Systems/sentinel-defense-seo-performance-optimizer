#!/usr/bin/env python3
"""Sentinel Final Owner Decision Snapshot (Phase 5.0).

Builds an immutable-style local evidence snapshot for the completed Manual
Evidence Review. This module is not an installation, not an active timer, and
not an apply mechanism.

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

MASTER_JSON = PROJECT_DIR / "reports/latest/sentinel-master-report.json"
TRACKER_JSON = PROJECT_DIR / "reports/latest/manual-evidence-review-completion-tracker.json"
GATE_JSON = PROJECT_DIR / "reports/latest/manual-evidence-review-completion-gate.json"
CONSOLE_JSON = PROJECT_DIR / "reports/latest/owner-evidence-review-console.json"
DASHBOARD_JSON = PROJECT_DIR / "reports/latest/manual-evidence-review-dashboard.json"
FINAL_SAFETY_JSON = PROJECT_DIR / "reports/latest/safe-draft-autonomy-final-safety-report.json"
RUNTIME_LOCK_JSON = PROJECT_DIR / "config/autonomy-runtime-lock.json"
STATE_JSON = PROJECT_DIR / "state/manual-evidence-review-completion.json"

REPORT_JSON = PROJECT_DIR / "reports/latest/final-owner-decision-snapshot.json"
REPORT_MD = PROJECT_DIR / "reports/latest/final-owner-decision-snapshot.md"
DRAFT_MD = PROJECT_DIR / "drafts/owner/final-owner-decision-snapshot.md"
SNAPSHOT_JSON = PROJECT_DIR / "snapshots/final-owner-decision-snapshot.json"
SNAPSHOT_MD = PROJECT_DIR / "snapshots/final-owner-decision-snapshot.md"
AUDIT_JSONL = PROJECT_DIR / "audit/final-owner-decision-snapshot.jsonl"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "drafts/owner",
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "audit",
    PROJECT_DIR / "snapshots",
)
ALLOWED_OUTPUT_PATHS = (REPORT_JSON, REPORT_MD, DRAFT_MD, SNAPSHOT_JSON, SNAPSHOT_MD, AUDIT_JSONL)
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

SCHEMA_VERSION = "final-owner-decision-snapshot-5.0"
APPLY_NOT_APPLIED = "not_applied"
TIMER_NOT_INSTALLED = "not_installed"

SNAPSHOT_LOCKED_COMPLETE = "FINAL_OWNER_SNAPSHOT_LOCKED_COMPLETE"
SNAPSHOT_INCOMPLETE = "FINAL_OWNER_SNAPSHOT_INCOMPLETE"
SNAPSHOT_BLOCKED_BY_BREACH = "FINAL_OWNER_SNAPSHOT_BLOCKED_BY_BREACH"
SNAPSHOT_PARTIAL_INPUTS = "FINAL_OWNER_SNAPSHOT_PARTIAL_INPUTS"
SNAPSHOT_BREACH = "FINAL_OWNER_SNAPSHOT_BREACH"

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
        raise ValueError(f"Refusing to write outside allowed snapshot roots: {path}")
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


def nested_dict(data: Optional[Any], key: str) -> Dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    child = data.get(key)
    return child if isinstance(child, dict) else {}


def review_counts(tracker: Optional[Any], gate: Optional[Any], console: Optional[Any], state: Optional[Any]) -> Dict[str, Any]:
    for source in (tracker, gate, console):
        if isinstance(source, dict) and parse_count(source.get("total_items")):
            return {
                "reviewed_count": parse_count(source.get("reviewed_count")),
                "total_items": parse_count(source.get("total_items")),
                "completion_percent": safe_float(source.get("completion_percent", 100.0 if bool_from(source, "all_required_reviewed") else 0.0)),
                "all_required_reviewed": bool(source.get("all_required_reviewed", False)),
            }
    if isinstance(state, dict) and isinstance(state.get("review_items"), list):
        items = [item for item in state["review_items"] if isinstance(item, dict)]
        total = len(items)
        reviewed = sum(1 for item in items if item.get("review_status") == "reviewed")
        return {
            "reviewed_count": reviewed,
            "total_items": total,
            "completion_percent": round((reviewed / total) * 100, 2) if total else 0.0,
            "all_required_reviewed": total > 0 and reviewed == total,
        }
    return {"reviewed_count": 0, "total_items": 0, "completion_percent": 0.0, "all_required_reviewed": False}


def upstream_breach_count(
    tracker: Optional[Any],
    gate: Optional[Any],
    console: Optional[Any],
    dashboard: Optional[Any],
    final_safety: Optional[Any],
    master: Optional[Any],
) -> Tuple[int, List[str]]:
    breach_fields = (
        ("tracker", tracker, "tracker_breach"),
        ("gate", gate, "gate_breach"),
        ("console", console, "console_breach"),
        ("dashboard", dashboard, "dashboard_breach"),
        ("final_safety", final_safety, "final_safety_breach"),
    )
    reasons: List[str] = []
    for label, data, key in breach_fields:
        if bool_from(data, key):
            reasons.append(f"{label}:{key}=true")

    master_children = (
        ("master.manual_evidence_review_completion_tracker", nested_dict(master, "manual_evidence_review_completion_tracker"), "tracker_breach"),
        ("master.manual_evidence_review_completion_gate", nested_dict(master, "manual_evidence_review_completion_gate"), "gate_breach"),
        ("master.owner_evidence_review_console", nested_dict(master, "owner_evidence_review_console"), "console_breach"),
        ("master.manual_evidence_review_dashboard", nested_dict(master, "manual_evidence_review_dashboard"), "dashboard_breach"),
        ("master.safe_draft_autonomy_final_safety", nested_dict(master, "safe_draft_autonomy_final_safety"), "final_safety_breach"),
    )
    for label, data, key in master_children:
        if bool_from(data, key):
            reasons.append(f"{label}:{key}=true")

    total = len(set(reasons))
    explicit_counts = [
        parse_count(dashboard.get("total_breaches")) if isinstance(dashboard, dict) else 0,
        parse_count(final_safety.get("total_breach_count")) if isinstance(final_safety, dict) else 0,
    ]
    total = max(total, max(explicit_counts))
    return total, sorted(set(reasons))


def detect_breach(
    tracker: Optional[Any],
    gate: Optional[Any],
    console: Optional[Any],
    dashboard: Optional[Any],
    final_safety: Optional[Any],
    master: Optional[Any],
    runtime_lock: Optional[Any],
    *,
    install_allowed_now: bool,
    can_install_timer_now: bool,
    can_execute_live: bool,
    live_apply: bool,
    apply_status: str,
    timer_installation_status: str,
    systemd_file_written: bool,
    crontab_file_written: bool,
    executable_install_script_generated: bool,
    output_path_breach: bool,
    secret_like_output: bool,
) -> Tuple[bool, List[str], int]:
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
    if timer_installation_status != TIMER_NOT_INSTALLED:
        reasons.append("timer_installation_status != not_installed")
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

    upstream_count, upstream_reasons = upstream_breach_count(tracker, gate, console, dashboard, final_safety, master)
    reasons.extend(upstream_reasons)

    for label, data in (
        ("tracker", tracker),
        ("gate", gate),
        ("console", console),
        ("dashboard", dashboard),
        ("final_safety", final_safety),
        ("runtime_lock", runtime_lock),
    ):
        if not isinstance(data, dict):
            continue
        if bool(data.get("install_allowed_now", False)):
            reasons.append(f"{label}:install_allowed_now=true")
        if bool(data.get("can_install_timer_now", False)):
            reasons.append(f"{label}:can_install_timer_now=true")
        if bool(data.get("can_execute_live", False)):
            reasons.append(f"{label}:can_execute_live=true")
        if bool(data.get("live_apply", False)) or bool(data.get("live_apply_allowed", False)):
            reasons.append(f"{label}:live_apply=true")
        upstream_apply_status = data.get("apply_status")
        if upstream_apply_status not in (None, "", APPLY_NOT_APPLIED):
            reasons.append(f"{label}:apply_status != not_applied")
        upstream_timer_status = data.get("timer_installation_status")
        if upstream_timer_status not in (None, "", TIMER_NOT_INSTALLED):
            reasons.append(f"{label}:timer_installation_status != not_installed")
        if bool(data.get("systemd_file_written", False)):
            reasons.append(f"{label}:systemd_file_written=true")
        if bool(data.get("crontab_file_written", False)):
            reasons.append(f"{label}:crontab_file_written=true")

    unique_reasons = sorted(set(reasons))
    total_breaches = max(upstream_count, len(unique_reasons))
    return bool(unique_reasons), unique_reasons, total_breaches


def decide_snapshot_status(
    *,
    breach: bool,
    inputs_missing: bool,
    reviewed_count: int,
    total_items: int,
    all_required_reviewed: bool,
    gate_complete: bool,
    console_complete_locked: bool,
    emergency_stop_active: bool,
    total_breaches: int,
) -> Tuple[str, bool, str]:
    if breach:
        return (
            SNAPSHOT_BLOCKED_BY_BREACH,
            False,
            "Do not proceed. Resolve breach before any further decision.",
        )
    if inputs_missing:
        return (
            SNAPSHOT_PARTIAL_INPUTS,
            False,
            "Generate missing evidence reports first.",
        )
    if reviewed_count < total_items or not all_required_reviewed:
        return (
            SNAPSHOT_INCOMPLETE,
            False,
            "Finish remaining evidence review items first.",
        )
    if (
        reviewed_count == total_items
        and gate_complete
        and console_complete_locked
        and emergency_stop_active
        and total_breaches == 0
    ):
        return (
            SNAPSHOT_LOCKED_COMPLETE,
            True,
            "Review completed. Keep Emergency Stop active. Do not install automatically. Any timer installation remains a separate manual Owner decision.",
        )
    return (
        SNAPSHOT_INCOMPLETE,
        False,
        "Evidence review is not in locked-complete final state; keep reviewing and do not install.",
    )


def build_report(
    master: Optional[Any],
    master_status: str,
    tracker: Optional[Any],
    tracker_status: str,
    gate: Optional[Any],
    gate_status: str,
    console: Optional[Any],
    console_status: str,
    dashboard: Optional[Any],
    dashboard_status: str,
    final_safety: Optional[Any],
    final_safety_status: str,
    runtime_lock: Optional[Any],
    runtime_lock_status: str,
    state: Optional[Any],
    state_status: str,
    *,
    generated_at: Optional[str] = None,
    forced_flags: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    generated = generated_at or utc_now()
    counts = review_counts(tracker, gate, console, state)
    flags = forced_flags or {}

    install_allowed_now = bool(flags.get("install_allowed_now", False))
    can_install_timer_now = bool(flags.get("can_install_timer_now", False))
    can_execute_live = bool(flags.get("can_execute_live", False))
    live_apply = bool(flags.get("live_apply", False))
    apply_status = str(flags.get("apply_status", APPLY_NOT_APPLIED))
    timer_installation_status = str(flags.get("timer_installation_status", TIMER_NOT_INSTALLED))
    systemd_file_written = bool(flags.get("systemd_file_written", False))
    crontab_file_written = bool(flags.get("crontab_file_written", False))
    executable_install_script_generated = bool(flags.get("executable_install_script_generated", False))
    output_path_breach = bool(flags.get("output_path_breach", False))
    secret_like_output = bool(flags.get("secret_like_output", False))

    emergency_stop_active = (
        bool_from(tracker, "emergency_stop_active")
        or bool_from(gate, "emergency_stop_active")
        or bool_from(console, "emergency_stop_active")
        or bool_from(dashboard, "emergency_stop_active")
        or bool_from(final_safety, "emergency_stop_active")
        or bool_from(runtime_lock, "emergency_stop")
        or bool_from(runtime_lock, "emergency_stop_active")
    )

    breach, breach_reasons, total_breaches = detect_breach(
        tracker,
        gate,
        console,
        dashboard,
        final_safety,
        master,
        runtime_lock,
        install_allowed_now=install_allowed_now,
        can_install_timer_now=can_install_timer_now,
        can_execute_live=can_execute_live,
        live_apply=live_apply,
        apply_status=apply_status,
        timer_installation_status=timer_installation_status,
        systemd_file_written=systemd_file_written,
        crontab_file_written=crontab_file_written,
        executable_install_script_generated=executable_install_script_generated,
        output_path_breach=output_path_breach,
        secret_like_output=secret_like_output,
    )

    inputs_missing = any(
        status != "ok"
        for status in (
            master_status,
            tracker_status,
            gate_status,
            console_status,
            dashboard_status,
            final_safety_status,
            runtime_lock_status,
            state_status,
        )
    )
    gate_complete = text_from(gate, "gate_status") == "COMPLETION_GATE_READY_BUT_LOCKED" and bool_from(gate, "all_required_reviewed")
    console_complete_locked = text_from(console, "console_status") == "REVIEW_CONSOLE_COMPLETE_LOCKED"

    snapshot_status, review_completed, recommended_owner_action = decide_snapshot_status(
        breach=breach,
        inputs_missing=inputs_missing,
        reviewed_count=counts["reviewed_count"],
        total_items=counts["total_items"],
        all_required_reviewed=bool(counts["all_required_reviewed"]),
        gate_complete=gate_complete,
        console_complete_locked=console_complete_locked,
        emergency_stop_active=emergency_stop_active,
        total_breaches=total_breaches,
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "timestamp_utc": generated,
        "generated_at_utc": generated,
        "snapshot_status": snapshot_status,
        "review_completed": review_completed,
        "reviewed_count": counts["reviewed_count"],
        "total_items": counts["total_items"],
        "completion_percent": counts["completion_percent"],
        "all_required_reviewed": counts["all_required_reviewed"],
        "gate_complete": gate_complete,
        "console_complete_locked": console_complete_locked,
        "emergency_stop_active": emergency_stop_active,
        "install_allowed_now": install_allowed_now,
        "can_install_timer_now": can_install_timer_now,
        "can_execute_live": can_execute_live,
        "live_apply": live_apply,
        "apply_status": apply_status,
        "timer_installation_status": timer_installation_status,
        "total_breaches": total_breaches,
        "owner_decision_required_for_any_install": True,
        "recommended_owner_action": recommended_owner_action,
        "snapshot_breach": breach,
        "snapshot_breach_reasons": breach_reasons,
        "read_only": True,
        "network_access": False,
        "wordpress_login": False,
        "api_access": False,
        "apply_function": False,
        "systemd_file_written": systemd_file_written,
        "crontab_file_written": crontab_file_written,
        "executable_install_script_generated": executable_install_script_generated,
        "secrets_output": False,
        "allowed_write_roots": [str(path) for path in ALLOWED_WRITE_ROOTS],
        "input_statuses": {
            "sentinel_master": master_status,
            "completion_tracker": tracker_status,
            "completion_gate": gate_status,
            "owner_evidence_console": console_status,
            "manual_evidence_dashboard": dashboard_status,
            "final_safety": final_safety_status,
            "runtime_lock": runtime_lock_status,
            "completion_state": state_status,
        },
        "source_statuses": {
            "tracker_status": text_from(tracker, "tracker_status"),
            "gate_status": text_from(gate, "gate_status"),
            "console_status": text_from(console, "console_status"),
            "dashboard_status": text_from(dashboard, "dashboard_status"),
            "final_safety_status": text_from(final_safety, "final_safety_status"),
        },
        "outputs": {
            "report_json": str(REPORT_JSON),
            "report_md": str(REPORT_MD),
            "draft_md": str(DRAFT_MD),
            "snapshot_json": str(SNAPSHOT_JSON),
            "snapshot_md": str(SNAPSHOT_MD),
            "audit_jsonl": str(AUDIT_JSONL),
        },
    }


def render_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# Final Owner Decision Snapshot",
        "",
        f"- Timestamp (UTC): `{report.get('timestamp_utc')}`",
        f"- Snapshot status: `{report.get('snapshot_status')}`",
        f"- Review completed: `{report.get('review_completed')}`",
        f"- Reviewed: `{report.get('reviewed_count')}` / `{report.get('total_items')}`",
        f"- Completion percent: `{report.get('completion_percent')}`",
        f"- Emergency stop active: `{report.get('emergency_stop_active')}`",
        f"- Install allowed now: `{report.get('install_allowed_now')}`",
        f"- Can install timer now: `{report.get('can_install_timer_now')}`",
        f"- Can execute live: `{report.get('can_execute_live')}`",
        f"- Live apply: `{report.get('live_apply')}`",
        f"- Apply status: `{report.get('apply_status')}`",
        f"- Timer installation status: `{report.get('timer_installation_status')}`",
        f"- Total breaches: `{report.get('total_breaches')}`",
        f"- Owner decision required for any install: `{report.get('owner_decision_required_for_any_install')}`",
        f"- Snapshot breach: `{report.get('snapshot_breach')}`",
        f"- Recommended owner action: {redact_text(report.get('recommended_owner_action'), max_len=900)}",
        "",
    ]
    if report.get("snapshot_breach_reasons"):
        lines.extend(["## Breach Reasons", ""])
        for reason in report.get("snapshot_breach_reasons", []):
            lines.append(f"- {redact_text(reason, max_len=400)}")
        lines.append("")
    lines.extend(
        [
            "## Source Statuses",
            "",
            "| Source | Status |",
            "|---|---|",
        ]
    )
    source_statuses = report.get("source_statuses") if isinstance(report.get("source_statuses"), dict) else {}
    for key, value in source_statuses.items():
        lines.append(f"| `{redact_text(key, max_len=120)}` | `{redact_text(value, max_len=220)}` |")
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
            "- Owner-Entscheidung fuer jede Installation bleibt separat und manuell.",
            "",
        ]
    )
    return "\n".join(lines)


def audit_record(report: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "timestamp_utc": report.get("timestamp_utc"),
        "schema_version": SCHEMA_VERSION,
        "snapshot_status": report.get("snapshot_status"),
        "review_completed": report.get("review_completed"),
        "reviewed_count": report.get("reviewed_count"),
        "total_items": report.get("total_items"),
        "emergency_stop_active": report.get("emergency_stop_active"),
        "total_breaches": report.get("total_breaches"),
        "snapshot_breach": report.get("snapshot_breach"),
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
    markdown = render_markdown(report)
    write_text_atomic(REPORT_MD, markdown)
    write_text_atomic(DRAFT_MD, markdown)
    write_json_atomic(SNAPSHOT_JSON, report)
    write_text_atomic(SNAPSHOT_MD, markdown)
    append_jsonl(AUDIT_JSONL, [audit_record(report)])


def build_current_report() -> Dict[str, Any]:
    master, master_status = read_optional_json(MASTER_JSON)
    tracker, tracker_status = read_optional_json(TRACKER_JSON)
    gate, gate_status = read_optional_json(GATE_JSON)
    console, console_status = read_optional_json(CONSOLE_JSON)
    dashboard, dashboard_status = read_optional_json(DASHBOARD_JSON)
    final_safety, final_safety_status = read_optional_json(FINAL_SAFETY_JSON)
    runtime_lock, runtime_lock_status = read_optional_json(RUNTIME_LOCK_JSON)
    state, state_status = read_optional_json(STATE_JSON)
    return build_report(
        master,
        master_status,
        tracker,
        tracker_status,
        gate,
        gate_status,
        console,
        console_status,
        dashboard,
        dashboard_status,
        final_safety,
        final_safety_status,
        runtime_lock,
        runtime_lock_status,
        state,
        state_status,
    )


def run_self_test() -> int:
    tracker = {
        "tracker_status": "REVIEW_TRACKER_COMPLETE_LOCKED",
        "reviewed_count": 10,
        "total_items": 10,
        "completion_percent": 100.0,
        "all_required_reviewed": True,
        "emergency_stop_active": True,
        "tracker_breach": False,
        "apply_status": APPLY_NOT_APPLIED,
        "timer_installation_status": TIMER_NOT_INSTALLED,
    }
    gate = {
        "gate_status": "COMPLETION_GATE_READY_BUT_LOCKED",
        "reviewed_count": 10,
        "total_items": 10,
        "completion_percent": 100.0,
        "all_required_reviewed": True,
        "emergency_stop_active": True,
        "gate_breach": False,
        "apply_status": APPLY_NOT_APPLIED,
        "timer_installation_status": TIMER_NOT_INSTALLED,
    }
    console = {
        "console_status": "REVIEW_CONSOLE_COMPLETE_LOCKED",
        "reviewed_count": 10,
        "total_items": 10,
        "emergency_stop_active": True,
        "console_breach": False,
        "apply_status": APPLY_NOT_APPLIED,
        "timer_installation_status": TIMER_NOT_INSTALLED,
    }
    dashboard = {"dashboard_status": "READY_FOR_MANUAL_EVIDENCE_REVIEW_LOCKED", "emergency_stop_active": True, "dashboard_breach": False, "total_breaches": 0, "apply_status": APPLY_NOT_APPLIED, "timer_installation_status": TIMER_NOT_INSTALLED}
    final = {"final_safety_status": "SAFE_BUT_LOCKED_BY_EMERGENCY_STOP", "emergency_stop_active": True, "final_safety_breach": False, "total_breach_count": 0, "apply_status": APPLY_NOT_APPLIED}
    runtime = {"emergency_stop": True, "apply_status": APPLY_NOT_APPLIED}
    state = {"review_items": [{"item_id": f"item_{idx}", "review_status": "reviewed"} for idx in range(10)]}

    report = build_report({}, "ok", tracker, "ok", gate, "ok", console, "ok", dashboard, "ok", final, "ok", runtime, "ok", state, "ok", generated_at="2026-06-12T00:00:00Z")
    if report["snapshot_status"] != SNAPSHOT_LOCKED_COMPLETE or report["snapshot_breach"] or not report["review_completed"]:
        raise AssertionError("locked complete snapshot failed")

    incomplete = dict(tracker, reviewed_count=9, total_items=10, completion_percent=90.0, all_required_reviewed=False)
    incomplete_report = build_report({}, "ok", incomplete, "ok", gate, "ok", console, "ok", dashboard, "ok", final, "ok", runtime, "ok", state, "ok", generated_at="2026-06-12T00:01:00Z")
    if incomplete_report["snapshot_status"] != SNAPSHOT_INCOMPLETE or incomplete_report["snapshot_breach"]:
        raise AssertionError("incomplete snapshot failed")

    partial_report = build_report({}, "not_available", tracker, "ok", gate, "ok", console, "ok", dashboard, "ok", final, "ok", runtime, "ok", state, "ok", generated_at="2026-06-12T00:02:00Z")
    if partial_report["snapshot_status"] != SNAPSHOT_PARTIAL_INPUTS or partial_report["snapshot_breach"]:
        raise AssertionError("partial inputs snapshot failed")

    for label, source in (
        ("tracker_breach", dict(tracker, tracker_breach=True)),
        ("gate_breach", dict(gate, gate_breach=True)),
        ("console_breach", dict(console, console_breach=True)),
        ("dashboard_breach", dict(dashboard, dashboard_breach=True)),
        ("final_safety_breach", dict(final, final_safety_breach=True)),
    ):
        bad = build_report({}, "ok", source if label == "tracker_breach" else tracker, "ok", source if label == "gate_breach" else gate, "ok", source if label == "console_breach" else console, "ok", source if label == "dashboard_breach" else dashboard, "ok", source if label == "final_safety_breach" else final, "ok", runtime, "ok", state, "ok", generated_at="2026-06-12T00:03:00Z")
        if not bad["snapshot_breach"] or bad["snapshot_status"] != SNAPSHOT_BLOCKED_BY_BREACH:
            raise AssertionError(f"{label} did not breach")

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
        bad = build_report({}, "ok", tracker, "ok", gate, "ok", console, "ok", dashboard, "ok", final, "ok", runtime, "ok", state, "ok", generated_at="2026-06-12T00:04:00Z", forced_flags={key: True})
        if not bad["snapshot_breach"]:
            raise AssertionError(f"{key} did not breach")
    for key, value in (("apply_status", "applied"), ("timer_installation_status", "installed")):
        bad = build_report({}, "ok", tracker, "ok", gate, "ok", console, "ok", dashboard, "ok", final, "ok", runtime, "ok", state, "ok", forced_flags={key: value})
        if not bad["snapshot_breach"]:
            raise AssertionError(f"{key} did not breach")
    for forbidden in (PROJECT_DIR / "drafts/owner/bad.sh", PROJECT_DIR / "reports/latest/bad.service", PROJECT_DIR / "snapshots/bad.timer"):
        try:
            assert_allowed_write(forbidden)
        except ValueError:
            pass
        else:
            raise AssertionError(f"forbidden artifact was not rejected: {forbidden}")
    try:
        assert_allowed_write(PROJECT_DIR / "state/final-owner-decision-snapshot.json")
    except ValueError:
        pass
    else:
        raise AssertionError("forbidden write root was not rejected")
    if not detect_secret_like("token=abc12345"):
        raise AssertionError("secret detector failed")
    print("final-owner-decision-snapshot self-tests: OK")
    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build Final Owner Decision Snapshot; no install, no live apply.")
    parser.add_argument("--self-test", action="store_true", help="Run in-memory safety tests and exit.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()
    report = build_current_report()
    write_outputs(report)
    print(
        "Final Owner Decision Snapshot: "
        f"status={report.get('snapshot_status')}, "
        f"review={report.get('reviewed_count')}/{report.get('total_items')}, "
        f"emergency_stop={report.get('emergency_stop_active')}, "
        f"breaches={report.get('total_breaches')}, "
        f"install_allowed={report.get('install_allowed_now')}, "
        f"breach={report.get('snapshot_breach')}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
