#!/usr/bin/env python3
"""Sentinel Owner Timer Install Decision Gate (Phase 4.2).

Records Pierre's owner decision for the manual timer install packet. This is
not an installer, not an active timer, and not an apply mechanism. Even the
"reviewed_ready_for_manual_install" decision only documents that the packet was
reviewed and may be considered later by the owner manually.

Hard safety guarantees:
- No live changes and no live-apply function.
- No systemctl execution, no crontab writes, no writes to /etc/systemd/system.
- No WordPress, .htaccess, Cloudflare, Nginx, DNS, API, login, or network work.
- apply_status stays not_applied; can_execute_live, can_install_timer_now, and
  install_allowed_now stay false.
- Writes are confined to config, drafts/owner, reports/latest, and audit.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


PROJECT_DIR = Path("/srv/sentinel-defense")

INPUT_PACKET_REPORT = PROJECT_DIR / "reports/latest/owner-manual-timer-install-packet-report.json"
INPUT_INSTALL_REVIEW = PROJECT_DIR / "reports/latest/safe-draft-autonomy-timer-install-review-report.json"
INPUT_RUNTIME_LOCK = PROJECT_DIR / "config/autonomy-runtime-lock.json"
INPUT_MASTER = PROJECT_DIR / "reports/latest/sentinel-master-report.json"

DECISION_JSON = PROJECT_DIR / "config/owner-timer-install-decision.json"
REPORT_JSON = PROJECT_DIR / "reports/latest/owner-timer-install-decision-gate-report.json"
REPORT_MD = PROJECT_DIR / "reports/latest/owner-timer-install-decision-gate-report.md"
SUMMARY_MD = PROJECT_DIR / "drafts/owner/owner-timer-install-decision-summary.md"
AUDIT_JSONL = PROJECT_DIR / "audit/owner-timer-install-decision-gate.jsonl"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "config",
    PROJECT_DIR / "drafts/owner",
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "audit",
)
ALLOWED_OUTPUT_PATHS = (DECISION_JSON, REPORT_JSON, REPORT_MD, SUMMARY_MD, AUDIT_JSONL)
FORBIDDEN_OUTPUT_SUFFIXES = (".sh", ".bash", ".zsh", ".service", ".timer", ".py", ".bin", ".run")
FORBIDDEN_INSTALL_PATH_TOKENS = (
    "/etc/systemd",
    "systemd/system",
    "/lib/systemd",
    "/usr/lib/systemd",
    "/etc/cron",
    "cron.d",
    "crontab",
)

SCHEMA_VERSION = "owner-timer-install-decision-gate-4.2"
APPLY_NOT_APPLIED = "not_applied"

DECISION_STATUS_NOT_REVIEWED = "not_reviewed"
DECISION_STATUS_REJECTED = "reviewed_rejected"
DECISION_STATUS_WAIT = "reviewed_wait"
DECISION_STATUS_READY = "reviewed_ready_for_manual_install"
VALID_DECISION_STATUSES = {
    DECISION_STATUS_NOT_REVIEWED,
    DECISION_STATUS_REJECTED,
    DECISION_STATUS_WAIT,
    DECISION_STATUS_READY,
}

GATE_NOT_REVIEWED = "DECISION_NOT_REVIEWED"
GATE_REJECTED = "DECISION_REJECTED"
GATE_WAIT = "DECISION_WAIT"
GATE_READY_REVIEW_ONLY = "DECISION_READY_FOR_MANUAL_INSTALL_REVIEW_ONLY"
GATE_BLOCKED_EMERGENCY = "DECISION_BLOCKED_BY_EMERGENCY_STOP"
GATE_BREACH = "DECISION_BREACH"

VALID_COMMANDS = ("status", "reject", "wait", "mark-review-ready", "comment")
FORBIDDEN_COMMANDS = {
    "install",
    "install-timer",
    "enable-timer",
    "systemctl-enable",
    "apply",
    "live-apply",
}

SECRETISH_RE = re.compile(
    r"(?i)(api[_-]?key|token|secret|password|passwd|bearer|authorization|"
    r"cookie|set-cookie|credential|x-api-key|access[_-]?key|session)"
)
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|password|passwd|bearer|token|credential|session|"
    r"authorization|set-cookie|cookie|x-api-key|access[_-]?key)\b\s*[:=]\s*"
    r"[\"']?(?!false\b|true\b|null\b|none\b|not_applied\b|<redacted|-\b|0\b)"
    r"[A-Za-z0-9+/=_\-]{8,}"
)
LONG_HEX_RE = re.compile(r"\b[A-Fa-f0-9]{32,}\b")
ENV_SECRET_RE = re.compile(
    r"(?im)^\s*Environment=\s*[\"']?[A-Za-z0-9_]*"
    r"(api[_-]?key|secret|token|password|passwd|bearer|credential|session|cookie|authorization)"
    r"[A-Za-z0-9_]*\s*=\s*"
    r"(?!false\b|true\b|null\b|none\b|<redacted)\S{4,}"
)


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
    text = SECRET_ASSIGNMENT_RE.sub("<redacted>", text)
    text = LONG_HEX_RE.sub("<redacted-hex>", text)
    if SECRETISH_RE.search(text):
        return "[redacted]"
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text or default


def detect_secret_in_text(text: str) -> bool:
    if not text:
        return False
    return bool(ENV_SECRET_RE.search(text) or SECRET_ASSIGNMENT_RE.search(text) or LONG_HEX_RE.search(text))


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError):
        return False


def within_allowed_roots(path: Path) -> bool:
    return any(is_within(path, root) for root in ALLOWED_WRITE_ROOTS)


def assert_allowed_write(path: Path) -> None:
    if not within_allowed_roots(path):
        raise ValueError(f"Refusing to write outside allowed decision-gate roots: {path}")
    if path.suffix.lower() in FORBIDDEN_OUTPUT_SUFFIXES:
        raise ValueError(f"Refusing to write an executable/automation artifact: {path}")


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


def default_decision(timestamp: Optional[str] = None) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "updated_at_utc": timestamp or utc_now(),
        "decision_status": DECISION_STATUS_NOT_REVIEWED,
        "manual_install_allowed": False,
        "install_allowed_now": False,
        "can_install_timer_now": False,
        "owner_acknowledged_no_live_apply": False,
        "owner_acknowledged_emergency_stop": False,
        "owner_acknowledged_manual_only": False,
        "owner_acknowledged_rollback": False,
        "decision_breach": False,
        "apply_status": APPLY_NOT_APPLIED,
        "can_execute_live": False,
        "live_apply": False,
        "systemd_file_written": False,
        "crontab_file_written": False,
        "last_owner_decision_action": {
            "command": "default_initialized",
            "note": "-",
            "timestamp_utc": timestamp or utc_now(),
        },
    }


def coerce_decision(raw: Any, timestamp: Optional[str] = None) -> Dict[str, Any]:
    decision = default_decision(timestamp)
    if not isinstance(raw, dict):
        return decision
    status = str(raw.get("decision_status") or "").strip()
    if status in VALID_DECISION_STATUSES:
        decision["decision_status"] = status
    for key in (
        "manual_install_allowed",
        "owner_acknowledged_no_live_apply",
        "owner_acknowledged_emergency_stop",
        "owner_acknowledged_manual_only",
        "owner_acknowledged_rollback",
    ):
        if key in raw:
            decision[key] = bool(raw.get(key))
    # Runtime/install fields are structurally forced safe.
    decision["install_allowed_now"] = False
    decision["can_install_timer_now"] = False
    decision["can_execute_live"] = False
    decision["live_apply"] = False
    decision["systemd_file_written"] = False
    decision["crontab_file_written"] = False
    decision["apply_status"] = APPLY_NOT_APPLIED
    action = raw.get("last_owner_decision_action")
    if isinstance(action, dict):
        decision["last_owner_decision_action"] = {
            "command": redact_text(action.get("command"), max_len=80),
            "note": redact_text(action.get("note"), default="", max_len=1000),
            "timestamp_utc": redact_text(action.get("timestamp_utc"), max_len=40),
        }
    decision["updated_at_utc"] = redact_text(raw.get("updated_at_utc"), default=decision["updated_at_utc"], max_len=40)
    return decision


def build_last_action(command: str, note: Optional[str], timestamp: str) -> Dict[str, str]:
    return {
        "command": redact_text(command, max_len=80),
        "note": redact_text(note, default="", max_len=1000),
        "timestamp_utc": timestamp,
    }


def apply_cli_decision(decision: Dict[str, Any], command: str, note: Optional[str], timestamp: str) -> Dict[str, Any]:
    updated = dict(decision)
    updated["updated_at_utc"] = timestamp
    updated["last_owner_decision_action"] = build_last_action(command, note, timestamp)

    if command == "reject":
        updated["decision_status"] = DECISION_STATUS_REJECTED
        updated["manual_install_allowed"] = False
    elif command == "wait":
        updated["decision_status"] = DECISION_STATUS_WAIT
        updated["manual_install_allowed"] = False
    elif command == "mark-review-ready":
        updated["decision_status"] = DECISION_STATUS_READY
        updated["manual_install_allowed"] = True
        updated["owner_acknowledged_no_live_apply"] = True
        updated["owner_acknowledged_manual_only"] = True
        updated["owner_acknowledged_rollback"] = True
        updated["owner_acknowledged_emergency_stop"] = True
    elif command == "comment":
        pass

    # These fields may never be lifted by any command.
    updated["install_allowed_now"] = False
    updated["can_install_timer_now"] = False
    updated["can_execute_live"] = False
    updated["live_apply"] = False
    updated["systemd_file_written"] = False
    updated["crontab_file_written"] = False
    updated["apply_status"] = APPLY_NOT_APPLIED
    return updated


def _as_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return bool(value)


def gather_signals(
    packet: Optional[Dict[str, Any]],
    install_review: Optional[Dict[str, Any]],
    runtime_lock: Optional[Dict[str, Any]],
    master: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    packet_summary = packet.get("summary") if isinstance(packet, dict) and isinstance(packet.get("summary"), dict) else {}
    review_summary = (
        install_review.get("summary")
        if isinstance(install_review, dict) and isinstance(install_review.get("summary"), dict)
        else {}
    )
    emergency_stop = _as_bool(runtime_lock.get("emergency_stop"), True) if isinstance(runtime_lock, dict) else True
    return {
        "packet_available": isinstance(packet, dict),
        "install_review_available": isinstance(install_review, dict),
        "runtime_lock_available": isinstance(runtime_lock, dict),
        "master_available": isinstance(master, dict),
        "packet_status": redact_text(packet.get("packet_status") if isinstance(packet, dict) else None),
        "packet_breach": _as_bool(packet_summary.get("packet_breach") or (packet.get("packet_breach") if isinstance(packet, dict) else None)),
        "packet_install_allowed_now": _as_bool(packet.get("install_allowed_now") if isinstance(packet, dict) else None),
        "packet_can_install_timer_now": _as_bool(packet.get("can_install_timer_now") if isinstance(packet, dict) else None),
        "packet_systemd_file_written": _as_bool(packet.get("systemd_file_written") if isinstance(packet, dict) else None),
        "packet_crontab_file_written": _as_bool(packet.get("crontab_file_written") if isinstance(packet, dict) else None),
        "packet_live_apply": _as_bool(packet.get("live_apply") if isinstance(packet, dict) else None),
        "packet_can_execute_live": _as_bool(packet.get("can_execute_live") if isinstance(packet, dict) else None),
        "packet_apply_status": redact_text(packet.get("apply_status") if isinstance(packet, dict) else APPLY_NOT_APPLIED),
        "install_review_status": redact_text(install_review.get("install_review_status") if isinstance(install_review, dict) else None),
        "install_reviewer_breach": _as_bool(review_summary.get("install_reviewer_breach") or (install_review.get("install_reviewer_breach") if isinstance(install_review, dict) else None)),
        "review_can_install_timer_now": _as_bool(install_review.get("can_install_timer_now") if isinstance(install_review, dict) else None),
        "review_can_execute_live": _as_bool(install_review.get("can_execute_live") if isinstance(install_review, dict) else None),
        "review_systemd_file_written": _as_bool(install_review.get("systemd_file_written") if isinstance(install_review, dict) else None),
        "review_crontab_file_written": _as_bool(install_review.get("crontab_file_written") if isinstance(install_review, dict) else None),
        "review_live_apply": _as_bool(install_review.get("live_apply") if isinstance(install_review, dict) else None),
        "review_apply_status": redact_text(install_review.get("apply_status") if isinstance(install_review, dict) else APPLY_NOT_APPLIED),
        "emergency_stop_active": emergency_stop,
        "runtime_lock_breach": _as_bool(runtime_lock.get("runtime_lock_breach") if isinstance(runtime_lock, dict) else None),
        "runtime_live_apply_enabled": _as_bool(runtime_lock.get("live_apply_enabled") if isinstance(runtime_lock, dict) else None),
        "runtime_apply_status": redact_text(runtime_lock.get("apply_status") if isinstance(runtime_lock, dict) else APPLY_NOT_APPLIED),
        "master_overall_status": redact_text(master.get("overall_master_status") if isinstance(master, dict) else None),
        "master_action_status": redact_text(master.get("action_status") if isinstance(master, dict) else None),
    }


def all_acknowledged(decision: Dict[str, Any]) -> bool:
    return bool(
        decision.get("owner_acknowledged_no_live_apply")
        and decision.get("owner_acknowledged_manual_only")
        and decision.get("owner_acknowledged_rollback")
        and decision.get("owner_acknowledged_emergency_stop")
    )


def compute_decision_breach(
    decision: Dict[str, Any],
    signals: Dict[str, Any],
    output_paths: List[str],
    output_texts: Optional[List[str]] = None,
    forbidden_command_accepted: bool = False,
) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    if decision.get("install_allowed_now") is True or signals.get("packet_install_allowed_now"):
        reasons.append("install_allowed_now is true")
    if decision.get("can_install_timer_now") is True or signals.get("packet_can_install_timer_now") or signals.get("review_can_install_timer_now"):
        reasons.append("can_install_timer_now is true")
    if decision.get("systemd_file_written") is True or signals.get("packet_systemd_file_written") or signals.get("review_systemd_file_written"):
        reasons.append("systemd_file_written is true")
    if decision.get("crontab_file_written") is True or signals.get("packet_crontab_file_written") or signals.get("review_crontab_file_written"):
        reasons.append("crontab_file_written is true")
    if decision.get("live_apply") is True or signals.get("packet_live_apply") or signals.get("review_live_apply") or signals.get("runtime_live_apply_enabled"):
        reasons.append("live_apply is true")
    if decision.get("can_execute_live") is True or signals.get("packet_can_execute_live") or signals.get("review_can_execute_live"):
        reasons.append("can_execute_live is true")
    if decision.get("apply_status") != APPLY_NOT_APPLIED:
        reasons.append("decision apply_status != not_applied")
    if signals.get("packet_apply_status") != APPLY_NOT_APPLIED:
        reasons.append("packet apply_status != not_applied")
    if signals.get("review_apply_status") != APPLY_NOT_APPLIED:
        reasons.append("install-review apply_status != not_applied")
    if signals.get("runtime_apply_status") != APPLY_NOT_APPLIED:
        reasons.append("runtime-lock apply_status != not_applied")
    if forbidden_command_accepted:
        reasons.append("forbidden CLI command accepted")
    if decision.get("manual_install_allowed") and not all_acknowledged(decision):
        reasons.append("manual_install_allowed=true without all owner acknowledgements")
    if signals.get("packet_breach"):
        reasons.append("manual timer install packet reported packet_breach")
    if signals.get("install_reviewer_breach"):
        reasons.append("timer install reviewer reported breach")
    if signals.get("runtime_lock_breach"):
        reasons.append("runtime lock reported breach")
    for raw in output_paths:
        path = Path(str(raw))
        lower = str(raw).lower()
        if path.suffix.lower() in FORBIDDEN_OUTPUT_SUFFIXES:
            reasons.append(f"executable/automation artifact generated: {redact_text(raw, max_len=120)}")
        if any(token in lower for token in FORBIDDEN_INSTALL_PATH_TOKENS):
            reasons.append(f"output path looks like a systemd/cron install path: {redact_text(raw, max_len=120)}")
        if not within_allowed_roots(path):
            reasons.append(f"output path outside allowed roots: {redact_text(raw, max_len=120)}")
    for text in output_texts or []:
        if detect_secret_in_text(text):
            reasons.append("secret-like values detected in generated output")
            break
    return bool(reasons), reasons


def determine_gate_status(decision: Dict[str, Any], signals: Dict[str, Any], breach: bool) -> Tuple[str, str]:
    if breach:
        return GATE_BREACH, "a decision-gate safety breach was detected."
    status = decision.get("decision_status")
    if status == DECISION_STATUS_READY and signals.get("emergency_stop_active"):
        return GATE_BLOCKED_EMERGENCY, "emergency_stop is active; manual install remains review-only blocked."
    if status == DECISION_STATUS_REJECTED:
        return GATE_REJECTED, "owner rejected timer installation for now."
    if status == DECISION_STATUS_WAIT:
        return GATE_WAIT, "owner chose to wait."
    if status == DECISION_STATUS_READY:
        return GATE_READY_REVIEW_ONLY, "owner marked packet as manually review-ready; no install is allowed by this gate."
    return GATE_NOT_REVIEWED, "owner has not reviewed the timer install packet decision gate."


def build_report(
    decision: Dict[str, Any],
    signals: Dict[str, Any],
    input_statuses: Dict[str, str],
    timestamp: Optional[str] = None,
    output_texts: Optional[List[str]] = None,
    output_paths: Optional[List[str]] = None,
    forbidden_command_accepted: bool = False,
) -> Dict[str, Any]:
    generated = timestamp or utc_now()
    paths = output_paths or [str(path) for path in ALLOWED_OUTPUT_PATHS]
    breach, breach_reasons = compute_decision_breach(
        decision,
        signals,
        paths,
        output_texts=output_texts,
        forbidden_command_accepted=forbidden_command_accepted,
    )
    gate_status, blocked_reason = determine_gate_status(decision, signals, breach)
    summary = {
        "decision_status": decision.get("decision_status"),
        "gate_status": gate_status,
        "manual_install_allowed": bool(decision.get("manual_install_allowed")),
        "install_allowed_now": False,
        "can_install_timer_now": False,
        "emergency_stop_active": bool(signals.get("emergency_stop_active")),
        "decision_breach": breach,
        "decision_breach_reasons": breach_reasons,
        "blocked_reason": blocked_reason,
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": generated,
        "status": gate_status,
        "gate_status": gate_status,
        "decision_status": decision.get("decision_status"),
        "manual_install_allowed": bool(decision.get("manual_install_allowed")),
        "install_allowed_now": False,
        "can_install_timer_now": False,
        "can_execute_live": False,
        "live_apply": False,
        "live_apply_function": False,
        "systemd_file_written": False,
        "crontab_file_written": False,
        "network_access": False,
        "wordpress_login": False,
        "api_access": False,
        "productive_change": False,
        "apply_status": APPLY_NOT_APPLIED,
        "owner_acknowledged_no_live_apply": bool(decision.get("owner_acknowledged_no_live_apply")),
        "owner_acknowledged_manual_only": bool(decision.get("owner_acknowledged_manual_only")),
        "owner_acknowledged_rollback": bool(decision.get("owner_acknowledged_rollback")),
        "owner_acknowledged_emergency_stop": bool(decision.get("owner_acknowledged_emergency_stop")),
        "emergency_stop_active": bool(signals.get("emergency_stop_active")),
        "decision_breach": breach,
        "decision_breach_reasons": breach_reasons,
        "last_owner_decision_action": decision.get("last_owner_decision_action"),
        "blocked_reason": blocked_reason,
        "forbidden_cli_commands": sorted(FORBIDDEN_COMMANDS),
        "forbidden_cli_command_accepted": forbidden_command_accepted,
        "input_statuses": input_statuses,
        "signals": signals,
        "summary": summary,
        "outputs": {
            "decision_json": str(DECISION_JSON),
            "report_json": str(REPORT_JSON),
            "report_md": str(REPORT_MD),
            "summary_md": str(SUMMARY_MD),
            "audit_jsonl": str(AUDIT_JSONL),
        },
        "safety": {
            "no_live_changes": True,
            "systemctl_executed": False,
            "systemd_file_written": False,
            "crontab_file_written": False,
            "network_access": False,
            "api_access": False,
            "wordpress_login": False,
            "cloudflare_mutation": False,
            "nginx_change": False,
            "htaccess_change": False,
            "secrets_output": False,
        },
    }


def render_report_markdown(report: Dict[str, Any]) -> str:
    action = report.get("last_owner_decision_action") if isinstance(report.get("last_owner_decision_action"), dict) else {}
    lines = [
        "# Owner Timer Install Decision Gate Report",
        "",
        f"- Generated (UTC): `{report.get('generated_at_utc')}`",
        f"- Gate status: `{report.get('gate_status')}`",
        f"- Decision status: `{report.get('decision_status')}`",
        f"- manual_install_allowed: `{report.get('manual_install_allowed')}`",
        f"- install_allowed_now: `{report.get('install_allowed_now')}`",
        f"- can_install_timer_now: `{report.get('can_install_timer_now')}`",
        f"- emergency_stop_active: `{report.get('emergency_stop_active')}`",
        f"- decision_breach: `{report.get('decision_breach')}`",
        f"- blocked_reason: `{redact_text(report.get('blocked_reason'), max_len=240)}`",
        f"- last_owner_decision_action: `{redact_text(action.get('command'), max_len=80)}`",
        "",
        "## Owner Acknowledgements",
        "",
        f"- no_live_apply: `{report.get('owner_acknowledged_no_live_apply')}`",
        f"- manual_only: `{report.get('owner_acknowledged_manual_only')}`",
        f"- rollback: `{report.get('owner_acknowledged_rollback')}`",
        f"- emergency_stop: `{report.get('owner_acknowledged_emergency_stop')}`",
        "",
        "## Sicherheitsgrenzen",
        "",
        "- Dies ist keine Installation und kein Apply-Mechanismus.",
        "- Kein systemctl, keine systemd-Datei, keine crontab, keine Live-Aenderung.",
        "- Auch reviewed_ready_for_manual_install bleibt review-only.",
        "- `install_allowed_now=false`, `can_install_timer_now=false`, `can_execute_live=false`, `apply_status=not_applied`.",
        "- Schreibzugriff nur unter config, drafts/owner, reports/latest, audit.",
        "",
    ]
    return "\n".join(lines)


def render_summary_markdown(report: Dict[str, Any]) -> str:
    action = report.get("last_owner_decision_action") if isinstance(report.get("last_owner_decision_action"), dict) else {}
    lines = [
        "# Owner Timer Install Decision Summary",
        "",
        "> Review-only. This file is not an install script and contains no executable install automation.",
        "",
        f"- Gate status: `{report.get('gate_status')}`",
        f"- Decision status: `{report.get('decision_status')}`",
        f"- Manual install allowed by owner review: `{report.get('manual_install_allowed')}`",
        f"- Install allowed now: `{report.get('install_allowed_now')}`",
        f"- Can install timer now: `{report.get('can_install_timer_now')}`",
        f"- Emergency stop active: `{report.get('emergency_stop_active')}`",
        f"- Decision breach: `{report.get('decision_breach')}`",
        f"- Last action: `{redact_text(action.get('command'), max_len=80)}`",
        f"- Last note: `{redact_text(action.get('note'), default='', max_len=400)}`",
        "",
        "## Meaning",
        "",
        "- `reviewed_rejected`: Owner rejected timer installation for now.",
        "- `reviewed_wait`: Owner wants to wait.",
        "- `reviewed_ready_for_manual_install`: Owner reviewed the packet; no automatic install follows.",
        "- `install_allowed_now` and `can_install_timer_now` are always false in this gate.",
        "",
    ]
    return "\n".join(lines)


def rendered_output_texts(report: Dict[str, Any], decision: Dict[str, Any]) -> List[str]:
    return [
        json.dumps(decision, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        render_report_markdown(report),
        render_summary_markdown(report),
    ]


def mark_secret_output_breach(report: Dict[str, Any], decision: Dict[str, Any]) -> Dict[str, Any]:
    if not any(detect_secret_in_text(text) for text in rendered_output_texts(report, decision)):
        return report
    updated = dict(report)
    reasons = list(updated.get("decision_breach_reasons") if isinstance(updated.get("decision_breach_reasons"), list) else [])
    reason = "secret-like values detected in generated output"
    if reason not in reasons:
        reasons.append(reason)
    updated["decision_breach"] = True
    updated["decision_breach_reasons"] = reasons
    updated["status"] = GATE_BREACH
    updated["gate_status"] = GATE_BREACH
    updated["blocked_reason"] = reason
    safety = dict(updated.get("safety") if isinstance(updated.get("safety"), dict) else {})
    safety["secrets_output"] = True
    updated["safety"] = safety
    summary = dict(updated.get("summary") if isinstance(updated.get("summary"), dict) else {})
    summary["decision_breach"] = True
    summary["decision_breach_reasons"] = reasons
    summary["gate_status"] = GATE_BREACH
    summary["blocked_reason"] = reason
    updated["summary"] = summary
    return updated


def audit_record(report: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "timestamp_utc": report.get("generated_at_utc"),
        "schema_version": SCHEMA_VERSION,
        "record_type": "owner_timer_install_decision_gate",
        "gate_status": report.get("gate_status"),
        "decision_status": report.get("decision_status"),
        "manual_install_allowed": report.get("manual_install_allowed"),
        "install_allowed_now": report.get("install_allowed_now"),
        "can_install_timer_now": report.get("can_install_timer_now"),
        "emergency_stop_active": report.get("emergency_stop_active"),
        "decision_breach": report.get("decision_breach"),
        "last_owner_decision_action": report.get("last_owner_decision_action"),
        "live_apply": False,
        "productive_change": False,
        "network_access": False,
    }


def write_outputs(decision: Dict[str, Any], report: Dict[str, Any]) -> Dict[str, Any]:
    report = mark_secret_output_breach(report, decision)
    decision_to_write = dict(decision)
    decision_to_write["decision_breach"] = bool(report.get("decision_breach"))
    write_json_atomic(DECISION_JSON, decision_to_write)
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, render_report_markdown(report))
    write_text_atomic(SUMMARY_MD, render_summary_markdown(report))
    append_jsonl(AUDIT_JSONL, [audit_record(report)])
    return report


def load_inputs() -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, str]]:
    decision_raw, decision_status = read_optional_json(DECISION_JSON)
    packet, packet_status = read_optional_json(INPUT_PACKET_REPORT)
    install_review, install_review_status = read_optional_json(INPUT_INSTALL_REVIEW)
    runtime_lock, runtime_lock_status = read_optional_json(INPUT_RUNTIME_LOCK)
    master, master_status = read_optional_json(INPUT_MASTER)
    statuses = {
        "owner_timer_install_decision": decision_status,
        "owner_manual_timer_install_packet_report": packet_status,
        "safe_draft_autonomy_timer_install_review_report": install_review_status,
        "autonomy_runtime_lock": runtime_lock_status,
        "sentinel_master": master_status,
    }
    decision = coerce_decision(decision_raw)
    signals = gather_signals(
        packet if isinstance(packet, dict) else None,
        install_review if isinstance(install_review, dict) else None,
        runtime_lock if isinstance(runtime_lock, dict) else None,
        master if isinstance(master, dict) else None,
    )
    return decision, signals, statuses


def run_command(command: str, note: Optional[str] = None, *, write: bool = True) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    timestamp = utc_now()
    decision, signals, statuses = load_inputs()
    if command != "status":
        decision = apply_cli_decision(decision, command, note, timestamp)
    report = build_report(decision, signals, statuses, timestamp=timestamp)
    if write:
        report = write_outputs(decision, report)
    return decision, report


def _signals(**overrides: Any) -> Dict[str, Any]:
    base = {
        "packet_available": True,
        "install_review_available": True,
        "runtime_lock_available": True,
        "master_available": True,
        "packet_status": "PACKET_READY_FOR_OWNER_REVIEW",
        "packet_breach": False,
        "packet_install_allowed_now": False,
        "packet_can_install_timer_now": False,
        "packet_systemd_file_written": False,
        "packet_crontab_file_written": False,
        "packet_live_apply": False,
        "packet_can_execute_live": False,
        "packet_apply_status": APPLY_NOT_APPLIED,
        "install_review_status": "INSTALL_REVIEW_READY",
        "install_reviewer_breach": False,
        "review_can_install_timer_now": False,
        "review_can_execute_live": False,
        "review_systemd_file_written": False,
        "review_crontab_file_written": False,
        "review_live_apply": False,
        "review_apply_status": APPLY_NOT_APPLIED,
        "emergency_stop_active": False,
        "runtime_lock_breach": False,
        "runtime_live_apply_enabled": False,
        "runtime_apply_status": APPLY_NOT_APPLIED,
        "master_overall_status": "WARNING",
        "master_action_status": "WARNING_REVIEW",
    }
    base.update(overrides)
    return base


def _report(decision: Optional[Dict[str, Any]] = None, signals: Optional[Dict[str, Any]] = None, **kwargs: Any) -> Dict[str, Any]:
    return build_report(
        decision or default_decision("2026-06-11T00:00:00Z"),
        signals or _signals(),
        {"owner_timer_install_decision": "ok"},
        timestamp="2026-06-11T00:00:00Z",
        **kwargs,
    )


def run_self_test() -> int:
    base_decision = default_decision("2026-06-11T00:00:00Z")
    default_report = _report(base_decision)
    if default_report["gate_status"] != GATE_NOT_REVIEWED:
        raise AssertionError("default decision must be DECISION_NOT_REVIEWED")
    if default_report["decision_breach"]:
        raise AssertionError("default decision must not breach")

    wait_decision = apply_cli_decision(base_decision, "wait", "owner wants to wait", "2026-06-11T00:01:00Z")
    if _report(wait_decision)["gate_status"] != GATE_WAIT:
        raise AssertionError("wait did not produce DECISION_WAIT")
    reject_decision = apply_cli_decision(base_decision, "reject", "owner rejects for now", "2026-06-11T00:02:00Z")
    if _report(reject_decision)["gate_status"] != GATE_REJECTED:
        raise AssertionError("reject did not produce DECISION_REJECTED")
    ready_decision = apply_cli_decision(base_decision, "mark-review-ready", "reviewed", "2026-06-11T00:03:00Z")
    ready_report = _report(ready_decision)
    if ready_report["gate_status"] != GATE_READY_REVIEW_ONLY:
        raise AssertionError("mark-review-ready did not produce review-only ready status")
    if ready_report["install_allowed_now"] or ready_report["can_install_timer_now"]:
        raise AssertionError("mark-review-ready must not allow install now")
    if not all_acknowledged(ready_decision):
        raise AssertionError("mark-review-ready did not set all acknowledgements")
    if _report(ready_decision, _signals(emergency_stop_active=True))["gate_status"] != GATE_BLOCKED_EMERGENCY:
        raise AssertionError("ready decision with emergency_stop must be blocked")

    for key in ("install_allowed_now", "can_install_timer_now", "systemd_file_written", "crontab_file_written", "live_apply", "can_execute_live"):
        bad_decision = dict(base_decision)
        bad_decision[key] = True
        if not _report(bad_decision)["decision_breach"]:
            raise AssertionError(f"{key}=true did not breach")
    bad_decision = dict(base_decision)
    bad_decision["apply_status"] = "applied"
    if not _report(bad_decision)["decision_breach"]:
        raise AssertionError("apply_status != not_applied did not breach")
    bad_decision = dict(base_decision)
    bad_decision["manual_install_allowed"] = True
    if not _report(bad_decision)["decision_breach"]:
        raise AssertionError("manual_install_allowed without acknowledgements did not breach")

    if not _report(base_decision, _signals(packet_can_install_timer_now=True))["decision_breach"]:
        raise AssertionError("input can_install_timer_now did not breach")
    if not _report(base_decision, _signals(review_systemd_file_written=True))["decision_breach"]:
        raise AssertionError("input systemd_file_written did not breach")
    if not _report(base_decision, _signals(runtime_live_apply_enabled=True))["decision_breach"]:
        raise AssertionError("input live_apply did not breach")
    if not _report(base_decision, _signals(packet_apply_status="applied"))["decision_breach"]:
        raise AssertionError("input apply_status did not breach")

    if not _report(base_decision, output_paths=["drafts/owner/install.sh"])["decision_breach"]:
        raise AssertionError("shell script output path did not breach")
    if not _report(base_decision, output_paths=["/etc/systemd/system/x.service"])["decision_breach"]:
        raise AssertionError("systemd output path did not breach")
    if not _report(base_decision, output_paths=["/tmp/outside.json"])["decision_breach"]:
        raise AssertionError("outside output path did not breach")
    if not _report(base_decision, output_texts=["password=0123456789abcdef"])["decision_breach"]:
        raise AssertionError("secret-like output did not breach")
    if not _report(base_decision, forbidden_command_accepted=True)["decision_breach"]:
        raise AssertionError("accepted forbidden command did not breach")
    if FORBIDDEN_COMMANDS.intersection(VALID_COMMANDS):
        raise AssertionError("forbidden command is present in VALID_COMMANDS")
    for command in FORBIDDEN_COMMANDS:
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                parse_args([command])
        except SystemExit:
            pass
        else:
            raise AssertionError(f"forbidden command was accepted by argparse: {command}")

    missing_report = _report(default_decision("2026-06-11T00:00:00Z"), _signals(packet_available=False, install_review_available=False, runtime_lock_available=False, master_available=False))
    if missing_report["decision_breach"]:
        raise AssertionError("missing inputs must not breach")

    for path in ALLOWED_OUTPUT_PATHS:
        assert_allowed_write(path)
    for bad in (Path("/etc/systemd/system/x.timer"), PROJECT_DIR / "drafts/owner/install.sh"):
        try:
            assert_allowed_write(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"forbidden write path not rejected: {bad}")

    print("owner-timer-install-decision-gate self-tests: OK")
    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Record owner timer install decisions (review-only; no install, no live apply)."
    )
    parser.add_argument("--self-test", action="store_true", help="Run built-in safety tests and exit.")
    subparsers = parser.add_subparsers(dest="command")
    for command in VALID_COMMANDS:
        sub = subparsers.add_parser(command)
        if command != "status":
            sub.add_argument("--note", required=True, help="Owner note; secret-like values are redacted.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()
    command = args.command or "status"
    if command not in VALID_COMMANDS:
        print(f"Refusing forbidden or unknown command: {redact_text(command, max_len=80)}", file=sys.stderr)
        return 2
    _, report = run_command(command, getattr(args, "note", None), write=True)
    print(
        "Owner Timer Install Decision Gate: "
        f"status={report.get('gate_status')}, "
        f"decision={report.get('decision_status')}, "
        f"manual_allowed={report.get('manual_install_allowed')}, "
        f"install_allowed={report.get('install_allowed_now')}, "
        f"can_install={report.get('can_install_timer_now')}, "
        f"emergency_stop={report.get('emergency_stop_active')}, "
        f"breach={report.get('decision_breach')}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
