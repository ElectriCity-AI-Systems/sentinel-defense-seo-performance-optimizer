#!/usr/bin/env python3
"""Sentinel Manual Timer Install Command Preview Generator (Phase 4.3).

Builds a pure review preview of possible manual timer installation commands
from the Owner Timer Install Decision Gate, Manual Install Packet, Install
Review, and Timer Drafts.

This is not an installation, not an active timer, and not an apply mechanism.
It never executes systemctl, never writes to /etc/systemd/system, never writes
crontab files, never generates shell scripts, and applies nothing live.

Hard safety guarantees:
- No live changes and no live-apply function.
- No WordPress, .htaccess, Cloudflare, Nginx, DNS, API, login, or network work.
- No shell script, systemd unit, timer unit, or crontab output is generated.
- apply_status stays not_applied; can_execute_live, can_install_timer_now, and
  install_allowed_now stay false.
- Writes are confined to drafts/owner, drafts/apply, reports/latest, and audit.
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

INPUT_DECISION_JSON = PROJECT_DIR / "config/owner-timer-install-decision.json"
INPUT_DECISION_REPORT = PROJECT_DIR / "reports/latest/owner-timer-install-decision-gate-report.json"
INPUT_PACKET_REPORT = PROJECT_DIR / "reports/latest/owner-manual-timer-install-packet-report.json"
INPUT_INSTALL_REVIEW = PROJECT_DIR / "reports/latest/safe-draft-autonomy-timer-install-review-report.json"
INPUT_TIMER_DRAFT_REPORT = PROJECT_DIR / "reports/latest/safe-draft-autonomy-timer-draft-report.json"
INPUT_RUNTIME_LOCK = PROJECT_DIR / "config/autonomy-runtime-lock.json"
INPUT_MASTER = PROJECT_DIR / "reports/latest/sentinel-master-report.json"
SERVICE_DRAFT = PROJECT_DIR / "drafts/apply/sentinel-safe-draft-autonomy.service.draft"
TIMER_DRAFT = PROJECT_DIR / "drafts/apply/sentinel-safe-draft-autonomy.timer.draft"

REPORT_JSON = PROJECT_DIR / "reports/latest/manual-timer-install-command-preview-report.json"
REPORT_MD = PROJECT_DIR / "reports/latest/manual-timer-install-command-preview-report.md"
OWNER_PREVIEW_MD = PROJECT_DIR / "drafts/owner/manual-timer-install-command-preview.md"
APPLY_REVIEW_ONLY_MD = PROJECT_DIR / "drafts/apply/manual-timer-install-command-preview-review-only.md"
AUDIT_JSONL = PROJECT_DIR / "audit/manual-timer-install-command-preview.jsonl"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "drafts/owner",
    PROJECT_DIR / "drafts/apply",
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "audit",
)
ALLOWED_OUTPUT_PATHS = (REPORT_JSON, REPORT_MD, OWNER_PREVIEW_MD, APPLY_REVIEW_ONLY_MD, AUDIT_JSONL)
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

SCHEMA_VERSION = "manual-timer-install-command-preview-4.3"
APPLY_NOT_APPLIED = "not_applied"
READY_DECISION = "reviewed_ready_for_manual_install"

PREVIEW_READY = "PREVIEW_READY_FOR_OWNER_REVIEW"
PREVIEW_BLOCKED_EMERGENCY = "PREVIEW_BLOCKED_BY_EMERGENCY_STOP"
PREVIEW_BLOCKED_DECISION = "PREVIEW_BLOCKED_BY_DECISION_NOT_READY"
PREVIEW_BLOCKED_INSTALL_REVIEW = "PREVIEW_BLOCKED_BY_INSTALL_REVIEW_BREACH"
PREVIEW_BLOCKED_PACKET = "PREVIEW_BLOCKED_BY_PACKET_BREACH"
PREVIEW_BREACH = "PREVIEW_BREACH"

REVIEW_COMMENT = "# REVIEW ONLY - DO NOT RUN WITHOUT OWNER FINAL CONFIRMATION"

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
        raise ValueError(f"Refusing to write outside allowed command-preview roots: {path}")
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


def file_available(path: Path) -> bool:
    try:
        return path.exists() and path.is_file()
    except OSError:
        return False


def _as_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return bool(value)


def _apply_status(value: Any) -> str:
    text = str(value or APPLY_NOT_APPLIED).strip()
    return text or APPLY_NOT_APPLIED


def gather_signals(
    decision: Optional[Dict[str, Any]],
    decision_report: Optional[Dict[str, Any]],
    packet: Optional[Dict[str, Any]],
    install_review: Optional[Dict[str, Any]],
    timer_draft: Optional[Dict[str, Any]],
    runtime_lock: Optional[Dict[str, Any]],
    master: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    packet_summary = packet.get("summary") if isinstance(packet, dict) and isinstance(packet.get("summary"), dict) else {}
    review_summary = (
        install_review.get("summary")
        if isinstance(install_review, dict) and isinstance(install_review.get("summary"), dict)
        else {}
    )
    timer_summary = (
        timer_draft.get("summary")
        if isinstance(timer_draft, dict) and isinstance(timer_draft.get("summary"), dict)
        else {}
    )
    decision_status = (
        decision_report.get("decision_status")
        if isinstance(decision_report, dict)
        else decision.get("decision_status") if isinstance(decision, dict) else "not_reviewed"
    )
    manual_install_allowed = (
        decision_report.get("manual_install_allowed")
        if isinstance(decision_report, dict)
        else decision.get("manual_install_allowed") if isinstance(decision, dict) else False
    )
    emergency_stop = _as_bool(runtime_lock.get("emergency_stop"), True) if isinstance(runtime_lock, dict) else True
    return {
        "decision_available": isinstance(decision, dict),
        "decision_report_available": isinstance(decision_report, dict),
        "packet_available": isinstance(packet, dict),
        "install_review_available": isinstance(install_review, dict),
        "timer_draft_report_available": isinstance(timer_draft, dict),
        "runtime_lock_available": isinstance(runtime_lock, dict),
        "master_available": isinstance(master, dict),
        "service_draft_available": file_available(SERVICE_DRAFT),
        "timer_draft_available": file_available(TIMER_DRAFT),
        "decision_status": redact_text(decision_status, max_len=80),
        "manual_install_allowed": _as_bool(manual_install_allowed),
        "decision_breach": _as_bool(decision_report.get("decision_breach") if isinstance(decision_report, dict) else None),
        "decision_install_allowed_now": _as_bool(decision_report.get("install_allowed_now") if isinstance(decision_report, dict) else None),
        "decision_can_install_timer_now": _as_bool(decision_report.get("can_install_timer_now") if isinstance(decision_report, dict) else None),
        "decision_live_apply": _as_bool(decision_report.get("live_apply") if isinstance(decision_report, dict) else None),
        "decision_can_execute_live": _as_bool(decision_report.get("can_execute_live") if isinstance(decision_report, dict) else None),
        "decision_apply_status": _apply_status(decision_report.get("apply_status") if isinstance(decision_report, dict) else APPLY_NOT_APPLIED),
        "packet_status": redact_text(packet.get("packet_status") if isinstance(packet, dict) else None, max_len=80),
        "packet_breach": _as_bool(packet_summary.get("packet_breach") or (packet.get("packet_breach") if isinstance(packet, dict) else None)),
        "packet_install_allowed_now": _as_bool(packet.get("install_allowed_now") if isinstance(packet, dict) else None),
        "packet_can_install_timer_now": _as_bool(packet.get("can_install_timer_now") if isinstance(packet, dict) else None),
        "packet_shell_script_generated": _as_bool(packet.get("shell_script_generated") if isinstance(packet, dict) else None),
        "packet_systemd_file_written": _as_bool(packet.get("systemd_file_written") if isinstance(packet, dict) else None),
        "packet_crontab_file_written": _as_bool(packet.get("crontab_file_written") if isinstance(packet, dict) else None),
        "packet_live_apply": _as_bool(packet.get("live_apply") if isinstance(packet, dict) else None),
        "packet_can_execute_live": _as_bool(packet.get("can_execute_live") if isinstance(packet, dict) else None),
        "packet_apply_status": _apply_status(packet.get("apply_status") if isinstance(packet, dict) else APPLY_NOT_APPLIED),
        "install_review_status": redact_text(install_review.get("install_review_status") if isinstance(install_review, dict) else None, max_len=80),
        "install_reviewer_breach": _as_bool(review_summary.get("install_reviewer_breach") or (install_review.get("install_reviewer_breach") if isinstance(install_review, dict) else None)),
        "review_install_allowed_now": _as_bool(install_review.get("install_allowed_now") if isinstance(install_review, dict) else None),
        "review_can_install_timer_now": _as_bool(install_review.get("can_install_timer_now") if isinstance(install_review, dict) else None),
        "review_systemd_file_written": _as_bool(install_review.get("systemd_file_written") if isinstance(install_review, dict) else None),
        "review_crontab_file_written": _as_bool(install_review.get("crontab_file_written") if isinstance(install_review, dict) else None),
        "review_live_apply": _as_bool(install_review.get("live_apply") if isinstance(install_review, dict) else None),
        "review_can_execute_live": _as_bool(install_review.get("can_execute_live") if isinstance(install_review, dict) else None),
        "review_apply_status": _apply_status(install_review.get("apply_status") if isinstance(install_review, dict) else APPLY_NOT_APPLIED),
        "timer_draft_breach": _as_bool(timer_summary.get("timer_draft_breach") or (timer_draft.get("timer_draft_breach") if isinstance(timer_draft, dict) else None)),
        "timer_install_allowed_now": _as_bool(timer_draft.get("install_allowed_now") if isinstance(timer_draft, dict) else None),
        "timer_can_install_timer_now": _as_bool(timer_draft.get("can_install_timer_now") if isinstance(timer_draft, dict) else None),
        "timer_shell_script_generated": _as_bool(timer_draft.get("shell_script_generated") if isinstance(timer_draft, dict) else None),
        "timer_systemd_file_written": _as_bool(timer_draft.get("systemd_file_written") if isinstance(timer_draft, dict) else None),
        "timer_crontab_file_written": _as_bool(timer_draft.get("crontab_file_written") if isinstance(timer_draft, dict) else None),
        "timer_live_apply": _as_bool(timer_draft.get("live_apply") if isinstance(timer_draft, dict) else None),
        "timer_can_execute_live": _as_bool(timer_draft.get("can_execute_live") if isinstance(timer_draft, dict) else None),
        "timer_apply_status": _apply_status(timer_draft.get("apply_status") if isinstance(timer_draft, dict) else APPLY_NOT_APPLIED),
        "emergency_stop_active": emergency_stop,
        "runtime_lock_breach": _as_bool(runtime_lock.get("runtime_lock_breach") if isinstance(runtime_lock, dict) else None),
        "runtime_live_apply_enabled": _as_bool(runtime_lock.get("live_apply_enabled") if isinstance(runtime_lock, dict) else None),
        "runtime_apply_status": _apply_status(runtime_lock.get("apply_status") if isinstance(runtime_lock, dict) else APPLY_NOT_APPLIED),
        "master_overall_status": redact_text(master.get("overall_master_status") if isinstance(master, dict) else None, max_len=80),
        "master_action_status": redact_text(master.get("action_status") if isinstance(master, dict) else None, max_len=80),
    }


def compute_preview_breach(
    signals: Dict[str, Any],
    output_paths: List[str],
    output_texts: Optional[List[str]] = None,
    forced_flags: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, List[str]]:
    flags = forced_flags or {}
    reasons: List[str] = []
    if flags.get("install_allowed_now") or signals.get("decision_install_allowed_now") or signals.get("packet_install_allowed_now") or signals.get("review_install_allowed_now") or signals.get("timer_install_allowed_now"):
        reasons.append("install_allowed_now is true")
    if flags.get("can_install_timer_now") or signals.get("decision_can_install_timer_now") or signals.get("packet_can_install_timer_now") or signals.get("review_can_install_timer_now") or signals.get("timer_can_install_timer_now"):
        reasons.append("can_install_timer_now is true")
    if flags.get("shell_script_generated") or signals.get("packet_shell_script_generated") or signals.get("timer_shell_script_generated"):
        reasons.append("shell_script_generated is true")
    if flags.get("systemd_file_written") or signals.get("packet_systemd_file_written") or signals.get("review_systemd_file_written") or signals.get("timer_systemd_file_written"):
        reasons.append("systemd_file_written is true")
    if flags.get("crontab_file_written") or signals.get("packet_crontab_file_written") or signals.get("review_crontab_file_written") or signals.get("timer_crontab_file_written"):
        reasons.append("crontab_file_written is true")
    if flags.get("live_apply") or signals.get("decision_live_apply") or signals.get("packet_live_apply") or signals.get("review_live_apply") or signals.get("timer_live_apply") or signals.get("runtime_live_apply_enabled"):
        reasons.append("live_apply is true")
    if flags.get("can_execute_live") or signals.get("decision_can_execute_live") or signals.get("packet_can_execute_live") or signals.get("review_can_execute_live") or signals.get("timer_can_execute_live"):
        reasons.append("can_execute_live is true")
    for label in ("decision_apply_status", "packet_apply_status", "review_apply_status", "timer_apply_status", "runtime_apply_status"):
        if signals.get(label) != APPLY_NOT_APPLIED:
            reasons.append(f"{label} != not_applied")
    if flags.get("apply_status") and flags.get("apply_status") != APPLY_NOT_APPLIED:
        reasons.append("apply_status != not_applied")
    for raw in output_paths:
        path = Path(str(raw))
        lower = str(raw).lower()
        if path.suffix.lower() in FORBIDDEN_OUTPUT_SUFFIXES:
            reasons.append(f"executable install artifact generated: {redact_text(raw, max_len=120)}")
        if any(token in lower for token in FORBIDDEN_INSTALL_PATH_TOKENS):
            reasons.append(f"output path looks like a systemd/cron install path: {redact_text(raw, max_len=120)}")
        if not within_allowed_roots(path):
            reasons.append(f"output path outside allowed roots: {redact_text(raw, max_len=120)}")
    for text in output_texts or []:
        if detect_secret_in_text(text):
            reasons.append("secret-like values detected in generated output")
            break
    return bool(reasons), reasons


def determine_preview_status(signals: Dict[str, Any], breach: bool) -> Tuple[str, str]:
    if breach:
        return PREVIEW_BREACH, "a command-preview safety breach was detected."
    if signals.get("packet_breach"):
        return PREVIEW_BLOCKED_PACKET, "owner manual timer install packet reported packet_breach."
    if signals.get("install_reviewer_breach") or signals.get("timer_draft_breach") or signals.get("runtime_lock_breach"):
        return PREVIEW_BLOCKED_INSTALL_REVIEW, "install review, timer draft, or runtime lock reported a breach."
    if not (signals.get("decision_status") == READY_DECISION and signals.get("manual_install_allowed")):
        return PREVIEW_BLOCKED_DECISION, "owner decision is not reviewed_ready_for_manual_install with manual_install_allowed=true."
    if signals.get("emergency_stop_active"):
        return PREVIEW_BLOCKED_EMERGENCY, "emergency_stop is active; preview remains blocked but breach-free."
    return PREVIEW_READY, "-"


def command_block(commands: List[str]) -> str:
    return "```text\n" + "\n".join([REVIEW_COMMENT] + commands) + "\n```"


def preview_commands() -> Dict[str, List[str]]:
    return {
        "pre_install_review_checks": [
            "# Confirm runtime lock and owner decision before any manual action.",
            "python3 sentinel_autonomy_runtime_lock.py status",
            "python3 sentinel_owner_timer_install_decision_gate.py status",
            "python3 sentinel_owner_manual_timer_install_packet.py",
            "python3 sentinel_safe_draft_autonomy_timer_install_reviewer.py",
        ],
        "manual_copy_commands": [
            "# Manually copy reviewed DRAFT files only after owner final confirmation.",
            "sudo cp /srv/sentinel-defense/drafts/apply/sentinel-safe-draft-autonomy.service.draft /etc/systemd/system/sentinel-safe-draft-autonomy.service",
            "sudo cp /srv/sentinel-defense/drafts/apply/sentinel-safe-draft-autonomy.timer.draft /etc/systemd/system/sentinel-safe-draft-autonomy.timer",
        ],
        "manual_systemd_commands": [
            "# Enable only after reviewing the copied unit files and keeping live-apply disabled.",
            "sudo systemctl daemon-reload",
            "sudo systemctl enable --now sentinel-safe-draft-autonomy.timer",
        ],
        "post_install_verification_commands": [
            "systemctl status sentinel-safe-draft-autonomy.timer",
            "systemctl list-timers sentinel-safe-draft-autonomy.timer",
            "python3 sentinel_safe_draft_autonomy_runner.py",
            "python3 sentinel_safe_draft_autonomy_verifier.py",
            "python3 sentinel_master.py",
        ],
        "emergency_stop_commands": [
            "python3 sentinel_autonomy_runtime_lock.py emergency-stop",
            "sudo systemctl disable --now sentinel-safe-draft-autonomy.timer",
        ],
        "rollback_commands": [
            "sudo systemctl disable --now sentinel-safe-draft-autonomy.timer",
            "sudo systemctl stop sentinel-safe-draft-autonomy.service",
            "sudo rm -f /etc/systemd/system/sentinel-safe-draft-autonomy.service",
            "sudo rm -f /etc/systemd/system/sentinel-safe-draft-autonomy.timer",
            "sudo systemctl daemon-reload",
            "python3 sentinel_autonomy_runtime_lock.py emergency-stop",
            "python3 sentinel_safe_draft_autonomy_verifier.py",
            "python3 sentinel_master.py",
        ],
    }


def do_not_run_conditions(signals: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [
        {"condition": "emergency_stop=true", "active": bool(signals.get("emergency_stop_active"))},
        {"condition": "decision_status is not reviewed_ready_for_manual_install", "active": signals.get("decision_status") != READY_DECISION},
        {"condition": "manual_install_allowed=false", "active": not bool(signals.get("manual_install_allowed"))},
        {"condition": "packet_breach=true", "active": bool(signals.get("packet_breach"))},
        {"condition": "install_reviewer_breach=true", "active": bool(signals.get("install_reviewer_breach"))},
        {"condition": "timer_draft_breach=true", "active": bool(signals.get("timer_draft_breach"))},
        {"condition": "runtime_lock_breach=true", "active": bool(signals.get("runtime_lock_breach"))},
        {"condition": "service/timer draft missing", "active": not (signals.get("service_draft_available") and signals.get("timer_draft_available"))},
        {"condition": "owner final confirmation missing", "active": True},
    ]


def build_report(
    signals: Dict[str, Any],
    input_statuses: Dict[str, str],
    timestamp: Optional[str] = None,
    output_texts: Optional[List[str]] = None,
    output_paths: Optional[List[str]] = None,
    forced_flags: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    generated = timestamp or utc_now()
    paths = output_paths or [str(path) for path in ALLOWED_OUTPUT_PATHS]
    breach, breach_reasons = compute_preview_breach(signals, paths, output_texts=output_texts, forced_flags=forced_flags)
    status, blocked_reason = determine_preview_status(signals, breach)
    commands = preview_commands()
    summary = {
        "preview_status": status,
        "decision_status": signals.get("decision_status"),
        "manual_install_allowed": bool(signals.get("manual_install_allowed")),
        "install_allowed_now": False,
        "can_install_timer_now": False,
        "emergency_stop_active": bool(signals.get("emergency_stop_active")),
        "command_preview_written": True,
        "preview_breach": breach,
        "preview_breach_reasons": breach_reasons,
        "blocked_reason": blocked_reason,
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": generated,
        "status": status,
        "preview_status": status,
        "decision_status": signals.get("decision_status"),
        "manual_install_allowed": bool(signals.get("manual_install_allowed")),
        "install_allowed_now": False,
        "can_install_timer_now": False,
        "emergency_stop_active": bool(signals.get("emergency_stop_active")),
        "command_preview_written": True,
        "shell_script_generated": False,
        "systemd_file_written": False,
        "crontab_file_written": False,
        "live_apply": False,
        "can_execute_live": False,
        "live_apply_function": False,
        "network_access": False,
        "wordpress_login": False,
        "api_access": False,
        "productive_change": False,
        "apply_status": APPLY_NOT_APPLIED,
        "preview_breach": breach,
        "preview_breach_reasons": breach_reasons,
        "blocked_reason": blocked_reason,
        "service_draft": str(SERVICE_DRAFT),
        "timer_draft": str(TIMER_DRAFT),
        "service_draft_available": bool(signals.get("service_draft_available")),
        "timer_draft_available": bool(signals.get("timer_draft_available")),
        "input_statuses": input_statuses,
        "signals": signals,
        "do_not_run_conditions": do_not_run_conditions(signals),
        "commands_review_only": commands,
        "summary": summary,
        "outputs": {
            "report_json": str(REPORT_JSON),
            "report_md": str(REPORT_MD),
            "owner_preview_md": str(OWNER_PREVIEW_MD),
            "apply_review_only_md": str(APPLY_REVIEW_ONLY_MD),
            "audit_jsonl": str(AUDIT_JSONL),
        },
        "safety": {
            "no_live_changes": True,
            "systemctl_executed": False,
            "systemd_file_written": False,
            "crontab_file_written": False,
            "shell_script_generated": False,
            "cloudflare_mutation": False,
            "nginx_change": False,
            "htaccess_change": False,
            "secrets_output": False,
        },
    }


def render_preview_markdown(report: Dict[str, Any]) -> str:
    conditions = report.get("do_not_run_conditions") if isinstance(report.get("do_not_run_conditions"), list) else []
    commands = report.get("commands_review_only") if isinstance(report.get("commands_review_only"), dict) else {}
    lines = [
        "# Manual Timer Install Command Preview (REVIEW ONLY)",
        "",
        f"- Generated (UTC): `{report.get('generated_at_utc')}`",
        f"- Preview status: `{report.get('preview_status')}`",
        f"- Decision status: `{report.get('decision_status')}`",
        f"- manual_install_allowed: `{report.get('manual_install_allowed')}`",
        f"- install_allowed_now: `{report.get('install_allowed_now')}`",
        f"- can_install_timer_now: `{report.get('can_install_timer_now')}`",
        f"- emergency_stop_active: `{report.get('emergency_stop_active')}`",
        f"- preview_breach: `{report.get('preview_breach')}`",
        f"- blocked_reason: `{redact_text(report.get('blocked_reason'), max_len=240)}`",
        "",
        "> Dies ist keine Installation. Die folgenden Kommandos sind reine Review-Texte in Markdown. "
        "Dieses Modul fuehrt nichts aus und erzeugt keine Shell-, systemd- oder crontab-Datei.",
        "",
        "## Pre-Install Review Checks",
        "",
        command_block(commands.get("pre_install_review_checks", [])),
        "",
        "## Manual Copy Commands as REVIEW ONLY",
        "",
        command_block(commands.get("manual_copy_commands", [])),
        "",
        "## Manual systemd Commands as REVIEW ONLY",
        "",
        command_block(commands.get("manual_systemd_commands", [])),
        "",
        "## Post-Install Verification Commands as REVIEW ONLY",
        "",
        command_block(commands.get("post_install_verification_commands", [])),
        "",
        "## Emergency Stop Commands as REVIEW ONLY",
        "",
        command_block(commands.get("emergency_stop_commands", [])),
        "",
        "## Rollback Commands as REVIEW ONLY",
        "",
        command_block(commands.get("rollback_commands", [])),
        "",
        "## Do Not Run Conditions",
        "",
    ]
    for item in conditions:
        if isinstance(item, dict):
            marker = "ACTIVE" if item.get("active") else "ok"
            lines.append(f"- `{marker}` — {redact_text(item.get('condition'), max_len=180)}")
    lines.extend(
        [
            "",
            "## Safety",
            "",
            "- `install_allowed_now=false`, `can_install_timer_now=false`, `can_execute_live=false`.",
            "- `apply_status=not_applied`; keine Live-Apply-Funktion.",
            "- Keine produktiven Dateien, keine systemd-Dateien, keine crontab-Dateien und keine `.sh`-Dateien werden erzeugt.",
            "",
        ]
    )
    return "\n".join(lines)


def render_report_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# Manual Timer Install Command Preview Report",
        "",
        f"- Generated (UTC): `{report.get('generated_at_utc')}`",
        f"- Preview status: `{report.get('preview_status')}`",
        f"- Decision status: `{report.get('decision_status')}`",
        f"- Manual install allowed: `{report.get('manual_install_allowed')}`",
        f"- Install allowed now: `{report.get('install_allowed_now')}`",
        f"- Can install timer now: `{report.get('can_install_timer_now')}`",
        f"- Emergency stop active: `{report.get('emergency_stop_active')}`",
        f"- Command preview written: `{report.get('command_preview_written')}`",
        f"- Shell script generated: `{report.get('shell_script_generated')}`",
        f"- systemd file written: `{report.get('systemd_file_written')}`",
        f"- crontab file written: `{report.get('crontab_file_written')}`",
        f"- Live apply: `{report.get('live_apply')}`",
        f"- Can execute live: `{report.get('can_execute_live')}`",
        f"- Apply status: `{report.get('apply_status')}`",
        f"- Preview breach: `{report.get('preview_breach')}`",
        f"- Blocked reason: `{redact_text(report.get('blocked_reason'), max_len=240)}`",
        "",
        "## Outputs",
        "",
        f"- Owner preview: `{OWNER_PREVIEW_MD}`",
        f"- Apply review-only preview: `{APPLY_REVIEW_ONLY_MD}`",
        "",
        "## Safety",
        "",
        "- Documentation only. No command execution, no live apply, no install.",
        "- Code blocks in preview markdown begin with the required REVIEW ONLY comment.",
        "",
    ]
    return "\n".join(lines)


def rendered_output_texts(report: Dict[str, Any]) -> List[str]:
    return [
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        render_report_markdown(report),
        render_preview_markdown(report),
    ]


def mark_secret_output_breach(report: Dict[str, Any]) -> Dict[str, Any]:
    if not any(detect_secret_in_text(text) for text in rendered_output_texts(report)):
        return report
    updated = dict(report)
    reasons = list(updated.get("preview_breach_reasons") if isinstance(updated.get("preview_breach_reasons"), list) else [])
    reason = "secret-like values detected in generated output"
    if reason not in reasons:
        reasons.append(reason)
    updated["preview_breach"] = True
    updated["preview_breach_reasons"] = reasons
    updated["preview_status"] = PREVIEW_BREACH
    updated["status"] = PREVIEW_BREACH
    updated["blocked_reason"] = reason
    summary = dict(updated.get("summary") if isinstance(updated.get("summary"), dict) else {})
    summary["preview_breach"] = True
    summary["preview_breach_reasons"] = reasons
    summary["preview_status"] = PREVIEW_BREACH
    summary["blocked_reason"] = reason
    updated["summary"] = summary
    safety = dict(updated.get("safety") if isinstance(updated.get("safety"), dict) else {})
    safety["secrets_output"] = True
    updated["safety"] = safety
    return updated


def audit_record(report: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "timestamp_utc": report.get("generated_at_utc"),
        "schema_version": SCHEMA_VERSION,
        "record_type": "manual_timer_install_command_preview",
        "preview_status": report.get("preview_status"),
        "decision_status": report.get("decision_status"),
        "manual_install_allowed": report.get("manual_install_allowed"),
        "install_allowed_now": report.get("install_allowed_now"),
        "can_install_timer_now": report.get("can_install_timer_now"),
        "emergency_stop_active": report.get("emergency_stop_active"),
        "command_preview_written": report.get("command_preview_written"),
        "preview_breach": report.get("preview_breach"),
        "live_apply": False,
        "productive_change": False,
        "network_access": False,
    }


def write_outputs(report: Dict[str, Any]) -> Dict[str, Any]:
    report = mark_secret_output_breach(report)
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, render_report_markdown(report))
    preview_md = render_preview_markdown(report)
    write_text_atomic(OWNER_PREVIEW_MD, preview_md)
    write_text_atomic(APPLY_REVIEW_ONLY_MD, preview_md)
    append_jsonl(AUDIT_JSONL, [audit_record(report)])
    return report


def load_inputs() -> Tuple[Dict[str, Any], Dict[str, str]]:
    decision, decision_status = read_optional_json(INPUT_DECISION_JSON)
    decision_report, decision_report_status = read_optional_json(INPUT_DECISION_REPORT)
    packet, packet_status = read_optional_json(INPUT_PACKET_REPORT)
    install_review, install_review_status = read_optional_json(INPUT_INSTALL_REVIEW)
    timer_draft, timer_draft_status = read_optional_json(INPUT_TIMER_DRAFT_REPORT)
    runtime_lock, runtime_lock_status = read_optional_json(INPUT_RUNTIME_LOCK)
    master, master_status = read_optional_json(INPUT_MASTER)
    statuses = {
        "owner_timer_install_decision": decision_status,
        "owner_timer_install_decision_gate_report": decision_report_status,
        "owner_manual_timer_install_packet_report": packet_status,
        "safe_draft_autonomy_timer_install_review_report": install_review_status,
        "safe_draft_autonomy_timer_draft_report": timer_draft_status,
        "autonomy_runtime_lock": runtime_lock_status,
        "sentinel_master": master_status,
        "service_draft": "ok" if file_available(SERVICE_DRAFT) else "not_available",
        "timer_draft": "ok" if file_available(TIMER_DRAFT) else "not_available",
    }
    signals = gather_signals(
        decision if isinstance(decision, dict) else None,
        decision_report if isinstance(decision_report, dict) else None,
        packet if isinstance(packet, dict) else None,
        install_review if isinstance(install_review, dict) else None,
        timer_draft if isinstance(timer_draft, dict) else None,
        runtime_lock if isinstance(runtime_lock, dict) else None,
        master if isinstance(master, dict) else None,
    )
    return signals, statuses


def _signals(**overrides: Any) -> Dict[str, Any]:
    base = {
        "decision_available": True,
        "decision_report_available": True,
        "packet_available": True,
        "install_review_available": True,
        "timer_draft_report_available": True,
        "runtime_lock_available": True,
        "master_available": True,
        "service_draft_available": True,
        "timer_draft_available": True,
        "decision_status": READY_DECISION,
        "manual_install_allowed": True,
        "decision_breach": False,
        "decision_install_allowed_now": False,
        "decision_can_install_timer_now": False,
        "decision_live_apply": False,
        "decision_can_execute_live": False,
        "decision_apply_status": APPLY_NOT_APPLIED,
        "packet_status": "PACKET_READY_FOR_OWNER_REVIEW",
        "packet_breach": False,
        "packet_install_allowed_now": False,
        "packet_can_install_timer_now": False,
        "packet_shell_script_generated": False,
        "packet_systemd_file_written": False,
        "packet_crontab_file_written": False,
        "packet_live_apply": False,
        "packet_can_execute_live": False,
        "packet_apply_status": APPLY_NOT_APPLIED,
        "install_review_status": "INSTALL_REVIEW_READY",
        "install_reviewer_breach": False,
        "review_install_allowed_now": False,
        "review_can_install_timer_now": False,
        "review_systemd_file_written": False,
        "review_crontab_file_written": False,
        "review_live_apply": False,
        "review_can_execute_live": False,
        "review_apply_status": APPLY_NOT_APPLIED,
        "timer_draft_breach": False,
        "timer_install_allowed_now": False,
        "timer_can_install_timer_now": False,
        "timer_shell_script_generated": False,
        "timer_systemd_file_written": False,
        "timer_crontab_file_written": False,
        "timer_live_apply": False,
        "timer_can_execute_live": False,
        "timer_apply_status": APPLY_NOT_APPLIED,
        "emergency_stop_active": False,
        "runtime_lock_breach": False,
        "runtime_live_apply_enabled": False,
        "runtime_apply_status": APPLY_NOT_APPLIED,
        "master_overall_status": "WARNING",
        "master_action_status": "WARNING_REVIEW",
    }
    base.update(overrides)
    return base


def _report(signals: Optional[Dict[str, Any]] = None, **kwargs: Any) -> Dict[str, Any]:
    return build_report(
        signals or _signals(),
        {"owner_timer_install_decision": "ok"},
        timestamp="2026-06-11T00:00:00Z",
        **kwargs,
    )


def run_self_test() -> int:
    ready = _report(_signals())
    if ready["preview_status"] != PREVIEW_READY:
        raise AssertionError("ready signals did not produce PREVIEW_READY_FOR_OWNER_REVIEW")
    if ready["install_allowed_now"] or ready["can_install_timer_now"]:
        raise AssertionError("preview must never allow install now")
    emergency = _report(_signals(emergency_stop_active=True))
    if emergency["preview_status"] != PREVIEW_BLOCKED_EMERGENCY or emergency["preview_breach"]:
        raise AssertionError("emergency stop must block without breach")
    if _report(_signals(decision_status="reviewed_wait", manual_install_allowed=False))["preview_status"] != PREVIEW_BLOCKED_DECISION:
        raise AssertionError("not-ready decision did not block")
    if _report(_signals(install_reviewer_breach=True))["preview_status"] != PREVIEW_BLOCKED_INSTALL_REVIEW:
        raise AssertionError("install review breach did not block")
    if _report(_signals(packet_breach=True))["preview_status"] != PREVIEW_BLOCKED_PACKET:
        raise AssertionError("packet breach did not block")

    for key in (
        "install_allowed_now",
        "can_install_timer_now",
        "shell_script_generated",
        "systemd_file_written",
        "crontab_file_written",
        "live_apply",
        "can_execute_live",
    ):
        if not _report(_signals(), forced_flags={key: True})["preview_breach"]:
            raise AssertionError(f"{key}=true did not breach")
    if not _report(_signals(), forced_flags={"apply_status": "applied"})["preview_breach"]:
        raise AssertionError("apply_status != not_applied did not breach")
    if not _report(_signals(decision_can_install_timer_now=True))["preview_breach"]:
        raise AssertionError("input can_install_timer_now did not breach")
    if not _report(_signals(timer_systemd_file_written=True))["preview_breach"]:
        raise AssertionError("input systemd_file_written did not breach")
    if not _report(_signals(runtime_live_apply_enabled=True))["preview_breach"]:
        raise AssertionError("input live_apply did not breach")
    if not _report(_signals(packet_apply_status="applied"))["preview_breach"]:
        raise AssertionError("input apply_status did not breach")
    if not _report(_signals(), output_paths=["drafts/owner/install.sh"])["preview_breach"]:
        raise AssertionError("executable install artifact did not breach")
    if not _report(_signals(), output_paths=["/etc/systemd/system/x.service"])["preview_breach"]:
        raise AssertionError("systemd output path did not breach")
    if not _report(_signals(), output_paths=["/tmp/preview.json"])["preview_breach"]:
        raise AssertionError("outside output path did not breach")
    if not _report(_signals(), output_texts=["token=0123456789abcdef"])["preview_breach"]:
        raise AssertionError("secret-like output did not breach")

    missing = _report(_signals(decision_available=False, decision_report_available=False, packet_available=False, install_review_available=False, timer_draft_report_available=False))
    if missing["preview_breach"]:
        raise AssertionError("missing inputs must not breach")

    rendered = render_preview_markdown(ready)
    for marker in ("```text\n" + REVIEW_COMMENT,):
        if marker not in rendered:
            raise AssertionError("review code blocks must begin with required comment")
    if ".sh" in " ".join(str(path) for path in ALLOWED_OUTPUT_PATHS):
        raise AssertionError("module output paths must not include .sh")
    for path in ALLOWED_OUTPUT_PATHS:
        assert_allowed_write(path)
    for bad in (Path("/etc/systemd/system/x.timer"), PROJECT_DIR / "drafts/owner/install.sh"):
        try:
            assert_allowed_write(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"forbidden write path not rejected: {bad}")

    print("manual-timer-install-command-preview self-tests: OK")
    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build review-only manual timer install command preview docs; no install, no live apply."
    )
    parser.add_argument("--self-test", action="store_true", help="Run built-in safety tests and exit.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()
    signals, statuses = load_inputs()
    report = build_report(signals, statuses)
    report = write_outputs(report)
    print(
        "Manual Timer Install Command Preview: "
        f"status={report.get('preview_status')}, "
        f"decision={report.get('decision_status')}, "
        f"manual_allowed={report.get('manual_install_allowed')}, "
        f"install_allowed={report.get('install_allowed_now')}, "
        f"can_install={report.get('can_install_timer_now')}, "
        f"emergency_stop={report.get('emergency_stop_active')}, "
        f"breach={report.get('preview_breach')}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
