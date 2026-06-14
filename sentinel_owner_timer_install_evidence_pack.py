#!/usr/bin/env python3
"""Sentinel Owner Timer Install Evidence Pack (Phase 4.4).

Prepares a safe evidence/checklist pack for a possible later manual timer
installation. It defines which outputs the owner would need to review and paste
after a manual install, but it never installs anything and never executes any
command.

Hard safety guarantees:
- No live changes and no live-apply function.
- No systemctl execution, no systemd writes, no crontab writes, no shell script.
- No WordPress, .htaccess, Cloudflare, Nginx, DNS, API, login, or network work.
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

INPUT_COMMAND_PREVIEW_REPORT = PROJECT_DIR / "reports/latest/manual-timer-install-command-preview-report.json"
INPUT_DECISION_REPORT = PROJECT_DIR / "reports/latest/owner-timer-install-decision-gate-report.json"
INPUT_PACKET_REPORT = PROJECT_DIR / "reports/latest/owner-manual-timer-install-packet-report.json"
INPUT_INSTALL_REVIEW = PROJECT_DIR / "reports/latest/safe-draft-autonomy-timer-install-review-report.json"
INPUT_TIMER_DRAFT_REPORT = PROJECT_DIR / "reports/latest/safe-draft-autonomy-timer-draft-report.json"
INPUT_RUNTIME_LOCK = PROJECT_DIR / "config/autonomy-runtime-lock.json"
INPUT_MASTER = PROJECT_DIR / "reports/latest/sentinel-master-report.json"
INPUT_OWNER_PREVIEW_MD = PROJECT_DIR / "drafts/owner/manual-timer-install-command-preview.md"
INPUT_APPLY_PREVIEW_MD = PROJECT_DIR / "drafts/apply/manual-timer-install-command-preview-review-only.md"

REPORT_JSON = PROJECT_DIR / "reports/latest/owner-timer-install-evidence-pack-report.json"
REPORT_MD = PROJECT_DIR / "reports/latest/owner-timer-install-evidence-pack-report.md"
PACK_MD = PROJECT_DIR / "drafts/owner/owner-timer-install-evidence-pack.md"
TEMPLATE_MD = PROJECT_DIR / "drafts/owner/owner-timer-install-evidence-template.md"
REVIEW_ONLY_MD = PROJECT_DIR / "drafts/apply/owner-timer-install-evidence-review-only.md"
AUDIT_JSONL = PROJECT_DIR / "audit/owner-timer-install-evidence-pack.jsonl"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "drafts/owner",
    PROJECT_DIR / "drafts/apply",
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "audit",
)
ALLOWED_OUTPUT_PATHS = (REPORT_JSON, REPORT_MD, PACK_MD, TEMPLATE_MD, REVIEW_ONLY_MD, AUDIT_JSONL)
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

SCHEMA_VERSION = "owner-timer-install-evidence-pack-4.4"
APPLY_NOT_APPLIED = "not_applied"
READY_DECISION = "reviewed_ready_for_manual_install"

EVIDENCE_READY = "EVIDENCE_PACK_READY_FOR_OWNER_REVIEW"
EVIDENCE_BLOCKED_EMERGENCY = "EVIDENCE_PACK_BLOCKED_BY_EMERGENCY_STOP"
EVIDENCE_BLOCKED_DECISION = "EVIDENCE_PACK_BLOCKED_BY_DECISION_NOT_READY"
EVIDENCE_BLOCKED_PREVIEW = "EVIDENCE_PACK_BLOCKED_BY_PREVIEW_BREACH"
EVIDENCE_BLOCKED_PACKET = "EVIDENCE_PACK_BLOCKED_BY_PACKET_BREACH"
EVIDENCE_BREACH = "EVIDENCE_PACK_BREACH"

EVIDENCE_COMMENT = "# EVIDENCE TEMPLATE ONLY - DO NOT RUN COMMANDS FROM THIS FILE"

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
        raise ValueError(f"Refusing to write outside allowed evidence-pack roots: {path}")
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


def read_optional_text_status(path: Path) -> str:
    try:
        if ".env" in str(path).lower() or SECRETISH_RE.search(path.name):
            return "refused_secret_like_path"
        if path.suffix.lower() != ".md":
            return "unsupported_suffix"
        if not path.exists():
            return "not_available"
        path.read_text(encoding="utf-8")
        return "ok"
    except OSError:
        return "read_error"


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
    preview: Optional[Dict[str, Any]],
    decision: Optional[Dict[str, Any]],
    packet: Optional[Dict[str, Any]],
    install_review: Optional[Dict[str, Any]],
    timer_draft: Optional[Dict[str, Any]],
    runtime_lock: Optional[Dict[str, Any]],
    master: Optional[Dict[str, Any]],
    owner_preview_status: str,
    apply_preview_status: str,
) -> Dict[str, Any]:
    preview_summary = preview.get("summary") if isinstance(preview, dict) and isinstance(preview.get("summary"), dict) else {}
    decision_summary = decision.get("summary") if isinstance(decision, dict) and isinstance(decision.get("summary"), dict) else {}
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
    emergency_stop = _as_bool(runtime_lock.get("emergency_stop"), True) if isinstance(runtime_lock, dict) else True
    return {
        "preview_available": isinstance(preview, dict),
        "decision_available": isinstance(decision, dict),
        "packet_available": isinstance(packet, dict),
        "install_review_available": isinstance(install_review, dict),
        "timer_draft_report_available": isinstance(timer_draft, dict),
        "runtime_lock_available": isinstance(runtime_lock, dict),
        "master_available": isinstance(master, dict),
        "owner_preview_md_available": owner_preview_status == "ok",
        "apply_preview_md_available": apply_preview_status == "ok",
        "preview_status": redact_text(preview.get("preview_status") if isinstance(preview, dict) else None, max_len=100),
        "preview_breach": _as_bool(preview_summary.get("preview_breach") or (preview.get("preview_breach") if isinstance(preview, dict) else None)),
        "preview_install_allowed_now": _as_bool(preview.get("install_allowed_now") if isinstance(preview, dict) else None),
        "preview_can_install_timer_now": _as_bool(preview.get("can_install_timer_now") if isinstance(preview, dict) else None),
        "preview_shell_script_generated": _as_bool(preview.get("shell_script_generated") if isinstance(preview, dict) else None),
        "preview_systemd_file_written": _as_bool(preview.get("systemd_file_written") if isinstance(preview, dict) else None),
        "preview_crontab_file_written": _as_bool(preview.get("crontab_file_written") if isinstance(preview, dict) else None),
        "preview_live_apply": _as_bool(preview.get("live_apply") if isinstance(preview, dict) else None),
        "preview_can_execute_live": _as_bool(preview.get("can_execute_live") if isinstance(preview, dict) else None),
        "preview_apply_status": _apply_status(preview.get("apply_status") if isinstance(preview, dict) else APPLY_NOT_APPLIED),
        "decision_status": redact_text(decision.get("decision_status") if isinstance(decision, dict) else "not_reviewed", max_len=100),
        "manual_install_allowed": _as_bool(decision.get("manual_install_allowed") if isinstance(decision, dict) else None),
        "decision_breach": _as_bool(decision_summary.get("decision_breach") or (decision.get("decision_breach") if isinstance(decision, dict) else None)),
        "decision_install_allowed_now": _as_bool(decision.get("install_allowed_now") if isinstance(decision, dict) else None),
        "decision_can_install_timer_now": _as_bool(decision.get("can_install_timer_now") if isinstance(decision, dict) else None),
        "decision_systemd_file_written": _as_bool(decision.get("systemd_file_written") if isinstance(decision, dict) else None),
        "decision_crontab_file_written": _as_bool(decision.get("crontab_file_written") if isinstance(decision, dict) else None),
        "decision_live_apply": _as_bool(decision.get("live_apply") if isinstance(decision, dict) else None),
        "decision_can_execute_live": _as_bool(decision.get("can_execute_live") if isinstance(decision, dict) else None),
        "decision_apply_status": _apply_status(decision.get("apply_status") if isinstance(decision, dict) else APPLY_NOT_APPLIED),
        "packet_status": redact_text(packet.get("packet_status") if isinstance(packet, dict) else None, max_len=100),
        "packet_breach": _as_bool(packet_summary.get("packet_breach") or (packet.get("packet_breach") if isinstance(packet, dict) else None)),
        "packet_install_allowed_now": _as_bool(packet.get("install_allowed_now") if isinstance(packet, dict) else None),
        "packet_can_install_timer_now": _as_bool(packet.get("can_install_timer_now") if isinstance(packet, dict) else None),
        "packet_shell_script_generated": _as_bool(packet.get("shell_script_generated") if isinstance(packet, dict) else None),
        "packet_systemd_file_written": _as_bool(packet.get("systemd_file_written") if isinstance(packet, dict) else None),
        "packet_crontab_file_written": _as_bool(packet.get("crontab_file_written") if isinstance(packet, dict) else None),
        "packet_live_apply": _as_bool(packet.get("live_apply") if isinstance(packet, dict) else None),
        "packet_can_execute_live": _as_bool(packet.get("can_execute_live") if isinstance(packet, dict) else None),
        "packet_apply_status": _apply_status(packet.get("apply_status") if isinstance(packet, dict) else APPLY_NOT_APPLIED),
        "install_review_status": redact_text(install_review.get("install_review_status") if isinstance(install_review, dict) else None, max_len=100),
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
        "master_overall_status": redact_text(master.get("overall_master_status") if isinstance(master, dict) else None, max_len=100),
        "master_action_status": redact_text(master.get("action_status") if isinstance(master, dict) else None, max_len=100),
    }


def compute_evidence_breach(
    signals: Dict[str, Any],
    output_paths: List[str],
    output_texts: Optional[List[str]] = None,
    forced_flags: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, List[str]]:
    flags = forced_flags or {}
    reasons: List[str] = []
    if flags.get("install_allowed_now") or any(signals.get(key) for key in ("preview_install_allowed_now", "decision_install_allowed_now", "packet_install_allowed_now", "review_install_allowed_now", "timer_install_allowed_now")):
        reasons.append("install_allowed_now is true")
    if flags.get("can_install_timer_now") or any(signals.get(key) for key in ("preview_can_install_timer_now", "decision_can_install_timer_now", "packet_can_install_timer_now", "review_can_install_timer_now", "timer_can_install_timer_now")):
        reasons.append("can_install_timer_now is true")
    if flags.get("shell_script_generated") or any(signals.get(key) for key in ("preview_shell_script_generated", "packet_shell_script_generated", "timer_shell_script_generated")):
        reasons.append("shell_script_generated is true")
    if flags.get("systemd_file_written") or any(signals.get(key) for key in ("preview_systemd_file_written", "decision_systemd_file_written", "packet_systemd_file_written", "review_systemd_file_written", "timer_systemd_file_written")):
        reasons.append("systemd_file_written is true")
    if flags.get("crontab_file_written") or any(signals.get(key) for key in ("preview_crontab_file_written", "decision_crontab_file_written", "packet_crontab_file_written", "review_crontab_file_written", "timer_crontab_file_written")):
        reasons.append("crontab_file_written is true")
    if flags.get("live_apply") or any(signals.get(key) for key in ("preview_live_apply", "decision_live_apply", "packet_live_apply", "review_live_apply", "timer_live_apply", "runtime_live_apply_enabled")):
        reasons.append("live_apply is true")
    if flags.get("can_execute_live") or any(signals.get(key) for key in ("preview_can_execute_live", "decision_can_execute_live", "packet_can_execute_live", "review_can_execute_live", "timer_can_execute_live")):
        reasons.append("can_execute_live is true")
    for label in ("preview_apply_status", "decision_apply_status", "packet_apply_status", "review_apply_status", "timer_apply_status", "runtime_apply_status"):
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


def determine_evidence_status(signals: Dict[str, Any], breach: bool) -> Tuple[str, str]:
    if breach:
        return EVIDENCE_BREACH, "an evidence-pack safety breach was detected."
    if signals.get("preview_breach"):
        return EVIDENCE_BLOCKED_PREVIEW, "manual timer command preview reported preview_breach."
    if signals.get("packet_breach"):
        return EVIDENCE_BLOCKED_PACKET, "owner manual timer install packet reported packet_breach."
    if signals.get("decision_breach") or signals.get("install_reviewer_breach") or signals.get("timer_draft_breach") or signals.get("runtime_lock_breach"):
        return EVIDENCE_BLOCKED_DECISION, "decision gate, install review, timer draft, or runtime lock reported a breach."
    if not (signals.get("decision_status") == READY_DECISION and signals.get("manual_install_allowed")):
        return EVIDENCE_BLOCKED_DECISION, "owner decision is not reviewed_ready_for_manual_install with manual_install_allowed=true."
    if signals.get("emergency_stop_active"):
        return EVIDENCE_BLOCKED_EMERGENCY, "emergency_stop is active; evidence pack remains blocked but breach-free."
    return EVIDENCE_READY, "-"


def evidence_sections() -> List[Dict[str, Any]]:
    return [
        {
            "section": "Current Safety Status",
            "required_evidence": [
                "Runtime Lock Status vor Installation",
                "Decision Gate Status",
                "Command Preview Status",
                "Timer Install Review Status",
                "Kein Live-Apply bestaetigt",
            ],
        },
        {
            "section": "Required Pre-Install Evidence",
            "required_evidence": [
                "Service-Draft manuell gelesen",
                "Timer-Draft manuell gelesen",
                "Owner Final Confirmation ausserhalb dieses Bots dokumentiert",
            ],
        },
        {
            "section": "Required Manual Install Evidence",
            "required_evidence": [
                "Nach manueller Installation: systemctl status als manuell eingefuegter Text",
                "Nach manueller Installation: systemctl list-timers als manuell eingefuegter Text",
            ],
        },
        {
            "section": "Required Runner Evidence",
            "required_evidence": ["Runner Report nach manuellem Testlauf"],
        },
        {
            "section": "Required Verifier Evidence",
            "required_evidence": ["Verifier Report nach Runner-Lauf"],
        },
        {
            "section": "Required Master Evidence",
            "required_evidence": ["Master Report nach Verifier-Lauf"],
        },
        {
            "section": "Required Rollback Evidence",
            "required_evidence": ["Rollback-Schritte und Ergebnis, falls ein Problem auftritt"],
        },
        {
            "section": "Required Emergency Stop Evidence",
            "required_evidence": ["Emergency-stop Nachweis bei jedem Zweifel oder Problem"],
        },
    ]


def do_not_proceed_conditions(signals: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [
        {"condition": "emergency_stop=true", "active": bool(signals.get("emergency_stop_active"))},
        {"condition": "decision_status is not reviewed_ready_for_manual_install", "active": signals.get("decision_status") != READY_DECISION},
        {"condition": "manual_install_allowed=false", "active": not bool(signals.get("manual_install_allowed"))},
        {"condition": "preview_breach=true", "active": bool(signals.get("preview_breach"))},
        {"condition": "packet_breach=true", "active": bool(signals.get("packet_breach"))},
        {"condition": "decision_breach=true", "active": bool(signals.get("decision_breach"))},
        {"condition": "install_reviewer_breach=true", "active": bool(signals.get("install_reviewer_breach"))},
        {"condition": "timer_draft_breach=true", "active": bool(signals.get("timer_draft_breach"))},
        {"condition": "runtime_lock_breach=true", "active": bool(signals.get("runtime_lock_breach"))},
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
    breach, breach_reasons = compute_evidence_breach(signals, paths, output_texts=output_texts, forced_flags=forced_flags)
    status, blocked_reason = determine_evidence_status(signals, breach)
    summary = {
        "evidence_pack_status": status,
        "decision_status": signals.get("decision_status"),
        "preview_status": signals.get("preview_status"),
        "manual_install_allowed": bool(signals.get("manual_install_allowed")),
        "install_allowed_now": False,
        "can_install_timer_now": False,
        "emergency_stop_active": bool(signals.get("emergency_stop_active")),
        "evidence_template_written": True,
        "evidence_pack_breach": breach,
        "evidence_pack_breach_reasons": breach_reasons,
        "blocked_reason": blocked_reason,
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": generated,
        "status": status,
        "evidence_pack_status": status,
        "decision_status": signals.get("decision_status"),
        "preview_status": signals.get("preview_status"),
        "manual_install_allowed": bool(signals.get("manual_install_allowed")),
        "install_allowed_now": False,
        "can_install_timer_now": False,
        "emergency_stop_active": bool(signals.get("emergency_stop_active")),
        "evidence_template_written": True,
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
        "evidence_pack_breach": breach,
        "evidence_pack_breach_reasons": breach_reasons,
        "blocked_reason": blocked_reason,
        "input_statuses": input_statuses,
        "signals": signals,
        "evidence_sections": evidence_sections(),
        "do_not_proceed_conditions": do_not_proceed_conditions(signals),
        "summary": summary,
        "outputs": {
            "report_json": str(REPORT_JSON),
            "report_md": str(REPORT_MD),
            "pack_md": str(PACK_MD),
            "template_md": str(TEMPLATE_MD),
            "review_only_md": str(REVIEW_ONLY_MD),
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


def evidence_text_block(title: str, prompt: str) -> List[str]:
    return [
        f"### {title}",
        "",
        "```text",
        EVIDENCE_COMMENT,
        f"# Required evidence: {prompt}",
        "# Paste manually reviewed output or note here after a future manual installation.",
        "# <owner evidence placeholder>",
        "```",
        "",
    ]


def render_evidence_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# Owner Timer Install Evidence Pack (REVIEW ONLY)",
        "",
        f"- Generated (UTC): `{report.get('generated_at_utc')}`",
        f"- Evidence pack status: `{report.get('evidence_pack_status')}`",
        f"- Decision status: `{report.get('decision_status')}`",
        f"- Preview status: `{report.get('preview_status')}`",
        f"- manual_install_allowed: `{report.get('manual_install_allowed')}`",
        f"- install_allowed_now: `{report.get('install_allowed_now')}`",
        f"- can_install_timer_now: `{report.get('can_install_timer_now')}`",
        f"- emergency_stop_active: `{report.get('emergency_stop_active')}`",
        f"- evidence_pack_breach: `{report.get('evidence_pack_breach')}`",
        f"- blocked_reason: `{redact_text(report.get('blocked_reason'), max_len=240)}`",
        "",
        "> Dies ist keine Installation. Dieses Evidence Pack beschreibt nur, welche Nachweise "
        "der Owner nach einer spaeteren manuellen Installation pruefen und dokumentieren muesste.",
        "",
    ]
    for section in report.get("evidence_sections", []):
        if not isinstance(section, dict):
            continue
        lines.extend([f"## {redact_text(section.get('section'), max_len=120)}", ""])
        for evidence in section.get("required_evidence", []):
            lines.extend(evidence_text_block(redact_text(evidence, max_len=160), redact_text(evidence, max_len=220)))
    lines.extend(["## Do Not Proceed Conditions", ""])
    for item in report.get("do_not_proceed_conditions", []):
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


def render_template_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# Owner Timer Install Evidence Template",
        "",
        "> Template only. Manually paste reviewed evidence here only after a future owner-driven manual install.",
        "",
        f"- Evidence pack status at generation: `{report.get('evidence_pack_status')}`",
        f"- Install allowed now at generation: `{report.get('install_allowed_now')}`",
        f"- Can install timer now at generation: `{report.get('can_install_timer_now')}`",
        "",
    ]
    for section in report.get("evidence_sections", []):
        if not isinstance(section, dict):
            continue
        lines.extend([f"## {redact_text(section.get('section'), max_len=120)}", ""])
        for evidence in section.get("required_evidence", []):
            lines.extend(evidence_text_block(redact_text(evidence, max_len=160), redact_text(evidence, max_len=220)))
    return "\n".join(lines)


def render_report_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# Owner Timer Install Evidence Pack Report",
        "",
        f"- Generated (UTC): `{report.get('generated_at_utc')}`",
        f"- Evidence pack status: `{report.get('evidence_pack_status')}`",
        f"- Decision status: `{report.get('decision_status')}`",
        f"- Preview status: `{report.get('preview_status')}`",
        f"- Manual install allowed: `{report.get('manual_install_allowed')}`",
        f"- Install allowed now: `{report.get('install_allowed_now')}`",
        f"- Can install timer now: `{report.get('can_install_timer_now')}`",
        f"- Emergency stop active: `{report.get('emergency_stop_active')}`",
        f"- Evidence template written: `{report.get('evidence_template_written')}`",
        f"- Shell script generated: `{report.get('shell_script_generated')}`",
        f"- systemd file written: `{report.get('systemd_file_written')}`",
        f"- crontab file written: `{report.get('crontab_file_written')}`",
        f"- Live apply: `{report.get('live_apply')}`",
        f"- Can execute live: `{report.get('can_execute_live')}`",
        f"- Apply status: `{report.get('apply_status')}`",
        f"- Evidence pack breach: `{report.get('evidence_pack_breach')}`",
        f"- Blocked reason: `{redact_text(report.get('blocked_reason'), max_len=240)}`",
        "",
        "## Outputs",
        "",
        f"- Evidence pack: `{PACK_MD}`",
        f"- Evidence template: `{TEMPLATE_MD}`",
        f"- Review-only evidence: `{REVIEW_ONLY_MD}`",
        "",
        "## Safety",
        "",
        "- Documentation/templates only. No command execution, no live apply, no install.",
        "",
    ]
    return "\n".join(lines)


def rendered_output_texts(report: Dict[str, Any]) -> List[str]:
    return [
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        render_report_markdown(report),
        render_evidence_markdown(report),
        render_template_markdown(report),
    ]


def mark_secret_output_breach(report: Dict[str, Any]) -> Dict[str, Any]:
    if not any(detect_secret_in_text(text) for text in rendered_output_texts(report)):
        return report
    updated = dict(report)
    reasons = list(updated.get("evidence_pack_breach_reasons") if isinstance(updated.get("evidence_pack_breach_reasons"), list) else [])
    reason = "secret-like values detected in generated output"
    if reason not in reasons:
        reasons.append(reason)
    updated["evidence_pack_breach"] = True
    updated["evidence_pack_breach_reasons"] = reasons
    updated["evidence_pack_status"] = EVIDENCE_BREACH
    updated["status"] = EVIDENCE_BREACH
    updated["blocked_reason"] = reason
    summary = dict(updated.get("summary") if isinstance(updated.get("summary"), dict) else {})
    summary["evidence_pack_breach"] = True
    summary["evidence_pack_breach_reasons"] = reasons
    summary["evidence_pack_status"] = EVIDENCE_BREACH
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
        "record_type": "owner_timer_install_evidence_pack",
        "evidence_pack_status": report.get("evidence_pack_status"),
        "decision_status": report.get("decision_status"),
        "preview_status": report.get("preview_status"),
        "manual_install_allowed": report.get("manual_install_allowed"),
        "install_allowed_now": report.get("install_allowed_now"),
        "can_install_timer_now": report.get("can_install_timer_now"),
        "emergency_stop_active": report.get("emergency_stop_active"),
        "evidence_template_written": report.get("evidence_template_written"),
        "evidence_pack_breach": report.get("evidence_pack_breach"),
        "live_apply": False,
        "productive_change": False,
        "network_access": False,
    }


def write_outputs(report: Dict[str, Any]) -> Dict[str, Any]:
    report = mark_secret_output_breach(report)
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, render_report_markdown(report))
    evidence_md = render_evidence_markdown(report)
    write_text_atomic(PACK_MD, evidence_md)
    write_text_atomic(TEMPLATE_MD, render_template_markdown(report))
    write_text_atomic(REVIEW_ONLY_MD, evidence_md)
    append_jsonl(AUDIT_JSONL, [audit_record(report)])
    return report


def load_inputs() -> Tuple[Dict[str, Any], Dict[str, str]]:
    preview, preview_status = read_optional_json(INPUT_COMMAND_PREVIEW_REPORT)
    decision, decision_status = read_optional_json(INPUT_DECISION_REPORT)
    packet, packet_status = read_optional_json(INPUT_PACKET_REPORT)
    install_review, install_review_status = read_optional_json(INPUT_INSTALL_REVIEW)
    timer_draft, timer_draft_status = read_optional_json(INPUT_TIMER_DRAFT_REPORT)
    runtime_lock, runtime_lock_status = read_optional_json(INPUT_RUNTIME_LOCK)
    master, master_status = read_optional_json(INPUT_MASTER)
    owner_preview_status = read_optional_text_status(INPUT_OWNER_PREVIEW_MD)
    apply_preview_status = read_optional_text_status(INPUT_APPLY_PREVIEW_MD)
    statuses = {
        "manual_timer_install_command_preview_report": preview_status,
        "owner_timer_install_decision_gate_report": decision_status,
        "owner_manual_timer_install_packet_report": packet_status,
        "safe_draft_autonomy_timer_install_review_report": install_review_status,
        "safe_draft_autonomy_timer_draft_report": timer_draft_status,
        "autonomy_runtime_lock": runtime_lock_status,
        "sentinel_master": master_status,
        "owner_command_preview_md": owner_preview_status,
        "apply_command_preview_md": apply_preview_status,
    }
    signals = gather_signals(
        preview if isinstance(preview, dict) else None,
        decision if isinstance(decision, dict) else None,
        packet if isinstance(packet, dict) else None,
        install_review if isinstance(install_review, dict) else None,
        timer_draft if isinstance(timer_draft, dict) else None,
        runtime_lock if isinstance(runtime_lock, dict) else None,
        master if isinstance(master, dict) else None,
        owner_preview_status,
        apply_preview_status,
    )
    return signals, statuses


def _signals(**overrides: Any) -> Dict[str, Any]:
    base = {
        "preview_available": True,
        "decision_available": True,
        "packet_available": True,
        "install_review_available": True,
        "timer_draft_report_available": True,
        "runtime_lock_available": True,
        "master_available": True,
        "owner_preview_md_available": True,
        "apply_preview_md_available": True,
        "preview_status": "PREVIEW_READY_FOR_OWNER_REVIEW",
        "preview_breach": False,
        "preview_install_allowed_now": False,
        "preview_can_install_timer_now": False,
        "preview_shell_script_generated": False,
        "preview_systemd_file_written": False,
        "preview_crontab_file_written": False,
        "preview_live_apply": False,
        "preview_can_execute_live": False,
        "preview_apply_status": APPLY_NOT_APPLIED,
        "decision_status": READY_DECISION,
        "manual_install_allowed": True,
        "decision_breach": False,
        "decision_install_allowed_now": False,
        "decision_can_install_timer_now": False,
        "decision_systemd_file_written": False,
        "decision_crontab_file_written": False,
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
        {"manual_timer_install_command_preview_report": "ok"},
        timestamp="2026-06-11T00:00:00Z",
        **kwargs,
    )


def run_self_test() -> int:
    ready = _report(_signals())
    if ready["evidence_pack_status"] != EVIDENCE_READY:
        raise AssertionError("ready signals did not produce EVIDENCE_PACK_READY_FOR_OWNER_REVIEW")
    if ready["install_allowed_now"] or ready["can_install_timer_now"]:
        raise AssertionError("evidence pack must never allow install now")
    emergency = _report(_signals(emergency_stop_active=True))
    if emergency["evidence_pack_status"] != EVIDENCE_BLOCKED_EMERGENCY or emergency["evidence_pack_breach"]:
        raise AssertionError("emergency stop must block without breach")
    if _report(_signals(decision_status="reviewed_wait", manual_install_allowed=False))["evidence_pack_status"] != EVIDENCE_BLOCKED_DECISION:
        raise AssertionError("not-ready decision did not block")
    if _report(_signals(preview_breach=True))["evidence_pack_status"] != EVIDENCE_BLOCKED_PREVIEW:
        raise AssertionError("preview breach did not block")
    if _report(_signals(packet_breach=True))["evidence_pack_status"] != EVIDENCE_BLOCKED_PACKET:
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
        if not _report(_signals(), forced_flags={key: True})["evidence_pack_breach"]:
            raise AssertionError(f"{key}=true did not breach")
    if not _report(_signals(), forced_flags={"apply_status": "applied"})["evidence_pack_breach"]:
        raise AssertionError("apply_status != not_applied did not breach")
    if not _report(_signals(preview_can_install_timer_now=True))["evidence_pack_breach"]:
        raise AssertionError("input can_install_timer_now did not breach")
    if not _report(_signals(timer_systemd_file_written=True))["evidence_pack_breach"]:
        raise AssertionError("input systemd_file_written did not breach")
    if not _report(_signals(runtime_live_apply_enabled=True))["evidence_pack_breach"]:
        raise AssertionError("input live_apply did not breach")
    if not _report(_signals(packet_apply_status="applied"))["evidence_pack_breach"]:
        raise AssertionError("input apply_status did not breach")
    if not _report(_signals(), output_paths=["drafts/owner/install.sh"])["evidence_pack_breach"]:
        raise AssertionError("executable install artifact did not breach")
    if not _report(_signals(), output_paths=["/etc/systemd/system/x.service"])["evidence_pack_breach"]:
        raise AssertionError("systemd output path did not breach")
    if not _report(_signals(), output_paths=["/tmp/evidence.json"])["evidence_pack_breach"]:
        raise AssertionError("outside output path did not breach")
    if not _report(_signals(), output_texts=["token=0123456789abcdef"])["evidence_pack_breach"]:
        raise AssertionError("secret-like output did not breach")

    missing = _report(_signals(preview_available=False, decision_available=False, packet_available=False, install_review_available=False, timer_draft_report_available=False))
    if missing["evidence_pack_breach"]:
        raise AssertionError("missing inputs must not breach")

    rendered = render_evidence_markdown(ready)
    if EVIDENCE_COMMENT not in rendered:
        raise AssertionError("evidence template must contain review-only comment")
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

    print("owner-timer-install-evidence-pack self-tests: OK")
    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build review-only owner timer install evidence pack; no install, no live apply."
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
        "Owner Timer Install Evidence Pack: "
        f"status={report.get('evidence_pack_status')}, "
        f"decision={report.get('decision_status')}, "
        f"preview={report.get('preview_status')}, "
        f"manual_allowed={report.get('manual_install_allowed')}, "
        f"install_allowed={report.get('install_allowed_now')}, "
        f"can_install={report.get('can_install_timer_now')}, "
        f"emergency_stop={report.get('emergency_stop_active')}, "
        f"breach={report.get('evidence_pack_breach')}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
