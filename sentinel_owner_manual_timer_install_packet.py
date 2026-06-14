#!/usr/bin/env python3
"""Sentinel Owner Manual Timer Install Packet Builder (Phase 4.1).

Assembles a complete, owner-facing *manual* install packet from the Phase 4.0
install-readiness review, the Phase 3.9 timer draft pack, and the Phase 3.8
scheduler plan. It gives Pierre a safe, step-by-step REVIEW guide in case he
later, deliberately and manually, decides to install the draft-only timer.

This is NOT an installation, NOT an active timer, NOT an apply mechanism. It
only produces documentation and checklists (Markdown/text). It never executes
systemctl, never writes a shell script, never writes to /etc/systemd/system or
any crontab, and applies nothing.

Hard safety guarantees (enforced structurally):
- No live changes; no live-apply function exists in this module.
- No timer installed/enabled; no systemctl executed; no .sh / executable file.
- Nothing written to /etc/systemd/system or any crontab location.
- Never edits WordPress files, .htaccess, Cloudflare rules, or Nginx config.
- No external writes, no network access, no WordPress login, no API calls.
- No secrets/cookies/auth values are stored or printed.
- apply_status stays not_applied; can_execute_live stays false;
  can_install_timer_now stays false; install_allowed_now stays false;
  timer_installation_status stays not_installed.
- Writes are confined to drafts/owner, drafts/apply, reports/latest, audit.
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

INPUT_INSTALL_REVIEW = PROJECT_DIR / "reports/latest/safe-draft-autonomy-timer-install-review-report.json"
INPUT_TIMER_DRAFT_REPORT = PROJECT_DIR / "reports/latest/safe-draft-autonomy-timer-draft-report.json"
INPUT_SCHEDULER_PLAN = PROJECT_DIR / "reports/latest/safe-draft-autonomy-scheduler-plan.json"
INPUT_RUNTIME_LOCK = PROJECT_DIR / "config/autonomy-runtime-lock.json"
INPUT_VERIFIER_REPORT = PROJECT_DIR / "reports/latest/safe-draft-autonomy-verifier-report.json"
INPUT_RUNNER_REPORT = PROJECT_DIR / "reports/latest/safe-draft-autonomy-runner-report.json"
INPUT_MASTER = PROJECT_DIR / "reports/latest/sentinel-master-report.json"

SERVICE_DRAFT = PROJECT_DIR / "drafts/apply/sentinel-safe-draft-autonomy.service.draft"
TIMER_DRAFT = PROJECT_DIR / "drafts/apply/sentinel-safe-draft-autonomy.timer.draft"
INSTALL_REVIEW_MD = PROJECT_DIR / "drafts/apply/sentinel-safe-draft-autonomy-install-review.md"
ROLLBACK_REVIEW_MD = PROJECT_DIR / "drafts/apply/sentinel-safe-draft-autonomy-rollback-review.md"

REPORT_JSON = PROJECT_DIR / "reports/latest/owner-manual-timer-install-packet-report.json"
REPORT_MD = PROJECT_DIR / "reports/latest/owner-manual-timer-install-packet-report.md"
PACKET_MD = PROJECT_DIR / "drafts/owner/owner-manual-timer-install-packet.md"
FINAL_CHECKLIST_MD = PROJECT_DIR / "drafts/owner/owner-manual-timer-install-final-checklist.md"
REVIEW_ONLY_MD = PROJECT_DIR / "drafts/apply/owner-manual-timer-install-review-only.md"
AUDIT_JSONL = PROJECT_DIR / "audit/owner-manual-timer-install-packet.jsonl"

# Where THIS module may write its own outputs.
ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "drafts/owner",
    PROJECT_DIR / "drafts/apply",
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "audit",
)

# Output files this module is allowed to produce (Markdown/JSON/JSONL only).
ALLOWED_OUTPUT_PATHS = (
    REPORT_JSON,
    REPORT_MD,
    PACKET_MD,
    FINAL_CHECKLIST_MD,
    REVIEW_ONLY_MD,
    AUDIT_JSONL,
)
# Suffixes that would indicate an executable/automation artifact (forbidden).
FORBIDDEN_OUTPUT_SUFFIXES = (".sh", ".bash", ".zsh", ".service", ".timer", ".py", ".bin", ".run")

SCHEMA_VERSION = "owner-manual-timer-install-packet-4.1"

APPLY_NOT_APPLIED = "not_applied"
TIMER_NOT_INSTALLED = "not_installed"
DRAFT_BANNER = "DRAFT ONLY - DO NOT COPY WITHOUT OWNER REVIEW"

# Packet status vocabulary (Phase 4.1).
PACKET_READY = "PACKET_READY_FOR_OWNER_REVIEW"
PACKET_BLOCKED_EMERGENCY = "PACKET_BLOCKED_BY_EMERGENCY_STOP"
PACKET_BLOCKED_INSTALL_REVIEW = "PACKET_BLOCKED_BY_INSTALL_REVIEW_BREACH"
PACKET_BLOCKED_TIMER_DRAFT = "PACKET_BLOCKED_BY_TIMER_DRAFT_BREACH"
PACKET_BLOCKED_RUNNER_VERIFIER = "PACKET_BLOCKED_BY_RUNNER_OR_VERIFIER_BREACH"
PACKET_NOT_READY_MISSING = "PACKET_NOT_READY_MISSING_INPUTS"
PACKET_BREACH = "PACKET_BREACH"

FORBIDDEN_INSTALL_PATH_TOKENS = [
    "/etc/systemd",
    "systemd/system",
    "/lib/systemd",
    "/usr/lib/systemd",
    "/etc/cron",
    "cron.d",
    "crontab",
]

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


def redact_text(value: Any, default: str = "-", max_len: int = 500) -> str:
    if value is None:
        return default
    text = str(value).replace("\r", " ").strip()
    text = SECRET_ASSIGNMENT_RE.sub("<redacted>", text)
    text = LONG_HEX_RE.sub("<redacted-hex>", text)
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text or default


def detect_secret_in_text(text: str) -> bool:
    if not text:
        return False
    if ENV_SECRET_RE.search(text):
        return True
    if SECRET_ASSIGNMENT_RE.search(text):
        return True
    if LONG_HEX_RE.search(text):
        return True
    return False


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
        raise ValueError(f"Refusing to write outside allowed packet roots: {path}")
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


def read_json_status(path: Path) -> Tuple[Optional[Any], str]:
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


def draft_available(path: Path) -> bool:
    try:
        return path.exists() and path.is_file() and within_allowed_roots(path)
    except OSError:
        return False


def _as_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return bool(value)


def gather_signals(
    install_review: Optional[Dict[str, Any]],
    timer_report: Optional[Dict[str, Any]],
    scheduler: Optional[Dict[str, Any]],
    lock: Optional[Dict[str, Any]],
    verifier: Optional[Dict[str, Any]],
    runner: Optional[Dict[str, Any]],
    master: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    install_review = install_review if isinstance(install_review, dict) else {}
    timer_report = timer_report if isinstance(timer_report, dict) else {}
    scheduler = scheduler if isinstance(scheduler, dict) else {}
    lock = lock if isinstance(lock, dict) else {}
    verifier = verifier if isinstance(verifier, dict) else {}
    runner = runner if isinstance(runner, dict) else {}
    master = master if isinstance(master, dict) else {}

    review_summary = install_review.get("summary") if isinstance(install_review.get("summary"), dict) else {}
    timer_summary = timer_report.get("summary") if isinstance(timer_report.get("summary"), dict) else {}
    sched_summary = scheduler.get("summary") if isinstance(scheduler.get("summary"), dict) else {}
    runner_summary = runner.get("summary") if isinstance(runner.get("summary"), dict) else {}
    verifier_summary = verifier.get("summary") if isinstance(verifier.get("summary"), dict) else {}
    master_lock = master.get("autonomy_runtime_lock") if isinstance(master.get("autonomy_runtime_lock"), dict) else {}
    master_autonomy = master.get("autonomy_policy") if isinstance(master.get("autonomy_policy"), dict) else {}

    install_reviewer_breach = _as_bool(review_summary.get("install_reviewer_breach")) or _as_bool(install_review.get("install_reviewer_breach"))
    timer_draft_breach = _as_bool(timer_summary.get("timer_draft_breach")) or _as_bool(timer_report.get("timer_draft_breach"))
    scheduler_breach = _as_bool(sched_summary.get("scheduler_breach")) or _as_bool(scheduler.get("scheduler_breach"))
    runner_breach = _as_bool(runner_summary.get("runner_breach")) or _as_bool(runner.get("runner_breach"))
    verifier_breach = _as_bool(verifier_summary.get("verifier_breach")) or _as_bool(verifier.get("verifier_breach"))
    runtime_lock_breach = _as_bool(master_lock.get("runtime_lock_breach")) or _as_bool(lock.get("runtime_lock_breach"))
    autonomy_policy_breach = _as_bool(master_autonomy.get("policy_breach"))

    master_overall = str(master.get("overall_master_status") or "").strip().upper()
    critical_with_autonomy_breach = master_overall == "CRITICAL" and (
        autonomy_policy_breach or runner_breach or verifier_breach or scheduler_breach or timer_draft_breach or install_reviewer_breach
    )

    return {
        "install_review_available": bool(install_review),
        "timer_draft_report_available": bool(timer_report),
        "scheduler_plan_available": bool(scheduler),
        "install_review_status": redact_text(install_review.get("install_review_status"), default="NOT_AVAILABLE", max_len=80),
        "install_reviewer_breach": install_reviewer_breach,
        "safe_checks_passed_count": int(review_summary.get("safe_checks_passed_count") or install_review.get("safe_checks_passed_count") or 0),
        "safe_checks_failed_count": int(review_summary.get("safe_checks_failed_count") or install_review.get("safe_checks_failed_count") or 0),
        "review_can_install_timer_now": _as_bool(install_review.get("can_install_timer_now")),
        "review_can_execute_live": _as_bool(install_review.get("can_execute_live")),
        "timer_installation_status": redact_text(timer_report.get("timer_installation_status"), default=TIMER_NOT_INSTALLED, max_len=40),
        "timer_can_install_timer_now": _as_bool(timer_report.get("can_install_timer_now")),
        "timer_can_execute_live": _as_bool(timer_report.get("can_execute_live")),
        "timer_live_apply": _as_bool(timer_report.get("live_apply")),
        "timer_apply_status": redact_text(timer_report.get("apply_status"), default=APPLY_NOT_APPLIED, max_len=40),
        "systemd_file_written": _as_bool(timer_report.get("systemd_file_written")),
        "crontab_file_written": _as_bool(timer_report.get("crontab_file_written")),
        "timer_draft_breach": timer_draft_breach,
        "scheduler_breach": scheduler_breach,
        "runner_breach": runner_breach,
        "verifier_breach": verifier_breach,
        "runtime_lock_breach": runtime_lock_breach,
        "autonomy_policy_breach": autonomy_policy_breach,
        "emergency_stop": _as_bool(lock.get("emergency_stop"), True),
        "owner_disable_switch": _as_bool(lock.get("owner_disable_switch")),
        "live_apply_enabled": _as_bool(lock.get("live_apply_enabled")),
        "autonomy_enabled": _as_bool(lock.get("autonomy_enabled")),
        "draft_only_enabled": _as_bool(lock.get("draft_only_enabled")),
        "validation_only_enabled": _as_bool(lock.get("validation_only_enabled")),
        "last_runner_status": redact_text(runner.get("runner_status"), max_len=80),
        "last_verifier_status": redact_text(verifier.get("verifier_status"), max_len=80),
        "scheduler_status": redact_text(scheduler.get("scheduler_status"), max_len=80),
        "website_status": redact_text(master.get("website_status"), max_len=40),
        "master_overall_status": redact_text(master.get("overall_master_status"), max_len=40),
        "master_action_status": redact_text(master.get("action_status"), max_len=40),
        "critical_with_autonomy_breach": critical_with_autonomy_breach,
        "service_draft_available": draft_available(SERVICE_DRAFT),
        "timer_draft_available": draft_available(TIMER_DRAFT),
        "install_review_md_available": draft_available(INSTALL_REVIEW_MD),
        "rollback_review_md_available": draft_available(ROLLBACK_REVIEW_MD),
    }


def do_not_proceed_conditions(signals: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [
        {"condition": "emergency_stop=true", "active": signals["emergency_stop"]},
        {"condition": "runtime_lock_breach=true", "active": signals["runtime_lock_breach"] or signals["autonomy_policy_breach"]},
        {"condition": "verifier_breach=true", "active": signals["verifier_breach"]},
        {"condition": "runner_breach=true", "active": signals["runner_breach"]},
        {"condition": "scheduler_breach=true", "active": signals["scheduler_breach"]},
        {"condition": "timer_draft_breach=true", "active": signals["timer_draft_breach"]},
        {"condition": "install_reviewer_breach=true", "active": signals["install_reviewer_breach"]},
        {"condition": "live_apply=true", "active": signals["timer_live_apply"] or signals["live_apply_enabled"]},
        {"condition": "can_execute_live=true", "active": signals["timer_can_execute_live"] or signals["review_can_execute_live"]},
        {"condition": "can_install_timer_now=true", "active": signals["timer_can_install_timer_now"] or signals["review_can_install_timer_now"]},
        {"condition": "Website/Server CRITICAL with autonomy breach", "active": signals["critical_with_autonomy_breach"]},
        {"condition": "Owner unsure / not manually reviewed", "active": True},
    ]


def install_preconditions(signals: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [
        {"precondition": "emergency_stop is false", "met": not signals["emergency_stop"]},
        {"precondition": "autonomy_enabled is true", "met": signals["autonomy_enabled"]},
        {"precondition": "draft_only_enabled is true", "met": signals["draft_only_enabled"]},
        {"precondition": "validation_only_enabled is true", "met": signals["validation_only_enabled"]},
        {"precondition": "live_apply_enabled is false", "met": not signals["live_apply_enabled"]},
        {"precondition": "owner_disable_switch is true", "met": signals["owner_disable_switch"]},
        {"precondition": "install_reviewer_breach is false", "met": not signals["install_reviewer_breach"]},
        {"precondition": "timer_draft_breach is false", "met": not signals["timer_draft_breach"]},
        {"precondition": "scheduler_breach is false", "met": not signals["scheduler_breach"]},
        {"precondition": "runner_breach is false", "met": not signals["runner_breach"]},
        {"precondition": "verifier_breach is false", "met": not signals["verifier_breach"]},
        {"precondition": "install_review_status is INSTALL_REVIEW_READY", "met": signals["install_review_status"] == "INSTALL_REVIEW_READY"},
        {"precondition": "all required drafts/reports are present", "met": bool(
            signals["install_review_available"]
            and signals["timer_draft_report_available"]
            and signals["scheduler_plan_available"]
            and signals["service_draft_available"]
            and signals["timer_draft_available"]
        )},
    ]


def compute_packet_breach(
    signals: Dict[str, Any],
    install_allowed_now: bool,
    output_paths: List[str],
    output_texts: Optional[List[str]] = None,
) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    if install_allowed_now:
        reasons.append("install_allowed_now is true")
    if signals["timer_can_install_timer_now"] or signals["review_can_install_timer_now"]:
        reasons.append("can_install_timer_now is true")
    if signals["timer_installation_status"] != TIMER_NOT_INSTALLED:
        reasons.append("timer_installation_status != not_installed")
    if signals["systemd_file_written"]:
        reasons.append("systemd_file_written is true")
    if signals["crontab_file_written"]:
        reasons.append("crontab_file_written is true")
    if signals["timer_live_apply"] or signals["live_apply_enabled"]:
        reasons.append("live_apply is true")
    if signals["timer_can_execute_live"] or signals["review_can_execute_live"]:
        reasons.append("can_execute_live is true")
    if signals["timer_apply_status"] != APPLY_NOT_APPLIED:
        reasons.append("apply_status != not_applied")
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


def determine_packet_status(signals: Dict[str, Any], breach: bool) -> Tuple[str, str]:
    if breach:
        return PACKET_BREACH, "a real security violation was detected; packet cannot be marked review-ready."
    inputs_present = bool(
        signals["install_review_available"]
        and signals["timer_draft_report_available"]
        and signals["scheduler_plan_available"]
        and signals["service_draft_available"]
        and signals["timer_draft_available"]
    )
    if signals["emergency_stop"]:
        return PACKET_BLOCKED_EMERGENCY, "emergency_stop is active; packet is review-blocked (not a breach)."
    if signals["install_reviewer_breach"]:
        return PACKET_BLOCKED_INSTALL_REVIEW, "install reviewer reported a breach."
    if signals["timer_draft_breach"]:
        return PACKET_BLOCKED_TIMER_DRAFT, "timer draft pack reported a breach."
    if signals["runner_breach"] or signals["verifier_breach"]:
        return PACKET_BLOCKED_RUNNER_VERIFIER, "runner or verifier reported a breach."
    if not inputs_present:
        return PACKET_NOT_READY_MISSING, "one or more required inputs (reports/drafts) are missing."
    return PACKET_READY, "-"


def owner_final_checklist() -> List[str]:
    return [
        "Ich habe den Code und alle Draft-Inhalte selbst gelesen.",
        "Der DRAFT ONLY Banner ist in Service- und Timer-Draft vorhanden.",
        "Alle ExecStart-Zeilen im Service-Draft sind auskommentiert und referenzieren nur die sichere lokale Sequenz.",
        "Runtime Lock geprueft: emergency_stop=false und draft-only ist bewusst aktiviert.",
        "Verifier, Runner und Scheduler melden keinen Breach.",
        "Install Reviewer Status ist INSTALL_REVIEW_READY ohne Breach.",
        "Ein Backup-/Recovery-Punkt existiert.",
        "Ich installiere bewusst und manuell, nicht automatisiert, und kann jederzeit emergency-stop setzen.",
        "Mir ist klar, dass dieses Modul nichts installiert und alle Befehle nur Review-Text sind.",
    ]


def render_packet_markdown(report: Dict[str, Any]) -> str:
    signals = report.get("signals") if isinstance(report.get("signals"), dict) else {}
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    preconditions = report.get("install_preconditions") if isinstance(report.get("install_preconditions"), list) else []
    do_not = report.get("do_not_proceed_conditions") if isinstance(report.get("do_not_proceed_conditions"), list) else []
    lines = [
        "# Owner Manual Timer Install Packet (REVIEW ONLY)",
        "",
        f"- Generated (UTC): `{report.get('generated_at_utc')}`",
        f"- Packet status: `{report.get('packet_status')}`",
        f"- install_allowed_now: `{report.get('install_allowed_now')}` (immer false in dieser Phase)",
        f"- can_install_timer_now: `{report.get('can_install_timer_now')}`",
        f"- timer_installation_status: `{report.get('timer_installation_status')}`",
        f"- emergency_stop_active: `{report.get('emergency_stop_active')}`",
        f"- packet_breach: `{summary.get('packet_breach')}`",
        "",
        "> **Wichtig:** Nur fuer eine spaetere, bewusste **manuelle** Owner-Entscheidung. "
        "Nicht automatisch ausfuehren. Nicht kopieren, solange Emergency Stop aktiv ist. "
        "Kein Live-Apply. Nur Draft-/Report-/Validation-only. Dieses Packet installiert nichts; "
        "alle systemctl-Befehle sind reiner Review-Text und stehen in keinem ausfuehrbaren Script.",
        "",
        "## 1. Current Safety Status",
        "",
        f"- Install review status: `{signals.get('install_review_status')}`",
        f"- Safe checks passed/failed: `{signals.get('safe_checks_passed_count')}` / `{signals.get('safe_checks_failed_count')}`",
        f"- emergency_stop: `{signals.get('emergency_stop')}`",
        f"- runtime_lock_breach: `{signals.get('runtime_lock_breach')}`",
        f"- verifier_breach: `{signals.get('verifier_breach')}`",
        f"- runner_breach: `{signals.get('runner_breach')}`",
        f"- scheduler_breach: `{signals.get('scheduler_breach')}`",
        f"- timer_draft_breach: `{signals.get('timer_draft_breach')}`",
        f"- install_reviewer_breach: `{signals.get('install_reviewer_breach')}`",
        f"- master_overall_status: `{signals.get('master_overall_status')}`",
        "",
        "## 2. Install Preconditions",
        "",
    ]
    for item in preconditions:
        if isinstance(item, dict):
            mark = "x" if item.get("met") else " "
            lines.append(f"- [{mark}] {redact_text(item.get('precondition'), max_len=160)}")
    lines.extend(
        [
            "",
            "## 3. Files to Review",
            "",
            f"- Service draft: `{SERVICE_DRAFT}` (available: `{signals.get('service_draft_available')}`)",
            f"- Timer draft: `{TIMER_DRAFT}` (available: `{signals.get('timer_draft_available')}`)",
            f"- Install review: `{INSTALL_REVIEW_MD}` (available: `{signals.get('install_review_md_available')}`)",
            f"- Rollback review: `{ROLLBACK_REVIEW_MD}` (available: `{signals.get('rollback_review_md_available')}`)",
            "",
            "## 4. Manual Installation Steps (REVIEW TEXT ONLY — nicht ausfuehren, nicht in ein Script kopieren)",
            "",
            "```text",
            "# REVIEW ONLY — vom Owner bewusst und manuell auszufuehren; dieses Modul fuehrt nichts davon aus.",
            "# 0. Voraussetzung: emergency_stop=false und draft-only aktiviert.",
            "#   python3 sentinel_autonomy_runtime_lock.py status",
            "#   python3 sentinel_autonomy_runtime_lock.py enable-draft-only",
            "# 1. Unit-Drafts pruefen und (manuell) kopieren:",
            "#   sudo cp drafts/apply/sentinel-safe-draft-autonomy.service.draft \\",
            "#       /etc/systemd/system/sentinel-safe-draft-autonomy.service",
            "#   sudo cp drafts/apply/sentinel-safe-draft-autonomy.timer.draft \\",
            "#       /etc/systemd/system/sentinel-safe-draft-autonomy.timer",
            "# 2. systemd neu laden und Timer aktivieren:",
            "#   sudo systemctl daemon-reload",
            "#   sudo systemctl enable --now sentinel-safe-draft-autonomy.timer",
            "```",
            "",
            "## 5. Post-Install Verification Steps",
            "",
            "```text",
            "# REVIEW ONLY:",
            "#   systemctl status sentinel-safe-draft-autonomy.timer",
            "#   python3 sentinel_safe_draft_autonomy_runner.py",
            "#   python3 sentinel_safe_draft_autonomy_verifier.py",
            "#   python3 sentinel_master.py",
            "```",
            "",
            "## 6. Emergency Stop Procedure",
            "",
            "```text",
            "# REVIEW ONLY — bei jedem Zweifel sofort:",
            "#   python3 sentinel_autonomy_runtime_lock.py emergency-stop",
            "#   sudo systemctl disable --now sentinel-safe-draft-autonomy.timer",
            "```",
            "",
            "## 7. Rollback Procedure",
            "",
            "```text",
            "# REVIEW ONLY:",
            "#   sudo systemctl disable --now sentinel-safe-draft-autonomy.timer",
            "#   sudo systemctl stop sentinel-safe-draft-autonomy.service",
            "#   sudo rm -f /etc/systemd/system/sentinel-safe-draft-autonomy.service",
            "#   sudo rm -f /etc/systemd/system/sentinel-safe-draft-autonomy.timer",
            "#   sudo systemctl daemon-reload",
            "#   python3 sentinel_autonomy_runtime_lock.py emergency-stop",
            "#   python3 sentinel_safe_draft_autonomy_verifier.py && python3 sentinel_master.py",
            "```",
            "",
            "## 8. Do Not Proceed Conditions",
            "",
        ]
    )
    for item in do_not:
        if isinstance(item, dict):
            mark = "ACTIVE" if item.get("active") else "ok"
            lines.append(f"- `{mark}` — {redact_text(item.get('condition'), max_len=160)}")
    lines.extend(["", "## 9. Owner Final Checklist", ""])
    for item in report.get("owner_final_checklist", []):
        lines.append(f"- [ ] {redact_text(item, max_len=200)}")
    lines.extend(
        [
            "",
            "## Sicherheitsgrenzen",
            "",
            "- Dieses Modul installiert nichts, fuehrt kein systemctl aus, erzeugt keine .sh-/Unit-/Cron-Datei.",
            "- Keine Live-Aenderungen, keine Live-Apply-Funktion, kein Netzwerk, keine API, keine Secrets.",
            "- `apply_status=not_applied`, `can_execute_live=false`, `can_install_timer_now=false`, "
            "`install_allowed_now=false`, `timer_installation_status=not_installed`.",
            "- Schreibzugriff nur unter drafts/owner, drafts/apply, reports/latest, audit.",
            f"- {DRAFT_BANNER}.",
            "",
        ]
    )
    return "\n".join(lines)


def render_final_checklist_markdown(report: Dict[str, Any]) -> str:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    lines = [
        "# Owner Manual Timer Install — Final Checklist (REVIEW ONLY)",
        "",
        f"- Generated (UTC): `{report.get('generated_at_utc')}`",
        f"- Packet status: `{report.get('packet_status')}`",
        f"- install_allowed_now: `{report.get('install_allowed_now')}`",
        f"- emergency_stop_active: `{report.get('emergency_stop_active')}`",
        f"- packet_breach: `{summary.get('packet_breach')}`",
        "",
        "> Diese Checkliste installiert nichts. Erst abhaken, wenn jede Zeile bewusst geprueft wurde.",
        "",
    ]
    for item in report.get("owner_final_checklist", []):
        lines.append(f"- [ ] {redact_text(item, max_len=200)}")
    lines.extend(
        [
            "",
            f"- {DRAFT_BANNER}.",
            "",
        ]
    )
    return "\n".join(lines)


def render_review_only_markdown(report: Dict[str, Any]) -> str:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    do_not = report.get("do_not_proceed_conditions") if isinstance(report.get("do_not_proceed_conditions"), list) else []
    active = [d for d in do_not if isinstance(d, dict) and d.get("active")]
    lines = [
        "# Owner Manual Timer Install — Review Only Summary",
        "",
        f"- Generated (UTC): `{report.get('generated_at_utc')}`",
        f"- Packet status: `{report.get('packet_status')}`",
        f"- install_allowed_now: `{report.get('install_allowed_now')}`",
        f"- can_install_timer_now: `{report.get('can_install_timer_now')}`",
        f"- timer_installation_status: `{report.get('timer_installation_status')}`",
        f"- Blocked reason: `{redact_text(report.get('blocked_reason'), max_len=200)}`",
        f"- packet_breach: `{summary.get('packet_breach')}`",
        "",
        "## Aktive Do-Not-Proceed-Bedingungen",
        "",
    ]
    if active:
        for item in active:
            lines.append(f"- `ACTIVE` — {redact_text(item.get('condition'), max_len=160)}")
    else:
        lines.append("- (keine aktiv)")
    lines.extend(
        [
            "",
            "## Hinweis",
            "",
            "- Review-only. Keine Installation, kein systemctl, keine echte Unit-/Cron-/.sh-Datei.",
            f"- {DRAFT_BANNER}.",
            "",
        ]
    )
    return "\n".join(lines)


def render_report_markdown(report: Dict[str, Any]) -> str:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    signals = report.get("signals") if isinstance(report.get("signals"), dict) else {}
    lines = [
        "# Owner Manual Timer Install Packet Report",
        "",
        f"- Generated (UTC): `{report.get('generated_at_utc')}`",
        f"- Status: `{report.get('status')}`",
        f"- Packet status: `{report.get('packet_status')}`",
        f"- Owner review required: `{report.get('owner_review_required')}`",
        f"- install_allowed_now: `{report.get('install_allowed_now')}`",
        f"- can_install_timer_now: `{report.get('can_install_timer_now')}`",
        f"- timer_installation_status: `{report.get('timer_installation_status')}`",
        f"- emergency_stop_active: `{report.get('emergency_stop_active')}`",
        f"- install_review_status: `{report.get('install_review_status')}`",
        f"- Safe checks passed: `{report.get('safe_checks_passed_count')}`",
        f"- Safe checks failed: `{report.get('safe_checks_failed_count')}`",
        f"- packet_breach: `{summary.get('packet_breach')}`",
        f"- Blocked reason: `{redact_text(report.get('blocked_reason'), max_len=200)}`",
        "",
        "## Packet Files (review-only)",
        "",
        f"- Owner packet: `{PACKET_MD}`",
        f"- Owner final checklist: `{FINAL_CHECKLIST_MD}`",
        f"- Review-only summary: `{REVIEW_ONLY_MD}`",
        "",
        "## Do Not Proceed Conditions (active?)",
        "",
    ]
    for item in report.get("do_not_proceed_conditions", []):
        if isinstance(item, dict):
            lines.append(f"- {redact_text(item.get('condition'), max_len=160)}: `{item.get('active')}`")
    lines.extend(
        [
            "",
            "## Sicherheitsgrenzen",
            "",
            "- Nur Dokumentation/Checklisten; keine Installation, kein systemctl, keine echte Unit-/Cron-/.sh-Datei.",
            "- Keine Live-Aenderungen, keine Live-Apply-Funktion.",
            "- Keine WordPress-, .htaccess-, Cloudflare-, Nginx- oder DNS-Aenderung.",
            "- Kein WordPress-Login, keine API, kein Netzwerkzugriff, keine externen Schreibzugriffe.",
            "- Keine Secrets/Cookies/Auth speichern oder ausgeben.",
            "- `apply_status=not_applied`, `can_execute_live=false`, `can_install_timer_now=false`, "
            "`install_allowed_now=false`, `timer_installation_status=not_installed`.",
            "- Schreibzugriff nur unter drafts/owner, drafts/apply, reports/latest, audit.",
            f"- {DRAFT_BANNER}.",
            "",
        ]
    )
    return "\n".join(lines)


def build_report(
    signals: Dict[str, Any],
    input_statuses: Dict[str, str],
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    generated = generated_at or utc_now()
    # install is NEVER allowed by this module; it only documents.
    install_allowed_now = False
    output_paths = [str(path) for path in ALLOWED_OUTPUT_PATHS]
    breach, breach_reasons = compute_packet_breach(signals, install_allowed_now, output_paths)
    packet_status, blocked_reason = determine_packet_status(signals, breach)

    preconditions = install_preconditions(signals)
    do_not = do_not_proceed_conditions(signals)
    checklist = owner_final_checklist()

    status = PACKET_BREACH if breach else packet_status

    summary = {
        "packet_status": packet_status,
        "owner_review_required": True,
        "install_allowed_now": install_allowed_now,
        "can_install_timer_now": False,
        "timer_installation_status": TIMER_NOT_INSTALLED,
        "emergency_stop_active": bool(signals["emergency_stop"]),
        "install_review_status": signals["install_review_status"],
        "safe_checks_passed_count": int(signals["safe_checks_passed_count"]),
        "safe_checks_failed_count": int(signals["safe_checks_failed_count"]),
        "packet_breach": breach,
        "packet_breach_reasons": breach_reasons,
        "blocked_reason": blocked_reason,
    }

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": generated,
        "status": status,
        "packet_status": packet_status,
        "read_only": True,
        "live_apply": False,
        "live_apply_function": False,
        "timer_installed": False,
        "systemd_file_written": False,
        "crontab_file_written": False,
        "shell_script_generated": False,
        "executable_install_file_generated": False,
        "network_access": False,
        "wordpress_login": False,
        "api_access": False,
        "productive_change": False,
        "secrets_output": False,
        "apply_status": APPLY_NOT_APPLIED,
        "can_execute_live": False,
        "can_install_timer_now": False,
        "install_allowed_now": install_allowed_now,
        "timer_installation_status": TIMER_NOT_INSTALLED,
        "owner_review_required": True,
        "emergency_stop_active": bool(signals["emergency_stop"]),
        "install_review_status": signals["install_review_status"],
        "safe_checks_passed_count": int(signals["safe_checks_passed_count"]),
        "safe_checks_failed_count": int(signals["safe_checks_failed_count"]),
        "packet_breach": breach,
        "blocked_reason": blocked_reason,
        "signals": signals,
        "install_preconditions": preconditions,
        "do_not_proceed_conditions": do_not,
        "owner_final_checklist": checklist,
        "allowed_write_roots": [str(path) for path in ALLOWED_WRITE_ROOTS],
        "input_statuses": input_statuses,
        "summary": summary,
        "outputs": {
            "report_json": str(REPORT_JSON),
            "report_md": str(REPORT_MD),
            "packet_md": str(PACKET_MD),
            "final_checklist_md": str(FINAL_CHECKLIST_MD),
            "review_only_md": str(REVIEW_ONLY_MD),
            "audit_jsonl": str(AUDIT_JSONL),
        },
    }


def audit_records(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    return [
        {
            "timestamp_utc": report.get("generated_at_utc"),
            "schema_version": SCHEMA_VERSION,
            "record_type": "owner_manual_timer_install_packet",
            "packet_status": report.get("packet_status"),
            "status": report.get("status"),
            "install_allowed_now": report.get("install_allowed_now"),
            "can_install_timer_now": report.get("can_install_timer_now"),
            "timer_installation_status": report.get("timer_installation_status"),
            "emergency_stop_active": report.get("emergency_stop_active"),
            "install_review_status": report.get("install_review_status"),
            "safe_checks_passed_count": report.get("safe_checks_passed_count"),
            "safe_checks_failed_count": report.get("safe_checks_failed_count"),
            "systemd_file_written": report.get("systemd_file_written"),
            "crontab_file_written": report.get("crontab_file_written"),
            "shell_script_generated": report.get("shell_script_generated"),
            "packet_breach": summary.get("packet_breach"),
            "blocked_reason": summary.get("blocked_reason"),
            "live_apply": False,
            "productive_change": False,
            "network_access": False,
        }
    ]


def rendered_output_texts(report: Dict[str, Any]) -> List[str]:
    return [
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        render_report_markdown(report),
        render_packet_markdown(report),
        render_final_checklist_markdown(report),
        render_review_only_markdown(report),
    ]


def mark_secret_output_breach(report: Dict[str, Any]) -> Dict[str, Any]:
    texts = rendered_output_texts(report)
    if not any(detect_secret_in_text(text) for text in texts):
        return report

    updated = dict(report)
    summary = dict(updated.get("summary") if isinstance(updated.get("summary"), dict) else {})
    reasons = list(summary.get("packet_breach_reasons") if isinstance(summary.get("packet_breach_reasons"), list) else [])
    reason = "secret-like values detected in generated output"
    if reason not in reasons:
        reasons.append(reason)
    summary["packet_breach"] = True
    summary["packet_breach_reasons"] = reasons
    updated["summary"] = summary
    updated["packet_breach"] = True
    updated["status"] = PACKET_BREACH
    updated["packet_status"] = PACKET_BREACH
    updated["blocked_reason"] = "secret-like values detected in generated output"
    updated["secrets_output"] = True
    return updated


def write_outputs(report: Dict[str, Any]) -> Dict[str, Any]:
    report = mark_secret_output_breach(report)
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, render_report_markdown(report))
    write_text_atomic(PACKET_MD, render_packet_markdown(report))
    write_text_atomic(FINAL_CHECKLIST_MD, render_final_checklist_markdown(report))
    write_text_atomic(REVIEW_ONLY_MD, render_review_only_markdown(report))
    append_jsonl(AUDIT_JSONL, audit_records(report))
    return report


def load_inputs() -> Tuple[Dict[str, Any], Dict[str, str]]:
    install_review, install_review_status = read_json_status(INPUT_INSTALL_REVIEW)
    timer_report, timer_status = read_json_status(INPUT_TIMER_DRAFT_REPORT)
    scheduler, scheduler_status = read_json_status(INPUT_SCHEDULER_PLAN)
    lock, lock_status = read_json_status(INPUT_RUNTIME_LOCK)
    verifier, verifier_status = read_json_status(INPUT_VERIFIER_REPORT)
    runner, runner_status = read_json_status(INPUT_RUNNER_REPORT)
    master, master_status = read_json_status(INPUT_MASTER)
    statuses = {
        "safe_draft_autonomy_timer_install_review_report": install_review_status,
        "safe_draft_autonomy_timer_draft_report": timer_status,
        "safe_draft_autonomy_scheduler_plan": scheduler_status,
        "autonomy_runtime_lock": lock_status,
        "safe_draft_autonomy_verifier_report": verifier_status,
        "safe_draft_autonomy_runner_report": runner_status,
        "sentinel_master": master_status,
    }
    signals = gather_signals(
        install_review if isinstance(install_review, dict) else None,
        timer_report if isinstance(timer_report, dict) else None,
        scheduler if isinstance(scheduler, dict) else None,
        lock if isinstance(lock, dict) else None,
        verifier if isinstance(verifier, dict) else None,
        runner if isinstance(runner, dict) else None,
        master if isinstance(master, dict) else None,
    )
    return signals, statuses


# --------------------------------------------------------------------------- #
# Self-test
# --------------------------------------------------------------------------- #

def _ready_signals(**overrides: Any) -> Dict[str, Any]:
    base = {
        "install_review_available": True,
        "timer_draft_report_available": True,
        "scheduler_plan_available": True,
        "install_review_status": "INSTALL_REVIEW_READY",
        "install_reviewer_breach": False,
        "safe_checks_passed_count": 23,
        "safe_checks_failed_count": 0,
        "review_can_install_timer_now": False,
        "review_can_execute_live": False,
        "timer_installation_status": TIMER_NOT_INSTALLED,
        "timer_can_install_timer_now": False,
        "timer_can_execute_live": False,
        "timer_live_apply": False,
        "timer_apply_status": APPLY_NOT_APPLIED,
        "systemd_file_written": False,
        "crontab_file_written": False,
        "timer_draft_breach": False,
        "scheduler_breach": False,
        "runner_breach": False,
        "verifier_breach": False,
        "runtime_lock_breach": False,
        "autonomy_policy_breach": False,
        "emergency_stop": False,
        "owner_disable_switch": True,
        "live_apply_enabled": False,
        "autonomy_enabled": True,
        "draft_only_enabled": True,
        "validation_only_enabled": True,
        "last_runner_status": "EXECUTED",
        "last_verifier_status": "VERIFIED_SAFE",
        "scheduler_status": "SCHEDULER_PLAN_READY_FOR_OWNER_REVIEW",
        "website_status": "WARNING",
        "master_overall_status": "WARNING",
        "master_action_status": "WARNING_REVIEW",
        "critical_with_autonomy_breach": False,
        "service_draft_available": True,
        "timer_draft_available": True,
        "install_review_md_available": True,
        "rollback_review_md_available": True,
    }
    base.update(overrides)
    return base


def _report(signals, at="2026-06-11T00:00:00Z"):
    return build_report(signals, {"safe_draft_autonomy_timer_install_review_report": "ok"}, at)


def run_self_test() -> int:
    # 1) Ready, no breach, install never allowed.
    ready = _report(_ready_signals())
    if ready["packet_status"] != PACKET_READY:
        raise AssertionError("ready signals did not produce PACKET_READY_FOR_OWNER_REVIEW")
    if ready["summary"]["packet_breach"]:
        raise AssertionError("clean packet must not breach")
    if ready["install_allowed_now"] or ready["can_install_timer_now"]:
        raise AssertionError("install must never be allowed by this module")
    # Owner-unsure do-not-proceed condition is always present/active.
    if not any(c["condition"].startswith("Owner unsure") and c["active"] for c in ready["do_not_proceed_conditions"]):
        raise AssertionError("owner-unsure do-not-proceed condition must always be active")

    # 2) Emergency stop blocks but is NOT a breach.
    es = _report(_ready_signals(emergency_stop=True))
    if es["packet_status"] != PACKET_BLOCKED_EMERGENCY:
        raise AssertionError("emergency stop did not block the packet")
    if es["summary"]["packet_breach"]:
        raise AssertionError("emergency stop must not be a breach")

    # 3) Blocking statuses.
    if _report(_ready_signals(install_reviewer_breach=True))["packet_status"] != PACKET_BLOCKED_INSTALL_REVIEW:
        raise AssertionError("install_reviewer_breach did not block correctly")
    if _report(_ready_signals(timer_draft_breach=True))["packet_status"] != PACKET_BLOCKED_TIMER_DRAFT:
        raise AssertionError("timer_draft_breach did not block correctly")
    if _report(_ready_signals(runner_breach=True))["packet_status"] != PACKET_BLOCKED_RUNNER_VERIFIER:
        raise AssertionError("runner_breach did not block correctly")
    if _report(_ready_signals(verifier_breach=True))["packet_status"] != PACKET_BLOCKED_RUNNER_VERIFIER:
        raise AssertionError("verifier_breach did not block correctly")

    # 4) Missing inputs -> NOT_READY_MISSING_INPUTS, no breach.
    miss = _report(_ready_signals(service_draft_available=False))
    if miss["packet_status"] != PACKET_NOT_READY_MISSING:
        raise AssertionError("missing input did not yield NOT_READY_MISSING_INPUTS")
    if miss["summary"]["packet_breach"]:
        raise AssertionError("missing input must not be a breach")

    # 5) Breach signals.
    if not _report(_ready_signals(timer_can_install_timer_now=True))["packet_breach"]:
        raise AssertionError("can_install_timer_now did not breach")
    if not _report(_ready_signals(timer_installation_status="installed"))["packet_breach"]:
        raise AssertionError("installed status did not breach")
    if not _report(_ready_signals(systemd_file_written=True))["packet_breach"]:
        raise AssertionError("systemd_file_written did not breach")
    if not _report(_ready_signals(crontab_file_written=True))["packet_breach"]:
        raise AssertionError("crontab_file_written did not breach")
    if not _report(_ready_signals(timer_live_apply=True))["packet_breach"]:
        raise AssertionError("live_apply did not breach")
    if not _report(_ready_signals(timer_can_execute_live=True))["packet_breach"]:
        raise AssertionError("can_execute_live did not breach")
    if not _report(_ready_signals(timer_apply_status="applied"))["packet_breach"]:
        raise AssertionError("apply_status change did not breach")

    # install_allowed_now=true forced -> breach.
    forced_breach, _ = compute_packet_breach(_ready_signals(), True, [str(REPORT_JSON)])
    if not forced_breach:
        raise AssertionError("install_allowed_now=true did not breach")

    # 6) Output-path breaches: shell script / executable / forbidden path.
    if not compute_packet_breach(_ready_signals(), False, ["drafts/owner/install.sh"])[0]:
        raise AssertionError("shell script output did not breach")
    if not compute_packet_breach(_ready_signals(), False, ["drafts/apply/sentinel.timer"])[0]:
        raise AssertionError("executable unit output did not breach")
    if not compute_packet_breach(_ready_signals(), False, ["/etc/systemd/system/x.conf"])[0]:
        raise AssertionError("systemd path output did not breach")
    if not compute_packet_breach(_ready_signals(), False, ["/tmp/outside.md"])[0]:
        raise AssertionError("outside-root output did not breach")
    if not compute_packet_breach(
        _ready_signals(),
        False,
        [str(REPORT_JSON)],
        ["token=0123456789abcdef"],
    )[0]:
        raise AssertionError("secret-like output did not breach")

    # 7) Default real output paths are all safe (markdown/json/jsonl under allowed roots).
    safe_breach, _ = compute_packet_breach(_ready_signals(), False, [str(p) for p in ALLOWED_OUTPUT_PATHS])
    if safe_breach:
        raise AssertionError("the module's own output paths must be breach-free")

    # 8) Missing everything must not crash and must default to emergency-stop block.
    empty = build_report(
        gather_signals(None, None, None, None, None, None, None),
        {"safe_draft_autonomy_timer_install_review_report": "not_available"},
        "2026-06-11T00:09:00Z",
    )
    if empty["packet_breach"]:
        raise AssertionError("missing inputs must not breach")
    if empty["packet_status"] != PACKET_BLOCKED_EMERGENCY:
        raise AssertionError("missing inputs should default to emergency-stop block")

    # 9) Rendered packet contains required sections and only review-text systemctl.
    rendered = render_packet_markdown(_report(_ready_signals()))
    for section in [
        "## 1. Current Safety Status", "## 2. Install Preconditions", "## 3. Files to Review",
        "## 4. Manual Installation Steps", "## 5. Post-Install Verification Steps",
        "## 6. Emergency Stop Procedure", "## 7. Rollback Procedure",
        "## 8. Do Not Proceed Conditions", "## 9. Owner Final Checklist",
    ]:
        if section not in rendered:
            raise AssertionError(f"packet missing section: {section}")
    for line in rendered.splitlines():
        if "systemctl" in line and not (line.lstrip().startswith("#") or line.lstrip().startswith(">") or "```" in line or "systemctl-Befehle" in line or "kein systemctl" in line):
            raise AssertionError(f"systemctl appears outside review-text: {line!r}")

    # Forbidden write paths for the module itself are rejected.
    for bad in (Path("/etc/systemd/system/x.timer"), PROJECT_DIR / "drafts/owner/install.sh"):
        try:
            assert_allowed_write(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"forbidden write path not rejected: {bad}")

    print("owner-manual-timer-install-packet self-tests: OK")
    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build the owner manual timer install packet (documentation/checklists only; no install, no live apply)."
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
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    print(
        "Owner Manual Timer Install Packet: "
        f"status={report.get('packet_status')}, "
        f"install_allowed={report.get('install_allowed_now')}, "
        f"can_install={report.get('can_install_timer_now')}, "
        f"emergency_stop={report.get('emergency_stop_active')}, "
        f"breach={summary.get('packet_breach')}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
