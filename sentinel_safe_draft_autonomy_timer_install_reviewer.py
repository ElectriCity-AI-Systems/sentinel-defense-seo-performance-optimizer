#!/usr/bin/env python3
"""Sentinel Safe Draft Autonomy Timer Install Readiness Reviewer (Phase 4.0).

Reviews the Phase 3.9 systemd service/timer DRAFTS and judges whether they
would, in principle, be review-ready for a *later, deliberate, manual* owner
installation. It installs NO timer, runs NO systemctl, copies nothing into
/etc/systemd/system, writes NO crontab, and applies nothing. It only emits an
install-readiness report plus an owner checklist.

Hard safety guarantees (enforced structurally):
- No live changes; no live-apply function exists in this module.
- No timer is installed/enabled; no systemctl is executed.
- Nothing is written to /etc/systemd/system or any crontab location.
- Never edits WordPress files, .htaccess, Cloudflare rules, or Nginx config.
- No external writes, no network access, no WordPress login, no API calls.
- No secrets/cookies/auth values are stored or printed.
- apply_status stays not_applied; can_execute_live stays false;
  can_install_timer_now stays false; timer_installation_status stays
  not_installed.
- Writes are confined to drafts/apply, drafts/owner, reports/latest, audit.
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

INPUT_TIMER_DRAFT_REPORT = PROJECT_DIR / "reports/latest/safe-draft-autonomy-timer-draft-report.json"
INPUT_SCHEDULER_PLAN = PROJECT_DIR / "reports/latest/safe-draft-autonomy-scheduler-plan.json"
INPUT_VERIFIER_REPORT = PROJECT_DIR / "reports/latest/safe-draft-autonomy-verifier-report.json"
INPUT_RUNNER_REPORT = PROJECT_DIR / "reports/latest/safe-draft-autonomy-runner-report.json"
INPUT_RUNTIME_LOCK = PROJECT_DIR / "config/autonomy-runtime-lock.json"
INPUT_MASTER = PROJECT_DIR / "reports/latest/sentinel-master-report.json"

SERVICE_DRAFT = PROJECT_DIR / "drafts/apply/sentinel-safe-draft-autonomy.service.draft"
TIMER_DRAFT = PROJECT_DIR / "drafts/apply/sentinel-safe-draft-autonomy.timer.draft"
INSTALL_REVIEW_MD = PROJECT_DIR / "drafts/apply/sentinel-safe-draft-autonomy-install-review.md"
ROLLBACK_REVIEW_MD = PROJECT_DIR / "drafts/apply/sentinel-safe-draft-autonomy-rollback-review.md"

REPORT_JSON = PROJECT_DIR / "reports/latest/safe-draft-autonomy-timer-install-review-report.json"
REPORT_MD = PROJECT_DIR / "reports/latest/safe-draft-autonomy-timer-install-review-report.md"
OWNER_CHECKLIST_MD = PROJECT_DIR / "drafts/owner/safe-draft-autonomy-timer-install-owner-checklist.md"
READINESS_MD = PROJECT_DIR / "drafts/apply/safe-draft-autonomy-timer-install-readiness.md"
AUDIT_JSONL = PROJECT_DIR / "audit/safe-draft-autonomy-timer-install-review.jsonl"

# Where THIS reviewer may write its own outputs.
ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "drafts/apply",
    PROJECT_DIR / "drafts/owner",
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "audit",
)

SCHEMA_VERSION = "safe-draft-autonomy-timer-install-review-4.0"

APPLY_NOT_APPLIED = "not_applied"
TIMER_NOT_INSTALLED = "not_installed"
DRAFT_BANNER = "DRAFT ONLY - DO NOT COPY WITHOUT OWNER REVIEW"

# Install review status vocabulary (Phase 4.0).
INSTALL_REVIEW_READY = "INSTALL_REVIEW_READY"
INSTALL_REVIEW_BLOCKED_EMERGENCY = "INSTALL_REVIEW_BLOCKED_BY_EMERGENCY_STOP"
INSTALL_REVIEW_BLOCKED_TIMER_DRAFT = "INSTALL_REVIEW_BLOCKED_BY_TIMER_DRAFT_BREACH"
INSTALL_REVIEW_BLOCKED_SCHEDULER = "INSTALL_REVIEW_BLOCKED_BY_SCHEDULER_BREACH"
INSTALL_REVIEW_BLOCKED_RUNNER_VERIFIER = "INSTALL_REVIEW_BLOCKED_BY_RUNNER_OR_VERIFIER_BREACH"
INSTALL_REVIEW_NOT_READY_MISSING = "INSTALL_REVIEW_NOT_READY_MISSING_DRAFTS"
INSTALL_REVIEW_BREACH = "INSTALL_REVIEW_BREACH"

# Tokens that must never appear as an active (uncommented) executable line.
PROHIBITED_COMMAND_TOKENS = [
    "systemctl",
    "crontab",
    "cron.d",
    "wp ",
    "curl",
    "wget",
    "ssh",
    "rsync",
    "scp",
    "git push",
    "cloudflare",
    "nginx",
    "service restart",
    "service ",
]
LIVE_APPLY_TOKENS = [
    "--confirm-apply",
    "apply-safe",
    "consolidate-apply",
    "sourcemap-apply",
    "live_apply",
    "live-apply",
    "apply_status=applied",
]
NETWORK_LOGIN_TOKENS = [
    "curl",
    "wget",
    "ssh",
    "scp",
    "rsync",
    "login",
    "wp-login",
    "cloudflare",
    " api",
    "api ",
    "http://",
    "https://",
]

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
# An Environment= assignment carrying a non-trivial value.
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
        raise ValueError(f"Refusing to write outside allowed install-review roots: {path}")


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


def read_text_safe(path: Path) -> Optional[str]:
    try:
        if not path.exists() or not path.is_file():
            return None
        if not within_allowed_roots(path):
            # Only ever read draft files that live under our allowed roots.
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _as_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return bool(value)


def active_lines(content: str) -> List[str]:
    """Return non-empty, non-comment lines of a unit/draft file."""
    lines: List[str] = []
    for raw in content.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lines.append(stripped)
    return lines


def scan_draft_content(content: Optional[str]) -> Dict[str, Any]:
    """Inspect one draft file's content for safety facts."""
    if content is None:
        return {
            "available": False,
            "has_banner": False,
            "active_forbidden_execstart": False,
            "systemctl_executable_line": False,
            "network_command": False,
            "live_apply_command": False,
            "secret_environment": False,
        }
    has_banner = DRAFT_BANNER in content
    active = active_lines(content)
    active_forbidden_execstart = False
    systemctl_line = False
    network_command = False
    live_apply_command = False
    for line in active:
        lower = line.lower()
        is_exec = lower.startswith("execstart=")
        if is_exec and any(token in lower for token in PROHIBITED_COMMAND_TOKENS + LIVE_APPLY_TOKENS):
            active_forbidden_execstart = True
        # systemctl / prohibited tokens anywhere in an active (uncommented) line.
        if "systemctl" in lower:
            systemctl_line = True
        if any(token in lower for token in NETWORK_LOGIN_TOKENS):
            network_command = True
        if any(token in lower for token in LIVE_APPLY_TOKENS):
            live_apply_command = True
    secret_environment = bool(ENV_SECRET_RE.search(content)) or detect_secret_in_text(content)
    return {
        "available": True,
        "has_banner": has_banner,
        "active_forbidden_execstart": active_forbidden_execstart,
        "systemctl_executable_line": systemctl_line,
        "network_command": network_command,
        "live_apply_command": live_apply_command,
        "secret_environment": secret_environment,
    }


def gather_signals(
    timer_report: Optional[Dict[str, Any]],
    scheduler: Optional[Dict[str, Any]],
    verifier: Optional[Dict[str, Any]],
    runner: Optional[Dict[str, Any]],
    lock: Optional[Dict[str, Any]],
    master: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    timer_report = timer_report if isinstance(timer_report, dict) else {}
    scheduler = scheduler if isinstance(scheduler, dict) else {}
    verifier = verifier if isinstance(verifier, dict) else {}
    runner = runner if isinstance(runner, dict) else {}
    lock = lock if isinstance(lock, dict) else {}
    master = master if isinstance(master, dict) else {}

    timer_summary = timer_report.get("summary") if isinstance(timer_report.get("summary"), dict) else {}
    sched_summary = scheduler.get("summary") if isinstance(scheduler.get("summary"), dict) else {}
    runner_summary = runner.get("summary") if isinstance(runner.get("summary"), dict) else {}
    verifier_summary = verifier.get("summary") if isinstance(verifier.get("summary"), dict) else {}

    timer_draft_breach = _as_bool(timer_summary.get("timer_draft_breach")) or _as_bool(timer_report.get("timer_draft_breach"))
    scheduler_breach = _as_bool(sched_summary.get("scheduler_breach")) or _as_bool(scheduler.get("scheduler_breach"))
    runner_breach = _as_bool(runner_summary.get("runner_breach")) or _as_bool(runner.get("runner_breach"))
    verifier_breach = _as_bool(verifier_summary.get("verifier_breach")) or _as_bool(verifier.get("verifier_breach"))

    return {
        "timer_draft_report_available": bool(timer_report),
        "timer_installation_status": redact_text(timer_report.get("timer_installation_status"), default=TIMER_NOT_INSTALLED, max_len=40),
        "systemd_file_written": _as_bool(timer_report.get("systemd_file_written")),
        "crontab_file_written": _as_bool(timer_report.get("crontab_file_written")),
        "timer_can_install_timer_now": _as_bool(timer_report.get("can_install_timer_now")),
        "timer_can_execute_live": _as_bool(timer_report.get("can_execute_live")),
        "timer_live_apply": _as_bool(timer_report.get("live_apply")),
        "timer_apply_status": redact_text(timer_report.get("apply_status"), default=APPLY_NOT_APPLIED, max_len=40),
        "timer_draft_breach": timer_draft_breach,
        "scheduler_breach": scheduler_breach,
        "runner_breach": runner_breach,
        "verifier_breach": verifier_breach,
        "emergency_stop": _as_bool(lock.get("emergency_stop"), True),
        "owner_disable_switch": _as_bool(lock.get("owner_disable_switch")),
        "live_apply_enabled": _as_bool(lock.get("live_apply_enabled")),
        "autonomy_enabled": _as_bool(lock.get("autonomy_enabled")),
        "draft_only_enabled": _as_bool(lock.get("draft_only_enabled")),
        "last_runner_status": redact_text(runner.get("runner_status"), max_len=80),
        "last_verifier_status": redact_text(verifier.get("verifier_status"), max_len=80),
        "scheduler_status": redact_text(scheduler.get("scheduler_status"), max_len=80),
        "master_action_status": redact_text(master.get("action_status"), max_len=40),
    }


def build_checks(
    signals: Dict[str, Any],
    service_scan: Dict[str, Any],
    timer_scan: Dict[str, Any],
    install_scan: Dict[str, Any],
    rollback_scan: Dict[str, Any],
) -> Dict[str, bool]:
    return {
        "timer_draft_report_available": bool(signals["timer_draft_report_available"]),
        "service_draft_available": bool(service_scan["available"]),
        "timer_draft_available": bool(timer_scan["available"]),
        "install_review_available": bool(install_scan["available"]),
        "rollback_review_available": bool(rollback_scan["available"]),
        "timer_installation_status_not_installed": signals["timer_installation_status"] == TIMER_NOT_INSTALLED,
        "systemd_file_written_false": not signals["systemd_file_written"],
        "crontab_file_written_false": not signals["crontab_file_written"],
        "service_draft_contains_draft_only_banner": bool(service_scan["has_banner"]),
        "timer_draft_contains_draft_only_banner": bool(timer_scan["has_banner"]),
        "no_active_forbidden_execstart": not (
            service_scan["active_forbidden_execstart"] or timer_scan["active_forbidden_execstart"]
        ),
        "no_systemctl_executable_line": not (
            service_scan["systemctl_executable_line"] or timer_scan["systemctl_executable_line"]
        ),
        "no_network_command": not (service_scan["network_command"] or timer_scan["network_command"]),
        "no_live_apply_command": not (service_scan["live_apply_command"] or timer_scan["live_apply_command"]),
        "no_secret_environment": not (
            service_scan["secret_environment"]
            or timer_scan["secret_environment"]
            or install_scan["secret_environment"]
            or rollback_scan["secret_environment"]
        ),
        "runtime_lock_owner_disable_switch_available": bool(signals["owner_disable_switch"]),
        "live_apply_disabled": not signals["live_apply_enabled"],
        "can_install_timer_now_false": not signals["timer_can_install_timer_now"],
        "can_execute_live_false": not signals["timer_can_execute_live"],
        "runner_breach_false": not signals["runner_breach"],
        "verifier_breach_false": not signals["verifier_breach"],
        "scheduler_breach_false": not signals["scheduler_breach"],
        "timer_draft_breach_false": not signals["timer_draft_breach"],
    }


# Checks whose failure is a genuine SECURITY breach (not just "not ready yet").
BREACH_CHECK_KEYS = (
    "systemd_file_written_false",
    "crontab_file_written_false",
    "no_active_forbidden_execstart",
    "no_systemctl_executable_line",
    "no_network_command",
    "no_live_apply_command",
    "no_secret_environment",
    "can_install_timer_now_false",
    "can_execute_live_false",
    "timer_installation_status_not_installed",
)


def compute_install_reviewer_breach(
    signals: Dict[str, Any],
    checks: Dict[str, bool],
    facts: Dict[str, Any],
) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    if signals["timer_can_install_timer_now"]:
        reasons.append("can_install_timer_now is true")
    if signals["timer_installation_status"] != TIMER_NOT_INSTALLED:
        reasons.append("timer_installation_status != not_installed")
    if signals["systemd_file_written"]:
        reasons.append("systemd_file_written is true")
    if signals["crontab_file_written"]:
        reasons.append("crontab_file_written is true")
    if not checks["no_active_forbidden_execstart"]:
        reasons.append("active forbidden ExecStart present in a draft")
    if not checks["no_systemctl_executable_line"]:
        reasons.append("active systemctl/executable line present in a draft")
    if not checks["no_network_command"]:
        reasons.append("network/API/login command present in a draft")
    if not checks["no_live_apply_command"]:
        reasons.append("live-apply command present in a draft")
    if not checks["no_secret_environment"]:
        reasons.append("secret-like Environment value present in a draft")
    if signals["timer_live_apply"]:
        reasons.append("timer report live_apply is true")
    if signals["timer_can_execute_live"]:
        reasons.append("timer report can_execute_live is true")
    if signals["timer_apply_status"] != APPLY_NOT_APPLIED:
        reasons.append("timer report apply_status != not_applied")
    # Our own output paths must stay inside the allowed roots.
    for raw in facts.get("output_paths", []):
        lower = str(raw).lower()
        if any(token in lower for token in FORBIDDEN_INSTALL_PATH_TOKENS):
            reasons.append(f"output path looks like a systemd/cron install path: {redact_text(raw, max_len=120)}")
        if not within_allowed_roots(Path(str(raw))):
            reasons.append(f"output path outside allowed roots: {redact_text(raw, max_len=120)}")
    return bool(reasons), reasons


def determine_status(
    signals: Dict[str, Any],
    checks: Dict[str, bool],
    breach: bool,
) -> Tuple[str, str]:
    """Return (install_review_status, blocked_reason)."""
    drafts_present = (
        checks["timer_draft_report_available"]
        and checks["service_draft_available"]
        and checks["timer_draft_available"]
        and checks["install_review_available"]
        and checks["rollback_review_available"]
    )
    # A genuine security breach takes precedence over everything except is reported
    # as the breach status.
    if breach:
        return INSTALL_REVIEW_BREACH, "a real security violation was detected in the drafts/report."
    # Emergency stop blocks (but is NOT a breach).
    if signals["emergency_stop"]:
        return INSTALL_REVIEW_BLOCKED_EMERGENCY, "emergency_stop is active; install review is blocked (not a breach)."
    if signals["timer_draft_breach"]:
        return INSTALL_REVIEW_BLOCKED_TIMER_DRAFT, "timer draft pack reported a breach."
    if signals["scheduler_breach"]:
        return INSTALL_REVIEW_BLOCKED_SCHEDULER, "scheduler plan reported a breach."
    if signals["runner_breach"] or signals["verifier_breach"]:
        return INSTALL_REVIEW_BLOCKED_RUNNER_VERIFIER, "runner or verifier reported a breach."
    if not drafts_present:
        return INSTALL_REVIEW_NOT_READY_MISSING, "one or more required drafts/reports are missing."
    return INSTALL_REVIEW_READY, "-"


def owner_checklist() -> Dict[str, List[str]]:
    return {
        "before_manual_install": [
            "Code pruefen (Diff der Module + Draft-Inhalte lesen).",
            "DRAFT ONLY Banner in Service- und Timer-Draft pruefen.",
            "ExecStart-Kommandos pruefen (nur lokale read-only/draft-only Sequenz, alle Zeilen kommentiert).",
            "Runtime Lock pruefen: emergency_stop, autonomy_enabled, draft_only_enabled, live_apply_enabled, owner_disable_switch.",
            "Verifier Status pruefen (verifier_breach=false).",
            "Runner Status pruefen (runner_breach=false).",
            "Scheduler Status pruefen (scheduler_breach=false).",
            "Backup-/Recovery-Punkt pruefen (Snapshot / Sicherung vorhanden).",
            "emergency_stop bewusst behandeln (vor Installation auf false setzen, danach wieder moeglich).",
        ],
        "after_manual_test_install_if_owner_later": [
            "systemctl status sentinel-safe-draft-autonomy.timer pruefen.",
            "Runner-Report pruefen (reports/latest/safe-draft-autonomy-runner-report.json).",
            "Verifier laufen lassen (python3 sentinel_safe_draft_autonomy_verifier.py).",
            "Master laufen lassen (python3 sentinel_master.py).",
            "Bei Problem sofort emergency-stop setzen (python3 sentinel_autonomy_runtime_lock.py emergency-stop).",
        ],
        "rollback": [
            "Timer deaktivieren (systemctl disable --now …timer).",
            "Service stoppen (systemctl stop …service).",
            "Unit-Dateien entfernen (/etc/systemd/system/sentinel-safe-draft-autonomy.{service,timer}).",
            "daemon-reload (systemctl daemon-reload).",
            "emergency-stop setzen (python3 sentinel_autonomy_runtime_lock.py emergency-stop).",
            "Master + Verifier erneut pruefen.",
        ],
    }


def build_report(
    signals: Dict[str, Any],
    service_scan: Dict[str, Any],
    timer_scan: Dict[str, Any],
    install_scan: Dict[str, Any],
    rollback_scan: Dict[str, Any],
    input_statuses: Dict[str, str],
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    generated = generated_at or utc_now()
    checks = build_checks(signals, service_scan, timer_scan, install_scan, rollback_scan)
    output_paths = [
        str(REPORT_JSON),
        str(REPORT_MD),
        str(OWNER_CHECKLIST_MD),
        str(READINESS_MD),
        str(AUDIT_JSONL),
    ]
    breach, breach_reasons = compute_install_reviewer_breach(signals, checks, {"output_paths": output_paths})
    install_review_status, blocked_reason = determine_status(signals, checks, breach)

    passed = sum(1 for value in checks.values() if value)
    failed = sum(1 for value in checks.values() if not value)

    def draft_safe(scan: Dict[str, Any]) -> bool:
        return bool(
            scan["available"]
            and not scan["active_forbidden_execstart"]
            and not scan["systemctl_executable_line"]
            and not scan["network_command"]
            and not scan["live_apply_command"]
            and not scan["secret_environment"]
        )

    service_draft_safe = draft_safe(service_scan) and bool(service_scan["has_banner"])
    timer_draft_safe = draft_safe(timer_scan) and bool(timer_scan["has_banner"])
    install_review_safe = bool(install_scan["available"]) and not install_scan["secret_environment"]
    rollback_review_safe = bool(rollback_scan["available"]) and not rollback_scan["secret_environment"]

    status = INSTALL_REVIEW_BREACH if breach else install_review_status

    summary = {
        "install_review_status": install_review_status,
        "service_draft_safe": service_draft_safe,
        "timer_draft_safe": timer_draft_safe,
        "install_review_safe": install_review_safe,
        "rollback_review_safe": rollback_review_safe,
        "owner_review_required": True,
        "can_install_timer_now": False,
        "timer_installation_status": TIMER_NOT_INSTALLED,
        "install_reviewer_breach": breach,
        "install_reviewer_breach_reasons": breach_reasons,
        "blocked_reason": blocked_reason,
        "safe_checks_passed_count": passed,
        "safe_checks_failed_count": failed,
    }

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": generated,
        "status": status,
        "install_review_status": install_review_status,
        "read_only": True,
        "live_apply": False,
        "live_apply_function": False,
        "timer_installed": False,
        "systemd_file_written": False,
        "crontab_file_written": False,
        "network_access": False,
        "wordpress_login": False,
        "api_access": False,
        "productive_change": False,
        "secrets_output": False,
        "apply_status": APPLY_NOT_APPLIED,
        "can_execute_live": False,
        "can_install_timer_now": False,
        "timer_installation_status": TIMER_NOT_INSTALLED,
        "owner_review_required": True,
        "service_draft_safe": service_draft_safe,
        "timer_draft_safe": timer_draft_safe,
        "install_review_safe": install_review_safe,
        "rollback_review_safe": rollback_review_safe,
        "install_reviewer_breach": breach,
        "blocked_reason": blocked_reason,
        "safe_checks_passed_count": passed,
        "safe_checks_failed_count": failed,
        "checks": checks,
        "signals": signals,
        "draft_scans": {
            "service_draft": service_scan,
            "timer_draft": timer_scan,
            "install_review": install_scan,
            "rollback_review": rollback_scan,
        },
        "owner_checklist": owner_checklist(),
        "allowed_write_roots": [str(path) for path in ALLOWED_WRITE_ROOTS],
        "input_statuses": input_statuses,
        "summary": summary,
        "outputs": {
            "report_json": str(REPORT_JSON),
            "report_md": str(REPORT_MD),
            "owner_checklist_md": str(OWNER_CHECKLIST_MD),
            "readiness_md": str(READINESS_MD),
            "audit_jsonl": str(AUDIT_JSONL),
        },
    }


def render_report_markdown(report: Dict[str, Any]) -> str:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    checks = report.get("checks") if isinstance(report.get("checks"), dict) else {}
    lines = [
        "# Safe Draft Autonomy Timer Install Review Report",
        "",
        f"- Generated (UTC): `{report.get('generated_at_utc')}`",
        f"- Status: `{report.get('status')}`",
        f"- Install review status: `{report.get('install_review_status')}`",
        f"- Timer installation status: `{report.get('timer_installation_status')}`",
        f"- Can install timer now: `{report.get('can_install_timer_now')}`",
        f"- Can execute live: `{report.get('can_execute_live')}`",
        f"- Service draft safe: `{summary.get('service_draft_safe')}`",
        f"- Timer draft safe: `{summary.get('timer_draft_safe')}`",
        f"- Install review safe: `{summary.get('install_review_safe')}`",
        f"- Rollback review safe: `{summary.get('rollback_review_safe')}`",
        f"- systemd file written: `{report.get('systemd_file_written')}`",
        f"- crontab file written: `{report.get('crontab_file_written')}`",
        f"- Owner review required: `{report.get('owner_review_required')}`",
        f"- Install reviewer breach: `{summary.get('install_reviewer_breach')}`",
        f"- Blocked reason: `{redact_text(report.get('blocked_reason'), max_len=200)}`",
        f"- Safe checks passed: `{summary.get('safe_checks_passed_count')}`",
        f"- Safe checks failed: `{summary.get('safe_checks_failed_count')}`",
        "",
        "## Checks",
        "",
    ]
    for key in sorted(checks):
        lines.append(f"- {key}: `{checks.get(key)}`")
    lines.extend(
        [
            "",
            "## Sicherheitsgrenzen",
            "",
            "- Nur Review/Readiness-Bewertung; kein aktiver Timer, kein systemctl, keine echte systemd-/crontab-Datei.",
            "- Keine Live-Aenderungen, keine Live-Apply-Funktion.",
            "- Keine WordPress-, .htaccess-, Cloudflare-, Nginx- oder DNS-Aenderung.",
            "- Kein WordPress-Login, keine API, kein Netzwerkzugriff, keine externen Schreibzugriffe.",
            "- Keine Secrets/Cookies/Auth speichern oder ausgeben.",
            "- `apply_status=not_applied`, `can_execute_live=false`, `can_install_timer_now=false`, "
            "`timer_installation_status=not_installed`.",
            "- Schreibzugriff nur unter drafts/apply, drafts/owner, reports/latest, audit.",
            f"- {DRAFT_BANNER}.",
            "",
        ]
    )
    return "\n".join(lines)


def render_owner_checklist_markdown(report: Dict[str, Any]) -> str:
    checklist = report.get("owner_checklist") if isinstance(report.get("owner_checklist"), dict) else {}
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    lines = [
        "# Owner Install-Readiness Checklist (DRAFT, review-only)",
        "",
        f"- Generated (UTC): `{report.get('generated_at_utc')}`",
        f"- Install review status: `{report.get('install_review_status')}`",
        f"- Install reviewer breach: `{summary.get('install_reviewer_breach')}`",
        f"- can_install_timer_now: `{report.get('can_install_timer_now')}` (immer false in dieser Phase)",
        f"- timer_installation_status: `{report.get('timer_installation_status')}`",
        "",
        "> Hinweis: Diese Checkliste installiert nichts. Eine Installation bleibt eine bewusste, "
        "manuelle Owner-Entscheidung. Alle systemctl-Befehle sind reiner Review-Text.",
        "",
        "## Vor manueller Installation",
        "",
    ]
    for item in checklist.get("before_manual_install", []):
        lines.append(f"- [ ] {redact_text(item, max_len=200)}")
    lines.extend(["", "## Nach manueller Testinstallation (falls spaeter durch Owner)", ""])
    for item in checklist.get("after_manual_test_install_if_owner_later", []):
        lines.append(f"- [ ] {redact_text(item, max_len=200)}")
    lines.extend(["", "## Rollback", ""])
    for item in checklist.get("rollback", []):
        lines.append(f"- [ ] {redact_text(item, max_len=200)}")
    lines.extend(
        [
            "",
            "## Sicherheitsgrenzen",
            "",
            "- Kein Live-Apply, kein systemctl-Aufruf, keine echte systemd-/crontab-Datei aus diesem Modul.",
            f"- {DRAFT_BANNER}.",
            "",
        ]
    )
    return "\n".join(lines)


def render_readiness_markdown(report: Dict[str, Any]) -> str:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    checks = report.get("checks") if isinstance(report.get("checks"), dict) else {}
    failed = [key for key, value in checks.items() if not value]
    lines = [
        "# Safe Draft Autonomy Timer Install Readiness (DRAFT)",
        "",
        f"- Generated (UTC): `{report.get('generated_at_utc')}`",
        f"- Install review status: `{report.get('install_review_status')}`",
        f"- Blocked reason: `{redact_text(report.get('blocked_reason'), max_len=200)}`",
        f"- Safe checks passed: `{summary.get('safe_checks_passed_count')}`",
        f"- Safe checks failed: `{summary.get('safe_checks_failed_count')}`",
        f"- Install reviewer breach: `{summary.get('install_reviewer_breach')}`",
        "",
        "## Offene/fehlgeschlagene Checks",
        "",
    ]
    if failed:
        for key in failed:
            lines.append(f"- [ ] {key}")
    else:
        lines.append("- (keine) — alle Safe-Checks bestanden")
    lines.extend(
        [
            "",
            "## Hinweis",
            "",
            "- Review-only. Kein Timer installiert, kein systemctl, keine echte systemd-/crontab-Datei.",
            f"- {DRAFT_BANNER}.",
            "",
        ]
    )
    return "\n".join(lines)


def audit_records(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    return [
        {
            "timestamp_utc": report.get("generated_at_utc"),
            "schema_version": SCHEMA_VERSION,
            "record_type": "timer_install_review",
            "install_review_status": report.get("install_review_status"),
            "status": report.get("status"),
            "service_draft_safe": summary.get("service_draft_safe"),
            "timer_draft_safe": summary.get("timer_draft_safe"),
            "install_review_safe": summary.get("install_review_safe"),
            "rollback_review_safe": summary.get("rollback_review_safe"),
            "timer_installation_status": report.get("timer_installation_status"),
            "can_install_timer_now": report.get("can_install_timer_now"),
            "systemd_file_written": report.get("systemd_file_written"),
            "crontab_file_written": report.get("crontab_file_written"),
            "install_reviewer_breach": summary.get("install_reviewer_breach"),
            "safe_checks_passed_count": summary.get("safe_checks_passed_count"),
            "safe_checks_failed_count": summary.get("safe_checks_failed_count"),
            "blocked_reason": summary.get("blocked_reason"),
            "live_apply": False,
            "productive_change": False,
            "network_access": False,
        }
    ]


def write_outputs(report: Dict[str, Any]) -> None:
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, render_report_markdown(report))
    write_text_atomic(OWNER_CHECKLIST_MD, render_owner_checklist_markdown(report))
    write_text_atomic(READINESS_MD, render_readiness_markdown(report))
    append_jsonl(AUDIT_JSONL, audit_records(report))


def load_inputs() -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any], Dict[str, Any], Dict[str, Any], Dict[str, str]]:
    timer_report, timer_status = read_json_status(INPUT_TIMER_DRAFT_REPORT)
    scheduler, scheduler_status = read_json_status(INPUT_SCHEDULER_PLAN)
    verifier, verifier_status = read_json_status(INPUT_VERIFIER_REPORT)
    runner, runner_status = read_json_status(INPUT_RUNNER_REPORT)
    lock, lock_status = read_json_status(INPUT_RUNTIME_LOCK)
    master, master_status = read_json_status(INPUT_MASTER)

    service_scan = scan_draft_content(read_text_safe(SERVICE_DRAFT))
    timer_scan = scan_draft_content(read_text_safe(TIMER_DRAFT))
    install_scan = scan_draft_content(read_text_safe(INSTALL_REVIEW_MD))
    rollback_scan = scan_draft_content(read_text_safe(ROLLBACK_REVIEW_MD))

    statuses = {
        "safe_draft_autonomy_timer_draft_report": timer_status,
        "safe_draft_autonomy_scheduler_plan": scheduler_status,
        "safe_draft_autonomy_verifier_report": verifier_status,
        "safe_draft_autonomy_runner_report": runner_status,
        "autonomy_runtime_lock": lock_status,
        "sentinel_master": master_status,
    }
    signals = gather_signals(
        timer_report if isinstance(timer_report, dict) else None,
        scheduler if isinstance(scheduler, dict) else None,
        verifier if isinstance(verifier, dict) else None,
        runner if isinstance(runner, dict) else None,
        lock if isinstance(lock, dict) else None,
        master if isinstance(master, dict) else None,
    )
    return signals, service_scan, timer_scan, install_scan, rollback_scan, statuses


# --------------------------------------------------------------------------- #
# Self-test
# --------------------------------------------------------------------------- #

def _safe_scan(**overrides: Any) -> Dict[str, Any]:
    base = {
        "available": True,
        "has_banner": True,
        "active_forbidden_execstart": False,
        "systemctl_executable_line": False,
        "network_command": False,
        "live_apply_command": False,
        "secret_environment": False,
    }
    base.update(overrides)
    return base


def _ready_signals(**overrides: Any) -> Dict[str, Any]:
    base = {
        "timer_draft_report_available": True,
        "timer_installation_status": TIMER_NOT_INSTALLED,
        "systemd_file_written": False,
        "crontab_file_written": False,
        "timer_can_install_timer_now": False,
        "timer_can_execute_live": False,
        "timer_live_apply": False,
        "timer_apply_status": APPLY_NOT_APPLIED,
        "timer_draft_breach": False,
        "scheduler_breach": False,
        "runner_breach": False,
        "verifier_breach": False,
        "emergency_stop": False,
        "owner_disable_switch": True,
        "live_apply_enabled": False,
        "autonomy_enabled": True,
        "draft_only_enabled": True,
        "last_runner_status": "EXECUTED",
        "last_verifier_status": "VERIFIED_SAFE",
        "scheduler_status": "SCHEDULER_PLAN_READY_FOR_OWNER_REVIEW",
        "master_action_status": "WARNING_REVIEW",
    }
    base.update(overrides)
    return base


def _report(signals, service=None, timer=None, install=None, rollback=None, at="2026-06-11T00:00:00Z"):
    return build_report(
        signals,
        service or _safe_scan(),
        timer or _safe_scan(),
        install or _safe_scan(),
        rollback or _safe_scan(),
        {"safe_draft_autonomy_timer_draft_report": "ok"},
        at,
    )


def run_self_test() -> int:
    # 1) Fully ready, no breach.
    ready = _report(_ready_signals())
    if ready["install_review_status"] != INSTALL_REVIEW_READY:
        raise AssertionError("ready signals did not produce INSTALL_REVIEW_READY")
    if ready["summary"]["install_reviewer_breach"]:
        raise AssertionError("clean review must not breach")
    if ready["summary"]["safe_checks_failed_count"] != 0:
        raise AssertionError("ready review should have zero failed checks")
    if not (ready["summary"]["service_draft_safe"] and ready["summary"]["timer_draft_safe"]):
        raise AssertionError("ready drafts should be marked safe")

    # 2) Emergency stop blocks but is NOT a breach.
    es = _report(_ready_signals(emergency_stop=True))
    if es["install_review_status"] != INSTALL_REVIEW_BLOCKED_EMERGENCY:
        raise AssertionError("emergency stop did not block install review")
    if es["summary"]["install_reviewer_breach"]:
        raise AssertionError("emergency stop must not be a breach")

    # 3) Timer draft breach / scheduler breach / runner-or-verifier breach blocks.
    if _report(_ready_signals(timer_draft_breach=True))["install_review_status"] != INSTALL_REVIEW_BLOCKED_TIMER_DRAFT:
        raise AssertionError("timer_draft_breach did not block correctly")
    if _report(_ready_signals(scheduler_breach=True))["install_review_status"] != INSTALL_REVIEW_BLOCKED_SCHEDULER:
        raise AssertionError("scheduler_breach did not block correctly")
    if _report(_ready_signals(runner_breach=True))["install_review_status"] != INSTALL_REVIEW_BLOCKED_RUNNER_VERIFIER:
        raise AssertionError("runner_breach did not block correctly")
    if _report(_ready_signals(verifier_breach=True))["install_review_status"] != INSTALL_REVIEW_BLOCKED_RUNNER_VERIFIER:
        raise AssertionError("verifier_breach did not block correctly")

    # 4) Missing drafts -> NOT_READY_MISSING_DRAFTS, no breach.
    miss = _report(_ready_signals(), service=_safe_scan(available=False, has_banner=False))
    if miss["install_review_status"] != INSTALL_REVIEW_NOT_READY_MISSING:
        raise AssertionError("missing draft did not yield NOT_READY_MISSING_DRAFTS")
    if miss["summary"]["install_reviewer_breach"]:
        raise AssertionError("missing draft must not be a breach")

    # 5) Breach signals.
    if not _report(_ready_signals(timer_can_install_timer_now=True))["install_reviewer_breach"]:
        raise AssertionError("can_install_timer_now did not breach")
    if not _report(_ready_signals(timer_installation_status="installed"))["install_reviewer_breach"]:
        raise AssertionError("installed status did not breach")
    if not _report(_ready_signals(systemd_file_written=True))["install_reviewer_breach"]:
        raise AssertionError("systemd_file_written did not breach")
    if not _report(_ready_signals(crontab_file_written=True))["install_reviewer_breach"]:
        raise AssertionError("crontab_file_written did not breach")
    if not _report(_ready_signals(timer_live_apply=True))["install_reviewer_breach"]:
        raise AssertionError("timer live_apply did not breach")
    if not _report(_ready_signals(timer_can_execute_live=True))["install_reviewer_breach"]:
        raise AssertionError("timer can_execute_live did not breach")
    if not _report(_ready_signals(timer_apply_status="applied"))["install_reviewer_breach"]:
        raise AssertionError("timer apply_status change did not breach")

    # active forbidden ExecStart in a draft -> breach.
    if not _report(_ready_signals(), service=_safe_scan(active_forbidden_execstart=True))["install_reviewer_breach"]:
        raise AssertionError("active forbidden ExecStart did not breach")
    # systemctl executable line -> breach.
    if not _report(_ready_signals(), service=_safe_scan(systemctl_executable_line=True))["install_reviewer_breach"]:
        raise AssertionError("systemctl executable line did not breach")
    # network command -> breach.
    if not _report(_ready_signals(), timer=_safe_scan(network_command=True))["install_reviewer_breach"]:
        raise AssertionError("network command did not breach")
    # live-apply command -> breach.
    if not _report(_ready_signals(), service=_safe_scan(live_apply_command=True))["install_reviewer_breach"]:
        raise AssertionError("live-apply command did not breach")
    # secret environment -> breach.
    if not _report(_ready_signals(), service=_safe_scan(secret_environment=True))["install_reviewer_breach"]:
        raise AssertionError("secret environment did not breach")

    # 6) Content scanner: real service draft (commented ExecStart + banner) is safe.
    safe_service = (
        f"# {DRAFT_BANNER}\n[Service]\nType=oneshot\nWorkingDirectory=/srv/sentinel-defense\n"
        "# ExecStart=/usr/bin/python3 sentinel_master.py\n"
    )
    scan_ok = scan_draft_content(safe_service)
    if scan_ok["active_forbidden_execstart"] or scan_ok["systemctl_executable_line"] or not scan_ok["has_banner"]:
        raise AssertionError("safe service draft was misjudged")
    # Active prohibited ExecStart in content is detected.
    bad_service = "[Service]\nExecStart=/usr/bin/systemctl restart nginx\n"
    scan_bad = scan_draft_content(bad_service)
    if not (scan_bad["active_forbidden_execstart"] and scan_bad["systemctl_executable_line"]):
        raise AssertionError("active prohibited ExecStart was not detected")
    # Secret Environment in content is detected.
    if not scan_draft_content("[Service]\nEnvironment=API_KEY=sk-0123456789abcdef0123\n")["secret_environment"]:
        raise AssertionError("secret Environment in content not detected")
    # A harmless 'no Environment secrets' comment must NOT be flagged.
    if scan_draft_content("# (no Environment= lines; no secrets, no credentials)\n")["secret_environment"]:
        raise AssertionError("harmless comment falsely flagged as secret")

    # 7) Missing everything must not crash.
    empty = build_report(
        gather_signals(None, None, None, None, None, None),
        scan_draft_content(None), scan_draft_content(None),
        scan_draft_content(None), scan_draft_content(None),
        {"safe_draft_autonomy_timer_draft_report": "not_available"},
        "2026-06-11T00:09:00Z",
    )
    if empty["install_reviewer_breach"]:
        raise AssertionError("missing inputs must not breach")
    if empty["install_review_status"] != INSTALL_REVIEW_BLOCKED_EMERGENCY:
        raise AssertionError("missing inputs should default to emergency-stop block (lock defaults stopped)")

    # Forbidden write path for the module itself is rejected.
    try:
        assert_allowed_write(Path("/etc/systemd/system/sentinel.timer"))
    except ValueError:
        pass
    else:
        raise AssertionError("forbidden write path (/etc/systemd) was not rejected")

    print("safe-draft-autonomy-timer-install-review self-tests: OK")
    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Review whether the Phase 3.9 timer drafts are install-readiness review-ready (no install, no live apply)."
    )
    parser.add_argument("--self-test", action="store_true", help="Run built-in safety tests and exit.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()
    signals, service_scan, timer_scan, install_scan, rollback_scan, statuses = load_inputs()
    report = build_report(signals, service_scan, timer_scan, install_scan, rollback_scan, statuses)
    write_outputs(report)
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    print(
        "Safe Draft Autonomy Timer Install Review: "
        f"status={report.get('install_review_status')}, "
        f"can_install={report.get('can_install_timer_now')}, "
        f"checks_passed={summary.get('safe_checks_passed_count')}, "
        f"checks_failed={summary.get('safe_checks_failed_count')}, "
        f"breach={summary.get('install_reviewer_breach')}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
