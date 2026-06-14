#!/usr/bin/env python3
"""Sentinel Safe Draft Autonomy Scheduler Plan (Phase 3.8).

Prepares a *review-only* scheduler plan describing how a future systemd timer
could safely drive the Safe Draft-Only Autonomy chain. It installs NO timer,
writes NO systemd/cron files, and applies nothing. It only documents the
planned frequency, sequence, preconditions, stop conditions, allowed/prohibited
commands, and safety boundaries for owner review.

Hard safety guarantees (enforced structurally):
- No live changes; no live-apply function exists in this module.
- No timer is installed; no systemd unit or crontab file is written.
- Never edits WordPress files, .htaccess, Cloudflare rules, or Nginx config.
- No external writes, no network access, no WordPress login, no API calls.
- No secrets/cookies/auth values are stored or printed.
- apply_status stays not_applied; can_execute_live stays false;
  timer_installation_status stays not_installed; can_install_timer_now is false.
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

INPUT_RUNTIME_LOCK = PROJECT_DIR / "config/autonomy-runtime-lock.json"
INPUT_RUNNER_REPORT = PROJECT_DIR / "reports/latest/safe-draft-autonomy-runner-report.json"
INPUT_VERIFIER_REPORT = PROJECT_DIR / "reports/latest/safe-draft-autonomy-verifier-report.json"
INPUT_MASTER = PROJECT_DIR / "reports/latest/sentinel-master-report.json"
INPUT_OWNER_DAILY = PROJECT_DIR / "reports/latest/owner-daily-action-summary.json"

REPORT_JSON = PROJECT_DIR / "reports/latest/safe-draft-autonomy-scheduler-plan.json"
REPORT_MD = PROJECT_DIR / "reports/latest/safe-draft-autonomy-scheduler-plan.md"
DRAFT_MD = PROJECT_DIR / "drafts/apply/safe-draft-autonomy-scheduler-plan.md"
OWNER_MD = PROJECT_DIR / "drafts/owner/safe-draft-autonomy-owner-scheduler-review.md"
AUDIT_JSONL = PROJECT_DIR / "audit/safe-draft-autonomy-scheduler-plan.jsonl"

# Where THIS planner may write its own outputs.
ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "drafts/apply",
    PROJECT_DIR / "drafts/owner",
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "audit",
)

SCHEMA_VERSION = "safe-draft-autonomy-scheduler-plan-3.8"

APPLY_NOT_APPLIED = "not_applied"
TIMER_NOT_INSTALLED = "not_installed"

PLANNED_FREQUENCY = "max_once_daily"

# Scheduler status vocabulary (Phase 3.8).
SCHEDULER_READY = "SCHEDULER_PLAN_READY_FOR_OWNER_REVIEW"
SCHEDULER_BLOCKED_EMERGENCY = "SCHEDULER_PLAN_BLOCKED_BY_EMERGENCY_STOP"
SCHEDULER_BLOCKED_RUNTIME = "SCHEDULER_PLAN_BLOCKED_BY_RUNTIME_BREACH"
SCHEDULER_BLOCKED_VERIFIER = "SCHEDULER_PLAN_BLOCKED_BY_VERIFIER_BREACH"
SCHEDULER_BLOCKED_RUNNER = "SCHEDULER_PLAN_BLOCKED_BY_RUNNER_BREACH"
SCHEDULER_WARNING = "SCHEDULER_PLAN_WARNING"

# The only commands a future safe timer may invoke (read-only / draft-only).
ALLOWED_COMMANDS = [
    "python3 sentinel_autonomy_runtime_lock.py status",
    "python3 sentinel_safe_draft_autonomy_runner.py",
    "python3 sentinel_safe_draft_autonomy_verifier.py",
    "python3 sentinel_owner_daily_action_summary.py",
    "python3 sentinel_master.py",
]

# Commands that must never appear in a safe plan.
PROHIBITED_COMMANDS = [
    "systemctl enable",
    "systemctl start",
    "systemctl restart",
    "crontab",
    "wp ",
    "curl",
    "wget",
    "ssh",
    "rsync",
    "scp",
    "git push",
    "cloudflare api",
    "nginx reload",
    "service restart",
]

# Token sets used for breach detection against any command string.
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

# Output-path tokens that would indicate a timer/cron/systemd install attempt.
TIMER_INSTALL_PATH_TOKENS = [
    "/etc/systemd",
    "systemd/system",
    ".timer",
    ".service",
    "/etc/cron",
    "crontab",
    "cron.d",
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
        raise ValueError(f"Refusing to write outside allowed scheduler-plan roots: {path}")


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


def _as_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return bool(value)


def gather_signals(
    lock: Optional[Dict[str, Any]],
    runner: Optional[Dict[str, Any]],
    verifier: Optional[Dict[str, Any]],
    master: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Collect the lock flags and breach signals needed by the planner."""
    lock = lock if isinstance(lock, dict) else {}
    runner = runner if isinstance(runner, dict) else {}
    verifier = verifier if isinstance(verifier, dict) else {}
    master = master if isinstance(master, dict) else {}

    runner_summary = runner.get("summary") if isinstance(runner.get("summary"), dict) else {}
    verifier_summary = verifier.get("summary") if isinstance(verifier.get("summary"), dict) else {}

    master_lock = master.get("autonomy_runtime_lock") if isinstance(master.get("autonomy_runtime_lock"), dict) else {}
    master_runner = master.get("safe_draft_autonomy_runner") if isinstance(master.get("safe_draft_autonomy_runner"), dict) else {}
    master_verifier = master.get("safe_draft_autonomy_verifier") if isinstance(master.get("safe_draft_autonomy_verifier"), dict) else {}
    master_autonomy = master.get("autonomy_policy") if isinstance(master.get("autonomy_policy"), dict) else {}

    runner_breach = _as_bool(runner_summary.get("runner_breach")) or _as_bool(runner.get("runner_breach")) or _as_bool(master_runner.get("runner_breach"))
    verifier_breach = _as_bool(verifier_summary.get("verifier_breach")) or _as_bool(verifier.get("verifier_breach")) or _as_bool(master_verifier.get("verifier_breach"))
    # runtime breach: lock report value (via master) or a master autonomy policy breach.
    runtime_lock_breach = _as_bool(master_lock.get("runtime_lock_breach")) or _as_bool(lock.get("runtime_lock_breach"))
    autonomy_policy_breach = _as_bool(master_autonomy.get("policy_breach"))

    return {
        "emergency_stop": _as_bool(lock.get("emergency_stop"), True),
        "autonomy_enabled": _as_bool(lock.get("autonomy_enabled")),
        "draft_only_enabled": _as_bool(lock.get("draft_only_enabled")),
        "validation_only_enabled": _as_bool(lock.get("validation_only_enabled")),
        "live_apply_enabled": _as_bool(lock.get("live_apply_enabled")),
        "owner_disable_switch": _as_bool(lock.get("owner_disable_switch")),
        "runtime_lock_breach": runtime_lock_breach,
        "autonomy_policy_breach": autonomy_policy_breach,
        "runner_breach": runner_breach,
        "verifier_breach": verifier_breach,
        "last_runner_status": redact_text(runner.get("runner_status"), max_len=80),
        "last_verifier_status": redact_text(verifier.get("verifier_status"), max_len=80),
        "website_status": redact_text(master.get("website_status"), max_len=40),
        "master_action_status": redact_text(master.get("action_status"), max_len=40),
        "master_overall_status": redact_text(master.get("overall_master_status"), max_len=40),
    }


def build_preconditions(signals: Dict[str, Any]) -> Dict[str, bool]:
    runtime_breach = signals["runtime_lock_breach"] or signals["autonomy_policy_breach"]
    master_breach_free = not (
        signals["autonomy_policy_breach"] or signals["runner_breach"] or signals["verifier_breach"]
    )
    return {
        "emergency_stop_false": not signals["emergency_stop"],
        "autonomy_enabled_true": signals["autonomy_enabled"],
        "draft_only_enabled_true": signals["draft_only_enabled"],
        "validation_only_enabled_true": signals["validation_only_enabled"],
        "live_apply_disabled": not signals["live_apply_enabled"],
        "owner_disable_switch_true": signals["owner_disable_switch"],
        "runtime_lock_breach_false": not runtime_breach,
        "last_verifier_breach_false": not signals["verifier_breach"],
        "last_runner_breach_false": not signals["runner_breach"],
        "master_no_autonomy_runner_verifier_breach": master_breach_free,
    }


def determine_scheduler_status(signals: Dict[str, Any]) -> Tuple[str, str]:
    """Return (scheduler_status, blocked_reason)."""
    if signals["emergency_stop"]:
        return SCHEDULER_BLOCKED_EMERGENCY, "emergency_stop is active; a timer must never run."
    if signals["runtime_lock_breach"] or signals["autonomy_policy_breach"]:
        return SCHEDULER_BLOCKED_RUNTIME, "runtime lock / autonomy policy breach is present."
    if signals["verifier_breach"]:
        return SCHEDULER_BLOCKED_VERIFIER, "last verifier reported a breach."
    if signals["runner_breach"]:
        return SCHEDULER_BLOCKED_RUNNER, "last runner reported a breach."
    return SCHEDULER_READY, "-"


def planned_sequence() -> List[Dict[str, Any]]:
    return [
        {"planned_step": 1, "command": "python3 sentinel_autonomy_runtime_lock.py status",
         "purpose": "Read owner runtime lock; abort if emergency_stop or autonomy disabled.",
         "network_access": False, "productive_change": False},
        {"planned_step": 2, "command": "python3 sentinel_safe_draft_autonomy_runner.py",
         "purpose": "Draft-only autonomous refresh (no live apply), gated by the lock.",
         "network_access": False, "productive_change": False},
        {"planned_step": 3, "command": "python3 sentinel_safe_draft_autonomy_verifier.py",
         "purpose": "Verify runner outputs are allowed and non-productive.",
         "network_access": False, "productive_change": False},
        {"planned_step": 4, "command": "python3 sentinel_owner_daily_action_summary.py",
         "purpose": "Refresh the short owner daily summary.",
         "network_access": False, "productive_change": False},
        {"planned_step": 5, "command": "python3 sentinel_master.py",
         "purpose": "Aggregate all reports into the master report.",
         "network_access": False, "productive_change": False},
        {"planned_step": 6, "command": "python3 sentinel_daily_mailer.py --send",
         "purpose": "OPTIONAL: only if the owner already uses the mailer manually/externally; "
                    "not part of the autonomous safe core.",
         "network_access": True, "productive_change": False, "optional": True},
    ]


def planned_frequency_detail() -> Dict[str, str]:
    return {
        "draft_only_reports": "once_daily",
        "validation_only_reports": "once_daily_after_runner",
        "owner_summary": "once_daily",
        "full_safe_cycle": "max_once_daily",
        "minute_or_hourly_autopilot": "not_allowed_in_this_phase",
    }


def build_plan(signals: Dict[str, Any]) -> Dict[str, Any]:
    scheduler_status, blocked_reason = determine_scheduler_status(signals)
    sequence = planned_sequence()
    return {
        "scheduler_plan_id": "safe_draft_autonomy_scheduler_plan:001",
        "planned_frequency": PLANNED_FREQUENCY,
        "planned_frequency_detail": planned_frequency_detail(),
        "planned_sequence": sequence,
        "preconditions": build_preconditions(signals),
        "stop_conditions": [
            "emergency_stop=true",
            "autonomy_enabled=false",
            "draft_only_enabled=false",
            "validation_only_enabled=false",
            "live_apply_enabled=true",
            "owner_disable_switch=false",
            "runtime_lock_breach=true",
            "last verifier verifier_breach=true",
            "last runner runner_breach=true",
            "master autonomy/runner/verifier breach present",
            "CRITICAL caused by a safety breach",
        ],
        "allowed_commands": list(ALLOWED_COMMANDS),
        "prohibited_commands": list(PROHIBITED_COMMANDS),
        "allowed_outputs": [
            str(REPORT_JSON),
            str(REPORT_MD),
            str(DRAFT_MD),
            str(OWNER_MD),
            str(AUDIT_JSONL),
        ],
        "owner_review_required": True,
        "timer_installation_status": TIMER_NOT_INSTALLED,
        "can_install_timer_now": False,
        "can_execute_live": False,
        "apply_status": APPLY_NOT_APPLIED,
        "website_warning_note": "Website WARNING does not block draft-only as long as there is no autonomy breach.",
        "scheduler_status": scheduler_status,
        "blocked_reason": blocked_reason,
        "reason": (
            "Review-only scheduler plan; no timer installed, nothing applied. "
            "A future timer may run at most once daily and only while every precondition holds."
        ),
    }


def command_breach_tokens(command: str) -> List[str]:
    lower = str(command).lower()
    hits: List[str] = []
    for token in PROHIBITED_COMMAND_TOKENS:
        if token in lower:
            hits.append(f"prohibited_command_token:{token.strip()}")
    for token in LIVE_APPLY_TOKENS:
        if token in lower:
            hits.append(f"live_apply_token:{token.strip()}")
    for token in NETWORK_LOGIN_TOKENS:
        if token in lower:
            hits.append(f"network_login_token:{token.strip()}")
    return hits


def scheduler_breach(plan: Dict[str, Any]) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    if _as_bool(plan.get("can_install_timer_now")):
        reasons.append("can_install_timer_now is true")
    if plan.get("timer_installation_status") != TIMER_NOT_INSTALLED:
        reasons.append("timer_installation_status != not_installed")
    if _as_bool(plan.get("can_execute_live")):
        reasons.append("can_execute_live is true")
    if plan.get("apply_status") != APPLY_NOT_APPLIED:
        reasons.append("apply_status != not_applied")

    allowed_commands = plan.get("allowed_commands") if isinstance(plan.get("allowed_commands"), list) else []
    for command in allowed_commands:
        for hit in command_breach_tokens(command):
            reasons.append(f"allowed_command '{redact_text(command, max_len=80)}': {hit}")

    outputs = plan.get("allowed_outputs") if isinstance(plan.get("allowed_outputs"), list) else []
    for raw in outputs:
        lower = str(raw).lower()
        if any(token in lower for token in TIMER_INSTALL_PATH_TOKENS):
            reasons.append(f"output path looks like a timer/cron install: {redact_text(raw, max_len=120)}")
        if not within_allowed_roots(Path(str(raw))):
            reasons.append(f"output path outside allowed roots: {redact_text(raw, max_len=120)}")
    return bool(reasons), reasons


def build_report(
    signals: Dict[str, Any],
    input_statuses: Dict[str, str],
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    generated = generated_at or utc_now()
    plan = build_plan(signals)
    breach, breach_reasons = scheduler_breach(plan)
    scheduler_status = plan["scheduler_status"]
    status = SCHEDULER_WARNING if breach else scheduler_status

    summary = {
        "scheduler_status": scheduler_status,
        "planned_frequency": plan["planned_frequency"],
        "planned_sequence_count": len(plan["planned_sequence"]),
        "timer_installation_status": plan["timer_installation_status"],
        "can_install_timer_now": plan["can_install_timer_now"],
        "can_execute_live": plan["can_execute_live"],
        "owner_review_required": plan["owner_review_required"],
        "scheduler_breach": breach,
        "scheduler_breach_reasons": breach_reasons,
        "blocked_reason": plan["blocked_reason"],
    }

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": generated,
        "status": status,
        "scheduler_status": scheduler_status,
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
        "timer_installation_status": TIMER_NOT_INSTALLED,
        "can_install_timer_now": False,
        "scheduler_breach": breach,
        "blocked_reason": plan["blocked_reason"],
        "planned_frequency": plan["planned_frequency"],
        "owner_review_required": plan["owner_review_required"],
        "signals": signals,
        "allowed_write_roots": [str(path) for path in ALLOWED_WRITE_ROOTS],
        "input_statuses": input_statuses,
        "summary": summary,
        "scheduler_plan": plan,
        "outputs": {
            "report_json": str(REPORT_JSON),
            "report_md": str(REPORT_MD),
            "draft_md": str(DRAFT_MD),
            "owner_md": str(OWNER_MD),
            "audit_jsonl": str(AUDIT_JSONL),
        },
    }


def render_markdown(report: Dict[str, Any], *, title: str, owner_view: bool = False) -> str:
    plan = report.get("scheduler_plan") if isinstance(report.get("scheduler_plan"), dict) else {}
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    preconditions = plan.get("preconditions") if isinstance(plan.get("preconditions"), dict) else {}
    freq = plan.get("planned_frequency_detail") if isinstance(plan.get("planned_frequency_detail"), dict) else {}
    lines = [
        f"# {title}",
        "",
        f"- Generated (UTC): `{report.get('generated_at_utc')}`",
        f"- Status: `{report.get('status')}`",
        f"- Scheduler status: `{report.get('scheduler_status')}`",
        f"- Planned frequency: `{plan.get('planned_frequency')}`",
        f"- Timer installation status: `{report.get('timer_installation_status')}`",
        f"- Can install timer now: `{report.get('can_install_timer_now')}`",
        f"- Can execute live: `{report.get('can_execute_live')}`",
        f"- Owner review required: `{plan.get('owner_review_required')}`",
        f"- Scheduler breach: `{summary.get('scheduler_breach')}`",
        f"- Blocked reason: `{redact_text(plan.get('blocked_reason'), max_len=200)}`",
        "",
        "## Geplante Frequenz",
        "",
    ]
    for key in sorted(freq):
        lines.append(f"- {key}: `{freq.get(key)}`")
    lines.extend(["", "## Vorbedingungen (aktueller Stand)", ""])
    for key in sorted(preconditions):
        lines.append(f"- {key}: `{preconditions.get(key)}`")
    lines.extend(["", "## Geplante Sequenz", ""])
    for step in plan.get("planned_sequence", []):
        if not isinstance(step, dict):
            continue
        optional = " (optional)" if step.get("optional") else ""
        lines.append(
            f"{step.get('planned_step')}. `{redact_text(step.get('command'), max_len=120)}`{optional} — "
            f"{redact_text(step.get('purpose'), max_len=200)}"
        )
    lines.extend(["", "## Erlaubte Commands", ""])
    for command in plan.get("allowed_commands", []):
        lines.append(f"- `{redact_text(command, max_len=120)}`")
    lines.extend(["", "## Verbotene Commands", ""])
    for command in plan.get("prohibited_commands", []):
        lines.append(f"- `{redact_text(command, max_len=120)}`")
    lines.extend(["", "## Stop-Bedingungen", ""])
    for cond in plan.get("stop_conditions", []):
        lines.append(f"- `{redact_text(cond, max_len=160)}`")
    if owner_view:
        lines.extend(
            [
                "",
                "## Owner-Hinweis",
                "",
                "- Dies ist nur ein Review-Plan. Es wurde KEIN Timer installiert.",
                "- Kein systemd-/crontab-File wurde geschrieben.",
                "- Ein spaeterer Timer darf maximal 1x taeglich laufen und nur, wenn alle Vorbedingungen erfuellt sind.",
                "- Die Installation eines Timers bleibt eine bewusste, manuelle Owner-Entscheidung ausserhalb dieser Phase.",
            ]
        )
    lines.extend(
        [
            "",
            "## Sicherheitsgrenzen",
            "",
            "- Nur Scheduler-Plan-Dokumentation; keine Live-Aenderungen, keine Live-Apply-Funktion.",
            "- Kein Timer installiert; keine systemd-/crontab-Datei geschrieben.",
            "- Keine WordPress-, .htaccess-, Cloudflare-, Nginx- oder DNS-Aenderung.",
            "- Kein WordPress-Login, keine API, kein Netzwerkzugriff, keine externen Schreibzugriffe.",
            "- Keine Secrets/Cookies/Auth speichern oder ausgeben.",
            "- `apply_status=not_applied`, `can_execute_live=false`, `timer_installation_status=not_installed`, "
            "`can_install_timer_now=false`.",
            "- Schreibzugriff nur unter drafts/apply, drafts/owner, reports/latest, audit.",
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
            "record_type": "scheduler_plan",
            "scheduler_status": report.get("scheduler_status"),
            "status": report.get("status"),
            "planned_frequency": summary.get("planned_frequency"),
            "planned_sequence_count": summary.get("planned_sequence_count"),
            "timer_installation_status": report.get("timer_installation_status"),
            "can_install_timer_now": report.get("can_install_timer_now"),
            "can_execute_live": report.get("can_execute_live"),
            "owner_review_required": summary.get("owner_review_required"),
            "scheduler_breach": summary.get("scheduler_breach"),
            "blocked_reason": summary.get("blocked_reason"),
            "timer_installed": False,
            "systemd_file_written": False,
            "crontab_file_written": False,
            "live_apply": False,
            "productive_change": False,
            "network_access": False,
        }
    ]


def write_outputs(report: Dict[str, Any]) -> None:
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, render_markdown(report, title="Safe Draft Autonomy Scheduler Plan"))
    write_text_atomic(DRAFT_MD, render_markdown(report, title="Safe Draft Autonomy Scheduler Plan (Draft)"))
    write_text_atomic(OWNER_MD, render_markdown(report, title="Safe Draft Autonomy Owner Scheduler Review", owner_view=True))
    append_jsonl(AUDIT_JSONL, audit_records(report))


def load_inputs() -> Tuple[Dict[str, Any], Dict[str, str]]:
    lock, lock_status = read_json_status(INPUT_RUNTIME_LOCK)
    runner, runner_status = read_json_status(INPUT_RUNNER_REPORT)
    verifier, verifier_status = read_json_status(INPUT_VERIFIER_REPORT)
    master, master_status = read_json_status(INPUT_MASTER)
    owner_daily, owner_daily_status = read_json_status(INPUT_OWNER_DAILY)
    statuses = {
        "autonomy_runtime_lock": lock_status,
        "safe_draft_autonomy_runner_report": runner_status,
        "safe_draft_autonomy_verifier_report": verifier_status,
        "sentinel_master": master_status,
        "owner_daily_action_summary": owner_daily_status,
    }
    signals = gather_signals(
        lock if isinstance(lock, dict) else None,
        runner if isinstance(runner, dict) else None,
        verifier if isinstance(verifier, dict) else None,
        master if isinstance(master, dict) else None,
    )
    signals["owner_daily_available"] = isinstance(owner_daily, dict)
    return signals, statuses


# --------------------------------------------------------------------------- #
# Self-test
# --------------------------------------------------------------------------- #

def _ready_signals(**overrides: Any) -> Dict[str, Any]:
    base = {
        "emergency_stop": False,
        "autonomy_enabled": True,
        "draft_only_enabled": True,
        "validation_only_enabled": True,
        "live_apply_enabled": False,
        "owner_disable_switch": True,
        "runtime_lock_breach": False,
        "autonomy_policy_breach": False,
        "runner_breach": False,
        "verifier_breach": False,
        "last_runner_status": "EXECUTED",
        "last_verifier_status": "VERIFIED_SAFE",
        "website_status": "WARNING",
        "master_action_status": "WARNING_REVIEW",
        "master_overall_status": "WARNING",
    }
    base.update(overrides)
    return base


def run_self_test() -> int:
    statuses = {"autonomy_runtime_lock": "ok"}

    # 1) Ready plan (website WARNING allowed), no scheduler breach.
    ready = build_report(_ready_signals(), statuses, "2026-06-11T00:00:00Z")
    if ready["scheduler_status"] != SCHEDULER_READY:
        raise AssertionError("ready signals did not produce READY_FOR_OWNER_REVIEW")
    if ready["summary"]["scheduler_breach"]:
        raise AssertionError("clean plan must not breach")
    if ready["timer_installation_status"] != TIMER_NOT_INSTALLED or ready["can_install_timer_now"]:
        raise AssertionError("ready plan must not be installable")
    if not ready["scheduler_plan"]["preconditions"]["emergency_stop_false"]:
        raise AssertionError("emergency_stop_false precondition wrong")

    # 2) Emergency stop blocks the plan, no breach.
    estop = build_report(_ready_signals(emergency_stop=True), statuses, "2026-06-11T00:01:00Z")
    if estop["scheduler_status"] != SCHEDULER_BLOCKED_EMERGENCY:
        raise AssertionError("emergency stop did not block the plan")
    if estop["summary"]["scheduler_breach"]:
        raise AssertionError("emergency-stop block must not be a breach")

    # 3) Runtime breach -> blocked by runtime breach.
    rt = build_report(_ready_signals(runtime_lock_breach=True), statuses, "2026-06-11T00:02:00Z")
    if rt["scheduler_status"] != SCHEDULER_BLOCKED_RUNTIME:
        raise AssertionError("runtime breach did not block correctly")
    ap = build_report(_ready_signals(autonomy_policy_breach=True), statuses, "2026-06-11T00:02:30Z")
    if ap["scheduler_status"] != SCHEDULER_BLOCKED_RUNTIME:
        raise AssertionError("autonomy policy breach did not map to runtime block")

    # 4) Verifier breach -> blocked by verifier breach.
    vb = build_report(_ready_signals(verifier_breach=True), statuses, "2026-06-11T00:03:00Z")
    if vb["scheduler_status"] != SCHEDULER_BLOCKED_VERIFIER:
        raise AssertionError("verifier breach did not block correctly")

    # 5) Runner breach -> blocked by runner breach.
    rb = build_report(_ready_signals(runner_breach=True), statuses, "2026-06-11T00:04:00Z")
    if rb["scheduler_status"] != SCHEDULER_BLOCKED_RUNNER:
        raise AssertionError("runner breach did not block correctly")

    # 6) can_install_timer_now=true -> scheduler breach.
    bad = build_plan(_ready_signals())
    bad["can_install_timer_now"] = True
    b, _ = scheduler_breach(bad)
    if not b:
        raise AssertionError("can_install_timer_now did not breach")

    # 7) timer_installation_status != not_installed -> breach.
    bad = build_plan(_ready_signals())
    bad["timer_installation_status"] = "installed"
    if not scheduler_breach(bad)[0]:
        raise AssertionError("installed timer status did not breach")

    # 8) prohibited command in allowed_commands -> breach.
    bad = build_plan(_ready_signals())
    bad["allowed_commands"] = list(ALLOWED_COMMANDS) + ["systemctl enable sentinel.timer"]
    if not scheduler_breach(bad)[0]:
        raise AssertionError("prohibited command in allowed_commands did not breach")

    # 9) live apply command present -> breach.
    bad = build_plan(_ready_signals())
    bad["allowed_commands"] = list(ALLOWED_COMMANDS) + ["python3 sentinel_defense_bot.py --mode apply-safe --confirm-apply"]
    if not scheduler_breach(bad)[0]:
        raise AssertionError("live apply command did not breach")

    # 10) can_execute_live=true -> breach.
    bad = build_plan(_ready_signals())
    bad["can_execute_live"] = True
    if not scheduler_breach(bad)[0]:
        raise AssertionError("can_execute_live did not breach")

    # 11) apply_status != not_applied -> breach.
    bad = build_plan(_ready_signals())
    bad["apply_status"] = "applied"
    if not scheduler_breach(bad)[0]:
        raise AssertionError("apply_status change did not breach")

    # 12) systemd/crontab path write -> breach.
    bad = build_plan(_ready_signals())
    bad["allowed_outputs"] = list(bad["allowed_outputs"]) + ["/etc/systemd/system/sentinel.timer"]
    if not scheduler_breach(bad)[0]:
        raise AssertionError("systemd path output did not breach")
    bad = build_plan(_ready_signals())
    bad["allowed_outputs"] = list(bad["allowed_outputs"]) + ["/etc/cron.d/sentinel"]
    if not scheduler_breach(bad)[0]:
        raise AssertionError("crontab path output did not breach")

    # 13) network/API/login command present -> breach.
    bad = build_plan(_ready_signals())
    bad["allowed_commands"] = list(ALLOWED_COMMANDS) + ["curl https://api.example.com/login"]
    if not scheduler_breach(bad)[0]:
        raise AssertionError("network/API/login command did not breach")

    # 14) Missing reports must not crash -> all-None signals via gather_signals.
    empty_signals = gather_signals(None, None, None, None)
    empty = build_report(empty_signals, {"autonomy_runtime_lock": "not_available"}, "2026-06-11T00:05:00Z")
    if empty["scheduler_status"] != SCHEDULER_BLOCKED_EMERGENCY:
        raise AssertionError("missing lock should default to emergency-stop safe block")
    if empty["summary"]["scheduler_breach"]:
        raise AssertionError("missing reports must not breach")

    # 15) The real default plan never permits installation or live apply.
    base_plan = build_plan(_ready_signals())
    if base_plan["can_install_timer_now"] or base_plan["can_execute_live"]:
        raise AssertionError("default plan must not allow install / live apply")
    if base_plan["timer_installation_status"] != TIMER_NOT_INSTALLED:
        raise AssertionError("default plan must be not_installed")
    if scheduler_breach(base_plan)[0]:
        raise AssertionError("default plan must not breach")

    # Forbidden write path for the planner itself is rejected.
    try:
        assert_allowed_write(PROJECT_DIR / "systemd/should-not-write.timer")
    except ValueError:
        pass
    else:
        raise AssertionError("forbidden planner write path (systemd) was not rejected")

    print("safe-draft-autonomy-scheduler-plan self-tests: OK")
    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Prepare a review-only Safe Draft Autonomy scheduler plan (no timer install; no live apply)."
    )
    parser.add_argument("--self-test", action="store_true", help="Run built-in safety tests and exit.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()
    signals, statuses = load_inputs()
    report = build_report(signals, statuses)
    write_outputs(report)
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    print(
        "Safe Draft Autonomy Scheduler Plan: "
        f"status={report.get('scheduler_status')}, "
        f"frequency={summary.get('planned_frequency')}, "
        f"timer={report.get('timer_installation_status')}, "
        f"can_install={report.get('can_install_timer_now')}, "
        f"owner_review={summary.get('owner_review_required')}, "
        f"breach={summary.get('scheduler_breach')}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
