#!/usr/bin/env python3
"""Sentinel Safe Draft Autonomy Timer Unit Draft Pack (Phase 3.9).

Turns the Safe Draft Autonomy Scheduler Plan (Phase 3.8) into safe systemd
service/timer *DRAFTS* plus install/rollback review docs. It installs NO timer,
runs NO systemctl, writes NO real systemd unit and NO crontab, and applies
nothing. Every artifact is a review-only draft under drafts/apply for a later,
deliberate owner decision.

Hard safety guarantees (enforced structurally):
- No live changes; no live-apply function exists in this module.
- No timer is installed/enabled; no systemctl is executed.
- Nothing is written to /etc/systemd/system or any crontab location.
- Never edits WordPress files, .htaccess, Cloudflare rules, or Nginx config.
- No external writes, no network access, no WordPress login, no API calls.
- No secrets/cookies/auth values are stored or printed; no Environment= secrets.
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

INPUT_SCHEDULER_PLAN = PROJECT_DIR / "reports/latest/safe-draft-autonomy-scheduler-plan.json"
INPUT_RUNTIME_LOCK = PROJECT_DIR / "config/autonomy-runtime-lock.json"
INPUT_VERIFIER_REPORT = PROJECT_DIR / "reports/latest/safe-draft-autonomy-verifier-report.json"
INPUT_RUNNER_REPORT = PROJECT_DIR / "reports/latest/safe-draft-autonomy-runner-report.json"
INPUT_MASTER = PROJECT_DIR / "reports/latest/sentinel-master-report.json"

SERVICE_DRAFT = PROJECT_DIR / "drafts/apply/sentinel-safe-draft-autonomy.service.draft"
TIMER_DRAFT = PROJECT_DIR / "drafts/apply/sentinel-safe-draft-autonomy.timer.draft"
INSTALL_REVIEW_MD = PROJECT_DIR / "drafts/apply/sentinel-safe-draft-autonomy-install-review.md"
ROLLBACK_REVIEW_MD = PROJECT_DIR / "drafts/apply/sentinel-safe-draft-autonomy-rollback-review.md"
REPORT_JSON = PROJECT_DIR / "reports/latest/safe-draft-autonomy-timer-draft-report.json"
REPORT_MD = PROJECT_DIR / "reports/latest/safe-draft-autonomy-timer-draft-report.md"
AUDIT_JSONL = PROJECT_DIR / "audit/safe-draft-autonomy-timer-draft.jsonl"

# Where THIS module may write its own outputs.
ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "drafts/apply",
    PROJECT_DIR / "drafts/owner",
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "audit",
)

SCHEMA_VERSION = "safe-draft-autonomy-timer-draft-3.9"

APPLY_NOT_APPLIED = "not_applied"
TIMER_NOT_INSTALLED = "not_installed"

DRAFT_BANNER = "DRAFT ONLY - DO NOT COPY WITHOUT OWNER REVIEW"

# Timer draft status vocabulary (Phase 3.9).
TIMER_DRAFT_READY = "TIMER_DRAFT_READY_FOR_OWNER_REVIEW"
TIMER_DRAFT_BLOCKED_EMERGENCY = "TIMER_DRAFT_BLOCKED_BY_EMERGENCY_STOP"
TIMER_DRAFT_BLOCKED_SCHEDULER = "TIMER_DRAFT_BLOCKED_BY_SCHEDULER_BREACH"
TIMER_DRAFT_BLOCKED_RUNTIME = "TIMER_DRAFT_BLOCKED_BY_RUNTIME_BREACH"
TIMER_DRAFT_BLOCKED_VERIFIER = "TIMER_DRAFT_BLOCKED_BY_VERIFIER_BREACH"
TIMER_DRAFT_BLOCKED_RUNNER = "TIMER_DRAFT_BLOCKED_BY_RUNNER_BREACH"
TIMER_DRAFT_WARNING = "TIMER_DRAFT_WARNING"

BLOCKED_STATUSES = {
    TIMER_DRAFT_BLOCKED_EMERGENCY,
    TIMER_DRAFT_BLOCKED_SCHEDULER,
    TIMER_DRAFT_BLOCKED_RUNTIME,
    TIMER_DRAFT_BLOCKED_VERIFIER,
    TIMER_DRAFT_BLOCKED_RUNNER,
}

# The only commands the draft service may reference (read-only / draft-only).
SAFE_SEQUENCE_COMMANDS = [
    "python3 sentinel_autonomy_runtime_lock.py status",
    "python3 sentinel_safe_draft_autonomy_runner.py",
    "python3 sentinel_safe_draft_autonomy_verifier.py",
    "python3 sentinel_owner_daily_action_summary.py",
    "python3 sentinel_master.py",
]

# Tokens that must never appear in an executable command position.
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

# Output-path tokens that would indicate a real systemd/cron install location.
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
        raise ValueError(f"Refusing to write outside allowed timer-draft roots: {path}")


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
    plan: Optional[Dict[str, Any]],
    lock: Optional[Dict[str, Any]],
    verifier: Optional[Dict[str, Any]],
    runner: Optional[Dict[str, Any]],
    master: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    plan = plan if isinstance(plan, dict) else {}
    lock = lock if isinstance(lock, dict) else {}
    verifier = verifier if isinstance(verifier, dict) else {}
    runner = runner if isinstance(runner, dict) else {}
    master = master if isinstance(master, dict) else {}

    plan_summary = plan.get("summary") if isinstance(plan.get("summary"), dict) else {}
    runner_summary = runner.get("summary") if isinstance(runner.get("summary"), dict) else {}
    verifier_summary = verifier.get("summary") if isinstance(verifier.get("summary"), dict) else {}

    master_lock = master.get("autonomy_runtime_lock") if isinstance(master.get("autonomy_runtime_lock"), dict) else {}
    master_autonomy = master.get("autonomy_policy") if isinstance(master.get("autonomy_policy"), dict) else {}

    scheduler_breach = _as_bool(plan_summary.get("scheduler_breach")) or _as_bool(plan.get("scheduler_breach"))
    runner_breach = _as_bool(runner_summary.get("runner_breach")) or _as_bool(runner.get("runner_breach"))
    verifier_breach = _as_bool(verifier_summary.get("verifier_breach")) or _as_bool(verifier.get("verifier_breach"))
    runtime_lock_breach = _as_bool(master_lock.get("runtime_lock_breach")) or _as_bool(lock.get("runtime_lock_breach"))
    autonomy_policy_breach = _as_bool(master_autonomy.get("policy_breach"))

    return {
        "scheduler_plan_available": bool(plan),
        "scheduler_status": redact_text(plan.get("scheduler_status"), max_len=80),
        "scheduler_breach": scheduler_breach,
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
    }


def determine_timer_draft_status(signals: Dict[str, Any]) -> Tuple[str, str]:
    """Return (timer_draft_status, blocked_reason)."""
    if signals["emergency_stop"]:
        return TIMER_DRAFT_BLOCKED_EMERGENCY, "emergency_stop is active; no timer draft is recommended."
    if signals["scheduler_breach"]:
        return TIMER_DRAFT_BLOCKED_SCHEDULER, "scheduler plan reported a breach."
    if signals["runtime_lock_breach"] or signals["autonomy_policy_breach"]:
        return TIMER_DRAFT_BLOCKED_RUNTIME, "runtime lock / autonomy policy breach is present."
    if signals["verifier_breach"]:
        return TIMER_DRAFT_BLOCKED_VERIFIER, "last verifier reported a breach."
    if signals["runner_breach"]:
        return TIMER_DRAFT_BLOCKED_RUNNER, "last runner reported a breach."
    return TIMER_DRAFT_READY, "-"


def render_service_draft(generated: str) -> str:
    lines = [
        f"# {DRAFT_BANNER}",
        "# Sentinel Safe Draft Autonomy systemd service DRAFT (Phase 3.9)",
        f"# Generated (UTC): {generated}",
        "# This is a DRAFT ONLY. It is NOT installed and NOT active.",
        "# Do not copy into /etc/systemd/system without a deliberate owner review.",
        "# No live apply, no network, no secrets, no Environment= credentials.",
        "",
        "[Unit]",
        "Description=Sentinel Safe Draft-Only Autonomy cycle (DRAFT, not installed)",
        "Documentation=file:///srv/sentinel-defense/drafts/apply/sentinel-safe-draft-autonomy-install-review.md",
        "",
        "[Service]",
        "Type=oneshot",
        "WorkingDirectory=/srv/sentinel-defense",
        "# No Environment= secrets. Non-secret EnvironmentFile is owner-managed via systemd, never sourced here.",
        "# ExecStart references ONLY the local, read-only / draft-only safe sequence:",
    ]
    for command in SAFE_SEQUENCE_COMMANDS:
        lines.append(f"# ExecStart=/usr/bin/{command}")
    lines.extend(
        [
            "# (The lines above are intentionally COMMENTED so this draft cannot execute if mis-copied.)",
            "# Prohibited in any ExecStart: wp, curl, wget, ssh, git push, systemctl, nginx reload,",
            "#   cloudflare api, service restart, or any live-apply command.",
            "",
            "[Install]",
            "WantedBy=multi-user.target",
            "",
            f"# {DRAFT_BANNER}",
        ]
    )
    return "\n".join(lines) + "\n"


def render_timer_draft(generated: str) -> str:
    return (
        "\n".join(
            [
                f"# {DRAFT_BANNER}",
                "# Sentinel Safe Draft Autonomy systemd timer DRAFT (Phase 3.9)",
                f"# Generated (UTC): {generated}",
                "# This is a DRAFT ONLY. It is NOT installed and NOT active.",
                "",
                "[Unit]",
                "Description=Sentinel Safe Draft-Only Autonomy daily timer (DRAFT, not installed)",
                "",
                "[Timer]",
                "OnCalendar=daily",
                "# Persistent= is shown only as a REVIEW hint (default false); not active in this draft.",
                "Persistent=false",
                "RandomizedDelaySec=30m",
                "AccuracySec=1h",
                "Unit=sentinel-safe-draft-autonomy.service",
                "",
                "[Install]",
                "WantedBy=timers.target",
                "",
                f"# {DRAFT_BANNER}",
            ]
        )
        + "\n"
    )


def render_install_review(generated: str, signals: Dict[str, Any], status: str) -> str:
    return (
        "\n".join(
            [
                "# Sentinel Safe Draft Autonomy — Install Review (DRAFT)",
                "",
                f"- Generated (UTC): `{generated}`",
                f"- Timer draft status: `{status}`",
                f"- timer_installation_status: `{TIMER_NOT_INSTALLED}`",
                "",
                "## Wichtig",
                "",
                "- **Nicht automatisch installieren.** Diese Dateien sind reine Drafts.",
                "- **Nur der Owner darf manuell entscheiden**, ob jemals ein Timer installiert wird.",
                "- **Vor einer Installation pruefen:** `emergency_stop=false` und draft-only ist aktiviert "
                "(`python3 sentinel_autonomy_runtime_lock.py status`, dann `enable-draft-only`).",
                "- **Nach einem Test** kann der Owner jederzeit wieder `emergency-stop` setzen.",
                "- Die folgenden systemd-Befehle sind **nur Kommentar/Review, nicht ausfuehrbar** aus diesem Pack heraus:",
                "",
                "```text",
                "# REVIEW ONLY — vom Owner bewusst und manuell auszufuehren, nicht durch dieses Modul:",
                "#   sudo cp drafts/apply/sentinel-safe-draft-autonomy.service.draft \\",
                "#       /etc/systemd/system/sentinel-safe-draft-autonomy.service",
                "#   sudo cp drafts/apply/sentinel-safe-draft-autonomy.timer.draft \\",
                "#       /etc/systemd/system/sentinel-safe-draft-autonomy.timer",
                "#   sudo systemctl daemon-reload",
                "#   sudo systemctl enable --now sentinel-safe-draft-autonomy.timer",
                "```",
                "",
                "## Vorbedingungen (aktueller Stand)",
                "",
                f"- emergency_stop: `{signals.get('emergency_stop')}`",
                f"- autonomy_enabled: `{signals.get('autonomy_enabled')}`",
                f"- draft_only_enabled: `{signals.get('draft_only_enabled')}`",
                f"- validation_only_enabled: `{signals.get('validation_only_enabled')}`",
                f"- live_apply_enabled: `{signals.get('live_apply_enabled')}`",
                f"- scheduler_breach: `{signals.get('scheduler_breach')}`",
                f"- runtime_lock_breach: `{signals.get('runtime_lock_breach')}`",
                f"- verifier_breach: `{signals.get('verifier_breach')}`",
                f"- runner_breach: `{signals.get('runner_breach')}`",
                "",
                "## Sicherheitsgrenzen",
                "",
                "- Kein Live-Apply, kein systemctl, keine echte systemd-/crontab-Datei aus diesem Modul.",
                "- Kein Netzwerk, keine API, kein WordPress-Login, keine Secrets/Environment-Credentials.",
                f"- {DRAFT_BANNER}.",
                "",
            ]
        )
        + "\n"
    )


def render_rollback_review(generated: str, status: str) -> str:
    return (
        "\n".join(
            [
                "# Sentinel Safe Draft Autonomy — Rollback Review (DRAFT)",
                "",
                f"- Generated (UTC): `{generated}`",
                f"- Timer draft status: `{status}`",
                "",
                "## Rollback-Schritte (nur Review, keine Ausfuehrung durch dieses Modul)",
                "",
                "1. **Timer deaktivieren** (Owner, manuell):",
                "   ```text",
                "   # REVIEW ONLY:",
                "   #   sudo systemctl disable --now sentinel-safe-draft-autonomy.timer",
                "   ```",
                "2. **Service stoppen**:",
                "   ```text",
                "   # REVIEW ONLY:",
                "   #   sudo systemctl stop sentinel-safe-draft-autonomy.service",
                "   ```",
                "3. **Dateien entfernen**:",
                "   ```text",
                "   # REVIEW ONLY:",
                "   #   sudo rm -f /etc/systemd/system/sentinel-safe-draft-autonomy.service",
                "   #   sudo rm -f /etc/systemd/system/sentinel-safe-draft-autonomy.timer",
                "   #   sudo systemctl daemon-reload",
                "   ```",
                "4. **emergency-stop setzen**:",
                "   `python3 sentinel_autonomy_runtime_lock.py emergency-stop`",
                "5. **Master + Verifier erneut laufen lassen**:",
                "   `python3 sentinel_safe_draft_autonomy_verifier.py && python3 sentinel_master.py`",
                "",
                "## Hinweis",
                "",
                "- Alle systemd-Befehle oben sind **nur Review-Text** und werden von diesem Modul nie ausgefuehrt.",
                f"- {DRAFT_BANNER}.",
                "",
            ]
        )
        + "\n"
    )


def build_environment_lines() -> List[str]:
    """Environment lines embedded in the draft. Always secret-free by design."""
    return ["# (no Environment= lines; no secrets, no credentials)"]


def build_draft_pack(signals: Dict[str, Any], generated: str) -> Dict[str, Any]:
    status, blocked_reason = determine_timer_draft_status(signals)
    service_text = render_service_draft(generated)
    timer_text = render_timer_draft(generated)
    install_text = render_install_review(generated, signals, status)
    rollback_text = render_rollback_review(generated, status)
    return {
        "timer_draft_status": status,
        "blocked_reason": blocked_reason,
        "draft_banner": DRAFT_BANNER,
        "environment_lines": build_environment_lines(),
        # Executable-command positions are intentionally EMPTY: the draft service
        # keeps every ExecStart commented out, so nothing can run if mis-copied.
        "executable_commands": [],
        "documented_safe_sequence": list(SAFE_SEQUENCE_COMMANDS),
        "service_draft": {"path": str(SERVICE_DRAFT), "content": service_text},
        "timer_unit_draft": {"path": str(TIMER_DRAFT), "content": timer_text},
        "install_review": {"path": str(INSTALL_REVIEW_MD), "content": install_text},
        "rollback_review": {"path": str(ROLLBACK_REVIEW_MD), "content": rollback_text},
        "timer_installation_status": TIMER_NOT_INSTALLED,
        "can_install_timer_now": False,
        "can_execute_live": False,
        "live_apply": False,
        "apply_status": APPLY_NOT_APPLIED,
        "owner_review_required": True,
    }


def timer_draft_breach(pack: Dict[str, Any]) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    if pack.get("timer_installation_status") != TIMER_NOT_INSTALLED:
        reasons.append("timer_installation_status != not_installed")
    if _as_bool(pack.get("can_install_timer_now")):
        reasons.append("can_install_timer_now is true")
    if _as_bool(pack.get("can_execute_live")):
        reasons.append("can_execute_live is true")
    if _as_bool(pack.get("live_apply")):
        reasons.append("live_apply is true")
    if pack.get("apply_status") != APPLY_NOT_APPLIED:
        reasons.append("apply_status != not_applied")

    # Every draft file must be written under drafts/apply (never /etc/systemd, /etc/cron).
    for key in ("service_draft", "timer_unit_draft", "install_review", "rollback_review"):
        entry = pack.get(key) if isinstance(pack.get(key), dict) else {}
        raw = str(entry.get("path", ""))
        lower = raw.lower()
        if any(token in lower for token in FORBIDDEN_INSTALL_PATH_TOKENS):
            reasons.append(f"{key}: real systemd/cron install path detected ({redact_text(raw, max_len=120)})")
        if not within_allowed_roots(Path(raw)):
            reasons.append(f"{key}: path outside allowed roots ({redact_text(raw, max_len=120)})")
        if not is_within(Path(raw), PROJECT_DIR / "drafts/apply"):
            # service/timer/install/rollback drafts must specifically live under drafts/apply
            reasons.append(f"{key}: draft not under drafts/apply ({redact_text(raw, max_len=120)})")

    # Executable command positions must be empty and free of prohibited/live/network tokens.
    for command in pack.get("executable_commands", []) or []:
        lower = str(command).lower()
        for token in PROHIBITED_COMMAND_TOKENS:
            if token in lower:
                reasons.append(f"executable command prohibited token: {token.strip()}")
        for token in LIVE_APPLY_TOKENS:
            if token in lower:
                reasons.append(f"executable command live-apply token: {token.strip()}")
        for token in NETWORK_LOGIN_TOKENS:
            if token in lower:
                reasons.append(f"executable command network/API/login token: {token.strip()}")

    # Environment lines must never carry secret-like values.
    for line in pack.get("environment_lines", []) or []:
        if detect_secret_in_text(str(line)):
            reasons.append("Environment line contains a secret-like value")

    # Defensive: scan generated draft CONTENT for any active (uncommented) systemctl
    # ExecStart and for secrets.
    for key in ("service_draft", "timer_unit_draft", "install_review", "rollback_review"):
        entry = pack.get(key) if isinstance(pack.get(key), dict) else {}
        content = str(entry.get("content", ""))
        if detect_secret_in_text(content):
            reasons.append(f"{key}: secret-like value in draft content")
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.lower().startswith("execstart="):
                # An active (uncommented) ExecStart must only reference the safe sequence.
                lowered = stripped.lower()
                if any(token in lowered for token in PROHIBITED_COMMAND_TOKENS + LIVE_APPLY_TOKENS):
                    reasons.append(f"{key}: active ExecStart contains a prohibited/live-apply command")
    return bool(reasons), reasons


def build_report(
    signals: Dict[str, Any],
    input_statuses: Dict[str, str],
    generated_at: Optional[str] = None,
    write_files: bool = False,
) -> Dict[str, Any]:
    generated = generated_at or utc_now()
    pack = build_draft_pack(signals, generated)

    files_written = {
        "service_draft_written": False,
        "timer_draft_written": False,
        "install_review_written": False,
        "rollback_review_written": False,
    }
    # The four draft files are pure review-only text under drafts/apply and never
    # install anything; they always carry the DRAFT banner and the install-review
    # states the preconditions. They are written regardless of the blocked status
    # (the status communicates whether a future install is even considerable).
    if write_files:
        write_text_atomic(SERVICE_DRAFT, pack["service_draft"]["content"])
        write_text_atomic(TIMER_DRAFT, pack["timer_unit_draft"]["content"])
        write_text_atomic(INSTALL_REVIEW_MD, pack["install_review"]["content"])
        write_text_atomic(ROLLBACK_REVIEW_MD, pack["rollback_review"]["content"])
        files_written = {
            "service_draft_written": True,
            "timer_draft_written": True,
            "install_review_written": True,
            "rollback_review_written": True,
        }

    breach, breach_reasons = timer_draft_breach(pack)
    timer_draft_status = pack["timer_draft_status"]
    status = TIMER_DRAFT_WARNING if breach else timer_draft_status

    summary = {
        "timer_draft_status": timer_draft_status,
        "service_draft_written": files_written["service_draft_written"],
        "timer_draft_written": files_written["timer_draft_written"],
        "install_review_written": files_written["install_review_written"],
        "rollback_review_written": files_written["rollback_review_written"],
        "timer_installation_status": TIMER_NOT_INSTALLED,
        "can_install_timer_now": False,
        "owner_review_required": True,
        "timer_draft_breach": breach,
        "timer_draft_breach_reasons": breach_reasons,
        "blocked_reason": pack["blocked_reason"],
    }

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": generated,
        "status": status,
        "timer_draft_status": timer_draft_status,
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
        "owner_review_required": True,
        "service_draft_written": files_written["service_draft_written"],
        "timer_draft_written": files_written["timer_draft_written"],
        "install_review_written": files_written["install_review_written"],
        "rollback_review_written": files_written["rollback_review_written"],
        "timer_draft_breach": breach,
        "blocked_reason": pack["blocked_reason"],
        "signals": signals,
        "draft_banner": DRAFT_BANNER,
        "documented_safe_sequence": pack["documented_safe_sequence"],
        "allowed_write_roots": [str(path) for path in ALLOWED_WRITE_ROOTS],
        "input_statuses": input_statuses,
        "summary": summary,
        "draft_paths": {
            "service_draft": str(SERVICE_DRAFT),
            "timer_draft": str(TIMER_DRAFT),
            "install_review": str(INSTALL_REVIEW_MD),
            "rollback_review": str(ROLLBACK_REVIEW_MD),
        },
        "outputs": {
            "report_json": str(REPORT_JSON),
            "report_md": str(REPORT_MD),
            "audit_jsonl": str(AUDIT_JSONL),
        },
    }


def render_report_markdown(report: Dict[str, Any]) -> str:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    signals = report.get("signals") if isinstance(report.get("signals"), dict) else {}
    draft_paths = report.get("draft_paths") if isinstance(report.get("draft_paths"), dict) else {}
    lines = [
        "# Safe Draft Autonomy Timer Draft Report",
        "",
        f"- Generated (UTC): `{report.get('generated_at_utc')}`",
        f"- Status: `{report.get('status')}`",
        f"- Timer draft status: `{report.get('timer_draft_status')}`",
        f"- Timer installation status: `{report.get('timer_installation_status')}`",
        f"- Can install timer now: `{report.get('can_install_timer_now')}`",
        f"- Can execute live: `{report.get('can_execute_live')}`",
        f"- Service draft written: `{summary.get('service_draft_written')}`",
        f"- Timer draft written: `{summary.get('timer_draft_written')}`",
        f"- Install review written: `{summary.get('install_review_written')}`",
        f"- Rollback review written: `{summary.get('rollback_review_written')}`",
        f"- systemd file written: `{report.get('systemd_file_written')}`",
        f"- crontab file written: `{report.get('crontab_file_written')}`",
        f"- Owner review required: `{report.get('owner_review_required')}`",
        f"- Timer draft breach: `{summary.get('timer_draft_breach')}`",
        f"- Blocked reason: `{redact_text(report.get('blocked_reason'), max_len=200)}`",
        "",
        "## Draft Files (review-only, under drafts/apply)",
        "",
    ]
    for key in ("service_draft", "timer_draft", "install_review", "rollback_review"):
        lines.append(f"- {key}: `{redact_text(draft_paths.get(key), max_len=160)}`")
    lines.extend(["", "## Documented Safe Sequence (commented in the service draft)", ""])
    for command in report.get("documented_safe_sequence", []):
        lines.append(f"- `{redact_text(command, max_len=120)}`")
    lines.extend(["", "## Signals (current)", ""])
    for key in ("emergency_stop", "scheduler_breach", "runtime_lock_breach", "verifier_breach", "runner_breach"):
        lines.append(f"- {key}: `{signals.get(key)}`")
    lines.extend(
        [
            "",
            "## Sicherheitsgrenzen",
            "",
            "- Nur Draft-Erzeugung; kein aktiver Timer, kein systemctl, keine echte systemd-/crontab-Datei.",
            "- Keine Live-Aenderungen, keine Live-Apply-Funktion.",
            "- Keine WordPress-, .htaccess-, Cloudflare-, Nginx- oder DNS-Aenderung.",
            "- Kein WordPress-Login, keine API, kein Netzwerkzugriff, keine externen Schreibzugriffe.",
            "- Keine Secrets/Cookies/Auth oder Environment-Credentials speichern oder ausgeben.",
            "- `apply_status=not_applied`, `can_execute_live=false`, `timer_installation_status=not_installed`, "
            "`can_install_timer_now=false`.",
            "- Schreibzugriff nur unter drafts/apply, drafts/owner, reports/latest, audit.",
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
            "record_type": "timer_draft",
            "timer_draft_status": report.get("timer_draft_status"),
            "status": report.get("status"),
            "service_draft_written": summary.get("service_draft_written"),
            "timer_draft_written": summary.get("timer_draft_written"),
            "install_review_written": summary.get("install_review_written"),
            "rollback_review_written": summary.get("rollback_review_written"),
            "timer_installation_status": report.get("timer_installation_status"),
            "can_install_timer_now": report.get("can_install_timer_now"),
            "systemd_file_written": report.get("systemd_file_written"),
            "crontab_file_written": report.get("crontab_file_written"),
            "timer_draft_breach": summary.get("timer_draft_breach"),
            "blocked_reason": summary.get("blocked_reason"),
            "live_apply": False,
            "productive_change": False,
            "network_access": False,
        }
    ]


def write_outputs(report: Dict[str, Any]) -> None:
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, render_report_markdown(report))
    append_jsonl(AUDIT_JSONL, audit_records(report))


def load_inputs() -> Tuple[Dict[str, Any], Dict[str, str]]:
    plan, plan_status = read_json_status(INPUT_SCHEDULER_PLAN)
    lock, lock_status = read_json_status(INPUT_RUNTIME_LOCK)
    verifier, verifier_status = read_json_status(INPUT_VERIFIER_REPORT)
    runner, runner_status = read_json_status(INPUT_RUNNER_REPORT)
    master, master_status = read_json_status(INPUT_MASTER)
    statuses = {
        "safe_draft_autonomy_scheduler_plan": plan_status,
        "autonomy_runtime_lock": lock_status,
        "safe_draft_autonomy_verifier_report": verifier_status,
        "safe_draft_autonomy_runner_report": runner_status,
        "sentinel_master": master_status,
    }
    signals = gather_signals(
        plan if isinstance(plan, dict) else None,
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
        "scheduler_plan_available": True,
        "scheduler_status": "SCHEDULER_PLAN_READY_FOR_OWNER_REVIEW",
        "scheduler_breach": False,
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
    }
    base.update(overrides)
    return base


def run_self_test() -> int:
    statuses = {"safe_draft_autonomy_scheduler_plan": "ok"}

    # 1) Ready (no file writes in self-test) -> READY, no breach, all invariants safe.
    ready = build_report(_ready_signals(), statuses, "2026-06-11T00:00:00Z")
    if ready["timer_draft_status"] != TIMER_DRAFT_READY:
        raise AssertionError("ready signals did not produce READY_FOR_OWNER_REVIEW")
    if ready["summary"]["timer_draft_breach"]:
        raise AssertionError("clean draft pack must not breach")
    if ready["timer_installation_status"] != TIMER_NOT_INSTALLED or ready["can_install_timer_now"]:
        raise AssertionError("ready draft must not be installable")
    if ready["systemd_file_written"] or ready["crontab_file_written"]:
        raise AssertionError("no systemd/crontab file may be written")

    # Status mapping per blocking signal.
    if build_report(_ready_signals(emergency_stop=True), statuses, "t")["timer_draft_status"] != TIMER_DRAFT_BLOCKED_EMERGENCY:
        raise AssertionError("emergency stop did not block")
    if build_report(_ready_signals(scheduler_breach=True), statuses, "t")["timer_draft_status"] != TIMER_DRAFT_BLOCKED_SCHEDULER:
        raise AssertionError("scheduler breach did not block")
    if build_report(_ready_signals(runtime_lock_breach=True), statuses, "t")["timer_draft_status"] != TIMER_DRAFT_BLOCKED_RUNTIME:
        raise AssertionError("runtime breach did not block")
    if build_report(_ready_signals(autonomy_policy_breach=True), statuses, "t")["timer_draft_status"] != TIMER_DRAFT_BLOCKED_RUNTIME:
        raise AssertionError("autonomy policy breach did not map to runtime block")
    if build_report(_ready_signals(verifier_breach=True), statuses, "t")["timer_draft_status"] != TIMER_DRAFT_BLOCKED_VERIFIER:
        raise AssertionError("verifier breach did not block")
    if build_report(_ready_signals(runner_breach=True), statuses, "t")["timer_draft_status"] != TIMER_DRAFT_BLOCKED_RUNNER:
        raise AssertionError("runner breach did not block")

    # 2) Real systemd .service path -> breach.
    pack = build_draft_pack(_ready_signals(), "t")
    pack["service_draft"] = {"path": "/etc/systemd/system/sentinel.service", "content": "x"}
    if not timer_draft_breach(pack)[0]:
        raise AssertionError("/etc/systemd/system/*.service write did not breach")

    # 3) Real systemd .timer path -> breach.
    pack = build_draft_pack(_ready_signals(), "t")
    pack["timer_unit_draft"] = {"path": "/etc/systemd/system/sentinel.timer", "content": "x"}
    if not timer_draft_breach(pack)[0]:
        raise AssertionError("/etc/systemd/system/*.timer write did not breach")

    # 4) crontab path -> breach.
    pack = build_draft_pack(_ready_signals(), "t")
    pack["install_review"] = {"path": "/etc/cron.d/sentinel", "content": "x"}
    if not timer_draft_breach(pack)[0]:
        raise AssertionError("/etc/cron.d write did not breach")

    # 5) systemctl enable/start in executable position -> breach.
    pack = build_draft_pack(_ready_signals(), "t")
    pack["executable_commands"] = ["systemctl enable sentinel.timer"]
    if not timer_draft_breach(pack)[0]:
        raise AssertionError("systemctl in executable position did not breach")

    # 6) Prohibited network/live commands in executable position -> breach.
    for cmd in ["curl https://x", "wget https://x", "wp plugin install x", "ssh host",
                "git push origin", "nginx reload", "cloudflare api call",
                "python3 sentinel_defense_bot.py --mode apply-safe --confirm-apply"]:
        pack = build_draft_pack(_ready_signals(), "t")
        pack["executable_commands"] = [cmd]
        if not timer_draft_breach(pack)[0]:
            raise AssertionError(f"executable command did not breach: {cmd}")

    # 7) can_install_timer_now -> breach.
    pack = build_draft_pack(_ready_signals(), "t")
    pack["can_install_timer_now"] = True
    if not timer_draft_breach(pack)[0]:
        raise AssertionError("can_install_timer_now did not breach")

    # 8) timer_installation_status != not_installed -> breach.
    pack = build_draft_pack(_ready_signals(), "t")
    pack["timer_installation_status"] = "installed"
    if not timer_draft_breach(pack)[0]:
        raise AssertionError("installed status did not breach")

    # 9) live_apply / apply_status -> breach.
    pack = build_draft_pack(_ready_signals(), "t")
    pack["live_apply"] = True
    if not timer_draft_breach(pack)[0]:
        raise AssertionError("live_apply did not breach")
    pack = build_draft_pack(_ready_signals(), "t")
    pack["apply_status"] = "applied"
    if not timer_draft_breach(pack)[0]:
        raise AssertionError("apply_status change did not breach")

    # 10) secret-like Environment -> breach.
    pack = build_draft_pack(_ready_signals(), "t")
    pack["environment_lines"] = ["Environment=API_KEY=sk-0123456789abcdef0123"]
    if not timer_draft_breach(pack)[0]:
        raise AssertionError("secret-like Environment did not breach")

    # 11) active (uncommented) ExecStart with systemctl inside content -> breach.
    pack = build_draft_pack(_ready_signals(), "t")
    pack["service_draft"] = {"path": str(SERVICE_DRAFT),
                             "content": "[Service]\nExecStart=/usr/bin/systemctl restart nginx\n"}
    if not timer_draft_breach(pack)[0]:
        raise AssertionError("active prohibited ExecStart did not breach")

    # 12) The generated default service draft keeps all ExecStart commented -> no breach.
    default_pack = build_draft_pack(_ready_signals(), "t")
    if timer_draft_breach(default_pack)[0]:
        raise AssertionError("default generated draft pack must not breach")
    if "\nExecStart=" in default_pack["service_draft"]["content"]:
        raise AssertionError("default service draft must not contain an active ExecStart")
    if DRAFT_BANNER not in default_pack["service_draft"]["content"]:
        raise AssertionError("service draft must carry the DRAFT banner")
    if DRAFT_BANNER not in default_pack["timer_unit_draft"]["content"]:
        raise AssertionError("timer draft must carry the DRAFT banner")
    if "OnCalendar=daily" not in default_pack["timer_unit_draft"]["content"]:
        raise AssertionError("timer draft must use OnCalendar=daily")

    # 13) Missing scheduler plan must not crash -> default safe emergency block.
    empty_signals = gather_signals(None, None, None, None, None)
    empty = build_report(empty_signals, {"safe_draft_autonomy_scheduler_plan": "not_available"}, "t")
    if empty["timer_draft_status"] != TIMER_DRAFT_BLOCKED_EMERGENCY:
        raise AssertionError("missing inputs should default to emergency-stop block")
    if empty["summary"]["timer_draft_breach"]:
        raise AssertionError("missing inputs must not breach")

    # Forbidden write path for the module itself is rejected.
    try:
        assert_allowed_write(Path("/etc/systemd/system/sentinel.timer"))
    except ValueError:
        pass
    else:
        raise AssertionError("forbidden write path (/etc/systemd) was not rejected")

    print("safe-draft-autonomy-timer-draft self-tests: OK")
    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate review-only Safe Draft Autonomy systemd service/timer DRAFTS (no install, no live apply)."
    )
    parser.add_argument("--self-test", action="store_true", help="Run built-in safety tests and exit.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()
    signals, statuses = load_inputs()
    report = build_report(signals, statuses, write_files=True)
    write_outputs(report)
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    print(
        "Safe Draft Autonomy Timer Draft: "
        f"status={report.get('timer_draft_status')}, "
        f"installed={report.get('timer_installation_status')}, "
        f"service_draft={summary.get('service_draft_written')}, "
        f"timer_draft={summary.get('timer_draft_written')}, "
        f"breach={summary.get('timer_draft_breach')}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
