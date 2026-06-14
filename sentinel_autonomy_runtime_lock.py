#!/usr/bin/env python3
"""Sentinel Autonomy Runtime Lock + Owner Disable Switch (Phase 3.5).

Maintains a single owner-controlled runtime lock that decides whether future
autonomous actions would be allowed, paused, or blocked. This is not an apply
mechanism: it only defines the global safety state for later autonomy.

Hard safety guarantees (enforced structurally):
- No live changes; no apply function exists in this module.
- Never edits WordPress files, .htaccess, Cloudflare rules, or Nginx config.
- No external writes, no network access, no WordPress login, no API calls.
- No secrets/cookies/auth values are stored or printed.
- All candidates stay apply_status=not_applied.
- Writes are confined to config, drafts/apply, reports/latest, and audit.
- There is deliberately NO enable-live-apply / enable-wordpress-write /
  enable-cloudflare-change command, and one can never be added safely.
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

LOCK_JSON = PROJECT_DIR / "config/autonomy-runtime-lock.json"
REPORT_JSON = PROJECT_DIR / "reports/latest/autonomy-runtime-lock-report.json"
REPORT_MD = PROJECT_DIR / "reports/latest/autonomy-runtime-lock-report.md"
SUMMARY_MD = PROJECT_DIR / "drafts/apply/autonomy-runtime-lock-summary.md"
AUDIT_JSONL = PROJECT_DIR / "audit/autonomy-runtime-lock.jsonl"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "config",
    PROJECT_DIR / "drafts/apply",
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "audit",
)

SCHEMA_VERSION = "autonomy-runtime-lock-3.5"

APPLY_NOT_APPLIED = "not_applied"

# Autonomy levels (aligned with sentinel_autonomy_policy.py).
LEVEL_0_READ_ONLY = "LEVEL_0_READ_ONLY"
LEVEL_1_DRAFT_ONLY = "LEVEL_1_DRAFT_ONLY"
LEVEL_2_SUPERVISED_LOW_RISK = "LEVEL_2_SUPERVISED_LOW_RISK"
LEVEL_3_GUARDED_AUTONOMOUS_LOW_RISK = "LEVEL_3_GUARDED_AUTONOMOUS_LOW_RISK"
LEVEL_4_ADAPTIVE_SAFE_AUTONOMY = "LEVEL_4_ADAPTIVE_SAFE_AUTONOMY"

VALID_LEVELS = {
    LEVEL_0_READ_ONLY,
    LEVEL_1_DRAFT_ONLY,
    LEVEL_2_SUPERVISED_LOW_RISK,
    LEVEL_3_GUARDED_AUTONOMOUS_LOW_RISK,
    LEVEL_4_ADAPTIVE_SAFE_AUTONOMY,
}

# Emergency stop may only be lifted at these (low) autonomy levels.
LEVELS_ALLOWING_NO_EMERGENCY = {LEVEL_0_READ_ONLY, LEVEL_1_DRAFT_ONLY, LEVEL_2_SUPERVISED_LOW_RISK}

ALLOWED_MODE_DRAFT_ONLY = "draft_only"
ALLOWED_MODE_VALIDATION_ONLY = "validation_only"
SAFE_ALLOWED_MODES = [ALLOWED_MODE_DRAFT_ONLY, ALLOWED_MODE_VALIDATION_ONLY]

BLOCKED_MODES = [
    "live_apply",
    "wordpress_write",
    "cloudflare_change",
    "nginx_change",
    "htaccess_change",
    "dns_change",
    "external_network_call",
    "browser_automation",
    "cms_login",
]
BLOCKED_MODE_SET = set(BLOCKED_MODES)

# Commands that must never exist. Used only to assert their absence.
FORBIDDEN_COMMANDS = {
    "enable-live-apply",
    "enable-wordpress-write",
    "enable-cloudflare-change",
    "enable-nginx-change",
    "enable-htaccess-change",
}

VALID_COMMANDS = ("status", "enable-draft-only", "pause", "emergency-stop", "comment")

SECRETISH_RE = re.compile(
    r"(?i)(api[_-]?key|token|secret|password|passwd|bearer|authorization|"
    r"cookie|set-cookie|credential|x-api-key|access[_-]?key|session)"
)
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|token|secret|password|passwd|bearer|authorization|"
    r"cookie|credential|session)\s*[:=]\s*[^\s,;]+"
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
    text = SECRET_ASSIGNMENT_RE.sub(lambda match: f"{match.group(1)}=<redacted>", text)
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
    except ValueError:
        return False


def assert_allowed_write(path: Path) -> None:
    if not any(is_within(path, root) for root in ALLOWED_WRITE_ROOTS):
        raise ValueError(f"Refusing to write outside allowed runtime-lock roots: {path}")


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


def normalize_level(value: Any) -> str:
    level = str(value or "").strip().upper()
    return level if level in VALID_LEVELS else LEVEL_1_DRAFT_ONLY


def default_lock() -> Dict[str, Any]:
    """The safe default runtime lock: autonomy off, draft/validation prepared only."""
    return {
        "autonomy_enabled": False,
        "draft_only_enabled": True,
        "validation_only_enabled": True,
        "live_apply_enabled": False,
        "owner_disable_switch": True,
        "emergency_stop": True,
        "max_autonomy_level": LEVEL_1_DRAFT_ONLY,
        "allowed_modes": list(SAFE_ALLOWED_MODES),
        "blocked_modes": list(BLOCKED_MODES),
        "apply_status": APPLY_NOT_APPLIED,
        "last_owner_lock_action": {
            "command": "default_initialized",
            "note": "-",
            "timestamp_utc": utc_now(),
        },
    }


def coerce_lock(raw: Any) -> Dict[str, Any]:
    """Coerce a loaded lock into a safe, fully-populated structure.

    Live-apply is always forced off and the blocked modes are always restored,
    so a tampered file can never silently enable a live apply path.
    """
    lock = default_lock()
    if not isinstance(raw, dict):
        return lock
    for key in (
        "autonomy_enabled",
        "draft_only_enabled",
        "validation_only_enabled",
        "owner_disable_switch",
        "emergency_stop",
    ):
        if key in raw:
            lock[key] = bool(raw.get(key))
    # live_apply_enabled is NEVER honored from disk; it is structurally off.
    lock["live_apply_enabled"] = False
    lock["max_autonomy_level"] = normalize_level(raw.get("max_autonomy_level"))
    # allowed_modes may only ever contain the two safe modes.
    raw_allowed = raw.get("allowed_modes")
    if isinstance(raw_allowed, list):
        lock["allowed_modes"] = [mode for mode in SAFE_ALLOWED_MODES if mode in raw_allowed]
    # blocked_modes are always the full canonical list.
    lock["blocked_modes"] = list(BLOCKED_MODES)
    lock["apply_status"] = APPLY_NOT_APPLIED
    last_action = raw.get("last_owner_lock_action")
    if isinstance(last_action, dict):
        lock["last_owner_lock_action"] = {
            "command": redact_text(last_action.get("command"), max_len=80),
            "note": redact_text(last_action.get("note"), max_len=400),
            "timestamp_utc": redact_text(last_action.get("timestamp_utc"), max_len=40),
        }
    return lock


def load_lock() -> Tuple[Dict[str, Any], str]:
    if SECRETISH_RE.search(LOCK_JSON.name):
        return default_lock(), "refused_secret_like_path"
    try:
        if not LOCK_JSON.exists():
            return default_lock(), "created_default"
        raw = json.loads(LOCK_JSON.read_text(encoding="utf-8"))
        return coerce_lock(raw), "loaded"
    except (OSError, ValueError, json.JSONDecodeError):
        return default_lock(), "invalid_reset_to_default"


def record_owner_action(lock: Dict[str, Any], command: str, note: Optional[str]) -> None:
    lock["last_owner_lock_action"] = {
        "command": redact_text(command, max_len=80),
        "note": redact_text(note, max_len=400),
        "timestamp_utc": utc_now(),
    }


def apply_command(lock: Dict[str, Any], command: str, note: Optional[str]) -> Dict[str, Any]:
    """Apply an owner command to the lock state. Never enables live apply."""
    if command == "enable-draft-only":
        lock["autonomy_enabled"] = True
        lock["draft_only_enabled"] = True
        lock["validation_only_enabled"] = True
        lock["live_apply_enabled"] = False
        lock["owner_disable_switch"] = True
        # Owner may lift the emergency stop, but only for draft/validation-only.
        lock["emergency_stop"] = False
        lock["max_autonomy_level"] = LEVEL_1_DRAFT_ONLY
        lock["allowed_modes"] = list(SAFE_ALLOWED_MODES)
    elif command == "pause":
        lock["autonomy_enabled"] = False
        lock["draft_only_enabled"] = False
        lock["validation_only_enabled"] = False
        lock["live_apply_enabled"] = False
        lock["owner_disable_switch"] = True
        lock["emergency_stop"] = True
        lock["allowed_modes"] = []
    elif command == "emergency-stop":
        lock["autonomy_enabled"] = False
        lock["draft_only_enabled"] = False
        lock["validation_only_enabled"] = False
        lock["live_apply_enabled"] = False
        lock["owner_disable_switch"] = True
        lock["emergency_stop"] = True
        lock["allowed_modes"] = []
    # "comment" and "status" do not change any flag.
    # live_apply is structurally impossible to enable here.
    lock["live_apply_enabled"] = False
    lock["blocked_modes"] = list(BLOCKED_MODES)
    lock["apply_status"] = APPLY_NOT_APPLIED
    record_owner_action(lock, command, note)
    return lock


def compute_breach(lock: Dict[str, Any]) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    if lock.get("live_apply_enabled") is True:
        reasons.append("live_apply_enabled is true")
    if lock.get("owner_disable_switch") is not True:
        reasons.append("owner_disable_switch is not true")
    if lock.get("emergency_stop") is False:
        level = normalize_level(lock.get("max_autonomy_level"))
        if lock.get("live_apply_enabled") is True or level not in LEVELS_ALLOWING_NO_EMERGENCY:
            reasons.append("emergency_stop=false is not permitted at this level / with live apply")
    allowed = lock.get("allowed_modes") if isinstance(lock.get("allowed_modes"), list) else []
    for mode in allowed:
        if mode in BLOCKED_MODE_SET:
            reasons.append(f"blocked mode '{mode}' present in allowed_modes")
    if normalize_level(lock.get("max_autonomy_level")) not in VALID_LEVELS:
        reasons.append("invalid max_autonomy_level")
    if lock.get("apply_status") != APPLY_NOT_APPLIED:
        reasons.append("apply_status != not_applied in lock output")
    # A forbidden command must never be exposed by the CLI.
    if forbidden_command_present():
        reasons.append("forbidden enable-live-apply style command exists")
    return bool(reasons), reasons


def forbidden_command_present() -> bool:
    """True if any forbidden command is registered on the CLI (must be False)."""
    parser = build_parser()
    registered = set()
    for action in parser._subparsers._actions if parser._subparsers else []:  # type: ignore[attr-defined]
        choices = getattr(action, "choices", None)
        if isinstance(choices, dict):
            registered.update(choices.keys())
    return bool(registered & FORBIDDEN_COMMANDS)


def build_report(lock: Dict[str, Any], lock_load_status: str, generated_at: Optional[str] = None) -> Dict[str, Any]:
    generated = generated_at or utc_now()
    breach, breach_reasons = compute_breach(lock)
    status = "RUNTIME_LOCK_WARNING" if breach else "OK"
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": generated,
        "status": status,
        "read_only": True,
        "network_access": False,
        "wordpress_login": False,
        "api_access": False,
        "apply_function": False,
        "productive_change": False,
        "secrets_output": False,
        "lock_load_status": lock_load_status,
        "allowed_write_roots": [str(path) for path in ALLOWED_WRITE_ROOTS],
        "valid_commands": list(VALID_COMMANDS),
        "forbidden_commands": sorted(FORBIDDEN_COMMANDS),
        "forbidden_command_present": forbidden_command_present(),
        # Report fields (Phase 3.5).
        "autonomy_enabled": bool(lock.get("autonomy_enabled")),
        "draft_only_enabled": bool(lock.get("draft_only_enabled")),
        "validation_only_enabled": bool(lock.get("validation_only_enabled")),
        "live_apply_enabled": bool(lock.get("live_apply_enabled")),
        "owner_disable_switch": bool(lock.get("owner_disable_switch")),
        "emergency_stop": bool(lock.get("emergency_stop")),
        "max_autonomy_level": normalize_level(lock.get("max_autonomy_level")),
        "allowed_modes": lock.get("allowed_modes") if isinstance(lock.get("allowed_modes"), list) else [],
        "blocked_modes": lock.get("blocked_modes") if isinstance(lock.get("blocked_modes"), list) else list(BLOCKED_MODES),
        "last_owner_lock_action": lock.get("last_owner_lock_action"),
        "apply_status": APPLY_NOT_APPLIED,
        "runtime_lock_breach": breach,
        "runtime_lock_breach_reasons": breach_reasons,
        "outputs": {
            "lock_json": str(LOCK_JSON),
            "report_json": str(REPORT_JSON),
            "report_md": str(REPORT_MD),
            "summary_md": str(SUMMARY_MD),
            "audit_jsonl": str(AUDIT_JSONL),
        },
    }


def render_markdown(report: Dict[str, Any], *, title: str) -> str:
    last_action = report.get("last_owner_lock_action") if isinstance(report.get("last_owner_lock_action"), dict) else {}
    lines = [
        f"# {title}",
        "",
        f"- Generated (UTC): `{report.get('generated_at_utc')}`",
        f"- Status: `{report.get('status')}`",
        f"- Autonomy enabled: `{report.get('autonomy_enabled')}`",
        f"- Draft-only enabled: `{report.get('draft_only_enabled')}`",
        f"- Validation-only enabled: `{report.get('validation_only_enabled')}`",
        f"- Live apply enabled: `{report.get('live_apply_enabled')}`",
        f"- Owner disable switch: `{report.get('owner_disable_switch')}`",
        f"- Emergency stop: `{report.get('emergency_stop')}`",
        f"- Max autonomy level: `{report.get('max_autonomy_level')}`",
        f"- Runtime lock breach: `{report.get('runtime_lock_breach')}`",
        "",
        "## Allowed Modes",
        "",
    ]
    for mode in report.get("allowed_modes", []) or ["-"]:
        lines.append(f"- `{redact_text(mode, max_len=80)}`")
    lines.extend(["", "## Blocked Modes", ""])
    for mode in report.get("blocked_modes", []):
        lines.append(f"- `{redact_text(mode, max_len=80)}`")
    lines.extend(
        [
            "",
            "## Last Owner Lock Action",
            "",
            f"- Command: `{redact_text(last_action.get('command'), max_len=80)}`",
            f"- Note: {redact_text(last_action.get('note'), max_len=300)}",
            f"- Timestamp (UTC): `{redact_text(last_action.get('timestamp_utc'), max_len=40)}`",
            "",
            "## Sicherheitsgrenzen",
            "",
            "- Keine Live-Aenderungen, keine Apply-Funktion, kein Apply-Mechanismus.",
            "- `enable-live-apply` / `enable-wordpress-write` / `enable-cloudflare-change` existieren nicht.",
            "- Keine WordPress-, .htaccess-, Cloudflare-, Nginx- oder DNS-Aenderung.",
            "- Kein WordPress-Login, keine API, kein Netzwerkzugriff, keine externen Schreibzugriffe.",
            "- Keine Secrets/Cookies/Auth speichern oder ausgeben.",
            "- `apply_status` bleibt immer `not_applied`; `owner_disable_switch` bleibt verfuegbar.",
            "- Schreibzugriff nur unter `config`, `drafts/apply`, `reports/latest`, `audit`.",
            "",
        ]
    )
    return "\n".join(lines)


def audit_record(report: Dict[str, Any], command: str) -> Dict[str, Any]:
    return {
        "timestamp_utc": report.get("generated_at_utc"),
        "schema_version": SCHEMA_VERSION,
        "command": redact_text(command, max_len=80),
        "status": report.get("status"),
        "autonomy_enabled": report.get("autonomy_enabled"),
        "draft_only_enabled": report.get("draft_only_enabled"),
        "validation_only_enabled": report.get("validation_only_enabled"),
        "live_apply_enabled": report.get("live_apply_enabled"),
        "owner_disable_switch": report.get("owner_disable_switch"),
        "emergency_stop": report.get("emergency_stop"),
        "max_autonomy_level": report.get("max_autonomy_level"),
        "runtime_lock_breach": report.get("runtime_lock_breach"),
        "apply_function": False,
        "productive_change": False,
        "network_access": False,
    }


def persist_lock_state(lock: Dict[str, Any]) -> None:
    """Write only the canonical lock state to config (no transient report fields)."""
    state = {
        "schema_version": SCHEMA_VERSION,
        "autonomy_enabled": bool(lock.get("autonomy_enabled")),
        "draft_only_enabled": bool(lock.get("draft_only_enabled")),
        "validation_only_enabled": bool(lock.get("validation_only_enabled")),
        "live_apply_enabled": False,
        "owner_disable_switch": bool(lock.get("owner_disable_switch")),
        "emergency_stop": bool(lock.get("emergency_stop")),
        "max_autonomy_level": normalize_level(lock.get("max_autonomy_level")),
        "allowed_modes": lock.get("allowed_modes") if isinstance(lock.get("allowed_modes"), list) else [],
        "blocked_modes": list(BLOCKED_MODES),
        "apply_status": APPLY_NOT_APPLIED,
        "last_owner_lock_action": lock.get("last_owner_lock_action"),
    }
    write_json_atomic(LOCK_JSON, state)


def write_outputs(lock: Dict[str, Any], report: Dict[str, Any], command: str) -> None:
    persist_lock_state(lock)
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, render_markdown(report, title="Autonomy Runtime Lock Report"))
    write_text_atomic(SUMMARY_MD, render_markdown(report, title="Autonomy Runtime Lock Summary"))
    append_jsonl(AUDIT_JSONL, [audit_record(report, command)])


def print_status(report: Dict[str, Any]) -> None:
    print(
        "Autonomy Runtime Lock: "
        f"autonomy_enabled={report.get('autonomy_enabled')}, "
        f"draft_only={report.get('draft_only_enabled')}, "
        f"validation_only={report.get('validation_only_enabled')}, "
        f"live_apply={report.get('live_apply_enabled')}, "
        f"emergency_stop={report.get('emergency_stop')}, "
        f"owner_disable_switch={report.get('owner_disable_switch')}, "
        f"level={report.get('max_autonomy_level')}, "
        f"breach={report.get('runtime_lock_breach')}"
    )


def run_command(command: str, note: Optional[str]) -> int:
    lock, load_status = load_lock()
    if command != "status":
        lock = apply_command(lock, command, note)
    else:
        # status still records who looked and refreshes the report.
        record_owner_action(lock, command, note)
    report = build_report(lock, load_status)
    write_outputs(lock, report, command)
    print_status(report)
    return 0


def run_self_test() -> int:
    # Default lock is safe and not a breach.
    lock = default_lock()
    report = build_report(lock, "created_default", "2026-06-10T00:00:00Z")
    if report["runtime_lock_breach"]:
        raise AssertionError("default lock unexpectedly reported a breach")
    if report["live_apply_enabled"] or report["autonomy_enabled"]:
        raise AssertionError("default lock must have live_apply and autonomy disabled")
    if not report["owner_disable_switch"] or not report["emergency_stop"]:
        raise AssertionError("default lock must keep disable switch and emergency stop on")

    # enable-draft-only: autonomy on, live_apply still off, no breach.
    draft = apply_command(default_lock(), "enable-draft-only", "owner allows draft-only")
    draft_report = build_report(draft, "loaded", "2026-06-10T00:01:00Z")
    if not draft_report["autonomy_enabled"] or not draft_report["draft_only_enabled"]:
        raise AssertionError("enable-draft-only did not enable draft autonomy")
    if draft_report["live_apply_enabled"]:
        raise AssertionError("enable-draft-only must not enable live apply")
    if draft_report["emergency_stop"] is not False:
        raise AssertionError("enable-draft-only should lift emergency stop for draft-only")
    if draft_report["runtime_lock_breach"]:
        raise AssertionError("draft-only at LEVEL_1 with emergency_stop=false must not breach")

    # pause: everything off, emergency stop on.
    paused = apply_command(default_lock(), "pause", "owner pause")
    paused_report = build_report(paused, "loaded", "2026-06-10T00:02:00Z")
    if paused_report["autonomy_enabled"] or paused_report["draft_only_enabled"] or paused_report["validation_only_enabled"]:
        raise AssertionError("pause did not disable autonomy/draft/validation")
    if not paused_report["emergency_stop"]:
        raise AssertionError("pause did not set emergency stop")
    if paused_report["allowed_modes"]:
        raise AssertionError("pause must clear allowed modes")
    if paused_report["runtime_lock_breach"]:
        raise AssertionError("pause state must not breach")

    # emergency-stop: blocks all.
    stopped = apply_command(default_lock(), "emergency-stop", "owner stop")
    stopped_report = build_report(stopped, "loaded", "2026-06-10T00:03:00Z")
    if not stopped_report["emergency_stop"] or stopped_report["autonomy_enabled"] or stopped_report["live_apply_enabled"]:
        raise AssertionError("emergency-stop did not block everything")
    if stopped_report["runtime_lock_breach"]:
        raise AssertionError("emergency-stop state must not breach")

    # comment: no flag change.
    commented = apply_command(coerce_lock(persist_state_dict(draft)), "comment", "just a note")
    if commented["autonomy_enabled"] is not True:
        raise AssertionError("comment must not change existing flags")
    if commented["last_owner_lock_action"]["command"] != "comment":
        raise AssertionError("comment did not record owner action")

    # Breach: live_apply_enabled true.
    bad_live = default_lock()
    bad_live["live_apply_enabled"] = True
    if not build_report(bad_live, "loaded", "2026-06-10T00:04:00Z")["runtime_lock_breach"]:
        raise AssertionError("live_apply_enabled=true did not raise runtime_lock_breach")

    # Breach: owner_disable_switch false.
    bad_switch = default_lock()
    bad_switch["owner_disable_switch"] = False
    if not build_report(bad_switch, "loaded", "2026-06-10T00:05:00Z")["runtime_lock_breach"]:
        raise AssertionError("owner_disable_switch=false did not raise runtime_lock_breach")

    # Breach: blocked mode in allowed_modes.
    bad_mode = default_lock()
    bad_mode["allowed_modes"] = ["draft_only", "live_apply"]
    if not build_report(bad_mode, "loaded", "2026-06-10T00:06:00Z")["runtime_lock_breach"]:
        raise AssertionError("blocked mode in allowed_modes did not raise runtime_lock_breach")

    # Breach: emergency_stop=false at a high level.
    bad_emergency = default_lock()
    bad_emergency["emergency_stop"] = False
    bad_emergency["max_autonomy_level"] = LEVEL_4_ADAPTIVE_SAFE_AUTONOMY
    if not build_report(bad_emergency, "loaded", "2026-06-10T00:07:00Z")["runtime_lock_breach"]:
        raise AssertionError("emergency_stop=false at high level did not raise runtime_lock_breach")

    # No forbidden command exists.
    if forbidden_command_present():
        raise AssertionError("a forbidden enable-live-apply style command is registered")
    parser = build_parser()
    registered = set()
    for action in parser._subparsers._actions if parser._subparsers else []:  # type: ignore[attr-defined]
        choices = getattr(action, "choices", None)
        if isinstance(choices, dict):
            registered.update(choices.keys())
    if "enable-live-apply" in registered:
        raise AssertionError("enable-live-apply must not be a valid command")

    # coerce_lock never honors live_apply from disk.
    coerced = coerce_lock({"live_apply_enabled": True, "allowed_modes": ["draft_only", "live_apply"]})
    if coerced["live_apply_enabled"] is not False:
        raise AssertionError("coerce_lock honored live_apply_enabled from disk")
    if "live_apply" in coerced["allowed_modes"]:
        raise AssertionError("coerce_lock kept a blocked mode in allowed_modes")

    # Forbidden write path is rejected.
    try:
        assert_allowed_write(PROJECT_DIR / "forbidden/autonomy-runtime-lock.json")
    except ValueError:
        pass
    else:
        raise AssertionError("forbidden write path was not rejected")

    print("autonomy-runtime-lock self-tests: OK")
    return 0


def persist_state_dict(lock: Dict[str, Any]) -> Dict[str, Any]:
    """Helper mirroring persist_lock_state output without writing (for tests)."""
    return {
        "autonomy_enabled": bool(lock.get("autonomy_enabled")),
        "draft_only_enabled": bool(lock.get("draft_only_enabled")),
        "validation_only_enabled": bool(lock.get("validation_only_enabled")),
        "live_apply_enabled": False,
        "owner_disable_switch": bool(lock.get("owner_disable_switch")),
        "emergency_stop": bool(lock.get("emergency_stop")),
        "max_autonomy_level": normalize_level(lock.get("max_autonomy_level")),
        "allowed_modes": lock.get("allowed_modes") if isinstance(lock.get("allowed_modes"), list) else [],
        "blocked_modes": list(BLOCKED_MODES),
        "apply_status": APPLY_NOT_APPLIED,
        "last_owner_lock_action": lock.get("last_owner_lock_action"),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Owner-controlled autonomy runtime lock (read-only, no apply).")
    parser.add_argument("--self-test", action="store_true", help="Run built-in safety tests and exit.")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("status", help="Show the current runtime lock.")
    for name, helptext in (
        ("enable-draft-only", "Allow draft-/report-/validation-only autonomy preparation."),
        ("pause", "Pause all autonomy preparation."),
        ("emergency-stop", "Block everything; set emergency stop."),
        ("comment", "Record an owner comment only."),
    ):
        p = sub.add_parser(name, help=helptext)
        p.add_argument("--note", default=None, help="Owner note (no secrets).")
    return parser


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    return build_parser().parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if getattr(args, "self_test", False):
        return run_self_test()
    command = getattr(args, "command", None)
    if not command:
        command = "status"
    note = getattr(args, "note", None)
    return run_command(command, note)


if __name__ == "__main__":
    sys.exit(main())
