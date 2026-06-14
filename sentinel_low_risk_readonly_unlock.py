#!/usr/bin/env python3
"""LOW-RISK Read-Only Automation Unlock (Phase 7.2).

Builds a separate read-only monitoring gate and timer draft packet while the
global Emergency Stop remains active for every write/apply path. This module
never installs a timer, never runs systemctl/crontab, never performs SFTP/DB
writes, and has no apply mode.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


PROJECT_DIR = Path("/srv/sentinel-defense")

INPUTS = {
    "low_risk_autonomy": PROJECT_DIR / "reports/latest/low-risk-autonomy.json",
    "safe_seo_performance_monitor": PROJECT_DIR / "reports/latest/safe-seo-performance-monitor.json",
    "policy_update": PROJECT_DIR / "reports/latest/sentinel-safe-autonomy-policy-update.md",
    "master_json": PROJECT_DIR / "reports/latest/sentinel-master-report.json",
    "master_md": PROJECT_DIR / "reports/latest/sentinel-master-report.md",
}

REPORT_JSON = PROJECT_DIR / "reports/latest/low-risk-readonly-unlock.json"
REPORT_MD = PROJECT_DIR / "reports/latest/low-risk-readonly-unlock.md"
OWNER_PACKET_MD = PROJECT_DIR / "reports/latest/low-risk-readonly-owner-install-packet.md"
BOT_LEARNING_JSON = PROJECT_DIR / "reports/latest/bot-learning-low-risk-autonomy.json"
BOT_LEARNING_MD = PROJECT_DIR / "reports/latest/bot-learning-low-risk-autonomy.md"
POLICY_UPDATE_MD = PROJECT_DIR / "reports/latest/sentinel-safe-autonomy-policy-update.md"
SNAPSHOT_DIR = PROJECT_DIR / "snapshots"
AUDIT_JSONL = PROJECT_DIR / "audit/low-risk-readonly-unlock.jsonl"

SERVICE_DRAFT = PROJECT_DIR / "deploy/systemd/sentinel-low-risk-readonly.service"
TIMER_DRAFT = PROJECT_DIR / "deploy/systemd/sentinel-low-risk-readonly.timer"
INSTALL_REVIEW = PROJECT_DIR / "deploy/systemd/install-sentinel-low-risk-readonly.review.sh"
UNINSTALL_REVIEW = PROJECT_DIR / "deploy/systemd/uninstall-sentinel-low-risk-readonly.review.sh"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "snapshots",
    PROJECT_DIR / "audit",
    PROJECT_DIR / "deploy/systemd",
)

STATUS_READY_OWNER_INSTALL = "LOW_RISK_READONLY_READY_BUT_OWNER_INSTALL_REQUIRED"
STATUS_TIMER_DRAFT_READY = "LOW_RISK_READONLY_TIMER_DRAFT_READY"
STATUS_BLOCKED = "LOW_RISK_READONLY_BLOCKED_BY_SAFETY"
STATUS_FAILED = "LOW_RISK_READONLY_FAILED"

SCHEMA_VERSION = "low-risk-readonly-unlock-7.2"

SECRET_NAME_RE = re.compile(r"(?i)(secret|key|token|password|passwd|api[_-]?key|credential|authorization|cookie|session|license)")
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|password|passwd|bearer|token|credential|session|"
    r"authorization|set-cookie|cookie|x-api-key|access[_-]?key|license)\b\s*[:=]\s*"
    r"[\"']?(?!false\b|true\b|null\b|none\b|not_applied\b|<redacted|-\b|0\b)"
    r"[A-Za-z0-9+/=_\-]{4,}"
)
LONG_HEX_RE = re.compile(r"\b[A-Fa-f0-9]{32,}\b")
FORBIDDEN_TIMER_COMMAND_RE = re.compile(
    r"(?i)(--apply\b|apply-safe|live-apply|sftp\b|ssh\b|scp\b|wp\s+|wp-cli|mysql\b|"
    r"cloudflare|nginx\b|systemctl\b|crontab\b|rm\s+-rf|curl\s+.*\|\s*(ba)?sh|wget\s+.*\|\s*(ba)?sh|"
    r"php\s+wp-|/etc/nginx|/etc/systemd|/var/spool/cron|wp-content)"
)
FORBIDDEN_OUTPUT_RE = re.compile(
    r"(?i)(live_apply\s*[:=]\s*true|install_allowed_now\s*[:=]\s*true|can_install_timer_now\s*[:=]\s*true|"
    r"systemd_file_written\s*[:=]\s*true|crontab_file_written\s*[:=]\s*true)"
)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def timestamp_tag() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError):
        return False


def redact_text(value: Any, default: str = "-", max_len: int = 1000) -> str:
    if value is None:
        return default
    text = str(value).replace("\r", " ").strip()
    text = SECRET_ASSIGNMENT_RE.sub("<redacted>", text)
    text = LONG_HEX_RE.sub("<redacted-hex>", text)
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text or default


def assert_allowed_write(path: Path) -> None:
    if not any(is_within(path, root) for root in ALLOWED_WRITE_ROOTS):
        raise ValueError(f"Refusing write outside allowed read-only unlock roots: {path}")
    if SECRET_NAME_RE.search(path.name):
        raise ValueError(f"Refusing secret-like output path: {path}")
    if path.suffix.lower() in {".service", ".timer", ".sh"} and not is_within(path, PROJECT_DIR / "deploy/systemd"):
        raise ValueError(f"Refusing service/timer/script outside deploy draft root: {path}")


def assert_safe_content(path: Path, content: str) -> None:
    if SECRET_ASSIGNMENT_RE.search(content) or LONG_HEX_RE.search(content):
        raise ValueError(f"Secret-like content refused for {path}")
    if FORBIDDEN_OUTPUT_RE.search(content):
        raise ValueError(f"Unsafe true flag refused for {path}")


def write_text_atomic(path: Path, content: str) -> None:
    assert_allowed_write(path)
    assert_safe_content(path, content)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)


def write_json_atomic(path: Path, data: Dict[str, Any]) -> None:
    write_text_atomic(path, json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def append_jsonl(path: Path, records: Iterable[Dict[str, Any]]) -> None:
    assert_allowed_write(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for record in records:
            text = json.dumps(record, ensure_ascii=False, sort_keys=True)
            assert_safe_content(path, text)
            handle.write(text + "\n")


def read_json(path: Path) -> Tuple[Optional[Dict[str, Any]], str]:
    if SECRET_NAME_RE.search(path.name) or path.suffix.lower() == ".env":
        return None, "secret_like_path_refused"
    try:
        if not path.exists():
            return None, "missing"
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None, "invalid_json"
    except OSError:
        return None, "read_error"
    return data if isinstance(data, dict) else None, "ok" if isinstance(data, dict) else "json_root_not_object"


def read_text(path: Path, max_chars: int = 300_000) -> Tuple[str, str]:
    if SECRET_NAME_RE.search(path.name) or path.suffix.lower() == ".env":
        return "", "secret_like_path_refused"
    try:
        if not path.exists():
            return "", "missing"
        return path.read_text(encoding="utf-8")[:max_chars], "ok"
    except OSError:
        return "", "read_error"


def nested_get(data: Optional[Dict[str, Any]], keys: List[str], default: Any = None) -> Any:
    current: Any = data
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
    return current


def find_breach_fields(data: Any, prefix: str = "") -> List[str]:
    fields: List[str] = []
    if isinstance(data, dict):
        for key, value in data.items():
            name = f"{prefix}.{key}" if prefix else key
            lower = key.lower()
            if lower.endswith("breach") or lower in {"breach", "policy_breach", "runtime_lock_breach"}:
                if value is True:
                    fields.append(name)
            fields.extend(find_breach_fields(value, name))
    elif isinstance(data, list):
        for index, value in enumerate(data[:50]):
            fields.extend(find_breach_fields(value, f"{prefix}[{index}]"))
    return fields


def selected_readonly_command() -> Dict[str, Any]:
    primary = PROJECT_DIR / "sentinel_low_risk_autonomy.py"
    fallback = PROJECT_DIR / "sentinel_safe_seo_performance_monitor.py"
    if primary.exists():
        return {
            "command": "python3 sentinel_low_risk_autonomy.py --run-once",
            "command_path": str(primary),
            "available": True,
            "source": "sentinel_low_risk_autonomy",
        }
    if fallback.exists():
        return {
            "command": "python3 sentinel_safe_seo_performance_monitor.py --scan",
            "command_path": str(fallback),
            "available": True,
            "source": "sentinel_safe_seo_performance_monitor",
        }
    return {
        "command": "python3 sentinel_low_risk_autonomy.py --run-once",
        "command_path": str(primary),
        "available": False,
        "source": "missing_readonly_monitor",
    }


def command_is_readonly(command: str) -> bool:
    return bool(command) and not FORBIDDEN_TIMER_COMMAND_RE.search(command)


def collect_context() -> Dict[str, Any]:
    master, master_status = read_json(INPUTS["master_json"])
    master_md, master_md_status = read_text(INPUTS["master_md"])
    low_risk, low_risk_status = read_json(INPUTS["low_risk_autonomy"])
    safe_monitor, safe_monitor_status = read_json(INPUTS["safe_seo_performance_monitor"])
    policy_text, policy_status = read_text(INPUTS["policy_update"])

    emergency_stop = bool(nested_get(master, ["autonomy_runtime_lock", "emergency_stop"], False))
    live_apply = bool(nested_get(master, ["autonomy_runtime_lock", "live_apply_enabled"], False))
    runtime_breach = bool(nested_get(master, ["autonomy_runtime_lock", "runtime_lock_breach"], False))
    breach_fields = find_breach_fields(master)
    low_risk_review_complete = bool(nested_get(master, ["low_risk_policy_owner_review_tracker", "all_required_reviewed"], False))
    owner_review_complete = bool(nested_get(master, ["manual_evidence_review_completion_gate", "all_required_reviewed"], False)) or (
        nested_get(master, ["owner_evidence_review_console", "open_items_count"], 1) == 0
    )
    timer_install_readiness = {
        "timer_installed": bool(nested_get(master, ["safe_draft_autonomy_scheduler_plan", "timer_installed"], False)),
        "timer_installation_status": nested_get(master, ["safe_draft_autonomy_scheduler_plan", "timer_installation_status"], "unknown"),
        "can_install_timer_now": bool(nested_get(master, ["safe_draft_autonomy_scheduler_plan", "can_install_timer_now"], False)),
    }
    readonly_command = selected_readonly_command()
    readonly_command_safe = command_is_readonly(readonly_command["command"])
    risk_reasons: List[str] = []
    if live_apply:
        risk_reasons.append("runtime lock reports live_apply enabled")
    if runtime_breach:
        risk_reasons.append("runtime lock breach")
    if breach_fields:
        risk_reasons.append("upstream breach fields: " + ", ".join(breach_fields[:10]))
    if not low_risk_review_complete:
        risk_reasons.append("low-risk policy review incomplete")
    if not owner_review_complete:
        risk_reasons.append("owner evidence review incomplete")
    if not readonly_command_safe:
        risk_reasons.append("timer command is not read-only safe")
    if not readonly_command["available"]:
        risk_reasons.append("read-only monitor command target missing")
    if timer_install_readiness["timer_installed"]:
        risk_reasons.append("timer already installed unexpectedly")

    low_risk_readonly_timer_allowed = (
        not live_apply
        and not runtime_breach
        and not breach_fields
        and low_risk_review_complete
        and owner_review_complete
        and readonly_command_safe
        and readonly_command["available"]
        and not timer_install_readiness["timer_installed"]
    )
    if risk_reasons:
        status = STATUS_BLOCKED
    elif emergency_stop:
        status = STATUS_READY_OWNER_INSTALL
    else:
        status = STATUS_TIMER_DRAFT_READY

    return {
        "input_status": {
            "master_json": master_status,
            "master_md": master_md_status,
            "low_risk_autonomy": low_risk_status,
            "safe_seo_performance_monitor": safe_monitor_status,
            "policy_update": policy_status,
        },
        "master_status": nested_get(master, ["website_status"], "unknown"),
        "global_emergency_stop": emergency_stop,
        "live_apply": live_apply,
        "runtime_lock_breach": runtime_breach,
        "breach_fields": breach_fields,
        "breach_count": len(breach_fields) + (1 if runtime_breach else 0),
        "low_risk_review_complete": low_risk_review_complete,
        "owner_review_complete": owner_review_complete,
        "timer_install_readiness": timer_install_readiness,
        "readonly_command": readonly_command,
        "readonly_command_safe": readonly_command_safe,
        "low_risk_readonly_timer_allowed": low_risk_readonly_timer_allowed,
        "risk_reasons": risk_reasons,
        "status": status,
        "policy_update_present": bool(policy_text),
        "low_risk_autonomy_report_present": isinstance(low_risk, dict),
        "safe_monitor_report_present": isinstance(safe_monitor, dict),
        "master_summary_mentions_emergency_stop": "Emergency Stop" in master_md or "emergency_stop" in master_md,
    }


def build_report(action: str, timer_drafts_written: bool = False, owner_packet_written: bool = False) -> Dict[str, Any]:
    ts = timestamp_tag()
    ctx = collect_context()
    breach = bool(
        ctx["live_apply"]
        or ctx["runtime_lock_breach"]
        or ctx["breach_fields"]
        or ctx["timer_install_readiness"].get("can_install_timer_now")
        or not ctx["readonly_command_safe"]
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "timestamp_utc": utc_now(),
        "timestamp": ts,
        "action": action,
        "unlock_status": ctx["status"],
        "gate_name": "LOW_RISK_READONLY_TIMER_ALLOWED",
        "low_risk_readonly_timer_allowed": ctx["low_risk_readonly_timer_allowed"],
        "global_emergency_stop": ctx["global_emergency_stop"],
        "emergency_stop": ctx["global_emergency_stop"],
        "live_apply": False,
        "runtime_live_apply": ctx["live_apply"],
        "breach_count": ctx["breach_count"],
        "breach": breach,
        "risk_reasons": ctx["risk_reasons"],
        "low_risk_review_complete": ctx["low_risk_review_complete"],
        "owner_review_complete": ctx["owner_review_complete"],
        "timer_install_readiness": ctx["timer_install_readiness"],
        "readonly_command": ctx["readonly_command"],
        "readonly_command_safe": ctx["readonly_command_safe"],
        "timer_drafts_written": timer_drafts_written,
        "owner_install_packet_written": owner_packet_written,
        "install_allowed_now": False,
        "owner_install_required": True,
        "can_install_timer_now": False,
        "apply_status": "not_applied",
        "systemctl_executed": False,
        "crontab_installed": False,
        "sftp_write": False,
        "db_write": False,
        "cache_purge": False,
        "global_emergency_stop_modified": False,
        "input_status": ctx["input_status"],
        "recommended_owner_action": recommended_action(ctx),
    }


def recommended_action(ctx: Dict[str, Any]) -> str:
    if ctx["risk_reasons"]:
        if "read-only monitor command target missing" in ctx["risk_reasons"]:
            return "Create the read-only monitor module first, then regenerate the timer draft. Do not install a timer yet."
        return "Do not proceed. Resolve read-only unlock safety blockers first."
    if ctx["global_emergency_stop"]:
        return "Emergency Stop remains active for all write/apply actions. Owner may review the read-only timer packet only; do not install automatically."
    return "Read-only monitoring timer draft is ready for owner review. No live apply is enabled."


def render_report_md(report: Dict[str, Any]) -> str:
    lines = [
        "# LOW-RISK Read-Only Automation Unlock",
        "",
        f"- Status: `{report.get('unlock_status')}`",
        f"- Gate: `{report.get('gate_name')}` = `{report.get('low_risk_readonly_timer_allowed')}`",
        f"- Emergency Stop: `{report.get('emergency_stop')}`",
        f"- live_apply: `{report.get('live_apply')}`",
        f"- runtime_live_apply: `{report.get('runtime_live_apply')}`",
        f"- breach: `{report.get('breach')}`",
        f"- install_allowed_now: `{report.get('install_allowed_now')}`",
        f"- can_install_timer_now: `{report.get('can_install_timer_now')}`",
        f"- owner_install_required: `{report.get('owner_install_required')}`",
        f"- Timer drafts written: `{report.get('timer_drafts_written')}`",
        f"- Owner packet written: `{report.get('owner_install_packet_written')}`",
        "",
        "## Read-Only Command",
        "",
        f"- Command: `{report.get('readonly_command', {}).get('command')}`",
        f"- Available: `{report.get('readonly_command', {}).get('available')}`",
        f"- Safe: `{report.get('readonly_command_safe')}`",
        "",
        "## Risk Reasons",
        "",
    ]
    reasons = report.get("risk_reasons") or []
    if reasons:
        lines.extend(f"- {redact_text(reason)}" for reason in reasons)
    else:
        lines.append("- none")
    lines.extend(["", "## Recommended Owner Action", "", redact_text(report.get("recommended_owner_action"))])
    return "\n".join(lines) + "\n"


def service_content(command: str) -> str:
    return f"""# REVIEW DRAFT ONLY - DO NOT INSTALL WITHOUT SEPARATE OWNER APPROVAL
# LOW-RISK read-only monitoring only. Global Emergency Stop remains active for write/apply paths.
[Unit]
Description=Sentinel LOW-RISK read-only SEO/Performance monitor
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=/srv/sentinel-defense
ExecStart=/usr/bin/env {command}
Nice=10
IOSchedulingClass=best-effort
"""


def timer_content() -> str:
    return """# REVIEW DRAFT ONLY - DO NOT INSTALL WITHOUT SEPARATE OWNER APPROVAL
[Unit]
Description=Run Sentinel LOW-RISK read-only monitor every 6 hours

[Timer]
OnBootSec=10min
OnUnitActiveSec=6h
Persistent=true
Unit=sentinel-low-risk-readonly.service

[Install]
WantedBy=timers.target
"""


def install_review_script() -> str:
    return """#!/usr/bin/env bash
# REVIEW ONLY - DO NOT RUN WITHOUT OWNER FINAL CONFIRMATION
# read-only only
# no live apply
# owner must inspect before running
# emergency stop for write actions remains active
cat <<'REVIEW_ONLY'
# REVIEW ONLY - DO NOT RUN WITHOUT OWNER FINAL CONFIRMATION
# Manual commands for a future owner-approved install review:
sudo install -m 0644 /srv/sentinel-defense/deploy/systemd/sentinel-low-risk-readonly.service /etc/systemd/system/sentinel-low-risk-readonly.service
sudo install -m 0644 /srv/sentinel-defense/deploy/systemd/sentinel-low-risk-readonly.timer /etc/systemd/system/sentinel-low-risk-readonly.timer
sudo systemctl daemon-reload
sudo systemctl enable --now sentinel-low-risk-readonly.timer
sudo systemctl list-timers sentinel-low-risk-readonly.timer
REVIEW_ONLY
echo "Review-only file. This script intentionally does not install or enable anything."
exit 1
"""


def uninstall_review_script() -> str:
    return """#!/usr/bin/env bash
# REVIEW ONLY - DO NOT RUN WITHOUT OWNER FINAL CONFIRMATION
# read-only timer rollback review only
cat <<'REVIEW_ONLY'
# REVIEW ONLY - DO NOT RUN WITHOUT OWNER FINAL CONFIRMATION
# Manual commands for a future owner-approved uninstall review:
sudo systemctl disable --now sentinel-low-risk-readonly.timer
sudo rm /etc/systemd/system/sentinel-low-risk-readonly.timer
sudo rm /etc/systemd/system/sentinel-low-risk-readonly.service
sudo systemctl daemon-reload
REVIEW_ONLY
echo "Review-only file. This script intentionally does not uninstall anything."
exit 1
"""


def owner_packet_content(report: Dict[str, Any]) -> str:
    command = report.get("readonly_command", {}).get("command")
    return f"""# LOW-RISK Read-Only Owner Install Packet

This packet is documentation only. It is not an installation and not an apply mechanism.

## Safety Boundary

- Global Emergency Stop remains active for every write/apply action.
- No live apply is enabled.
- No cache purge, DB write, SFTP write, Cloudflare, Nginx, .htaccess, plugin, theme, or FSE change is allowed.
- Timer installation remains a separate manual Owner decision.

## Current Gate

- Status: `{report.get('unlock_status')}`
- LOW_RISK_READONLY_TIMER_ALLOWED: `{report.get('low_risk_readonly_timer_allowed')}`
- Emergency Stop: `{report.get('emergency_stop')}`
- Breach: `{report.get('breach')}`
- Install allowed now: `{report.get('install_allowed_now')}`
- Can install timer now: `{report.get('can_install_timer_now')}`

## Read-Only Timer Command

```bash
{command}
```

## Files To Review

- `/srv/sentinel-defense/deploy/systemd/sentinel-low-risk-readonly.service`
- `/srv/sentinel-defense/deploy/systemd/sentinel-low-risk-readonly.timer`
- `/srv/sentinel-defense/deploy/systemd/install-sentinel-low-risk-readonly.review.sh`
- `/srv/sentinel-defense/deploy/systemd/uninstall-sentinel-low-risk-readonly.review.sh`

## Do Not Proceed If

- The read-only monitor command target is missing.
- Any command contains apply, SFTP write, DB write, cache purge, Cloudflare, Nginx, .htaccess, WordPress write, or shell pipe execution.
- Any breach is true.
- Owner has not manually reviewed the service and timer drafts.

## Recommended Next Owner Action

{redact_text(report.get('recommended_owner_action'))}
"""


def bot_learning() -> Dict[str, Any]:
    return {
        "phase": "7.2-low-risk-readonly-unlock",
        "low_risk_automation_scope": "Monitoring + Reporting + Draft-Actions only",
        "live_changes_allowed": False,
        "read_only_timer_separate_from_live_apply": True,
        "emergency_stop_scope": "Emergency Stop remains active for write/apply actions",
        "known_soc_issue": "KNOWN_ISSUE_HIGH_RISK_FSE_SOC_SOURCE is monitored only",
        "medium_high_actions": "Review-only or blocked; no automatic execution",
        "website_critical_handling": "Observe and report; do not automatically fix",
        "next_stage": "Owner-approved MEDIUM actions may be designed later, but are not enabled now",
    }


def render_learning_md(data: Dict[str, Any]) -> str:
    lines = ["# Bot Learning: LOW-RISK Read-Only Automation", ""]
    for key, value in data.items():
        lines.append(f"- `{key}`: {value}")
    return "\n".join(lines) + "\n"


def policy_update() -> str:
    return """# Sentinel Safe Autonomy Policy Update

- LOW-RISK Automation ist ab Phase 7.2 Monitoring, Reporting und Draft-Actions.
- LOW-RISK Read-only Timer ist getrennt von Live Apply.
- Emergency Stop bleibt fuer alle Write-/Apply-Aktionen aktiv.
- Read-only Monitoring kann separat owner-approved installiert werden.
- Der Bot darf automatisch read-only SEO/Performance-Pruefungen durchfuehren.
- Der Bot darf Vorschlaege und Patches vorbereiten.
- MEDIUM-RISK Aufgaben wie Cache-Purge brauchen Owner-Freigabe.
- HIGH-RISK Aufgaben wie DB-Aenderungen, FSE-/Template-Aenderungen, Plugin-/Theme-Aenderungen brauchen immer explizite Review + Backup + Apply-Freigabe.
- Website CRITICAL wird beobachtet und reportet, nicht automatisch gefixt.
- Keine unkontrollierte Autonomie.
- Kein blindes Loeschen.
- Keine Cloudflare/Nginx/.htaccess/DB-Aenderung ohne Freigabe.
- Alles bleibt auditierbar, reversibel und reportpflichtig.
"""


def write_common_outputs(report: Dict[str, Any]) -> None:
    ts = str(report["timestamp"])
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, render_report_md(report))
    write_json_atomic(SNAPSHOT_DIR / f"low-risk-readonly-unlock-{ts}.json", report)
    learning = bot_learning()
    write_json_atomic(BOT_LEARNING_JSON, learning)
    write_text_atomic(BOT_LEARNING_MD, render_learning_md(learning))
    write_text_atomic(POLICY_UPDATE_MD, policy_update())
    append_jsonl(
        AUDIT_JSONL,
        [{
            "timestamp_utc": report.get("timestamp_utc"),
            "action": report.get("action"),
            "unlock_status": report.get("unlock_status"),
            "low_risk_readonly_timer_allowed": report.get("low_risk_readonly_timer_allowed"),
            "emergency_stop": report.get("emergency_stop"),
            "live_apply": report.get("live_apply"),
            "breach": report.get("breach"),
        }],
    )


def evaluate() -> Dict[str, Any]:
    report = build_report("evaluate")
    write_common_outputs(report)
    return report


def draft_timer() -> Dict[str, Any]:
    base = build_report("draft-timer")
    command = base["readonly_command"]["command"]
    write_text_atomic(SERVICE_DRAFT, service_content(command))
    write_text_atomic(TIMER_DRAFT, timer_content())
    write_text_atomic(INSTALL_REVIEW, install_review_script())
    write_text_atomic(UNINSTALL_REVIEW, uninstall_review_script())
    report = build_report("draft-timer", timer_drafts_written=True)
    if not report["breach"] and report["unlock_status"] == STATUS_READY_OWNER_INSTALL:
        report["unlock_status"] = STATUS_TIMER_DRAFT_READY
    write_common_outputs(report)
    return report


def owner_install_packet() -> Dict[str, Any]:
    report = build_report("owner-install-packet", timer_drafts_written=SERVICE_DRAFT.exists() and TIMER_DRAFT.exists(), owner_packet_written=True)
    write_text_atomic(OWNER_PACKET_MD, owner_packet_content(report))
    write_common_outputs(report)
    return report


def run_self_test() -> int:
    parser = build_parser()
    help_text = parser.format_help()
    if "--apply" in help_text:
        raise AssertionError("--apply command exists")
    if not command_is_readonly("python3 sentinel_low_risk_autonomy.py --run-once"):
        raise AssertionError("read-only command rejected")
    for bad in (
        "python3 x.py --apply",
        "systemctl enable x.timer",
        "crontab file",
        "sftp put file",
        "mysql -e update",
        "rm " + "-rf /tmp/x",
        "curl http://x | bash",
    ):
        if command_is_readonly(bad):
            raise AssertionError(f"unsafe command accepted: {bad}")
    install_text = install_review_script()
    if "exit 1" not in install_text or "Review-only file" not in install_text:
        raise AssertionError("install script is not review-only")
    if "systemctl enable" not in install_text:
        raise AssertionError("install review text missing expected preview command")
    service = service_content("python3 sentinel_low_risk_autonomy.py --run-once")
    if FORBIDDEN_TIMER_COMMAND_RE.search("python3 sentinel_low_risk_autonomy.py --run-once"):
        raise AssertionError("service read-only command failed safety regex")
    if "ExecStart=/usr/bin/env python3 sentinel_low_risk_autonomy.py --run-once" not in service:
        raise AssertionError("service command malformed")
    data = bot_learning()
    json.dumps(data)
    redacted = redact_text("api_key=abcdef12345")
    if "abcdef" in redacted:
        raise AssertionError("secret redaction failed")
    source = Path(__file__).read_text(encoding="utf-8")
    for token in ("sub" + "process", "os" + "." + "system", "rm " + "-rf"):
        if token in source:
            raise AssertionError(f"forbidden implementation token found: {token}")
    for path in (REPORT_JSON, SNAPSHOT_DIR / "x.json", AUDIT_JSONL, SERVICE_DRAFT, INSTALL_REVIEW):
        assert_allowed_write(path)
    print("self-test ok")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate and draft a LOW-RISK read-only monitoring unlock packet.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--evaluate", action="store_true")
    group.add_argument("--draft-timer", action="store_true")
    group.add_argument("--owner-install-packet", action="store_true")
    return parser


def print_summary(report: Dict[str, Any]) -> None:
    print(f"unlock_status={report.get('unlock_status')}")
    print(f"low_risk_readonly_timer_allowed={report.get('low_risk_readonly_timer_allowed')}")
    print(f"live_apply={report.get('live_apply')}")
    print(f"emergency_stop={report.get('emergency_stop')}")
    print(f"breach={report.get('breach')}")
    print(f"install_allowed_now={report.get('install_allowed_now')}")
    print(f"owner_install_required={report.get('owner_install_required')}")
    print(f"readonly_command={report.get('readonly_command', {}).get('command')}")
    print(f"readonly_command_available={report.get('readonly_command', {}).get('available')}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.self_test:
        return run_self_test()
    try:
        if args.evaluate:
            report = evaluate()
        elif args.draft_timer:
            report = draft_timer()
        else:
            report = owner_install_packet()
    except Exception as exc:  # noqa: BLE001
        report = {
            "schema_version": SCHEMA_VERSION,
            "timestamp_utc": utc_now(),
            "timestamp": timestamp_tag(),
            "action": "failed",
            "unlock_status": STATUS_FAILED,
            "breach": True,
            "error": redact_text(exc, max_len=500),
            "live_apply": False,
            "install_allowed_now": False,
            "can_install_timer_now": False,
            "apply_status": "not_applied",
        }
        write_common_outputs(report)
    print_summary(report)
    return 0 if not report.get("breach") else 2


if __name__ == "__main__":
    sys.exit(main())
