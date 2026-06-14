#!/usr/bin/env python3
"""Manual Website Recheck Gate (Phase 5.4).

Read-only gate that decides whether a manual Website/Origin recheck is
reasonable based on low-growth readiness and rolling-window observer reports.
It never runs diagnostics, never applies countermeasures, and never changes the
Master status.
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

LOW_GROWTH_TIMELINE_JSON = PROJECT_DIR / "reports/latest/low-growth-readiness-timeline.json"
ROLLING_OBSERVER_JSON = PROJECT_DIR / "reports/latest/rolling-window-decay-observer.json"
MASTER_CRITICAL_CAUSE_JSON = PROJECT_DIR / "reports/latest/master-critical-cause-snapshot.json"
FINAL_OWNER_SNAPSHOT_JSON = PROJECT_DIR / "reports/latest/final-owner-decision-snapshot.json"
MASTER_JSON = PROJECT_DIR / "reports/latest/sentinel-master-report.json"
LOW_GROWTH_AUDIT_JSONL = PROJECT_DIR / "audit/low-growth-readiness-timeline.jsonl"
ROLLING_AUDIT_JSONL = PROJECT_DIR / "audit/rolling-window-decay-observer.jsonl"

REPORT_JSON = PROJECT_DIR / "reports/latest/manual-website-recheck-gate.json"
REPORT_MD = PROJECT_DIR / "reports/latest/manual-website-recheck-gate.md"
OWNER_SUMMARY_MD = PROJECT_DIR / "drafts/owner/manual-website-recheck-gate-summary.md"
SNAPSHOT_JSON = PROJECT_DIR / "snapshots/manual-website-recheck-gate.json"
SNAPSHOT_MD = PROJECT_DIR / "snapshots/manual-website-recheck-gate.md"
AUDIT_JSONL = PROJECT_DIR / "audit/manual-website-recheck-gate.jsonl"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "drafts/owner",
    PROJECT_DIR / "snapshots",
    PROJECT_DIR / "audit",
)
ALLOWED_OUTPUT_PATHS = (REPORT_JSON, REPORT_MD, OWNER_SUMMARY_MD, SNAPSHOT_JSON, SNAPSHOT_MD, AUDIT_JSONL)
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

SCHEMA_VERSION = "manual-website-recheck-gate-5.4"
APPLY_NOT_APPLIED = "not_applied"

STATUS_WAIT = "MANUAL_RECHECK_GATE_WAIT"
STATUS_EARLY_STABLE_WAIT = "MANUAL_RECHECK_GATE_EARLY_STABLE_WAIT"
STATUS_READY = "MANUAL_RECHECK_GATE_READY_FOR_MANUAL_RECHECK"
STATUS_BLOCKED_BY_BREACH = "MANUAL_RECHECK_GATE_BLOCKED_BY_BREACH"
STATUS_PARTIAL_INPUTS = "MANUAL_RECHECK_GATE_PARTIAL_INPUTS"
STATUS_BREACH = "MANUAL_RECHECK_GATE_BREACH"

LOW_GROWTH_EARLY_STABLE = "LOW_GROWTH_TIMELINE_EARLY_STABLE"
LOW_GROWTH_INSUFFICIENT = "LOW_GROWTH_TIMELINE_INSUFFICIENT_HISTORY"

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
FORBIDDEN_APPLY_COMMAND_RE = re.compile(
    r"(?i)\b(cloudflare\s+api|cfcli|wp\s+|wp-cli|nginx\s+reload|nginx\s+-s|"
    r"htaccess|\\.htaccess|apply-safe|consolidate-apply-safe|systemctl|crontab|"
    r"curl\s+.*(api|cloudflare|wp-json)|wget\s+.*(api|cloudflare|wp-json))\b"
)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


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


def detect_secret_like(value: Any) -> bool:
    text = "" if value is None else str(value)
    return bool(SECRET_ASSIGNMENT_RE.search(text) or LONG_HEX_RE.search(text))


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError):
        return False


def assert_allowed_write(path: Path) -> None:
    if path not in ALLOWED_OUTPUT_PATHS and not any(is_within(path, root) for root in ALLOWED_WRITE_ROOTS):
        raise ValueError(f"Refusing to write outside allowed manual-recheck roots: {path}")
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


def read_jsonl_count(path: Path) -> Tuple[int, str]:
    if ".env" in str(path).lower() or SECRETISH_RE.search(path.name):
        return 0, "refused_secret_like_path"
    if not path.exists():
        return 0, "not_available"
    try:
        count = 0
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except (ValueError, json.JSONDecodeError):
                continue
            if isinstance(item, dict):
                count += 1
        return count, "ok"
    except OSError:
        return 0, "read_error"


def parse_count(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def bool_from(data: Optional[Any], key: str, default: bool = False) -> bool:
    if not isinstance(data, dict):
        return default
    return bool(data.get(key, default))


def text_from(data: Optional[Any], key: str, default: str = "") -> str:
    if not isinstance(data, dict):
        return default
    return redact_text(data.get(key), default=default, max_len=500)


def detect_breach(
    *,
    live_apply: bool,
    install_allowed_now: bool,
    can_install_timer_now: bool,
    apply_status: str,
    forbidden_apply_command_detected: bool,
    systemd_file_written: bool,
    crontab_file_written: bool,
    executable_install_script_generated: bool,
    secret_like_output: bool,
    output_path_breach: bool,
) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    if live_apply:
        reasons.append("live_apply=true")
    if install_allowed_now:
        reasons.append("install_allowed_now=true")
    if can_install_timer_now:
        reasons.append("can_install_timer_now=true")
    if apply_status != APPLY_NOT_APPLIED:
        reasons.append("apply_status != not_applied")
    if forbidden_apply_command_detected:
        reasons.append("Cloudflare/WordPress/Nginx/.htaccess apply command detected")
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
    return bool(reasons), sorted(set(reasons))


def status_and_action(
    *,
    direct_breach: bool,
    upstream_breach: bool,
    partial_inputs: bool,
    manual_recheck_recommended: bool,
    timeline_status: str,
) -> Tuple[str, bool, str]:
    if direct_breach:
        return STATUS_BREACH, True, "Do not proceed. Resolve breach first."
    if upstream_breach:
        return STATUS_BLOCKED_BY_BREACH, True, "Do not proceed. Resolve breach first."
    if partial_inputs:
        return STATUS_PARTIAL_INPUTS, False, "Collect missing read-only gate inputs before deciding."
    if manual_recheck_recommended:
        return (
            STATUS_READY,
            False,
            "Manual owner may re-run website diagnostics and compare 24h status. No automatic apply.",
        )
    if timeline_status == LOW_GROWTH_EARLY_STABLE:
        return (
            STATUS_EARLY_STABLE_WAIT,
            False,
            "Early stabilization detected. Collect more stable/decreasing snapshots before manual recheck.",
        )
    if timeline_status == LOW_GROWTH_INSUFFICIENT:
        return STATUS_WAIT, False, "Continue read-only observation. Do not recheck yet."
    return STATUS_WAIT, False, "Continue read-only observation. Do not recheck yet."


def build_report(
    timeline: Optional[Any],
    timeline_status_read: str,
    observer: Optional[Any],
    observer_status_read: str,
    critical_cause: Optional[Any],
    critical_cause_status_read: str,
    final_owner_snapshot: Optional[Any],
    final_owner_status_read: str,
    master: Optional[Any],
    master_status_read: str,
    low_growth_audit_count: int,
    low_growth_audit_status: str,
    rolling_audit_count: int,
    rolling_audit_status: str,
    *,
    generated_at: Optional[str] = None,
    forced_flags: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    generated = generated_at or utc_now()
    flags = forced_flags or {}
    live_apply = bool(flags.get("live_apply", False))
    install_allowed_now = bool(flags.get("install_allowed_now", False))
    can_install_timer_now = bool(flags.get("can_install_timer_now", False))
    apply_status = str(flags.get("apply_status", APPLY_NOT_APPLIED))
    forbidden_apply_command_detected = bool(flags.get("forbidden_apply_command_detected", False))
    systemd_file_written = bool(flags.get("systemd_file_written", False))
    crontab_file_written = bool(flags.get("crontab_file_written", False))
    executable_install_script_generated = bool(flags.get("executable_install_script_generated", False))
    secret_like_output = bool(flags.get("secret_like_output", False))
    output_path_breach = bool(flags.get("output_path_breach", False))

    direct_breach, direct_breach_reasons = detect_breach(
        live_apply=live_apply,
        install_allowed_now=install_allowed_now,
        can_install_timer_now=can_install_timer_now,
        apply_status=apply_status,
        forbidden_apply_command_detected=forbidden_apply_command_detected,
        systemd_file_written=systemd_file_written,
        crontab_file_written=crontab_file_written,
        executable_install_script_generated=executable_install_script_generated,
        secret_like_output=secret_like_output,
        output_path_breach=output_path_breach,
    )
    upstream_breach_reasons: List[str] = []
    for label, data in (
        ("low_growth_timeline", timeline),
        ("rolling_window_observer", observer),
        ("master_critical_cause", critical_cause),
        ("final_owner_snapshot", final_owner_snapshot),
    ):
        if bool_from(data, "snapshot_breach"):
            upstream_breach_reasons.append(f"{label}:snapshot_breach=true")
    upstream_breach = bool(upstream_breach_reasons)

    timeline_status = text_from(timeline, "timeline_status", "NOT_AVAILABLE")
    manual_recheck_recommended = bool_from(timeline, "manual_recheck_recommended")
    partial_inputs = any(
        status != "ok"
        for status in (
            timeline_status_read,
            observer_status_read,
            critical_cause_status_read,
            final_owner_status_read,
            master_status_read,
        )
    )
    gate_status, gate_breach, recommended_owner_action = status_and_action(
        direct_breach=direct_breach,
        upstream_breach=upstream_breach,
        partial_inputs=partial_inputs,
        manual_recheck_recommended=manual_recheck_recommended,
        timeline_status=timeline_status,
    )
    breach_reasons = direct_breach_reasons + upstream_breach_reasons

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": generated,
        "gate_status": gate_status,
        "manual_recheck_recommended": manual_recheck_recommended if not gate_breach else False,
        "timeline_status": timeline_status,
        "decay_status": text_from(observer, "decay_status", "NOT_AVAILABLE"),
        "last_trend": text_from(timeline, "last_trend", text_from(observer, "trend", "unknown")),
        "consecutive_stable_or_decreasing_points": parse_count(text_from(timeline, "consecutive_stable_or_decreasing_points", 0)),
        "total_points": parse_count(text_from(timeline, "total_points", 0)),
        "increasing_points": parse_count(text_from(timeline, "increasing_points", 0)),
        "stable_points": parse_count(text_from(timeline, "stable_points", 0)),
        "decreasing_points": parse_count(text_from(timeline, "decreasing_points", 0)),
        "latest_5xx_total": timeline.get("latest_5xx_total") if isinstance(timeline, dict) else None,
        "latest_504_total": timeline.get("latest_504_total") if isinstance(timeline, dict) else None,
        "latest_delta_5xx": timeline.get("latest_delta_5xx") if isinstance(timeline, dict) else None,
        "latest_delta_504": timeline.get("latest_delta_504") if isinstance(timeline, dict) else None,
        "master_status": text_from(master, "overall_master_status", "UNKNOWN"),
        "critical_caused_by_website": bool_from(critical_cause, "critical_caused_by_website"),
        "critical_caused_by_autonomy": bool_from(critical_cause, "critical_caused_by_autonomy"),
        "emergency_stop_active": bool_from(final_owner_snapshot, "emergency_stop_active") or bool_from(critical_cause, "emergency_stop_active"),
        "apply_status": apply_status,
        "live_apply": live_apply,
        "install_allowed_now": install_allowed_now,
        "can_install_timer_now": can_install_timer_now,
        "gate_breach": gate_breach,
        "gate_breach_reasons": sorted(set(breach_reasons)),
        "recommended_owner_action": recommended_owner_action,
        "read_only": True,
        "network_access": False,
        "api_access": False,
        "cloudflare_mutations": False,
        "wordpress_mutations": False,
        "nginx_mutations": False,
        "htaccess_mutations": False,
        "systemd_file_written": systemd_file_written,
        "crontab_file_written": crontab_file_written,
        "executable_install_script_generated": executable_install_script_generated,
        "master_status_not_auto_changed": True,
        "low_growth_audit_points": low_growth_audit_count,
        "rolling_window_audit_points": rolling_audit_count,
        "input_statuses": {
            "low_growth_timeline": timeline_status_read,
            "rolling_window_observer": observer_status_read,
            "master_critical_cause_snapshot": critical_cause_status_read,
            "final_owner_snapshot": final_owner_status_read,
            "sentinel_master_json": master_status_read,
            "low_growth_audit": low_growth_audit_status,
            "rolling_window_audit": rolling_audit_status,
        },
        "decision_template": {
            "recheck_not_recommended": gate_status in {STATUS_WAIT, STATUS_EARLY_STABLE_WAIT, STATUS_PARTIAL_INPUTS},
            "recheck_soon_possible": gate_status == STATUS_EARLY_STABLE_WAIT,
            "recheck_manually_recommended": gate_status == STATUS_READY,
            "recheck_blocked_by_breach": gate_status in {STATUS_BLOCKED_BY_BREACH, STATUS_BREACH},
        },
        "safe_owner_next_actions": [
            recommended_owner_action,
            "This gate does not run diagnostics and does not apply countermeasures.",
            "Do not use this gate to change Master status automatically.",
        ],
        "do_not_apply_conditions": [
            "Do not create WAF rules from this gate.",
            "Do not install timers from this gate.",
            "Do not change WordPress, Nginx, .htaccess, systemd, or crontab from this gate.",
        ],
        "outputs": {
            "report_json": str(REPORT_JSON),
            "report_md": str(REPORT_MD),
            "owner_summary_md": str(OWNER_SUMMARY_MD),
            "snapshot_json": str(SNAPSHOT_JSON),
            "snapshot_md": str(SNAPSHOT_MD),
            "audit_jsonl": str(AUDIT_JSONL),
        },
    }


def render_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# Manual Website Recheck Gate",
        "",
        "## Executive Summary",
        "",
        f"- Generated (UTC): `{report.get('generated_at_utc')}`",
        f"- Gate status: `{report.get('gate_status')}`",
        f"- Manual recheck recommended: `{report.get('manual_recheck_recommended')}`",
        f"- Timeline status: `{report.get('timeline_status')}`",
        f"- Decay status: `{report.get('decay_status')}`",
        f"- Last trend: `{report.get('last_trend')}`",
        f"- Consecutive stable/decreasing points: `{report.get('consecutive_stable_or_decreasing_points')}`",
        f"- Total points: `{report.get('total_points')}`",
        f"- Latest 5xx total: `{report.get('latest_5xx_total')}`",
        f"- Latest 504 total: `{report.get('latest_504_total')}`",
        f"- Latest delta 5xx: `{report.get('latest_delta_5xx')}`",
        f"- Latest delta 504: `{report.get('latest_delta_504')}`",
        f"- Master status: `{report.get('master_status')}`",
        f"- Critical caused by website: `{report.get('critical_caused_by_website')}`",
        f"- Critical caused by autonomy: `{report.get('critical_caused_by_autonomy')}`",
        f"- Emergency stop active: `{report.get('emergency_stop_active')}`",
        f"- Gate breach: `{report.get('gate_breach')}`",
        f"- Recommended owner action: {redact_text(report.get('recommended_owner_action'), max_len=900)}",
        "",
        "## Owner Decision Template",
        "",
    ]
    decision = report.get("decision_template") if isinstance(report.get("decision_template"), dict) else {}
    for key in ("recheck_not_recommended", "recheck_soon_possible", "recheck_manually_recommended", "recheck_blocked_by_breach"):
        lines.append(f"- {key}: `{decision.get(key)}`")
    lines.extend(["", "## Safe Owner Next Actions", ""])
    for item in report.get("safe_owner_next_actions", []):
        lines.append(f"- {redact_text(item, max_len=800)}")
    lines.extend(["", "## Do Not Apply Conditions", ""])
    for item in report.get("do_not_apply_conditions", []):
        lines.append(f"- {redact_text(item, max_len=700)}")
    lines.append("")
    return "\n".join(lines)


def audit_record(report: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "timestamp_utc": report.get("generated_at_utc"),
        "schema_version": SCHEMA_VERSION,
        "gate_status": report.get("gate_status"),
        "manual_recheck_recommended": report.get("manual_recheck_recommended"),
        "timeline_status": report.get("timeline_status"),
        "decay_status": report.get("decay_status"),
        "last_trend": report.get("last_trend"),
        "consecutive_stable_or_decreasing_points": report.get("consecutive_stable_or_decreasing_points"),
        "total_points": report.get("total_points"),
        "latest_5xx_total": report.get("latest_5xx_total"),
        "latest_504_total": report.get("latest_504_total"),
        "gate_breach": report.get("gate_breach"),
        "install_allowed_now": False,
        "can_install_timer_now": False,
        "live_apply": False,
        "apply_status": APPLY_NOT_APPLIED,
        "network_access": False,
    }


def write_outputs(report: Dict[str, Any]) -> None:
    markdown = render_markdown(report)
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, markdown)
    write_text_atomic(OWNER_SUMMARY_MD, markdown)
    write_json_atomic(SNAPSHOT_JSON, report)
    write_text_atomic(SNAPSHOT_MD, markdown)
    append_jsonl(AUDIT_JSONL, [audit_record(report)])


def build_current_report() -> Dict[str, Any]:
    timeline, timeline_status = read_optional_json(LOW_GROWTH_TIMELINE_JSON)
    observer, observer_status = read_optional_json(ROLLING_OBSERVER_JSON)
    critical, critical_status = read_optional_json(MASTER_CRITICAL_CAUSE_JSON)
    final_owner, final_owner_status = read_optional_json(FINAL_OWNER_SNAPSHOT_JSON)
    master, master_status = read_optional_json(MASTER_JSON)
    low_growth_audit_count, low_growth_audit_status = read_jsonl_count(LOW_GROWTH_AUDIT_JSONL)
    rolling_audit_count, rolling_audit_status = read_jsonl_count(ROLLING_AUDIT_JSONL)
    return build_report(
        timeline,
        timeline_status,
        observer,
        observer_status,
        critical,
        critical_status,
        final_owner,
        final_owner_status,
        master,
        master_status,
        low_growth_audit_count,
        low_growth_audit_status,
        rolling_audit_count,
        rolling_audit_status,
    )


def run_self_test() -> int:
    observer = {"decay_status": "ROLLING_WINDOW_DECAY_STABLE", "snapshot_breach": False}
    critical = {"critical_caused_by_website": True, "critical_caused_by_autonomy": False, "snapshot_breach": False, "emergency_stop_active": True}
    final_owner = {"snapshot_breach": False, "emergency_stop_active": True}
    master = {"overall_master_status": "CRITICAL"}
    early = {
        "timeline_status": LOW_GROWTH_EARLY_STABLE,
        "manual_recheck_recommended": False,
        "last_trend": "stable",
        "consecutive_stable_or_decreasing_points": 2,
        "total_points": 3,
        "increasing_points": 1,
        "stable_points": 2,
        "decreasing_points": 0,
        "latest_5xx_total": 925,
        "latest_504_total": 702,
        "latest_delta_5xx": 0,
        "latest_delta_504": 0,
        "snapshot_breach": False,
    }
    report = build_report(early, "ok", observer, "ok", critical, "ok", final_owner, "ok", master, "ok", 3, "ok", 3, "ok")
    if report["gate_status"] != STATUS_EARLY_STABLE_WAIT or report["manual_recheck_recommended"]:
        raise AssertionError("early stable wait failed")

    ready_timeline = dict(early, timeline_status="LOW_GROWTH_TIMELINE_READY_FOR_MANUAL_RECHECK", manual_recheck_recommended=True, consecutive_stable_or_decreasing_points=4)
    ready = build_report(ready_timeline, "ok", observer, "ok", critical, "ok", final_owner, "ok", master, "ok", 4, "ok", 4, "ok")
    if ready["gate_status"] != STATUS_READY or not ready["manual_recheck_recommended"]:
        raise AssertionError("ready gate failed")

    insufficient = dict(early, timeline_status=LOW_GROWTH_INSUFFICIENT, total_points=1)
    wait = build_report(insufficient, "ok", observer, "ok", critical, "ok", final_owner, "ok", master, "ok", 1, "ok", 1, "ok")
    if wait["gate_status"] != STATUS_WAIT or wait["gate_breach"]:
        raise AssertionError("wait gate failed")

    partial = build_report(None, "not_available", observer, "ok", critical, "ok", final_owner, "ok", master, "ok", 0, "not_available", 0, "not_available")
    if partial["gate_status"] != STATUS_PARTIAL_INPUTS or partial["gate_breach"]:
        raise AssertionError("partial inputs failed")

    upstream_bad = build_report(dict(early, snapshot_breach=True), "ok", observer, "ok", critical, "ok", final_owner, "ok", master, "ok", 3, "ok", 3, "ok")
    if upstream_bad["gate_status"] != STATUS_BLOCKED_BY_BREACH or not upstream_bad["gate_breach"]:
        raise AssertionError("upstream breach failed")

    for key in ("live_apply", "install_allowed_now", "can_install_timer_now", "forbidden_apply_command_detected", "systemd_file_written", "crontab_file_written", "executable_install_script_generated", "secret_like_output", "output_path_breach"):
        bad = build_report(early, "ok", observer, "ok", critical, "ok", final_owner, "ok", master, "ok", 3, "ok", 3, "ok", forced_flags={key: True})
        if not bad["gate_breach"] or bad["gate_status"] != STATUS_BREACH:
            raise AssertionError(f"{key} did not breach")
    bad_apply = build_report(early, "ok", observer, "ok", critical, "ok", final_owner, "ok", master, "ok", 3, "ok", 3, "ok", forced_flags={"apply_status": "applied"})
    if not bad_apply["gate_breach"]:
        raise AssertionError("apply_status breach failed")
    if not FORBIDDEN_APPLY_COMMAND_RE.search("cloudflare api update"):
        raise AssertionError("forbidden command detector failed")
    if not detect_secret_like("token=abc12345"):
        raise AssertionError("secret detector failed")
    for forbidden in (PROJECT_DIR / "reports/latest/bad.sh", PROJECT_DIR / "drafts/owner/bad.service", PROJECT_DIR / "snapshots/bad.timer"):
        try:
            assert_allowed_write(forbidden)
        except ValueError:
            pass
        else:
            raise AssertionError(f"forbidden artifact was not rejected: {forbidden}")
    try:
        assert_allowed_write(PROJECT_DIR / "state/manual-website-recheck-gate.json")
    except ValueError:
        pass
    else:
        raise AssertionError("forbidden write root was not rejected")
    print("manual-website-recheck-gate self-tests: OK")
    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build Manual Website Recheck Gate; read-only, no apply.")
    parser.add_argument("--self-test", action="store_true", help="Run in-memory safety tests and exit.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()
    report = build_current_report()
    write_outputs(report)
    print(
        "Manual Website Recheck Gate: "
        f"status={report.get('gate_status')}, "
        f"recommended={report.get('manual_recheck_recommended')}, "
        f"breach={report.get('gate_breach')}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
