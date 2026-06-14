#!/usr/bin/env python3
"""Website Low-Growth Readiness Timeline Snapshot (Phase 5.3).

Read-only decision snapshot that evaluates whether enough stable or decreasing
rolling-window observations exist to support a later manual website/origin
recheck. It never changes Master status to OK and never performs apply work.
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

ROLLING_AUDIT_JSONL = PROJECT_DIR / "audit/rolling-window-decay-observer.jsonl"
ROLLING_OBSERVER_JSON = PROJECT_DIR / "reports/latest/rolling-window-decay-observer.json"
MASTER_CRITICAL_CAUSE_JSON = PROJECT_DIR / "reports/latest/master-critical-cause-snapshot.json"
FINAL_OWNER_SNAPSHOT_JSON = PROJECT_DIR / "reports/latest/final-owner-decision-snapshot.json"
MASTER_JSON = PROJECT_DIR / "reports/latest/sentinel-master-report.json"
MASTER_MD = PROJECT_DIR / "reports/latest/sentinel-master-report.md"

REPORT_JSON = PROJECT_DIR / "reports/latest/low-growth-readiness-timeline.json"
REPORT_MD = PROJECT_DIR / "reports/latest/low-growth-readiness-timeline.md"
OWNER_SUMMARY_MD = PROJECT_DIR / "drafts/owner/low-growth-readiness-owner-summary.md"
SNAPSHOT_JSON = PROJECT_DIR / "snapshots/low-growth-readiness-timeline.json"
SNAPSHOT_MD = PROJECT_DIR / "snapshots/low-growth-readiness-timeline.md"
AUDIT_JSONL = PROJECT_DIR / "audit/low-growth-readiness-timeline.jsonl"

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

SCHEMA_VERSION = "low-growth-readiness-timeline-5.3"
APPLY_NOT_APPLIED = "not_applied"

STATUS_INSUFFICIENT_HISTORY = "LOW_GROWTH_TIMELINE_INSUFFICIENT_HISTORY"
STATUS_EARLY_STABLE = "LOW_GROWTH_TIMELINE_EARLY_STABLE"
STATUS_STABLE_BUT_WAIT = "LOW_GROWTH_TIMELINE_STABLE_BUT_WAIT"
STATUS_IMPROVING_BUT_WAIT = "LOW_GROWTH_TIMELINE_IMPROVING_BUT_WAIT"
STATUS_READY_FOR_MANUAL_RECHECK = "LOW_GROWTH_TIMELINE_READY_FOR_MANUAL_RECHECK"
STATUS_BREACH = "LOW_GROWTH_TIMELINE_BREACH"

TREND_INCREASING = "increasing"
TREND_STABLE = "stable"
TREND_DECREASING = "decreasing"
TREND_INSUFFICIENT = "insufficient_history"
STABLE_OR_DECREASING = {TREND_STABLE, TREND_DECREASING}

READINESS_NOT_ENOUGH = "not_enough_history"
READINESS_EARLY_STABLE = "early_stable"
READINESS_STABLE_WAIT = "stable_but_wait"
READINESS_IMPROVING_WAIT = "improving_but_wait"
READINESS_READY_RECHECK = "ready_for_manual_recheck"
READINESS_BREACH = "breach"

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
        raise ValueError(f"Refusing to write outside allowed low-growth roots: {path}")
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


def read_optional_text(path: Path, max_chars: int = 120_000) -> Tuple[str, str]:
    if ".env" in str(path).lower() or SECRETISH_RE.search(path.name):
        return "", "refused_secret_like_path"
    try:
        if not path.exists():
            return "", "not_available"
        return path.read_text(encoding="utf-8", errors="replace")[:max_chars], "ok"
    except OSError:
        return "", "read_error"


def read_jsonl(path: Path, max_records: int = 100) -> Tuple[List[Dict[str, Any]], str]:
    if ".env" in str(path).lower() or SECRETISH_RE.search(path.name):
        return [], "refused_secret_like_path"
    if not path.exists():
        return [], "not_available"
    records: List[Dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except (ValueError, json.JSONDecodeError):
                continue
            if isinstance(item, dict):
                records.append(item)
    except OSError:
        return [], "read_error"
    return records[-max_records:], "ok"


def parse_count(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def parse_optional_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def bool_from(data: Optional[Any], key: str, default: bool = False) -> bool:
    if not isinstance(data, dict):
        return default
    return bool(data.get(key, default))


def text_from(data: Optional[Any], key: str, default: str = "") -> str:
    if not isinstance(data, dict):
        return default
    return redact_text(data.get(key), default=default, max_len=500)


def normalize_trend(value: Any) -> str:
    trend = str(value or "").strip().lower()
    if trend in {TREND_INCREASING, TREND_STABLE, TREND_DECREASING, TREND_INSUFFICIENT}:
        return trend
    return TREND_INSUFFICIENT


def timeline_item(record: Dict[str, Any], source: str) -> Dict[str, Any]:
    return {
        "timestamp_utc": redact_text(record.get("timestamp_utc") or record.get("generated_at_utc")),
        "source": source,
        "decay_status": redact_text(record.get("decay_status")),
        "trend": normalize_trend(record.get("trend")),
        "current_5xx_total": parse_optional_int(record.get("current_5xx_total")),
        "current_504_total": parse_optional_int(record.get("current_504_total")),
        "current_sourcemap_404_total": parse_optional_int(record.get("current_sourcemap_404_total")),
        "delta_5xx": parse_optional_int(record.get("delta_5xx")),
        "delta_504": parse_optional_int(record.get("delta_504")),
        "delta_sourcemap_404": parse_optional_int(record.get("delta_sourcemap_404")),
        "snapshot_breach": bool(record.get("snapshot_breach", False)),
        "apply_status": redact_text(record.get("apply_status"), default=APPLY_NOT_APPLIED),
        "live_apply": bool(record.get("live_apply", False)),
        "install_allowed_now": bool(record.get("install_allowed_now", False)),
        "can_install_timer_now": bool(record.get("can_install_timer_now", False)),
    }


def build_timeline(audit_records: List[Dict[str, Any]], latest_observer: Optional[Any]) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    seen: set = set()
    for record in audit_records:
        item = timeline_item(record, "rolling_window_decay_audit")
        key = (item.get("timestamp_utc"), item.get("current_5xx_total"), item.get("trend"))
        if key in seen:
            continue
        seen.add(key)
        items.append(item)
    if isinstance(latest_observer, dict):
        item = timeline_item(latest_observer, "latest_rolling_window_decay_report")
        key = (item.get("timestamp_utc"), item.get("current_5xx_total"), item.get("trend"))
        if key not in seen:
            items.append(item)
    return items[-50:]


def count_trends(timeline: List[Dict[str, Any]]) -> Dict[str, int]:
    return {
        "increasing": sum(1 for item in timeline if item.get("trend") == TREND_INCREASING),
        "stable": sum(1 for item in timeline if item.get("trend") == TREND_STABLE),
        "decreasing": sum(1 for item in timeline if item.get("trend") == TREND_DECREASING),
    }


def consecutive_from_end(timeline: List[Dict[str, Any]], accepted: set) -> int:
    count = 0
    for item in reversed(timeline):
        if item.get("trend") in accepted:
            count += 1
            continue
        break
    return count


def decide_timeline_status(
    *,
    total_points: int,
    last_trend: str,
    consecutive_stable_or_decreasing: int,
    consecutive_decreasing: int,
    recent_four_has_increasing: bool,
    breach: bool,
) -> Tuple[str, str, bool, bool, str]:
    if breach:
        return STATUS_BREACH, READINESS_BREACH, False, False, "Do not proceed. Resolve low-growth timeline breach before any further decision."
    if total_points < 3:
        return STATUS_INSUFFICIENT_HISTORY, READINESS_NOT_ENOUGH, False, True, "Collect more read-only observer snapshots."
    if consecutive_stable_or_decreasing >= 4 and not recent_four_has_increasing:
        return (
            STATUS_READY_FOR_MANUAL_RECHECK,
            READINESS_READY_RECHECK,
            True,
            False,
            "Manual owner may re-run website diagnostics and compare 24h status. No automatic apply.",
        )
    if consecutive_decreasing >= 3:
        return STATUS_IMPROVING_BUT_WAIT, READINESS_IMPROVING_WAIT, False, True, "Trend is improving. Continue observation, no WAF action."
    if consecutive_stable_or_decreasing >= 3:
        return STATUS_STABLE_BUT_WAIT, READINESS_STABLE_WAIT, False, True, "Keep observing until enough 24h low-growth evidence exists."
    if last_trend in STABLE_OR_DECREASING:
        return STATUS_EARLY_STABLE, READINESS_EARLY_STABLE, False, True, "Continue observation. Do not apply changes."
    return STATUS_STABLE_BUT_WAIT, READINESS_STABLE_WAIT, False, True, "Keep observing until enough 24h low-growth evidence exists."


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


def build_report(
    audit_records: List[Dict[str, Any]],
    audit_status: str,
    latest_observer: Optional[Any],
    latest_observer_status: str,
    critical_cause: Optional[Any],
    critical_cause_status: str,
    final_owner_snapshot: Optional[Any],
    final_owner_status: str,
    master: Optional[Any],
    master_status_read: str,
    master_md: str,
    master_md_status: str,
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

    timeline = build_timeline(audit_records, latest_observer)
    trends = count_trends(timeline)
    total_points = len(timeline)
    last = timeline[-1] if timeline else {}
    last_trend = normalize_trend(last.get("trend"))
    consecutive_stable_or_decreasing = consecutive_from_end(timeline, STABLE_OR_DECREASING)
    consecutive_decreasing = consecutive_from_end(timeline, {TREND_DECREASING})
    recent_four = timeline[-4:]
    recent_four_has_increasing = any(item.get("trend") == TREND_INCREASING for item in recent_four)

    breach, breach_reasons = detect_breach(
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
    timeline_status, readiness_level, manual_recheck_recommended, observation_required, recommended_owner_action = decide_timeline_status(
        total_points=total_points,
        last_trend=last_trend,
        consecutive_stable_or_decreasing=consecutive_stable_or_decreasing,
        consecutive_decreasing=consecutive_decreasing,
        recent_four_has_increasing=recent_four_has_increasing,
        breach=breach,
    )

    latest_5xx_total = parse_optional_int(last.get("current_5xx_total"))
    latest_504_total = parse_optional_int(last.get("current_504_total"))
    latest_delta_5xx = parse_optional_int(last.get("delta_5xx"))
    latest_delta_504 = parse_optional_int(last.get("delta_504"))
    master_status = text_from(master, "overall_master_status", "UNKNOWN")
    autonomy_cause = bool_from(critical_cause, "critical_caused_by_autonomy")
    website_cause = bool_from(critical_cause, "critical_caused_by_website")

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": generated,
        "timeline_status": timeline_status,
        "total_points": total_points,
        "increasing_points": trends["increasing"],
        "stable_points": trends["stable"],
        "decreasing_points": trends["decreasing"],
        "last_trend": last_trend,
        "consecutive_stable_or_decreasing_points": consecutive_stable_or_decreasing,
        "consecutive_decreasing_points": consecutive_decreasing,
        "latest_5xx_total": latest_5xx_total,
        "latest_504_total": latest_504_total,
        "latest_delta_5xx": latest_delta_5xx,
        "latest_delta_504": latest_delta_504,
        "readiness_level": readiness_level,
        "manual_recheck_recommended": manual_recheck_recommended,
        "observation_required": observation_required,
        "recommended_owner_action": recommended_owner_action,
        "apply_status": apply_status,
        "live_apply": live_apply,
        "install_allowed_now": install_allowed_now,
        "can_install_timer_now": can_install_timer_now,
        "snapshot_breach": breach,
        "snapshot_breach_reasons": breach_reasons,
        "master_status": master_status,
        "critical_caused_by_autonomy": autonomy_cause,
        "critical_caused_by_website": website_cause,
        "final_owner_snapshot_breach": bool_from(final_owner_snapshot, "snapshot_breach"),
        "emergency_stop_active": bool_from(final_owner_snapshot, "emergency_stop_active") or bool_from(critical_cause, "emergency_stop_active"),
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
        "timeline": timeline[-12:],
        "recent_four_has_increasing": recent_four_has_increasing,
        "input_statuses": {
            "rolling_window_audit": audit_status,
            "latest_rolling_window_observer": latest_observer_status,
            "master_critical_cause_snapshot": critical_cause_status,
            "final_owner_snapshot": final_owner_status,
            "sentinel_master_json": master_status_read,
            "sentinel_master_md": master_md_status,
        },
        "safe_owner_next_actions": [
            recommended_owner_action,
            "Do not use this readiness timeline to change Master status automatically.",
            "Do not derive WAF, WordPress, Nginx, .htaccess, systemd, or crontab actions from this snapshot.",
        ],
        "do_not_apply_conditions": [
            "Do not create WAF rules from this timeline.",
            "Do not install timers from this timeline.",
            "Do not change WordPress, Nginx, .htaccess, systemd, or crontab from this timeline.",
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
        "# Low Growth Readiness Timeline",
        "",
        "## Executive Summary",
        "",
        f"- Generated (UTC): `{report.get('generated_at_utc')}`",
        f"- Timeline status: `{report.get('timeline_status')}`",
        f"- Readiness level: `{report.get('readiness_level')}`",
        f"- Total points: `{report.get('total_points')}`",
        f"- Increasing/stable/decreasing: `{report.get('increasing_points')}` / `{report.get('stable_points')}` / `{report.get('decreasing_points')}`",
        f"- Last trend: `{report.get('last_trend')}`",
        f"- Consecutive stable or decreasing points: `{report.get('consecutive_stable_or_decreasing_points')}`",
        f"- Latest 5xx total: `{report.get('latest_5xx_total')}`",
        f"- Latest 504 total: `{report.get('latest_504_total')}`",
        f"- Latest delta 5xx: `{report.get('latest_delta_5xx')}`",
        f"- Latest delta 504: `{report.get('latest_delta_504')}`",
        f"- Manual recheck recommended: `{report.get('manual_recheck_recommended')}`",
        f"- Observation required: `{report.get('observation_required')}`",
        f"- Snapshot breach: `{report.get('snapshot_breach')}`",
        f"- Recommended owner action: {redact_text(report.get('recommended_owner_action'), max_len=900)}",
        "",
        "## Timeline",
        "",
        "| Timestamp UTC | Trend | 5xx | 504 | Delta 5xx | Delta 504 | Breach |",
        "|---|---|---:|---:|---:|---:|---|",
    ]
    for item in report.get("timeline", []):
        if not isinstance(item, dict):
            continue
        lines.append(
            f"| `{redact_text(item.get('timestamp_utc'), max_len=80)}` "
            f"| `{redact_text(item.get('trend'), max_len=40)}` "
            f"| `{item.get('current_5xx_total')}` "
            f"| `{item.get('current_504_total')}` "
            f"| `{item.get('delta_5xx')}` "
            f"| `{item.get('delta_504')}` "
            f"| `{item.get('snapshot_breach')}` |"
        )
    if not report.get("timeline"):
        lines.append("| - | - | - | - | - | - | - |")
    lines.extend(["", "## Interpretation", ""])
    lines.append(f"- Master status is not automatically changed: `{report.get('master_status_not_auto_changed')}`")
    lines.append(f"- Critical caused by autonomy: `{report.get('critical_caused_by_autonomy')}`")
    lines.append(f"- Critical caused by website: `{report.get('critical_caused_by_website')}`")
    lines.append(f"- Emergency stop active: `{report.get('emergency_stop_active')}`")
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
        "timeline_status": report.get("timeline_status"),
        "readiness_level": report.get("readiness_level"),
        "total_points": report.get("total_points"),
        "increasing_points": report.get("increasing_points"),
        "stable_points": report.get("stable_points"),
        "decreasing_points": report.get("decreasing_points"),
        "last_trend": report.get("last_trend"),
        "consecutive_stable_or_decreasing_points": report.get("consecutive_stable_or_decreasing_points"),
        "latest_5xx_total": report.get("latest_5xx_total"),
        "latest_504_total": report.get("latest_504_total"),
        "latest_delta_5xx": report.get("latest_delta_5xx"),
        "latest_delta_504": report.get("latest_delta_504"),
        "manual_recheck_recommended": report.get("manual_recheck_recommended"),
        "snapshot_breach": report.get("snapshot_breach"),
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
    audit, audit_status = read_jsonl(ROLLING_AUDIT_JSONL)
    latest_observer, latest_observer_status = read_optional_json(ROLLING_OBSERVER_JSON)
    critical_cause, critical_cause_status = read_optional_json(MASTER_CRITICAL_CAUSE_JSON)
    final_owner, final_owner_status = read_optional_json(FINAL_OWNER_SNAPSHOT_JSON)
    master, master_status = read_optional_json(MASTER_JSON)
    master_md, master_md_status = read_optional_text(MASTER_MD)
    return build_report(
        audit,
        audit_status,
        latest_observer,
        latest_observer_status,
        critical_cause,
        critical_cause_status,
        final_owner,
        final_owner_status,
        master,
        master_status,
        master_md,
        master_md_status,
    )


def run_self_test() -> int:
    base_master = {"overall_master_status": "CRITICAL"}
    critical = {"critical_caused_by_autonomy": False, "critical_caused_by_website": True, "emergency_stop_active": True}
    final_owner = {"snapshot_breach": False, "emergency_stop_active": True}

    insufficient = build_report(
        [{"timestamp_utc": "1", "trend": "stable", "current_5xx_total": 10}],
        "ok",
        None,
        "not_available",
        critical,
        "ok",
        final_owner,
        "ok",
        base_master,
        "ok",
        "",
        "ok",
    )
    if insufficient["timeline_status"] != STATUS_INSUFFICIENT_HISTORY or insufficient["snapshot_breach"]:
        raise AssertionError("insufficient history failed")

    early = build_report(
        [
            {"timestamp_utc": "1", "trend": "increasing", "current_5xx_total": 900, "current_504_total": 700, "delta_5xx": 23},
            {"timestamp_utc": "2", "trend": "stable", "current_5xx_total": 900, "current_504_total": 700, "delta_5xx": 0},
            {"timestamp_utc": "3", "trend": "stable", "current_5xx_total": 900, "current_504_total": 700, "delta_5xx": 0},
        ],
        "ok",
        None,
        "not_available",
        critical,
        "ok",
        final_owner,
        "ok",
        base_master,
        "ok",
        "",
        "ok",
    )
    if early["timeline_status"] != STATUS_EARLY_STABLE or early["manual_recheck_recommended"]:
        raise AssertionError("early stable failed")

    stable_wait = build_report(
        [
            {"timestamp_utc": "1", "trend": "increasing", "current_5xx_total": 900},
            {"timestamp_utc": "2", "trend": "stable", "current_5xx_total": 900},
            {"timestamp_utc": "3", "trend": "stable", "current_5xx_total": 900},
            {"timestamp_utc": "4", "trend": "stable", "current_5xx_total": 900},
        ],
        "ok",
        None,
        "not_available",
        critical,
        "ok",
        final_owner,
        "ok",
        base_master,
        "ok",
        "",
        "ok",
    )
    if stable_wait["timeline_status"] != STATUS_STABLE_BUT_WAIT:
        raise AssertionError("stable but wait failed")

    improving = build_report(
        [
            {"timestamp_utc": "1", "trend": "increasing", "current_5xx_total": 900},
            {"timestamp_utc": "2", "trend": "decreasing", "current_5xx_total": 850},
            {"timestamp_utc": "3", "trend": "decreasing", "current_5xx_total": 800},
            {"timestamp_utc": "4", "trend": "decreasing", "current_5xx_total": 750},
        ],
        "ok",
        None,
        "not_available",
        critical,
        "ok",
        final_owner,
        "ok",
        base_master,
        "ok",
        "",
        "ok",
    )
    if improving["timeline_status"] != STATUS_IMPROVING_BUT_WAIT:
        raise AssertionError("improving but wait failed")

    ready = build_report(
        [
            {"timestamp_utc": "1", "trend": "stable", "current_5xx_total": 900},
            {"timestamp_utc": "2", "trend": "stable", "current_5xx_total": 900},
            {"timestamp_utc": "3", "trend": "decreasing", "current_5xx_total": 850},
            {"timestamp_utc": "4", "trend": "stable", "current_5xx_total": 850},
        ],
        "ok",
        None,
        "not_available",
        critical,
        "ok",
        final_owner,
        "ok",
        base_master,
        "ok",
        "",
        "ok",
    )
    if ready["timeline_status"] != STATUS_READY_FOR_MANUAL_RECHECK or not ready["manual_recheck_recommended"]:
        raise AssertionError("ready for manual recheck failed")

    for key in ("live_apply", "install_allowed_now", "can_install_timer_now", "forbidden_apply_command_detected", "systemd_file_written", "crontab_file_written", "executable_install_script_generated", "secret_like_output", "output_path_breach"):
        bad = build_report([], "not_available", None, "not_available", critical, "ok", final_owner, "ok", base_master, "ok", "", "ok", forced_flags={key: True})
        if not bad["snapshot_breach"] or bad["timeline_status"] != STATUS_BREACH:
            raise AssertionError(f"{key} did not breach")
    bad_apply = build_report([], "not_available", None, "not_available", critical, "ok", final_owner, "ok", base_master, "ok", "", "ok", forced_flags={"apply_status": "applied"})
    if not bad_apply["snapshot_breach"]:
        raise AssertionError("apply_status breach failed")
    if not FORBIDDEN_APPLY_COMMAND_RE.search("wp-cli post update"):
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
        assert_allowed_write(PROJECT_DIR / "state/low-growth-readiness-timeline.json")
    except ValueError:
        pass
    else:
        raise AssertionError("forbidden write root was not rejected")
    print("low-growth-readiness-timeline self-tests: OK")
    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build Low Growth Readiness Timeline; read-only, no apply.")
    parser.add_argument("--self-test", action="store_true", help="Run in-memory safety tests and exit.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()
    report = build_current_report()
    write_outputs(report)
    print(
        "Low Growth Readiness Timeline: "
        f"status={report.get('timeline_status')}, "
        f"last_trend={report.get('last_trend')}, "
        f"consecutive={report.get('consecutive_stable_or_decreasing_points')}, "
        f"breach={report.get('snapshot_breach')}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
