#!/usr/bin/env python3
"""Website / Origin Rolling Window Decay Observer (Phase 5.2).

Read-only observer for determining whether the current Master CRITICAL state is
still driven by 24h rolling-window leftovers or by new website/origin growth.

This is not an apply mechanism, not a WAF module, not an installation, and not
an active timer. It performs no network/API access and no production mutation.
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

MASTER_JSON = PROJECT_DIR / "reports/latest/sentinel-master-report.json"
MASTER_MD = PROJECT_DIR / "reports/latest/sentinel-master-report.md"
MASTER_CRITICAL_CAUSE_JSON = PROJECT_DIR / "reports/latest/master-critical-cause-snapshot.json"
FINAL_OWNER_SNAPSHOT_JSON = PROJECT_DIR / "reports/latest/final-owner-decision-snapshot.json"
WEBSITE_JSON = PROJECT_DIR / "reports/latest/sentinel-defense-report.json"
STATUS_24H_JSON = PROJECT_DIR / "cloudflare-monitor/latest/status-24h.json"
ERRORS_5XX_JSON = PROJECT_DIR / "cloudflare-monitor/latest/errors-5xx-24h.json"
CLOUDFLARE_DAILY_MD = PROJECT_DIR / "cloudflare-monitor/latest/cloudflare-daily-monitor.md"
MASTER_CRITICAL_AUDIT_JSONL = PROJECT_DIR / "audit/master-critical-cause-snapshot.jsonl"

REPORT_JSON = PROJECT_DIR / "reports/latest/rolling-window-decay-observer.json"
REPORT_MD = PROJECT_DIR / "reports/latest/rolling-window-decay-observer.md"
OWNER_SUMMARY_MD = PROJECT_DIR / "drafts/owner/rolling-window-decay-owner-summary.md"
SNAPSHOT_JSON = PROJECT_DIR / "snapshots/rolling-window-decay-observer.json"
SNAPSHOT_MD = PROJECT_DIR / "snapshots/rolling-window-decay-observer.md"
AUDIT_JSONL = PROJECT_DIR / "audit/rolling-window-decay-observer.jsonl"

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

SCHEMA_VERSION = "rolling-window-decay-observer-5.2"
APPLY_NOT_APPLIED = "not_applied"

STATUS_OBSERVE_ONLY = "ROLLING_WINDOW_DECAY_OBSERVE_ONLY"
STATUS_IMPROVING = "ROLLING_WINDOW_DECAY_IMPROVING"
STATUS_STABLE = "ROLLING_WINDOW_DECAY_STABLE"
STATUS_GROWING = "ROLLING_WINDOW_DECAY_GROWING"
STATUS_INSUFFICIENT_HISTORY = "ROLLING_WINDOW_DECAY_INSUFFICIENT_HISTORY"
STATUS_BREACH = "ROLLING_WINDOW_DECAY_BREACH"

TREND_DECREASING = "decreasing"
TREND_STABLE = "stable"
TREND_INCREASING = "increasing"
TREND_INSUFFICIENT = "insufficient_history"

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
        raise ValueError(f"Refusing to write outside allowed rolling-window roots: {path}")
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


def read_optional_text(path: Path, max_chars: int = 160_000) -> Tuple[str, str]:
    if ".env" in str(path).lower() or SECRETISH_RE.search(path.name):
        return "", "refused_secret_like_path"
    try:
        if not path.exists():
            return "", "not_available"
        return path.read_text(encoding="utf-8", errors="replace")[:max_chars], "ok"
    except OSError:
        return "", "read_error"


def read_jsonl(path: Path, max_records: int = 25) -> Tuple[List[Dict[str, Any]], str]:
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


def text_from(data: Optional[Any], key: str, default: str = "") -> str:
    if not isinstance(data, dict):
        return default
    return redact_text(data.get(key), default=default, max_len=500)


def bool_from(data: Optional[Any], key: str, default: bool = False) -> bool:
    if not isinstance(data, dict):
        return default
    return bool(data.get(key, default))


def nested_dict(data: Optional[Any], key: str) -> Dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    value = data.get(key)
    return value if isinstance(value, dict) else {}


def metric_by_key_or_label(website: Optional[Any], key_or_label: str) -> Dict[str, Any]:
    if not isinstance(website, dict) or not isinstance(website.get("metrics"), list):
        return {}
    for metric in website["metrics"]:
        if not isinstance(metric, dict):
            continue
        keys = {
            str(metric.get("key", "")),
            str(metric.get("label", "")),
            str(metric.get("source_label", "")),
        }
        if key_or_label in keys:
            return metric
    return {}


def status_24h_counts(status_24h: Optional[Any]) -> Dict[int, int]:
    counts: Dict[int, int] = {}
    if not isinstance(status_24h, dict):
        return counts
    zones = nested_dict(nested_dict(status_24h.get("data"), "viewer"), "zones")
    # The helper above returns {} for lists; handle GraphQL's viewer.zones list
    viewer = status_24h.get("data", {}).get("viewer") if isinstance(status_24h.get("data"), dict) else {}
    raw_zones = viewer.get("zones") if isinstance(viewer, dict) else []
    if not isinstance(raw_zones, list):
        raw_zones = []
    for zone in raw_zones:
        groups = zone.get("httpRequestsAdaptiveGroups") if isinstance(zone, dict) else []
        if not isinstance(groups, list):
            continue
        for group in groups:
            if not isinstance(group, dict):
                continue
            dimensions = group.get("dimensions") if isinstance(group.get("dimensions"), dict) else {}
            status = parse_optional_int(dimensions.get("edgeResponseStatus"))
            if status is None:
                continue
            counts[status] = counts.get(status, 0) + parse_count(group.get("count"))
    _ = zones  # Keeps the structure intent visible without changing behavior.
    return counts


def errors_5xx_total_by_status(errors_5xx: Optional[Any], status: int) -> int:
    if not isinstance(errors_5xx, dict):
        return 0
    viewer = errors_5xx.get("data", {}).get("viewer") if isinstance(errors_5xx.get("data"), dict) else {}
    zones = viewer.get("zones") if isinstance(viewer, dict) else []
    if not isinstance(zones, list):
        return 0
    total = 0
    for zone in zones:
        groups = zone.get("httpRequestsAdaptiveGroups") if isinstance(zone, dict) else []
        if not isinstance(groups, list):
            continue
        for group in groups:
            dimensions = group.get("dimensions") if isinstance(group, dict) and isinstance(group.get("dimensions"), dict) else {}
            if parse_optional_int(dimensions.get("edgeResponseStatus")) == status:
                total += parse_count(group.get("count"))
    return total


def extract_daily_watchpoints(daily_md: str) -> Dict[str, int]:
    result: Dict[str, int] = {}
    for match in re.finditer(r"\|\s*([^|\n]+?)\s*\|\s*(-?[0-9]+)\s*\|", daily_md):
        label = match.group(1).strip()
        if label in {"Metrik", "---"}:
            continue
        try:
            result[label] = int(match.group(2))
        except ValueError:
            continue
    return result


def extract_daily_deltas(daily_md: str) -> Dict[str, int]:
    if "## Vergleich Zum Vorlauf" not in daily_md:
        return {}
    section = daily_md.split("## Vergleich Zum Vorlauf", 1)[1]
    if "\n## " in section:
        section = section.split("\n## ", 1)[0]
    result: Dict[str, int] = {}
    for match in re.finditer(r"\|\s*([^|\n]+?)\s*\|\s*(-?[0-9]+)\s*\|", section):
        label = match.group(1).strip()
        if label in {"Metrik", "---"}:
            continue
        try:
            result[label] = int(match.group(2))
        except ValueError:
            continue
    return result


def previous_from_audit(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    for record in reversed(records):
        if "current_5xx_total" in record or "current_504_total" in record:
            return {
                "generated_at_utc": record.get("timestamp_utc") or record.get("generated_at_utc"),
                "previous_5xx_total": parse_optional_int(record.get("current_5xx_total")),
                "previous_504_total": parse_optional_int(record.get("current_504_total")),
                "previous_sourcemap_404_total": parse_optional_int(record.get("current_sourcemap_404_total")),
                "source": "rolling_window_decay_audit",
            }
    return {}


def previous_from_daily_delta(current: Optional[int], delta: Optional[int]) -> Optional[int]:
    if current is None or delta is None:
        return None
    return max(0, current - delta)


def delta(current: Optional[int], previous: Optional[int]) -> Optional[int]:
    if current is None or previous is None:
        return None
    return current - previous


def decide_trend(deltas: List[Optional[int]]) -> str:
    available = [item for item in deltas if item is not None]
    if not available:
        return TREND_INSUFFICIENT
    if any(item > 0 for item in available):
        return TREND_INCREASING
    if any(item < 0 for item in available):
        return TREND_DECREASING
    return TREND_STABLE


def decide_status(master_status: str, trend: str, breach: bool) -> str:
    if breach:
        return STATUS_BREACH
    if trend == TREND_INSUFFICIENT:
        return STATUS_INSUFFICIENT_HISTORY
    if master_status != "CRITICAL":
        return STATUS_OBSERVE_ONLY
    if trend == TREND_INCREASING:
        return STATUS_GROWING
    if trend == TREND_DECREASING:
        return STATUS_IMPROVING
    return STATUS_STABLE


def recommendation_for_status(status: str) -> str:
    if status == STATUS_IMPROVING:
        return "Continue observation. Do not add WAF rules. Wait for 24h rolling-window decay."
    if status == STATUS_STABLE:
        return "Continue observation and compare next snapshot. No apply action."
    if status == STATUS_GROWING:
        return "Investigate origin/PHP/WordPress logs manually. Do not create WAF or install actions from this module."
    if status == STATUS_INSUFFICIENT_HISTORY:
        return "Collect more read-only snapshots before deciding."
    if status == STATUS_BREACH:
        return "Do not proceed. Resolve rolling-window observer breach before any further decision."
    return "Observe only. No apply action."


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
    master: Optional[Any],
    master_status_read: str,
    master_md: str,
    master_md_status: str,
    critical_cause: Optional[Any],
    critical_cause_status: str,
    final_owner_snapshot: Optional[Any],
    final_owner_status: str,
    website: Optional[Any],
    website_status_read: str,
    status_24h: Optional[Any],
    status_24h_status: str,
    errors_5xx: Optional[Any],
    errors_5xx_status: str,
    daily_md: str,
    daily_md_status: str,
    rolling_audit_records: List[Dict[str, Any]],
    rolling_audit_status: str,
    master_critical_audit_records: List[Dict[str, Any]],
    master_critical_audit_status: str,
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

    status_counts = status_24h_counts(status_24h)
    daily_watchpoints = extract_daily_watchpoints(daily_md)
    daily_deltas = extract_daily_deltas(daily_md)

    total_5xx_status_count = sum(count for status, count in status_counts.items() if 500 <= status <= 599)
    current_5xx_total = total_5xx_status_count or parse_count(daily_watchpoints.get("5xx gesamt")) or parse_count((metric_by_key_or_label(website, "total_5xx") or {}).get("value"))
    current_504_total = status_counts.get(504) or errors_5xx_total_by_status(errors_5xx, 504) or None
    map_metric = metric_by_key_or_label(website, "map_404") or metric_by_key_or_label(website, "404 auf .map")
    current_sourcemap_404_total = parse_count(map_metric.get("value")) if map_metric else parse_count(daily_watchpoints.get("404 auf .map"))

    previous = previous_from_audit(rolling_audit_records)
    previous_5xx_total = parse_optional_int(previous.get("previous_5xx_total"))
    previous_504_total = parse_optional_int(previous.get("previous_504_total"))
    previous_sourcemap_404_total = parse_optional_int(previous.get("previous_sourcemap_404_total"))
    previous_source = previous.get("source")

    daily_5xx_delta = parse_optional_int(daily_deltas.get("5xx gesamt"))
    daily_map_delta = parse_optional_int(daily_deltas.get("404 auf .map"))
    if previous_5xx_total is None:
        previous_5xx_total = previous_from_daily_delta(current_5xx_total, daily_5xx_delta)
        if previous_5xx_total is not None:
            previous_source = "cloudflare_daily_delta"
    if previous_sourcemap_404_total is None:
        previous_sourcemap_404_total = previous_from_daily_delta(current_sourcemap_404_total, daily_map_delta)
        if previous_sourcemap_404_total is not None and previous_source is None:
            previous_source = "cloudflare_daily_delta"

    delta_5xx = delta(current_5xx_total, previous_5xx_total)
    delta_504 = delta(current_504_total, previous_504_total)
    delta_sourcemap_404 = delta(current_sourcemap_404_total, previous_sourcemap_404_total)

    trend = decide_trend([delta_5xx, delta_504, delta_sourcemap_404])
    master_status = text_from(master, "overall_master_status", "UNKNOWN")
    website_critical = (
        text_from(master, "website_status") == "CRITICAL"
        or text_from(website, "overall_status") == "CRITICAL"
        or current_5xx_total >= 600
    )
    autonomy_cause = bool_from(critical_cause, "critical_caused_by_autonomy")
    website_cause = bool_from(critical_cause, "critical_caused_by_website", website_critical)
    rolling_window_cause = bool_from(critical_cause, "critical_caused_by_rolling_window", current_5xx_total > 0)
    sourcemap_warning = (
        bool_from(critical_cause, "critical_caused_by_sourcemap")
        or current_sourcemap_404_total > 0
        or text_from(nested_dict(master, "sourcemap_prevention"), "status") in {"WARNING", "CRITICAL"}
    )

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
    decay_status = decide_status(master_status, trend, breach)
    recommended_owner_action = recommendation_for_status(decay_status)
    observation_required = decay_status in {
        STATUS_IMPROVING,
        STATUS_STABLE,
        STATUS_GROWING,
        STATUS_INSUFFICIENT_HISTORY,
        STATUS_OBSERVE_ONLY,
    }

    history_points = len(rolling_audit_records) + (1 if previous_source == "cloudflare_daily_delta" else 0)
    if master_critical_audit_status == "ok":
        history_points += len(master_critical_audit_records)

    rolling_window_leftovers = trend in {TREND_DECREASING, TREND_STABLE} and current_5xx_total > 0
    real_new_growth = trend == TREND_INCREASING

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": generated,
        "decay_status": decay_status,
        "master_status": master_status,
        "website_critical": website_critical,
        "autonomy_cause": autonomy_cause,
        "website_cause": website_cause,
        "rolling_window_cause": rolling_window_cause,
        "sourcemap_warning": sourcemap_warning,
        "current_5xx_total": current_5xx_total,
        "previous_5xx_total": previous_5xx_total,
        "delta_5xx": delta_5xx,
        "current_504_total": current_504_total,
        "previous_504_total": previous_504_total,
        "delta_504": delta_504,
        "current_sourcemap_404_total": current_sourcemap_404_total,
        "previous_sourcemap_404_total": previous_sourcemap_404_total,
        "delta_sourcemap_404": delta_sourcemap_404,
        "trend": trend,
        "history_points": history_points,
        "previous_source": previous_source or "not_available",
        "observation_required": observation_required,
        "recommended_owner_action": recommended_owner_action,
        "apply_status": apply_status,
        "live_apply": live_apply,
        "install_allowed_now": install_allowed_now,
        "can_install_timer_now": can_install_timer_now,
        "snapshot_breach": breach,
        "snapshot_breach_reasons": breach_reasons,
        "rolling_window_leftovers": rolling_window_leftovers,
        "real_new_growth": real_new_growth,
        "source_map_diagnostic_only": True,
        "no_countermeasure_executed": True,
        "no_waf_rule_derived": True,
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
        "input_statuses": {
            "sentinel_master_json": master_status_read,
            "sentinel_master_md": master_md_status,
            "master_critical_cause_snapshot": critical_cause_status,
            "final_owner_snapshot": final_owner_status,
            "sentinel_defense_json": website_status_read,
            "status_24h": status_24h_status,
            "errors_5xx": errors_5xx_status,
            "cloudflare_daily_md": daily_md_status,
            "rolling_window_audit": rolling_audit_status,
            "master_critical_cause_audit": master_critical_audit_status,
        },
        "website_origin_context": {
            "website_status": text_from(master, "website_status", text_from(website, "overall_status", "UNKNOWN")),
            "website_correlation_status": text_from(master, "website_correlation_status", text_from(website, "correlation_status", "UNKNOWN")),
            "action_status": text_from(master, "action_status", "UNKNOWN"),
            "critical_snapshot_status": text_from(critical_cause, "critical_snapshot_status", "NOT_AVAILABLE"),
            "daily_delta_5xx": daily_5xx_delta,
            "daily_delta_map_404": daily_map_delta,
            "daily_watchpoints": daily_watchpoints,
        },
        "autonomy_context": {
            "critical_caused_by_autonomy": autonomy_cause,
            "final_owner_snapshot_breach": bool_from(final_owner_snapshot, "snapshot_breach"),
            "emergency_stop_active": (
                bool_from(final_owner_snapshot, "emergency_stop_active")
                or bool_from(nested_dict(master, "final_owner_decision_snapshot"), "emergency_stop_active")
                or bool_from(critical_cause, "emergency_stop_active")
            ),
            "install_allowed_now": False,
            "live_apply": False,
        },
        "owner_interpretation": {
            "rolling_window_leftovers": rolling_window_leftovers,
            "real_new_growth": real_new_growth,
            "source_map_diagnostic_only": True,
            "autonomy_is_not_cause": not autonomy_cause,
        },
        "safe_owner_next_actions": [
            recommended_owner_action,
            "Keep this module observe-only; it does not create Cloudflare, WordPress, Nginx, .htaccess, systemd, or crontab actions.",
            "Use the next read-only snapshot to confirm whether the 24h window decays or grows.",
        ],
        "do_not_apply_conditions": [
            "Do not create WAF rules from this observer.",
            "Do not install timers from this observer.",
            "Do not change WordPress, Nginx, .htaccess, systemd, or crontab from this observer.",
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
    owner = report.get("owner_interpretation") if isinstance(report.get("owner_interpretation"), dict) else {}
    website = report.get("website_origin_context") if isinstance(report.get("website_origin_context"), dict) else {}
    autonomy = report.get("autonomy_context") if isinstance(report.get("autonomy_context"), dict) else {}
    lines = [
        "# Rolling Window Decay Observer",
        "",
        "## Executive Summary",
        "",
        f"- Generated (UTC): `{report.get('generated_at_utc')}`",
        f"- Decay status: `{report.get('decay_status')}`",
        f"- Trend: `{report.get('trend')}`",
        f"- Master status: `{report.get('master_status')}`",
        f"- Website critical: `{report.get('website_critical')}`",
        f"- Autonomy cause: `{report.get('autonomy_cause')}`",
        f"- Website cause: `{report.get('website_cause')}`",
        f"- Rolling-window cause: `{report.get('rolling_window_cause')}`",
        f"- SourceMap warning: `{report.get('sourcemap_warning')}`",
        f"- Snapshot breach: `{report.get('snapshot_breach')}`",
        f"- Recommended owner action: {redact_text(report.get('recommended_owner_action'), max_len=900)}",
        "",
        "## Current And Previous Values",
        "",
        "| Metric | Current | Previous | Delta |",
        "|---|---:|---:|---:|",
        f"| 5xx total | `{report.get('current_5xx_total')}` | `{report.get('previous_5xx_total')}` | `{report.get('delta_5xx')}` |",
        f"| 504 total | `{report.get('current_504_total')}` | `{report.get('previous_504_total')}` | `{report.get('delta_504')}` |",
        f"| .map 404 total | `{report.get('current_sourcemap_404_total')}` | `{report.get('previous_sourcemap_404_total')}` | `{report.get('delta_sourcemap_404')}` |",
        "",
        "## Rolling Window Status",
        "",
        f"- Previous source: `{report.get('previous_source')}`",
        f"- History points: `{report.get('history_points')}`",
        f"- 24h rolling-window leftovers: `{owner.get('rolling_window_leftovers')}`",
        f"- Real new growth: `{owner.get('real_new_growth')}`",
        f"- Observation required: `{report.get('observation_required')}`",
        "",
        "## SourceMap Status",
        "",
        f"- Current .map 404 total: `{report.get('current_sourcemap_404_total')}`",
        f"- SourceMap diagnostic only: `{report.get('source_map_diagnostic_only')}`",
        "",
        "## Autonomy Status",
        "",
        f"- Critical caused by autonomy: `{autonomy.get('critical_caused_by_autonomy')}`",
        f"- Final owner snapshot breach: `{autonomy.get('final_owner_snapshot_breach')}`",
        f"- Emergency stop active: `{autonomy.get('emergency_stop_active')}`",
        f"- Install allowed now: `{report.get('install_allowed_now')}`",
        f"- Live apply: `{report.get('live_apply')}`",
        "",
        "## Website / Origin Context",
        "",
        f"- Website status: `{website.get('website_status')}`",
        f"- Website correlation status: `{website.get('website_correlation_status')}`",
        f"- Master action status: `{website.get('action_status')}`",
        f"- Master critical cause status: `{website.get('critical_snapshot_status')}`",
        "",
        "## Safe Owner Next Actions",
        "",
    ]
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
        "decay_status": report.get("decay_status"),
        "master_status": report.get("master_status"),
        "trend": report.get("trend"),
        "current_5xx_total": report.get("current_5xx_total"),
        "current_504_total": report.get("current_504_total"),
        "current_sourcemap_404_total": report.get("current_sourcemap_404_total"),
        "delta_5xx": report.get("delta_5xx"),
        "delta_504": report.get("delta_504"),
        "delta_sourcemap_404": report.get("delta_sourcemap_404"),
        "observation_required": report.get("observation_required"),
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
    master, master_status = read_optional_json(MASTER_JSON)
    master_md, master_md_status = read_optional_text(MASTER_MD)
    critical_cause, critical_cause_status = read_optional_json(MASTER_CRITICAL_CAUSE_JSON)
    final_owner, final_owner_status = read_optional_json(FINAL_OWNER_SNAPSHOT_JSON)
    website, website_status = read_optional_json(WEBSITE_JSON)
    status_24h, status_24h_status = read_optional_json(STATUS_24H_JSON)
    errors_5xx, errors_5xx_status = read_optional_json(ERRORS_5XX_JSON)
    daily_md, daily_md_status = read_optional_text(CLOUDFLARE_DAILY_MD)
    rolling_audit, rolling_audit_status = read_jsonl(AUDIT_JSONL)
    master_critical_audit, master_critical_audit_status = read_jsonl(MASTER_CRITICAL_AUDIT_JSONL)
    return build_report(
        master,
        master_status,
        master_md,
        master_md_status,
        critical_cause,
        critical_cause_status,
        final_owner,
        final_owner_status,
        website,
        website_status,
        status_24h,
        status_24h_status,
        errors_5xx,
        errors_5xx_status,
        daily_md,
        daily_md_status,
        rolling_audit,
        rolling_audit_status,
        master_critical_audit,
        master_critical_audit_status,
    )


def run_self_test() -> int:
    master = {"overall_master_status": "CRITICAL", "website_status": "CRITICAL", "website_correlation_status": "NORMAL", "action_status": "WARNING_REVIEW"}
    critical = {"critical_caused_by_autonomy": False, "critical_caused_by_website": True, "critical_caused_by_rolling_window": True, "critical_caused_by_sourcemap": False}
    final_owner = {"snapshot_breach": False, "emergency_stop_active": True}
    website = {"overall_status": "CRITICAL", "metrics": [{"key": "map_404", "label": "404 auf .map", "value": 2, "status": "OK"}]}
    status_24h = {
        "data": {
            "viewer": {
                "zones": [
                    {
                        "httpRequestsAdaptiveGroups": [
                            {"count": 520, "dimensions": {"edgeResponseStatus": 504}},
                            {"count": 80, "dimensions": {"edgeResponseStatus": 503}},
                        ]
                    }
                ]
            }
        }
    }
    daily = "## Watchpoints\n| 5xx gesamt | 600 |\n| 404 auf .map | 2 |\n## Vergleich Zum Vorlauf\n| 5xx gesamt | -50 |\n| 404 auf .map | 0 |\n"
    improving = build_report(master, "ok", "", "ok", critical, "ok", final_owner, "ok", website, "ok", status_24h, "ok", {}, "ok", daily, "ok", [], "not_available", [], "not_available", generated_at="2026-06-12T00:00:00Z")
    if improving["decay_status"] != STATUS_IMPROVING or improving["trend"] != TREND_DECREASING:
        raise AssertionError("improving trend failed")

    growing_daily = "## Watchpoints\n| 5xx gesamt | 600 |\n| 404 auf .map | 2 |\n## Vergleich Zum Vorlauf\n| 5xx gesamt | 25 |\n| 404 auf .map | 0 |\n"
    growing = build_report(master, "ok", "", "ok", critical, "ok", final_owner, "ok", website, "ok", status_24h, "ok", {}, "ok", growing_daily, "ok", [], "not_available", [], "not_available")
    if growing["decay_status"] != STATUS_GROWING or growing["snapshot_breach"]:
        raise AssertionError("growing trend failed")

    stable_daily = "## Watchpoints\n| 5xx gesamt | 600 |\n| 404 auf .map | 2 |\n## Vergleich Zum Vorlauf\n| 5xx gesamt | 0 |\n| 404 auf .map | 0 |\n"
    stable = build_report(master, "ok", "", "ok", critical, "ok", final_owner, "ok", website, "ok", status_24h, "ok", {}, "ok", stable_daily, "ok", [], "not_available", [], "not_available")
    if stable["decay_status"] != STATUS_STABLE or stable["trend"] != TREND_STABLE:
        raise AssertionError("stable trend failed")

    insufficient = build_report(master, "ok", "", "ok", critical, "ok", final_owner, "ok", website, "ok", status_24h, "ok", {}, "ok", "", "not_available", [], "not_available", [], "not_available")
    if insufficient["decay_status"] != STATUS_INSUFFICIENT_HISTORY or insufficient["snapshot_breach"]:
        raise AssertionError("insufficient history failed")

    previous_records = [{"current_5xx_total": 700, "current_504_total": 610, "current_sourcemap_404_total": 9}]
    audit_based = build_report(master, "ok", "", "ok", critical, "ok", final_owner, "ok", website, "ok", status_24h, "ok", {}, "ok", "", "not_available", previous_records, "ok", [], "not_available")
    if audit_based["previous_5xx_total"] != 700 or audit_based["trend"] != TREND_DECREASING:
        raise AssertionError("audit comparison failed")

    for key in ("live_apply", "install_allowed_now", "can_install_timer_now", "forbidden_apply_command_detected", "systemd_file_written", "crontab_file_written", "executable_install_script_generated", "secret_like_output", "output_path_breach"):
        bad = build_report(master, "ok", "", "ok", critical, "ok", final_owner, "ok", website, "ok", status_24h, "ok", {}, "ok", growing_daily, "ok", [], "not_available", [], "not_available", forced_flags={key: True})
        if not bad["snapshot_breach"] or bad["decay_status"] != STATUS_BREACH:
            raise AssertionError(f"{key} did not breach")
    bad_apply = build_report(master, "ok", "", "ok", critical, "ok", final_owner, "ok", website, "ok", status_24h, "ok", {}, "ok", growing_daily, "ok", [], "not_available", [], "not_available", forced_flags={"apply_status": "applied"})
    if not bad_apply["snapshot_breach"]:
        raise AssertionError("apply_status breach failed")
    if not FORBIDDEN_APPLY_COMMAND_RE.search("nginx reload"):
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
        assert_allowed_write(PROJECT_DIR / "state/rolling-window-decay-observer.json")
    except ValueError:
        pass
    else:
        raise AssertionError("forbidden write root was not rejected")
    print("rolling-window-decay-observer self-tests: OK")
    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Observe website/origin rolling-window decay; read-only, no apply.")
    parser.add_argument("--self-test", action="store_true", help="Run in-memory safety tests and exit.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()
    report = build_current_report()
    write_outputs(report)
    print(
        "Rolling Window Decay Observer: "
        f"status={report.get('decay_status')}, "
        f"trend={report.get('trend')}, "
        f"delta_5xx={report.get('delta_5xx')}, "
        f"breach={report.get('snapshot_breach')}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
