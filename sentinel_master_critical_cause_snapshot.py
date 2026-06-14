#!/usr/bin/env python3
"""Sentinel Master Critical Cause Snapshot (Phase 5.1).

Explains why the Sentinel Master is CRITICAL while the Safe-Draft-Autonomy
chain remains breach-free. This module is read-only analysis plus local report
output. It is not an apply mechanism, not an installation, and not an active
timer.

Hard safety guarantees:
- no live changes
- no network, API, WordPress login, Cloudflare, Nginx, .htaccess, systemd, or
  crontab work
- install_allowed_now, can_install_timer_now, live_apply stay false
- apply_status remains not_applied
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
WEBSITE_JSON = PROJECT_DIR / "reports/latest/sentinel-defense-report.json"
FINAL_OWNER_SNAPSHOT_JSON = PROJECT_DIR / "reports/latest/final-owner-decision-snapshot.json"
FINAL_SAFETY_JSON = PROJECT_DIR / "reports/latest/safe-draft-autonomy-final-safety-report.json"
COMPLETION_GATE_JSON = PROJECT_DIR / "reports/latest/manual-evidence-review-completion-gate.json"
OWNER_CONSOLE_JSON = PROJECT_DIR / "reports/latest/owner-evidence-review-console.json"
RUNTIME_LOCK_JSON = PROJECT_DIR / "config/autonomy-runtime-lock.json"
STATUS_24H_JSON = PROJECT_DIR / "cloudflare-monitor/latest/status-24h.json"
ERRORS_5XX_JSON = PROJECT_DIR / "cloudflare-monitor/latest/errors-5xx-24h.json"
CLOUDFLARE_DAILY_MD = PROJECT_DIR / "cloudflare-monitor/latest/cloudflare-daily-monitor.md"

REPORT_JSON = PROJECT_DIR / "reports/latest/master-critical-cause-snapshot.json"
REPORT_MD = PROJECT_DIR / "reports/latest/master-critical-cause-snapshot.md"
OWNER_SUMMARY_MD = PROJECT_DIR / "drafts/owner/master-critical-cause-owner-summary.md"
SNAPSHOT_JSON = PROJECT_DIR / "snapshots/master-critical-cause-snapshot.json"
SNAPSHOT_MD = PROJECT_DIR / "snapshots/master-critical-cause-snapshot.md"
AUDIT_JSONL = PROJECT_DIR / "audit/master-critical-cause-snapshot.jsonl"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "drafts/owner",
    PROJECT_DIR / "audit",
    PROJECT_DIR / "snapshots",
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

SCHEMA_VERSION = "master-critical-cause-snapshot-5.1"
APPLY_NOT_APPLIED = "not_applied"

STATUS_WEBSITE_ONLY = "CRITICAL_CAUSE_IDENTIFIED_WEBSITE_ONLY"
STATUS_AUTONOMY = "CRITICAL_CAUSE_IDENTIFIED_AUTONOMY"
STATUS_MIXED = "CRITICAL_CAUSE_MIXED"
STATUS_NOT_CRITICAL = "CRITICAL_CAUSE_NOT_CRITICAL"
STATUS_PARTIAL_INPUTS = "CRITICAL_CAUSE_PARTIAL_INPUTS"
STATUS_BREACH = "CRITICAL_CAUSE_BREACH"

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
        raise ValueError(f"Refusing to write outside allowed critical-cause roots: {path}")
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


def nested_dict(data: Optional[Any], key: str) -> Dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    value = data.get(key)
    return value if isinstance(value, dict) else {}


def metric_by_key_or_label(website: Optional[Any], key_or_label: str) -> Dict[str, Any]:
    if not isinstance(website, dict):
        return {}
    metrics = website.get("metrics")
    if not isinstance(metrics, list):
        return {}
    for metric in metrics:
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


def critical_v2_findings(website: Optional[Any]) -> List[Dict[str, Any]]:
    if not isinstance(website, dict) or not isinstance(website.get("correlation_v2_findings"), list):
        return []
    findings: List[Dict[str, Any]] = []
    for finding in website["correlation_v2_findings"]:
        if isinstance(finding, dict) and str(finding.get("status", "")).upper() in {"CRITICAL", "WARNING"}:
            findings.append(
                {
                    "signal_id": redact_text(finding.get("signal_id"), max_len=120),
                    "status": redact_text(finding.get("status"), max_len=80),
                    "count": parse_count(finding.get("count")),
                    "recommendation": redact_text(finding.get("recommendation"), max_len=400),
                }
            )
    return findings[:10]


def extract_cloudflare_watchpoints(daily_md: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for label in ("5xx gesamt", "504 auf /", "404 auf .map", "SiteLockSpider in Top User-Agents"):
        match = re.search(rf"\|\s*{re.escape(label)}\s*\|\s*([0-9]+)\s*\|", daily_md)
        if match:
            result[label] = parse_count(match.group(1))
    delta_match = re.search(r"\|\s*5xx gesamt\s*\|\s*([-0-9]+)\s*\|", daily_md.split("## Vergleich Zum Vorlauf", 1)[-1])
    if delta_match:
        try:
            result["5xx_delta"] = int(delta_match.group(1))
        except ValueError:
            result["5xx_delta"] = 0
    return result


def autonomy_breach_reasons(
    final_owner_snapshot: Optional[Any],
    final_safety: Optional[Any],
    completion_gate: Optional[Any],
    owner_console: Optional[Any],
    master: Optional[Any],
) -> List[str]:
    checks = (
        ("final_owner_snapshot", final_owner_snapshot, "snapshot_breach"),
        ("final_safety", final_safety, "final_safety_breach"),
        ("completion_gate", completion_gate, "gate_breach"),
        ("owner_console", owner_console, "console_breach"),
        ("master.final_owner_decision_snapshot", nested_dict(master, "final_owner_decision_snapshot"), "snapshot_breach"),
        ("master.safe_draft_autonomy_final_safety", nested_dict(master, "safe_draft_autonomy_final_safety"), "final_safety_breach"),
        ("master.manual_evidence_review_completion_gate", nested_dict(master, "manual_evidence_review_completion_gate"), "gate_breach"),
        ("master.owner_evidence_review_console", nested_dict(master, "owner_evidence_review_console"), "console_breach"),
    )
    reasons: List[str] = []
    for label, data, key in checks:
        if bool_from(data, key):
            reasons.append(f"{label}:{key}=true")
    return sorted(set(reasons))


def total_autonomy_breaches(
    final_owner_snapshot: Optional[Any],
    final_safety: Optional[Any],
    completion_gate: Optional[Any],
    owner_console: Optional[Any],
    master: Optional[Any],
) -> int:
    explicit = [
        parse_count(final_owner_snapshot.get("total_breaches")) if isinstance(final_owner_snapshot, dict) else 0,
        parse_count(final_safety.get("total_breach_count")) if isinstance(final_safety, dict) else 0,
    ]
    return max(max(explicit), len(autonomy_breach_reasons(final_owner_snapshot, final_safety, completion_gate, owner_console, master)))


def detect_breach(
    *,
    live_apply: bool,
    install_allowed_now: bool,
    can_install_timer_now: bool,
    apply_status: str,
    systemd_file_written: bool,
    crontab_file_written: bool,
    forbidden_apply_command_detected: bool,
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
    if systemd_file_written:
        reasons.append("systemd_file_written=true")
    if crontab_file_written:
        reasons.append("crontab_file_written=true")
    if forbidden_apply_command_detected:
        reasons.append("Cloudflare/WordPress/Nginx/.htaccess apply command detected")
    if secret_like_output:
        reasons.append("secret-like output")
    if output_path_breach:
        reasons.append("writing outside allowed roots")
    return bool(reasons), sorted(set(reasons))


def decide_status(
    master_status: str,
    *,
    autonomy_cause: bool,
    website_cause: bool,
    partial_inputs: bool,
    breach: bool,
) -> str:
    if breach:
        return STATUS_BREACH
    if partial_inputs:
        return STATUS_PARTIAL_INPUTS
    if master_status != "CRITICAL":
        return STATUS_NOT_CRITICAL
    if autonomy_cause and website_cause:
        return STATUS_MIXED
    if autonomy_cause:
        return STATUS_AUTONOMY
    return STATUS_WEBSITE_ONLY


def build_report(
    master: Optional[Any],
    master_status_read: str,
    master_md: str,
    master_md_status: str,
    website: Optional[Any],
    website_status_read: str,
    final_owner_snapshot: Optional[Any],
    final_owner_status: str,
    final_safety: Optional[Any],
    final_safety_status: str,
    completion_gate: Optional[Any],
    completion_gate_status: str,
    owner_console: Optional[Any],
    owner_console_status: str,
    runtime_lock: Optional[Any],
    runtime_lock_status: str,
    status_24h: Optional[Any],
    status_24h_status: str,
    errors_5xx: Optional[Any],
    errors_5xx_status: str,
    daily_md: str,
    daily_md_status: str,
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
    systemd_file_written = bool(flags.get("systemd_file_written", False))
    crontab_file_written = bool(flags.get("crontab_file_written", False))
    output_path_breach = bool(flags.get("output_path_breach", False))
    secret_like_output = bool(flags.get("secret_like_output", False))
    forbidden_apply_command_detected = bool(flags.get("forbidden_apply_command_detected", False))

    master_status = text_from(master, "overall_master_status", "UNKNOWN")
    action_status = text_from(master, "action_status", "UNKNOWN")
    website_master_status = text_from(master, "website_status", "")
    website_json_status = text_from(website, "overall_status", "")
    website_correlation_status = text_from(master, "website_correlation_status", text_from(website, "correlation_status", "UNKNOWN"))
    total_5xx_metric = metric_by_key_or_label(website, "total_5xx") or metric_by_key_or_label(website, "5xx gesamt")
    source_map_metric = metric_by_key_or_label(website, "404 auf .map")
    root_504_metric = metric_by_key_or_label(website, "root_504") or metric_by_key_or_label(website, "504 auf /")
    cloudflare_watchpoints = extract_cloudflare_watchpoints(daily_md)

    autonomy_reasons = autonomy_breach_reasons(final_owner_snapshot, final_safety, completion_gate, owner_console, master)
    autonomy_total = total_autonomy_breaches(final_owner_snapshot, final_safety, completion_gate, owner_console, master)
    critical_caused_by_autonomy = bool(autonomy_reasons or autonomy_total > 0)

    total_5xx_value = parse_count(total_5xx_metric.get("value")) if total_5xx_metric else parse_count(cloudflare_watchpoints.get("5xx gesamt"))
    total_5xx_status = redact_text(total_5xx_metric.get("status"), default="UNKNOWN") if total_5xx_metric else ("CRITICAL" if total_5xx_value >= 600 else "WARNING" if total_5xx_value >= 300 else "OK")
    critical_caused_by_website = (
        website_master_status == "CRITICAL"
        or website_json_status == "CRITICAL"
        or total_5xx_status == "CRITICAL"
        or total_5xx_value >= 600
    )
    critical_caused_by_rolling_window = total_5xx_value > 0 or parse_count(cloudflare_watchpoints.get("5xx_delta")) >= 0
    critical_caused_by_sourcemap = (
        text_from(nested_dict(master, "sourcemap_prevention"), "status") in {"WARNING", "CRITICAL"}
        or parse_count(cloudflare_watchpoints.get("404 auf .map")) > 0
        or parse_count(source_map_metric.get("value")) > 0
    )
    emergency_stop_active = (
        bool_from(final_owner_snapshot, "emergency_stop_active")
        or bool_from(final_safety, "emergency_stop_active")
        or bool_from(completion_gate, "emergency_stop_active")
        or bool_from(owner_console, "emergency_stop_active")
        or bool_from(runtime_lock, "emergency_stop")
        or bool_from(runtime_lock, "emergency_stop_active")
    )

    # We do not scan input reports for words like apply-safe because many
    # historical reports discuss safe boundaries. The breach rule applies to
    # commands generated by this snapshot; this module generates no apply
    # command. The forced flag is used by self-tests.
    breach, breach_reasons = detect_breach(
        live_apply=live_apply,
        install_allowed_now=install_allowed_now,
        can_install_timer_now=can_install_timer_now,
        apply_status=apply_status,
        systemd_file_written=systemd_file_written,
        crontab_file_written=crontab_file_written,
        forbidden_apply_command_detected=forbidden_apply_command_detected,
        secret_like_output=secret_like_output,
        output_path_breach=output_path_breach,
    )
    partial_inputs = master_status_read != "ok" or website_status_read != "ok"
    critical_snapshot_status = decide_status(
        master_status,
        autonomy_cause=critical_caused_by_autonomy,
        website_cause=critical_caused_by_website,
        partial_inputs=partial_inputs,
        breach=breach,
    )

    if breach:
        recommended_owner_action = "Do not proceed. Resolve critical-cause snapshot breach before any further decision."
    elif critical_snapshot_status == STATUS_WEBSITE_ONLY:
        recommended_owner_action = "Autonomy chain is not the cause. Continue read-only observation of website/origin 24h window; no WAF or install action from this snapshot."
    elif critical_snapshot_status == STATUS_NOT_CRITICAL:
        recommended_owner_action = "Master is not CRITICAL. Keep monitoring; no apply action."
    elif critical_snapshot_status == STATUS_PARTIAL_INPUTS:
        recommended_owner_action = "Regenerate missing master or website reports, then rerun this snapshot."
    else:
        recommended_owner_action = "Review autonomy breach and website signals separately; do not apply changes from this snapshot."

    website_signals = {
        "website_status": website_master_status or website_json_status or "UNKNOWN",
        "website_correlation_status": website_correlation_status,
        "total_5xx_value": total_5xx_value,
        "total_5xx_status": total_5xx_status,
        "root_504_value": parse_count(root_504_metric.get("value")) if root_504_metric else parse_count(cloudflare_watchpoints.get("504 auf /")),
        "source_map_404_value": parse_count(source_map_metric.get("value")) if source_map_metric else parse_count(cloudflare_watchpoints.get("404 auf .map")),
        "cloudflare_watchpoints": cloudflare_watchpoints,
        "critical_v2_findings": critical_v2_findings(website),
    }

    rolling_window = {
        "total_5xx_24h": total_5xx_value,
        "delta_5xx": cloudflare_watchpoints.get("5xx_delta", "not_available"),
        "interpretation": "24h rolling-window / origin-pressure remains the website-side reason for CRITICAL." if total_5xx_value >= 600 else "Rolling window is below CRITICAL threshold or partial.",
        "no_waf_rule_derived": True,
    }
    sourcemap = {
        "master_sourcemap_status": text_from(nested_dict(master, "sourcemap_prevention"), "status", "NOT_AVAILABLE"),
        "map_404_count": website_signals["source_map_404_value"],
        "diagnostic_only": True,
    }
    autonomy = {
        "critical_caused_by_autonomy": critical_caused_by_autonomy,
        "autonomy_total_breaches": autonomy_total,
        "autonomy_breach_reasons": autonomy_reasons,
        "final_owner_snapshot_status": text_from(final_owner_snapshot, "snapshot_status", "NOT_AVAILABLE"),
        "final_owner_snapshot_breach": bool_from(final_owner_snapshot, "snapshot_breach"),
        "final_safety_status": text_from(final_safety, "final_safety_status", text_from(final_safety, "status", "NOT_AVAILABLE")),
        "final_safety_breach": bool_from(final_safety, "final_safety_breach"),
        "completion_gate_status": text_from(completion_gate, "gate_status", "NOT_AVAILABLE"),
        "completion_gate_breach": bool_from(completion_gate, "gate_breach"),
        "owner_console_status": text_from(owner_console, "console_status", "NOT_AVAILABLE"),
        "owner_console_breach": bool_from(owner_console, "console_breach"),
        "emergency_stop_active": emergency_stop_active,
    }

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": generated,
        "critical_snapshot_status": critical_snapshot_status,
        "master_status": master_status,
        "action_status": action_status,
        "critical_caused_by_autonomy": critical_caused_by_autonomy,
        "critical_caused_by_website": critical_caused_by_website,
        "critical_caused_by_rolling_window": critical_caused_by_rolling_window,
        "critical_caused_by_sourcemap": critical_caused_by_sourcemap,
        "autonomy_total_breaches": autonomy_total,
        "final_owner_snapshot_breach": bool_from(final_owner_snapshot, "snapshot_breach"),
        "emergency_stop_active": emergency_stop_active,
        "install_allowed_now": install_allowed_now,
        "can_install_timer_now": can_install_timer_now,
        "live_apply": live_apply,
        "apply_status": apply_status,
        "recommended_owner_action": recommended_owner_action,
        "snapshot_breach": breach,
        "snapshot_breach_reasons": breach_reasons,
        "read_only": True,
        "network_access": False,
        "api_access": False,
        "wordpress_login": False,
        "cloudflare_mutations": False,
        "nginx_mutations": False,
        "htaccess_mutations": False,
        "systemd_file_written": systemd_file_written,
        "crontab_file_written": crontab_file_written,
        "cloudflare_api_used": False,
        "apply_function": False,
        "secrets_output": False,
        "input_statuses": {
            "sentinel_master_json": master_status_read,
            "sentinel_master_md": master_md_status,
            "sentinel_defense_json": website_status_read,
            "final_owner_snapshot": final_owner_status,
            "final_safety": final_safety_status,
            "completion_gate": completion_gate_status,
            "owner_console": owner_console_status,
            "runtime_lock": runtime_lock_status,
            "status_24h": status_24h_status,
            "errors_5xx": errors_5xx_status,
            "cloudflare_daily_md": daily_md_status,
        },
        "autonomy_chain": autonomy,
        "website_origin_cloudflare_signals": website_signals,
        "rolling_window_status": rolling_window,
        "sourcemap_status": sourcemap,
        "what_is_not_the_cause": [
            "Safe-Draft-Autonomy chain is breach-free." if not critical_caused_by_autonomy else "Autonomy chain has breach signals; review required.",
            "No Cloudflare mutation was performed by this snapshot.",
            "No WordPress, Nginx, .htaccess, systemd, crontab, or live apply action was performed.",
        ],
        "safe_owner_next_actions": [
            recommended_owner_action,
            "Keep Emergency Stop active for timer/autonomy chain unless the Owner separately decides otherwise.",
            "Do not derive a WAF rule from diagnostic-only or observe-24h reports.",
        ],
        "do_not_apply_conditions": [
            "Do not run apply-safe from this snapshot.",
            "Do not add Cloudflare rules from this snapshot.",
            "Do not install timers from this snapshot.",
            "Do not change WordPress, Nginx, .htaccess, systemd, or crontab from this snapshot.",
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
    website = report.get("website_origin_cloudflare_signals", {}) if isinstance(report.get("website_origin_cloudflare_signals"), dict) else {}
    rolling = report.get("rolling_window_status", {}) if isinstance(report.get("rolling_window_status"), dict) else {}
    sourcemap = report.get("sourcemap_status", {}) if isinstance(report.get("sourcemap_status"), dict) else {}
    autonomy = report.get("autonomy_chain", {}) if isinstance(report.get("autonomy_chain"), dict) else {}
    lines = [
        "# Master Critical Cause Snapshot",
        "",
        "## Executive Summary",
        "",
        f"- Generated (UTC): `{report.get('generated_at_utc')}`",
        f"- Critical snapshot status: `{report.get('critical_snapshot_status')}`",
        f"- Master status: `{report.get('master_status')}`",
        f"- Action status: `{report.get('action_status')}`",
        f"- Critical caused by autonomy: `{report.get('critical_caused_by_autonomy')}`",
        f"- Critical caused by website: `{report.get('critical_caused_by_website')}`",
        f"- Autonomy total breaches: `{report.get('autonomy_total_breaches')}`",
        f"- Emergency stop active: `{report.get('emergency_stop_active')}`",
        f"- Install allowed now: `{report.get('install_allowed_now')}`",
        f"- Live apply: `{report.get('live_apply')}`",
        f"- Snapshot breach: `{report.get('snapshot_breach')}`",
        f"- Recommended owner action: {redact_text(report.get('recommended_owner_action'), max_len=900)}",
        "",
        "## Why Master Is Critical",
        "",
        f"- Website status: `{website.get('website_status', 'UNKNOWN')}`",
        f"- Website correlation status: `{website.get('website_correlation_status', 'UNKNOWN')}`",
        f"- 5xx total in 24h window: `{website.get('total_5xx_value', 0)}` (`{website.get('total_5xx_status', 'UNKNOWN')}`)",
        f"- Root 504 count: `{website.get('root_504_value', 0)}`",
        f"- SourceMap 404 count: `{website.get('source_map_404_value', 0)}`",
        "",
        "## Autonomy Chain Status",
        "",
        f"- Final owner snapshot: `{autonomy.get('final_owner_snapshot_status')}`",
        f"- Final owner snapshot breach: `{autonomy.get('final_owner_snapshot_breach')}`",
        f"- Final safety: `{autonomy.get('final_safety_status')}`",
        f"- Final safety breach: `{autonomy.get('final_safety_breach')}`",
        f"- Completion gate: `{autonomy.get('completion_gate_status')}`",
        f"- Completion gate breach: `{autonomy.get('completion_gate_breach')}`",
        f"- Owner console: `{autonomy.get('owner_console_status')}`",
        f"- Owner console breach: `{autonomy.get('owner_console_breach')}`",
        f"- Emergency stop active: `{autonomy.get('emergency_stop_active')}`",
        "",
        "## Website / Origin / Cloudflare Cause Signals",
        "",
        "| Signal | Status | Count | Recommendation |",
        "|---|---|---:|---|",
    ]
    for finding in website.get("critical_v2_findings", []):
        if not isinstance(finding, dict):
            continue
        lines.append(
            "| "
            f"`{redact_text(finding.get('signal_id'), max_len=140)}` | "
            f"`{redact_text(finding.get('status'), max_len=80)}` | "
            f"`{finding.get('count', 0)}` | "
            f"{redact_text(finding.get('recommendation'), max_len=400)} |"
        )
    if not website.get("critical_v2_findings"):
        lines.append("| - | - | 0 | - |")
    lines.extend(
        [
            "",
            "## Rolling Window Status",
            "",
            f"- Total 5xx 24h: `{rolling.get('total_5xx_24h')}`",
            f"- 5xx delta: `{rolling.get('delta_5xx')}`",
            f"- Interpretation: {redact_text(rolling.get('interpretation'), max_len=600)}",
            f"- No WAF rule derived: `{rolling.get('no_waf_rule_derived')}`",
            "",
            "## SourceMap Status",
            "",
            f"- Master SourceMap status: `{sourcemap.get('master_sourcemap_status')}`",
            f"- .map 404 count: `{sourcemap.get('map_404_count')}`",
            f"- Diagnostic only: `{sourcemap.get('diagnostic_only')}`",
            "",
            "## What Is NOT The Cause",
            "",
        ]
    )
    for item in report.get("what_is_not_the_cause", []):
        lines.append(f"- {redact_text(item, max_len=600)}")
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
        "critical_snapshot_status": report.get("critical_snapshot_status"),
        "master_status": report.get("master_status"),
        "critical_caused_by_autonomy": report.get("critical_caused_by_autonomy"),
        "critical_caused_by_website": report.get("critical_caused_by_website"),
        "autonomy_total_breaches": report.get("autonomy_total_breaches"),
        "snapshot_breach": report.get("snapshot_breach"),
        "install_allowed_now": False,
        "can_install_timer_now": False,
        "live_apply": False,
        "apply_status": APPLY_NOT_APPLIED,
        "network_access": False,
        "apply_function": False,
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
    website, website_status = read_optional_json(WEBSITE_JSON)
    final_owner, final_owner_status = read_optional_json(FINAL_OWNER_SNAPSHOT_JSON)
    final_safety, final_safety_status = read_optional_json(FINAL_SAFETY_JSON)
    gate, gate_status = read_optional_json(COMPLETION_GATE_JSON)
    console, console_status = read_optional_json(OWNER_CONSOLE_JSON)
    runtime_lock, runtime_lock_status = read_optional_json(RUNTIME_LOCK_JSON)
    status_24h, status_24h_status = read_optional_json(STATUS_24H_JSON)
    errors_5xx, errors_5xx_status = read_optional_json(ERRORS_5XX_JSON)
    daily_md, daily_md_status = read_optional_text(CLOUDFLARE_DAILY_MD)
    return build_report(
        master,
        master_status,
        master_md,
        master_md_status,
        website,
        website_status,
        final_owner,
        final_owner_status,
        final_safety,
        final_safety_status,
        gate,
        gate_status,
        console,
        console_status,
        runtime_lock,
        runtime_lock_status,
        status_24h,
        status_24h_status,
        errors_5xx,
        errors_5xx_status,
        daily_md,
        daily_md_status,
    )


def run_self_test() -> int:
    master = {"overall_master_status": "CRITICAL", "action_status": "WARNING_REVIEW", "website_status": "CRITICAL", "website_correlation_status": "NORMAL"}
    website = {
        "overall_status": "CRITICAL",
        "correlation_status": "NORMAL",
        "metrics": [{"key": "total_5xx", "label": "5xx gesamt", "value": 615, "status": "CRITICAL"}],
        "correlation_v2_findings": [{"signal_id": "generic_origin_pressure", "status": "CRITICAL", "count": 615, "recommendation": "observe 24h"}],
    }
    final_owner = {"snapshot_status": "FINAL_OWNER_SNAPSHOT_LOCKED_COMPLETE", "snapshot_breach": False, "total_breaches": 0, "emergency_stop_active": True, "apply_status": APPLY_NOT_APPLIED}
    final_safety = {"final_safety_status": "SAFE_BUT_LOCKED_BY_EMERGENCY_STOP", "final_safety_breach": False, "total_breach_count": 0, "emergency_stop_active": True, "apply_status": APPLY_NOT_APPLIED}
    gate = {"gate_status": "COMPLETION_GATE_READY_BUT_LOCKED", "gate_breach": False, "emergency_stop_active": True, "apply_status": APPLY_NOT_APPLIED}
    console = {"console_status": "REVIEW_CONSOLE_COMPLETE_LOCKED", "console_breach": False, "emergency_stop_active": True, "apply_status": APPLY_NOT_APPLIED}
    runtime = {"emergency_stop": True, "apply_status": APPLY_NOT_APPLIED}
    daily = "| 5xx gesamt | 615 |\n| 404 auf .map | 13 |\n## Vergleich Zum Vorlauf\n| 5xx gesamt | 0 |\n"
    report = build_report(master, "ok", "", "ok", website, "ok", final_owner, "ok", final_safety, "ok", gate, "ok", console, "ok", runtime, "ok", {}, "ok", {}, "ok", daily, "ok", generated_at="2026-06-12T00:00:00Z")
    if report["critical_snapshot_status"] != STATUS_WEBSITE_ONLY or report["critical_caused_by_autonomy"] or report["snapshot_breach"]:
        raise AssertionError("website-only critical cause failed")

    not_critical = build_report({"overall_master_status": "OK", "action_status": "OK", "website_status": "OK"}, "ok", "", "ok", {"overall_status": "OK", "metrics": []}, "ok", final_owner, "ok", final_safety, "ok", gate, "ok", console, "ok", runtime, "ok", {}, "ok", {}, "ok", "", "ok", generated_at="2026-06-12T00:01:00Z")
    if not_critical["critical_snapshot_status"] != STATUS_NOT_CRITICAL:
        raise AssertionError("not critical status failed")

    autonomy_bad = dict(final_owner, snapshot_breach=True)
    auto_report = build_report(master, "ok", "", "ok", website, "ok", autonomy_bad, "ok", final_safety, "ok", gate, "ok", console, "ok", runtime, "ok", {}, "ok", {}, "ok", daily, "ok", generated_at="2026-06-12T00:02:00Z")
    if not auto_report["critical_caused_by_autonomy"] or auto_report["critical_snapshot_status"] != STATUS_MIXED:
        raise AssertionError("autonomy breach did not produce mixed cause")

    partial = build_report(None, "not_available", "", "not_available", website, "ok", final_owner, "ok", final_safety, "ok", gate, "ok", console, "ok", runtime, "ok", {}, "ok", {}, "ok", daily, "ok", generated_at="2026-06-12T00:03:00Z")
    if partial["critical_snapshot_status"] != STATUS_PARTIAL_INPUTS or partial["snapshot_breach"]:
        raise AssertionError("partial inputs failed")

    for key in ("live_apply", "install_allowed_now", "can_install_timer_now", "systemd_file_written", "crontab_file_written", "forbidden_apply_command_detected", "secret_like_output", "output_path_breach"):
        bad = build_report(master, "ok", "", "ok", website, "ok", final_owner, "ok", final_safety, "ok", gate, "ok", console, "ok", runtime, "ok", {}, "ok", {}, "ok", daily, "ok", forced_flags={key: True})
        if not bad["snapshot_breach"] or bad["critical_snapshot_status"] != STATUS_BREACH:
            raise AssertionError(f"{key} did not breach")
    bad = build_report(master, "ok", "", "ok", website, "ok", final_owner, "ok", final_safety, "ok", gate, "ok", console, "ok", runtime, "ok", {}, "ok", {}, "ok", daily, "ok", forced_flags={"apply_status": "applied"})
    if not bad["snapshot_breach"]:
        raise AssertionError("apply_status != not_applied did not breach")
    if not FORBIDDEN_APPLY_COMMAND_RE.search("cloudflare api update rule"):
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
        assert_allowed_write(PROJECT_DIR / "state/master-critical-cause-snapshot.json")
    except ValueError:
        pass
    else:
        raise AssertionError("forbidden write root was not rejected")
    print("master-critical-cause-snapshot self-tests: OK")
    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build Master Critical Cause Snapshot; read-only, no apply.")
    parser.add_argument("--self-test", action="store_true", help="Run in-memory safety tests and exit.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()
    report = build_current_report()
    write_outputs(report)
    print(
        "Master Critical Cause Snapshot: "
        f"status={report.get('critical_snapshot_status')}, "
        f"master={report.get('master_status')}, "
        f"autonomy_cause={report.get('critical_caused_by_autonomy')}, "
        f"website_cause={report.get('critical_caused_by_website')}, "
        f"breach={report.get('snapshot_breach')}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
