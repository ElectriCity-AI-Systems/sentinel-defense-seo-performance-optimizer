#!/usr/bin/env python3
"""Build a consistency layer for Sentinel's private master report.

Phase 10.16 is a local report-processing phase. This module reads existing
Sentinel evidence and writes private consistency reports plus one sanitized
public summary. It never changes a website, invokes a remote service, installs
a scheduler, or executes a production action.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


PROJECT_DIR = Path(__file__).resolve().parent
SCHEMA_VERSION = "sentinel-master-report-consistency-10.16"

REPORT_DIR = PROJECT_DIR / "reports/latest"
STATE_DIR = PROJECT_DIR / "state/adaptive-learning"
AUDIT_DIR = PROJECT_DIR / "audit"
PLAYBOOK_DIR = PROJECT_DIR / "playbooks"

MASTER_JSON = REPORT_DIR / "sentinel-master-report.json"
WEBSITE_JSON = REPORT_DIR / "sentinel-defense-report.json"
LOCAL_JSON = PROJECT_DIR / "inbox/local/local-defense-report.json"
PRIVATE_PC_JSON = PROJECT_DIR / "inbox/private-pc/local-defense-report.json"
SOURCEMAP_JSON = REPORT_DIR / "sourcemap-prevention-report.json"
AI_RADIO_JSON = REPORT_DIR / "ai-radio-api-timeout-diagnosis.json"
AI_RADIO_MICROCACHE_JSON = REPORT_DIR / "ai-radio-nowplaying-microcache-status.json"
ROLLING_WINDOW_JSON = REPORT_DIR / "rolling-window-decay-observer.json"
LOW_GROWTH_JSON = REPORT_DIR / "low-growth-readiness-timeline.json"
OWNER_DAILY_JSON = REPORT_DIR / "owner-daily-action-summary.json"
SAFE_SFTP_APPLY_JSON = REPORT_DIR / "safe-sftp-seo-apply-lane.json"
OWNER_APPROVAL_JSON = (
    PROJECT_DIR / "state/used-approvals/owner-approved-seo-jsonld-apply-20260612-193010.json"
)
AUTONOMY_RUNTIME_LOCK_JSON = REPORT_DIR / "autonomy-runtime-lock-report.json"
LATEST_CYCLE_RUNNER_JSON = STATE_DIR / "latest_autonomous_cycle_runner.json"

REPORT_JSON = REPORT_DIR / "sentinel-master-consistency.json"
REPORT_MD = REPORT_DIR / "sentinel-master-consistency.md"
EXECUTIVE_MD = REPORT_DIR / "sentinel-master-executive-summary.md"
TECHNICAL_MD = REPORT_DIR / "sentinel-master-technical-appendix.md"
PUBLIC_MD = REPORT_DIR / "sentinel-master-public-sanitized-summary.md"
FRESHNESS_MD = REPORT_DIR / "sentinel-subreport-freshness.md"
APPLY_MD = REPORT_DIR / "sentinel-apply-semantics.md"
PRIORITY_MD = REPORT_DIR / "sentinel-owner-priority-decision.md"

STATE_JSON = STATE_DIR / "master_report_consistency.json"
LATEST_STATE_JSON = STATE_DIR / "latest_master_report_consistency.json"
HISTORY_JSON = STATE_DIR / "master_report_consistency_history.json"
AUDIT_JSONL = AUDIT_DIR / "sentinel-master-report-consistency.jsonl"

PLAYBOOKS = (
    PLAYBOOK_DIR / "sentinel-master-report-consistency.playbook.json",
    PLAYBOOK_DIR / "sentinel-subreport-freshness.playbook.json",
    PLAYBOOK_DIR / "sentinel-owner-priority.playbook.json",
    PLAYBOOK_DIR / "sentinel-private-public-report-split.playbook.json",
)

OUTPUT_JSONS = (REPORT_JSON, STATE_JSON, LATEST_STATE_JSON, HISTORY_JSON, *PLAYBOOKS)
OUTPUT_MARKDOWN = (
    REPORT_MD,
    EXECUTIVE_MD,
    TECHNICAL_MD,
    PUBLIC_MD,
    FRESHNESS_MD,
    APPLY_MD,
    PRIORITY_MD,
)

CURRENT = "CURRENT"
STALE_INFORMATIONAL = "STALE_INFORMATIONAL"
STALE_EXCLUDED = "STALE_EXCLUDED_FROM_MASTER_STATUS"
MISSING = "MISSING"
INVALID_TIMESTAMP = "INVALID_TIMESTAMP"

FRESHNESS_LIMITS = {
    "current_max_seconds": 24 * 60 * 60,
    "stale_informational_max_seconds": 7 * 24 * 60 * 60,
}

SAFETY_FLAGS = {
    "live_apply": False,
    "emergency_stop": True,
    "allowed_apply_now": False,
    "high_blocked": True,
    "medium_executable": False,
    "low_live_executable": False,
    "breach": False,
}

EMERGENCY_STOP_SEMANTICS = {
    "production_apply_lock": True,
    "remote_write_lock": True,
    "scheduler_install_lock": True,
    "timer_execution_lock": True,
    "local_analysis_allowed": True,
    "local_draft_generation_allowed": True,
    "local_validation_allowed": True,
    "interpretation": (
        "Emergency Stop blocks productive execution, remote writes and scheduler "
        "installation. Local analysis, sanitized report generation and draft-only "
        "output remain allowed."
    ),
}

REPORT_CLASSIFICATION = [
    "PRIVATE_OWNER_OPERATIONAL_REPORT",
    "NOT_FOR_PUBLIC_RELEASE",
    "NOT_FOR_GIT",
    "CONTAINS_INFRASTRUCTURE_METADATA",
]

RECOMMENDED_GIT_FILES = [
    "sentinel_master_report_consistency.py",
    "playbooks/sentinel-master-report-consistency.playbook.json",
    "playbooks/sentinel-subreport-freshness.playbook.json",
    "playbooks/sentinel-owner-priority.playbook.json",
    "playbooks/sentinel-private-public-report-split.playbook.json",
]

FIXED_SUBREPORTS = {
    "sentinel_master_report": MASTER_JSON,
    "website": WEBSITE_JSON,
    "hetzner_local": LOCAL_JSON,
    "private_pc_local": PRIVATE_PC_JSON,
    "sourcemap_prevention": SOURCEMAP_JSON,
    "ai_radio_timeout_diagnosis": AI_RADIO_JSON,
    "ai_radio_microcache_status": AI_RADIO_MICROCACHE_JSON,
    "rolling_window_decay_observer": ROLLING_WINDOW_JSON,
    "low_growth_readiness_timeline": LOW_GROWTH_JSON,
    "owner_daily_action_summary": OWNER_DAILY_JSON,
    "safe_sftp_seo_apply_lane": SAFE_SFTP_APPLY_JSON,
    "autonomy_runtime_lock": AUTONOMY_RUNTIME_LOCK_JSON,
    "performance_safe_improvement": REPORT_DIR / "performance-safe-audit-report.json",
}

TIMESTAMP_KEYS = (
    "generated_at_utc",
    "generated_at",
    "timestamp_utc",
    "timestamp",
    "created_at_utc",
    "created_at",
)

IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
FQDN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}\b"
)
PRIVATE_PATH_RE = re.compile(r"/(?:srv|etc|var|home|root|opt|mnt|tmp)/[^\s\]})>,\"']+")
INTERNAL_ENDPOINT_RE = re.compile(r"/api/(?:internal|admin|station)/[^\s\]})>,\"']+", re.IGNORECASE)
SECRET_RE = re.compile(
    r"(?i)(?:password|passwd|secret|api[_-]?key|access[_-]?token|private[_-]?key)"
    r"\s*[:=]\s*[^\s,;]+"
)
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(PROJECT_DIR))
    except (OSError, ValueError):
        return str(path)


def is_within_project(path: Path) -> bool:
    try:
        path.resolve().relative_to(PROJECT_DIR.resolve())
        return True
    except (OSError, ValueError):
        return False


def ensure_dirs() -> None:
    for directory in (REPORT_DIR, STATE_DIR, AUDIT_DIR, PLAYBOOK_DIR):
        directory.mkdir(parents=True, exist_ok=True)


def read_json(path: Path) -> Tuple[Any, str]:
    if not path.exists():
        return None, "missing"
    try:
        return json.loads(path.read_text(encoding="utf-8")), "ok"
    except json.JSONDecodeError:
        return None, "invalid_json"
    except OSError:
        return None, "read_error"


def load_dict(path: Path) -> Dict[str, Any]:
    data, status = read_json(path)
    return data if status == "ok" and isinstance(data, dict) else {}


def write_text(path: Path, text: str) -> None:
    if not is_within_project(path):
        raise RuntimeError(f"write outside project blocked: {path}")
    if SECRET_RE.search(text) or PRIVATE_KEY_RE.search(text):
        raise RuntimeError(f"secret-like content blocked: {rel(path)}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def write_json(path: Path, data: Any) -> None:
    text = json.dumps(data, indent=2, sort_keys=True)
    json.loads(text)
    write_text(path, text)


def append_jsonl(path: Path, row: Dict[str, Any]) -> None:
    if not is_within_project(path):
        raise RuntimeError(f"write outside project blocked: {path}")
    line = json.dumps(row, sort_keys=True)
    if SECRET_RE.search(line) or PRIVATE_KEY_RE.search(line):
        raise RuntimeError("secret-like audit content blocked")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def parse_timestamp(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if re.fullmatch(r"\d{8}-\d{6}", text):
        try:
            return datetime.strptime(text, "%Y%m%d-%H%M%S").replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        result = datetime.fromisoformat(text)
    except ValueError:
        return None
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result.astimezone(timezone.utc)


def timestamp_from_data(data: Any) -> Tuple[Optional[datetime], Optional[str], Optional[str]]:
    if not isinstance(data, dict):
        return None, None, None
    containers = [data]
    for key in ("metadata", "meta", "report", "summary"):
        value = data.get(key)
        if isinstance(value, dict):
            containers.append(value)
    for container in containers:
        for key in TIMESTAMP_KEYS:
            if key not in container:
                continue
            parsed = parse_timestamp(container.get(key))
            return parsed, key, str(container.get(key))
    return None, None, None


def format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def freshness_from_timestamp(
    report_name: str,
    timestamp: Optional[datetime],
    as_of: datetime,
    raw_timestamp: Optional[str] = None,
) -> Dict[str, Any]:
    if timestamp is None:
        return {
            "report_name": report_name,
            "generated_at": raw_timestamp,
            "age_seconds": None,
            "freshness_status": INVALID_TIMESTAMP,
            "included_in_master_status": False,
            "reason": "No valid report timestamp is available; current facts are not inferred.",
        }
    age_seconds = (as_of - timestamp).total_seconds()
    if age_seconds < -300:
        return {
            "report_name": report_name,
            "generated_at": format_timestamp(timestamp),
            "age_seconds": round(age_seconds, 2),
            "freshness_status": INVALID_TIMESTAMP,
            "included_in_master_status": False,
            "reason": "Timestamp is materially in the future and is excluded.",
        }
    age_seconds = max(0.0, age_seconds)
    if age_seconds <= FRESHNESS_LIMITS["current_max_seconds"]:
        status = CURRENT
        included = True
        reason = "Generated within the configured 24-hour current window."
    elif age_seconds <= FRESHNESS_LIMITS["stale_informational_max_seconds"]:
        status = STALE_INFORMATIONAL
        included = True
        reason = "Older than 24 hours; retained with an explicit informational warning."
    else:
        status = STALE_EXCLUDED
        included = False
        reason = "Older than seven days; excluded from master-status calculation."
    return {
        "report_name": report_name,
        "generated_at": format_timestamp(timestamp),
        "age_seconds": round(age_seconds, 2),
        "freshness_status": status,
        "included_in_master_status": included,
        "reason": reason,
    }


def source_path_from_summary(value: Dict[str, Any]) -> Optional[Path]:
    for key in ("path", "report_path", "source_path"):
        candidate = value.get(key)
        if isinstance(candidate, str) and candidate.strip():
            path = Path(candidate)
            return path if path.is_absolute() else PROJECT_DIR / path
    return None


def discover_subreports(master: Dict[str, Any]) -> Dict[str, Path]:
    reports = dict(FIXED_SUBREPORTS)
    for name, value in master.items():
        if not isinstance(value, dict):
            continue
        path = source_path_from_summary(value)
        if path is not None and is_within_project(path):
            reports.setdefault(name, path)
    sources = master.get("sources")
    if isinstance(sources, dict):
        for name, value in sources.items():
            if not isinstance(value, dict):
                continue
            path = source_path_from_summary(value)
            if path is not None and is_within_project(path):
                reports.setdefault(name, path)
    return dict(sorted(reports.items()))


def metric_map(website: Dict[str, Any]) -> Dict[str, int]:
    result: Dict[str, int] = {}
    metrics = website.get("metrics")
    if not isinstance(metrics, list):
        return result
    for item in metrics:
        if not isinstance(item, dict) or not isinstance(item.get("key"), str):
            continue
        value = item.get("value")
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            result[item["key"]] = int(value)
    return result


def website_path_rows(website: Dict[str, Any]) -> List[Dict[str, Any]]:
    origin = website.get("origin_pressure_breakdown")
    if not isinstance(origin, dict):
        return []
    rows = origin.get("top_5xx_paths")
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def find_path_row(website: Dict[str, Any], path: str) -> Dict[str, Any]:
    for row in website_path_rows(website):
        if row.get("path") == path:
            return row
    return {}


def status_count(row: Dict[str, Any], status: int) -> int:
    statuses = row.get("statuses")
    if not isinstance(statuses, list):
        return 0
    return sum(
        int(item.get("count", 0))
        for item in statuses
        if isinstance(item, dict) and int(item.get("status", 0)) == status
    )


def deep_numeric_values(data: Any, keys: Sequence[str]) -> List[int]:
    wanted = set(keys)
    values: List[int] = []
    if isinstance(data, dict):
        for key, value in data.items():
            if key in wanted and isinstance(value, (int, float)) and not isinstance(value, bool):
                values.append(int(value))
            values.extend(deep_numeric_values(value, keys))
    elif isinstance(data, list):
        for value in data:
            values.extend(deep_numeric_values(value, keys))
    return values


def max_deep_number(data: Any, keys: Sequence[str], default: int = 0) -> int:
    values = deep_numeric_values(data, keys)
    return max(values) if values else default


def evaluate_freshness(master: Dict[str, Any], website: Dict[str, Any]) -> Dict[str, Any]:
    as_of = datetime.now(timezone.utc)
    rows: List[Dict[str, Any]] = []
    for report_name, path in discover_subreports(master).items():
        data, read_status = read_json(path)
        if read_status == "missing":
            row = {
                "report_name": report_name,
                "generated_at": None,
                "age_seconds": None,
                "freshness_status": MISSING,
                "included_in_master_status": False,
                "reason": "Expected local subreport is missing; no current facts are inferred.",
            }
        elif read_status != "ok":
            row = {
                "report_name": report_name,
                "generated_at": None,
                "age_seconds": None,
                "freshness_status": INVALID_TIMESTAMP,
                "included_in_master_status": False,
                "reason": f"Subreport read status is {read_status}; it is excluded.",
            }
        else:
            timestamp, key, raw = timestamp_from_data(data)
            row = freshness_from_timestamp(report_name, timestamp, as_of, raw)
            row["timestamp_field"] = key
        row["source_path"] = rel(path)
        rows.append(row)

    by_name = {row["report_name"]: row for row in rows}
    metrics = metric_map(website)
    sourcemap = by_name.get("sourcemap_prevention", {})
    source_map_reconciliation = {
        "current_map_404": metrics.get("map_404"),
        "legacy_report_freshness": sourcemap.get("freshness_status"),
        "legacy_warning_included": bool(sourcemap.get("included_in_master_status")),
        "effective_status": "CURRENT_WEBSITE_MAP_404_ZERO",
        "reason": (
            "Current website evidence reports zero .map 404s; the old SourceMap warning "
            "is excluded and cannot keep an active warning."
            if metrics.get("map_404") == 0 and not sourcemap.get("included_in_master_status")
            else "Freshness and current website evidence are evaluated independently."
        ),
    }
    ai_radio = by_name.get("ai_radio_timeout_diagnosis", {})
    ai_radio_reconciliation = {
        "legacy_report_freshness": ai_radio.get("freshness_status"),
        "legacy_status_included": bool(ai_radio.get("included_in_master_status")),
        "effective_status": (
            "STALE_DIAGNOSIS_EXCLUDED_CURRENT_WEBSITE_EVIDENCE_REQUIRED"
            if not ai_radio.get("included_in_master_status")
            else "DIAGNOSIS_INCLUDED_WITH_FRESHNESS_LABEL"
        ),
        "microcache_deployment_treated_as": "HISTORICAL_DEPLOYMENT_EVIDENCE",
    }
    excluded = [
        row["report_name"]
        for row in rows
        if row["freshness_status"] in {STALE_EXCLUDED, MISSING, INVALID_TIMESTAMP}
    ]
    counts = {
        status: sum(1 for row in rows if row["freshness_status"] == status)
        for status in (CURRENT, STALE_INFORMATIONAL, STALE_EXCLUDED, MISSING, INVALID_TIMESTAMP)
    }
    return {
        "status": "SUBREPORT_FRESHNESS_OK",
        "evaluated_at": format_timestamp(as_of),
        "thresholds_seconds": dict(FRESHNESS_LIMITS),
        "reports": rows,
        "status_counts": counts,
        "excluded_from_master_status": excluded,
        "source_map_reconciliation": source_map_reconciliation,
        "ai_radio_reconciliation": ai_radio_reconciliation,
    }


def classify_productive_action(action: Dict[str, Any], approval: Dict[str, Any]) -> Dict[str, Any]:
    uploaded = bool(action.get("uploaded") or action.get("upload_executed"))
    owner_approval = bool(action.get("owner_approved") or action.get("owner_approval"))
    approval_present = bool(owner_approval and approval.get("approved"))
    autonomous = bool(action.get("autonomous", False))
    if uploaded and owner_approval and not autonomous:
        execution_type = "owner_approved_manual_apply"
    elif uploaded and autonomous:
        execution_type = "autonomous_live_apply"
    elif uploaded:
        execution_type = "productive_apply_evidence_incomplete"
    else:
        execution_type = "prepared_not_applied"
    changed_files = action.get("changed_remote_paths")
    if not isinstance(changed_files, list):
        changed_files = action.get("changed_files") if isinstance(action.get("changed_files"), list) else []
    record = {
        "action_id": "safe_sftp_seo_jsonld_apply",
        "execution_type": execution_type,
        "owner_approval_present": approval_present,
        "approved_at": approval.get("timestamp_utc") if approval_present else None,
        "executed_at": action.get("generated_at_utc") or action.get("timestamp_utc"),
        "changed_files": changed_files,
        "before_hash": action.get("before_hash"),
        "after_hash": action.get("after_hash") or action.get("plugin_sha256"),
        "rollback_reference": action.get("rollback_reference"),
        "healthcheck_status": action.get("healthcheck_status"),
        "autonomous": autonomous,
    }
    required_evidence = (
        "owner_approval_present",
        "approved_at",
        "executed_at",
        "changed_files",
        "before_hash",
        "after_hash",
        "rollback_reference",
        "healthcheck_status",
    )
    missing = [key for key in required_evidence if record.get(key) in (None, [], "")]
    record["evidence_status"] = "EVIDENCE_COMPLETE" if not missing else "EVIDENCE_INCOMPLETE"
    record["missing_evidence"] = missing
    record["owner_review_note"] = (
        "Review missing evidence fields; no value was inferred."
        if missing
        else "Recorded evidence is complete."
    )
    return record


def evaluate_apply_semantics(master: Dict[str, Any]) -> Dict[str, Any]:
    action = load_dict(SAFE_SFTP_APPLY_JSON)
    approval = load_dict(OWNER_APPROVAL_JSON)
    productive_actions: List[Dict[str, Any]] = []
    if action:
        productive_actions.append(classify_productive_action(action, approval))
    autonomous = sum(1 for row in productive_actions if row["execution_type"] == "autonomous_live_apply")
    manual = sum(1 for row in productive_actions if row["execution_type"] == "owner_approved_manual_apply")
    prepared = max_deep_number(
        master,
        ("preflight_ready_draft_only_count", "ready_draft_only_count", "draft_only_count"),
    )
    drafts = max_deep_number(
        master,
        ("executed_draft_only_count", "draft_only_output_count", "draft_only_count"),
    )
    validation = max_deep_number(
        master,
        ("executed_validation_only_count", "preflight_ready_validation_only_count", "validation_only_count"),
    )
    blocked = max_deep_number(
        master,
        ("preflight_blocked_count", "skipped_count", "blocked_count"),
    )
    monitor = max_deep_number(
        master,
        ("monitor_only_count", "preflight_monitor_only_count", "monitor_count"),
    )
    all_not_applied = autonomous == 0 and manual == 0
    incomplete = [row["action_id"] for row in productive_actions if row["evidence_status"] == "EVIDENCE_INCOMPLETE"]
    return {
        "status": "APPLY_SEMANTICS_CONSISTENT",
        "autonomous_live_applies": autonomous,
        "owner_approved_manual_applies": manual,
        "prepared_not_applied": prepared,
        "draft_only_outputs": drafts,
        "validation_only_outputs": validation,
        "blocked_actions": blocked,
        "monitor_only_actions": monitor,
        "all_not_applied": all_not_applied,
        "all_not_applied_statement_allowed": all_not_applied,
        "productive_changes": productive_actions,
        "evidence_incomplete_actions": incomplete,
        "interpretation": (
            "Historical owner-approved production evidence is recorded separately from "
            "current autonomous runtime locks. Draft-only counts do not imply production apply."
        ),
    }


def choose_owner_priority(context: Dict[str, Any]) -> Dict[str, Any]:
    breach = bool(context.get("breach"))
    website_status = str(context.get("website_status", "UNKNOWN")).upper()
    origin_5xx = int(context.get("origin_5xx") or 0)
    root_504 = int(context.get("root_504") or 0)
    recent_growth = bool(context.get("recent_significant_growth"))
    low_growth_24h = bool(context.get("24h_low_growth_evidence"))
    if breach:
        selected = "SAFETY_BREACH_ESCALATION"
        reason = "A safety breach is active; no lower-priority operation is recommended."
        next_action = "Stop local operation processing and perform owner safety review."
        suppressed = ["WEBSITE_ORIGIN_STABILITY", "SEO_TITLE_REVIEW", "META_DESCRIPTION_REVIEW"]
    elif website_status == "CRITICAL" and (
        origin_5xx > 0 or root_504 > 0 or recent_growth or not low_growth_24h
    ):
        selected = "WEBSITE_ORIGIN_STABILITY"
        reason = "Website is CRITICAL with active origin timeout evidence."
        next_action = (
            "Correlate current IONOS, PHP and WordPress logs for /, /wp-login.php and the "
            "highest-volume legacy paths. Do not create a new WAF rule. Re-evaluate after "
            "a complete stable 24-hour window."
        )
        suppressed = ["SEO_TITLE_REVIEW", "META_DESCRIPTION_REVIEW"]
    elif website_status == "WARNING":
        selected = "WEBSITE_TARGETED_MONITORING"
        reason = "Website is WARNING; targeted manual monitoring precedes SEO optimization."
        next_action = "Review current website evidence and continue targeted manual monitoring."
        suppressed = ["SEO_TITLE_REVIEW", "META_DESCRIPTION_REVIEW"]
    elif website_status == "OK":
        selected = "SEO_TITLE_REVIEW"
        reason = "Website is OK; lower-risk SEO review can become the leading owner task."
        next_action = "Review the queued SEO title draft manually."
        suppressed = []
    else:
        selected = "WEBSITE_STATUS_EVIDENCE_REVIEW"
        reason = "Website status is unknown; establish current evidence before optimization."
        next_action = "Collect a current local website status report."
        suppressed = ["SEO_TITLE_REVIEW", "META_DESCRIPTION_REVIEW"]
    return {
        "status": f"OWNER_PRIORITY_{selected}",
        "selected_priority": selected,
        "suppressed_lower_priorities": suppressed,
        "reason": reason,
        "next_owner_action": next_action,
        "inputs": {
            "website_status": website_status,
            "origin_5xx": origin_5xx,
            "root_504": root_504,
            "recent_significant_growth": recent_growth,
            "24h_low_growth_evidence": low_growth_24h,
            "breach": breach,
        },
    }


def waf_decision(website: Dict[str, Any]) -> Dict[str, Any]:
    failure_modes = website.get("top_5xx_failure_modes")
    modes = {
        str(item.get("failure_mode")): int(item.get("count", 0))
        for item in failure_modes
        if isinstance(item, dict)
    } if isinstance(failure_modes, list) else {}
    origin_dominant = modes.get("cloudflare_to_origin_timeout", 0) > 0 or modes.get(
        "origin_php_or_upstream_error", 0
    ) > 0
    return {
        "new_waf_rule_recommended": False,
        "status": "NEW_WAF_RULE_RECOMMENDED_FALSE",
        "origin_or_upstream_pressure_present": origin_dominant,
        "reason": (
            "The signal is dominated by origin, PHP or upstream pressure; no narrow actor/path "
            "proof supports a safe rule, and a broad rule could affect legitimate users."
        ),
        "recommendation": "Do not add a new WAF rule. Correlate origin, PHP and WordPress logs first.",
    }


def build_rolling_window(website: Dict[str, Any]) -> Dict[str, Any]:
    context = website.get("rolling_window_context")
    history = context.get("history") if isinstance(context, dict) else {}
    blockers = history.get("old_window_blockers") if isinstance(history, dict) else []
    blocker_rows = [row for row in blockers if isinstance(row, dict)] if isinstance(blockers, list) else []
    selected = max(
        blocker_rows,
        key=lambda row: float(row.get("remaining_stable_minutes_for_old_window", 0) or 0),
        default={},
    )
    required = float(
        history.get("old_window_required_stable_minutes", 1440)
        if isinstance(history, dict)
        else 1440
    )
    stable_since = parse_timestamp(selected.get("stable_since_utc"))
    stable_minutes = float(selected.get("stable_minutes", 0) or 0) if selected else 0.0
    remaining = float(
        selected.get("remaining_stable_minutes_for_old_window", max(0.0, required - stable_minutes)) or 0
    ) if selected else required
    earliest = format_timestamp(stable_since + timedelta(minutes=required)) if stable_since else None
    new_growth = False
    if selected and stable_since:
        key = selected.get("key")
        elevated = history.get("elevated_metrics") if isinstance(history, dict) else []
        for metric in elevated if isinstance(elevated, list) else []:
            if not isinstance(metric, dict) or metric.get("key") != key:
                continue
            limit = float(metric.get("low_growth_limit", 0) or 0)
            snapshots = metric.get("recent_snapshots")
            for snapshot in snapshots if isinstance(snapshots, list) else []:
                if not isinstance(snapshot, dict):
                    continue
                timestamp = parse_timestamp(snapshot.get("generated_at_utc"))
                delta = snapshot.get("delta")
                if timestamp and timestamp > stable_since and isinstance(delta, (int, float)) and delta > limit:
                    new_growth = True
    return {
        "status": "WAIT_FOR_COMPLETE_STABLE_WINDOW" if selected else "ROLLING_WINDOW_EVIDENCE_MISSING",
        "governing_watchpoint": selected.get("key") if selected else None,
        "stable_since": format_timestamp(stable_since) if stable_since else None,
        "stable_minutes": round(stable_minutes, 2),
        "required_minutes": round(required, 2),
        "remaining_minutes": round(remaining, 2),
        "earliest_recheck_at": earliest,
        "new_growth_since_stable_start": new_growth,
        "ok_transition_allowed": False,
        "projection_note": (
            "The earliest recheck time is a projection only. A new complete snapshot must "
            "confirm the state; the website does not become OK automatically."
        ),
    }


def build_cause_impact(website: Dict[str, Any]) -> Dict[str, Any]:
    root = find_path_row(website, "/")
    statuses = root.get("statuses") if isinstance(root.get("statuses"), list) else []
    primary_status = max(
        (item for item in statuses if isinstance(item, dict)),
        key=lambda item: int(item.get("count", 0)),
        default={},
    )
    return {
        "technical_cause": root.get("failure_mode") or "origin_or_upstream_pressure",
        "traffic_actor": root.get("actor_signal") or "unknown_actor_signal",
        "affected_path": "/",
        "failure_mode": str(primary_status.get("status")) if primary_status else "unknown",
        "verified_user_impact": "unknown",
        "confidence": "medium" if root else "low",
        "evidence_count": int(root.get("count", 0) or 0),
        "interpretation": (
            "Automated traffic is not assumed harmless, and 5xx traffic is not equated with "
            "verified human-user loss without browser, RUM, server-log or analytics correlation."
        ),
    }


def sanitize_public_text(text: str) -> str:
    result = IP_RE.sub("[infrastructure address omitted]", text)
    result = PRIVATE_PATH_RE.sub("[private path omitted]", result)
    result = INTERNAL_ENDPOINT_RE.sub("[internal endpoint omitted]", result)
    result = FQDN_RE.sub("[infrastructure hostname omitted]", result)
    return result


def public_scan(text: str) -> List[str]:
    findings: List[str] = []
    if IP_RE.search(text):
        findings.append("ip_address")
    if PRIVATE_PATH_RE.search(text):
        findings.append("private_server_path")
    if INTERNAL_ENDPOINT_RE.search(text):
        findings.append("internal_endpoint")
    if FQDN_RE.search(text):
        findings.append("hostname_or_domain")
    if SECRET_RE.search(text) or PRIVATE_KEY_RE.search(text):
        findings.append("secret_pattern")
    return sorted(set(findings))


def classify_private_metadata(master_text: str) -> Dict[str, Any]:
    categories = [
        ("ip_addresses", len(IP_RE.findall(master_text))),
        ("server_hostnames", len(FQDN_RE.findall(master_text))),
        ("absolute_server_paths", len(PRIVATE_PATH_RE.findall(master_text))),
        ("internal_api_endpoints", len(INTERNAL_ENDPOINT_RE.findall(master_text))),
        (
            "domain_origin_mappings",
            len(re.findall(r'(?i)"(?:origin_ip|hostnames?|deployed_on_host)"\s*:', master_text)),
        ),
        (
            "firewall_security_configuration",
            len(re.findall(r"(?i)\b(?:firewall|waf|fail2ban|ufw|security_actions)\b", master_text)),
        ),
    ]
    return {
        "classification": REPORT_CLASSIFICATION,
        "categories": [
            {"category": name, "detected": count > 0, "occurrence_count": count}
            for name, count in categories
        ],
        "handling": "Retain in private owner reports; omit identifiers from the public summary.",
    }


def extract_current_context(master: Dict[str, Any], website: Dict[str, Any]) -> Dict[str, Any]:
    metrics = metric_map(website)
    rolling = website.get("rolling_window_context")
    rolling_status = rolling.get("status") if isinstance(rolling, dict) else None
    return {
        "website_status": website.get("overall_status") or master.get("website_status") or "UNKNOWN",
        "origin_5xx": metrics.get("total_5xx", 0),
        "root_504": metrics.get("root_504", 0),
        "recent_significant_growth": rolling_status == "RECENT_SIGNIFICANT_GROWTH",
        "24h_low_growth_evidence": bool(
            isinstance(rolling, dict)
            and rolling.get("ok_eligible")
            and rolling_status not in {"RECENT_SIGNIFICANT_GROWTH", "NEW_GROWTH_PRESENT"}
        ),
        "breach": SAFETY_FLAGS["breach"],
    }


def evaluate_safety_evidence() -> Dict[str, Any]:
    runner = load_dict(LATEST_CYCLE_RUNNER_JSON)
    discrepancies: List[Dict[str, Any]] = []
    for key, expected in SAFETY_FLAGS.items():
        if key not in runner or not isinstance(runner.get(key), bool):
            continue
        if runner[key] is not expected:
            discrepancies.append({"field": key, "expected": expected, "observed": runner[key]})
    return {
        "status": "SAFETY_FLAGS_CONFIRMED" if not discrepancies else "SAFETY_DRIFT_DETECTED",
        "source": rel(LATEST_CYCLE_RUNNER_JSON),
        "source_present": bool(runner),
        "source_status": runner.get("status") if runner else None,
        "discrepancies": discrepancies,
        "historical_manual_apply_changes_current_runtime_lock": False,
    }


def build_public_summary(report: Dict[str, Any]) -> str:
    priority = report["owner_priority"]
    safety = report["safety"]
    text = f"""# Sentinel Public Status Summary

The website currently shows elevated origin timeout pressure. Sentinel remains breach-free and live automation remains disabled.

- operational priority: website stability and owner-led diagnosis
- local analysis and sanitized reporting: allowed
- productive or remote execution: blocked
- emergency stop: active
- new broad security rule: not recommended from the current evidence

The next step is manual correlation of hosting, application-runtime and content-management logs, followed by a new complete observation window. The projected recheck time is not an automatic OK transition.

Private infrastructure identifiers, detailed paths, host mappings and security configuration are intentionally omitted from this public summary.

Safety state: live apply `{str(safety['live_apply']).lower()}`, breach `{str(safety['breach']).lower()}`. Selected priority: `{priority['selected_priority']}`.
"""
    return sanitize_public_text(text)


def build_report() -> Dict[str, Any]:
    master = load_dict(MASTER_JSON)
    website = load_dict(WEBSITE_JSON)
    master_text = MASTER_JSON.read_text(encoding="utf-8", errors="replace") if MASTER_JSON.exists() else ""
    freshness = evaluate_freshness(master, website)
    apply_semantics = evaluate_apply_semantics(master)
    owner_priority = choose_owner_priority(extract_current_context(master, website))
    rolling = build_rolling_window(website)
    metrics = metric_map(website)
    root = find_path_row(website, "/")
    login = find_path_row(website, "/wp-login.php")
    status_counts: Dict[str, int] = {}
    origin = website.get("origin_pressure_breakdown")
    status_rows = origin.get("top_5xx_status_codes") if isinstance(origin, dict) else []
    for item in status_rows if isinstance(status_rows, list) else []:
        if not isinstance(item, dict):
            continue
        key = str(item.get("status"))
        status_counts[key] = int(item.get("count", 0) or 0)
    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "status": "MASTER_CONSISTENCY_VALIDATION_PENDING",
        "report_classification": REPORT_CLASSIFICATION,
        "source_master": {
            "path": rel(MASTER_JSON),
            "generated_at_utc": master.get("generated_at_utc"),
            "overall_master_status": master.get("overall_master_status"),
            "website_status": master.get("website_status"),
            "local_status": master.get("local_status"),
            "autonomy_policy_status": master.get("autonomy_policy_status"),
        },
        "current_website_evidence": {
            "generated_at_utc": website.get("generated_at_utc"),
            "website_status": website.get("overall_status") or master.get("website_status"),
            "total_5xx": metrics.get("total_5xx", 0),
            "root_5xx": int(root.get("count", 0) or 0),
            "root_504": metrics.get("root_504", 0),
            "wp_login_5xx": int(login.get("count", 0) or 0),
            "map_404": metrics.get("map_404", 0),
            "status_code_counts": dict(sorted(status_counts.items())),
        },
        "subreport_freshness": freshness,
        "apply_semantics": apply_semantics,
        "emergency_stop_semantics": dict(EMERGENCY_STOP_SEMANTICS),
        "owner_priority": owner_priority,
        "rolling_window": rolling,
        "cause_and_impact": build_cause_impact(website),
        "waf_decision": waf_decision(website),
        "private_metadata": classify_private_metadata(master_text),
        "known_missing_evidence": [
            "Productive apply before_hash is unavailable in the recorded local lane evidence."
            if any(
                "before_hash" in row.get("missing_evidence", [])
                for row in apply_semantics["productive_changes"]
            )
            else None,
            "Productive apply rollback_reference is unavailable in the recorded local lane evidence."
            if any(
                "rollback_reference" in row.get("missing_evidence", [])
                for row in apply_semantics["productive_changes"]
            )
            else None,
            "Verified human-user impact remains unknown without correlated browser, RUM, server-log or analytics evidence.",
        ],
        "git_checkpoint": {
            "status": "GIT_RECOMMENDATION_SOURCE_AND_PLAYBOOKS_ONLY",
            "recommended_files": RECOMMENDED_GIT_FILES,
            "excluded_prefixes": ["reports/", "state/", "audit/", "exports/", "backups/", "snapshots/"],
        },
        "safety": dict(SAFETY_FLAGS),
        "safety_evidence": evaluate_safety_evidence(),
    }
    report["known_missing_evidence"] = [item for item in report["known_missing_evidence"] if item]
    public_text = build_public_summary(report)
    report["public_summary_sanitization"] = {
        "status": "PUBLIC_SUMMARY_SANITIZED" if not public_scan(public_text) else "PUBLIC_SUMMARY_FINDINGS",
        "findings": public_scan(public_text),
        "omitted_categories": [
            "ip_addresses",
            "server_hostnames",
            "absolute_server_paths",
            "internal_api_endpoints",
            "domain_origin_mappings",
            "firewall_security_configuration",
        ],
    }
    return report


def render_executive_summary(report: Dict[str, Any]) -> str:
    source = report["source_master"]
    evidence = report["current_website_evidence"]
    priority = report["owner_priority"]
    rolling = report["rolling_window"]
    safety = report["safety"]
    excluded_count = len(report["subreport_freshness"]["excluded_from_master_status"])
    return f"""# Sentinel Master Executive Summary

**Classification:** `PRIVATE_OWNER_OPERATIONAL_REPORT` / `NOT_FOR_GIT`

- Overall status: `{source.get('overall_master_status')}`
- Main cause: active website origin/PHP/upstream 5xx pressure; local and autonomy policy status do not cause the critical state

## Five Key Metrics

| Metric | Value |
| --- | ---: |
| Website 5xx (24h) | {evidence['total_5xx']} |
| 504 on root path (24h) | {evidence['root_504']} |
| 5xx on login path (24h) | {evidence['wp_login_5xx']} |
| Current source-map 404 | {evidence['map_404']} |
| Stable minutes / required | {rolling['stable_minutes']} / {rolling['required_minutes']} |

## Next Owner Action

{priority['next_owner_action']}

## Safety Flags

`live_apply={str(safety['live_apply']).lower()}` | `emergency_stop={str(safety['emergency_stop']).lower()}` | `allowed_apply_now={str(safety['allowed_apply_now']).lower()}` | `HIGH blocked={str(safety['high_blocked']).lower()}` | `breach={str(safety['breach']).lower()}`

## Three Open Points

1. Correlate current hosting, PHP and WordPress logs before considering any control change.
2. Wait for a complete stable 24-hour window and confirm it with a new snapshot.
3. Review {excluded_count} missing, invalid or older-than-seven-day subreports as historical evidence only.
"""


def render_freshness(report: Dict[str, Any]) -> str:
    freshness = report["subreport_freshness"]
    lines = [
        "# Sentinel Subreport Freshness",
        "",
        f"Status: `{freshness['status']}`",
        "",
        "| Report | Generated | Age seconds | Freshness | Included | Reason |",
        "| --- | --- | ---: | --- | --- | --- |",
    ]
    for row in freshness["reports"]:
        reason = str(row["reason"]).replace("|", "\\|")
        lines.append(
            f"| `{row['report_name']}` | `{row.get('generated_at')}` | "
            f"{row.get('age_seconds')} | `{row['freshness_status']}` | "
            f"`{str(row['included_in_master_status']).lower()}` | {reason} |"
        )
    lines.extend([
        "",
        "## Reconciliation",
        "",
        f"- SourceMap: {freshness['source_map_reconciliation']['reason']}",
        f"- AI-Radio: `{freshness['ai_radio_reconciliation']['effective_status']}`.",
    ])
    return "\n".join(lines) + "\n"


def render_apply_semantics(report: Dict[str, Any]) -> str:
    apply = report["apply_semantics"]
    lines = [
        "# Sentinel Apply Semantics",
        "",
        f"Status: `{apply['status']}`",
        "",
        "| Category | Count |",
        "| --- | ---: |",
    ]
    for key in (
        "autonomous_live_applies",
        "owner_approved_manual_applies",
        "prepared_not_applied",
        "draft_only_outputs",
        "validation_only_outputs",
        "blocked_actions",
        "monitor_only_actions",
    ):
        lines.append(f"| `{key}` | {apply[key]} |")
    lines.extend([
        "",
        f"- `all_not_applied` statement allowed: `{str(apply['all_not_applied_statement_allowed']).lower()}`",
        "- Historical owner-approved production evidence is not current autonomous execution.",
        "",
        "## Productive Change Evidence",
        "",
    ])
    if not apply["productive_changes"]:
        lines.append("No productive change evidence was found.")
    for row in apply["productive_changes"]:
        lines.extend([
            f"### `{row['action_id']}`",
            "",
            f"- execution type: `{row['execution_type']}`",
            f"- owner approval present: `{str(row['owner_approval_present']).lower()}`",
            f"- approved at: `{row['approved_at']}`",
            f"- executed at: `{row['executed_at']}`",
            f"- changed files: `{len(row['changed_files'])}`",
            f"- healthcheck: `{row['healthcheck_status']}`",
            f"- autonomous: `{str(row['autonomous']).lower()}`",
            f"- evidence status: `{row['evidence_status']}`",
            f"- missing evidence: `{', '.join(row['missing_evidence']) or 'none'}`",
            "",
        ])
    return "\n".join(lines) + "\n"


def render_priority(report: Dict[str, Any]) -> str:
    priority = report["owner_priority"]
    waf = report["waf_decision"]
    return f"""# Sentinel Owner Priority Decision

- status: `{priority['status']}`
- selected priority: `{priority['selected_priority']}`
- reason: {priority['reason']}
- suppressed lower priorities: `{', '.join(priority['suppressed_lower_priorities']) or 'none'}`

## Owner Action

{priority['next_owner_action']}

## WAF Decision

- new WAF rule recommended: `{str(waf['new_waf_rule_recommended']).lower()}`
- recommendation: {waf['recommendation']}
"""


def render_technical_appendix(report: Dict[str, Any]) -> str:
    evidence = report["current_website_evidence"]
    rolling = report["rolling_window"]
    cause = report["cause_and_impact"]
    private = report["private_metadata"]
    safety = report["safety"]
    lines = [
        "# Sentinel Master Technical Appendix",
        "",
        "**Classification:** `PRIVATE_OWNER_OPERATIONAL_REPORT` / `NOT_FOR_PUBLIC_RELEASE` / `NOT_FOR_GIT` / `CONTAINS_INFRASTRUCTURE_METADATA`",
        "",
        "## Current Website Evidence",
        "",
        f"- snapshot: `{evidence['generated_at_utc']}`",
        f"- status-code totals: `{json.dumps(evidence['status_code_counts'], sort_keys=True)}`",
        f"- root 5xx: `{evidence['root_5xx']}`; login-path 5xx: `{evidence['wp_login_5xx']}`",
        "",
        "## Rolling Window",
        "",
        f"- stable since: `{rolling['stable_since']}`",
        f"- stable / required / remaining minutes: `{rolling['stable_minutes']} / {rolling['required_minutes']} / {rolling['remaining_minutes']}`",
        f"- earliest projected recheck: `{rolling['earliest_recheck_at']}`",
        f"- new growth since stable start: `{str(rolling['new_growth_since_stable_start']).lower()}`",
        f"- OK transition allowed: `{str(rolling['ok_transition_allowed']).lower()}`",
        f"- note: {rolling['projection_note']}",
        "",
        "## Cause and Impact",
        "",
        "| Field | Value |",
        "| --- | --- |",
    ]
    for key in (
        "technical_cause",
        "traffic_actor",
        "affected_path",
        "failure_mode",
        "verified_user_impact",
        "confidence",
    ):
        lines.append(f"| `{key}` | `{cause[key]}` |")
    lines.extend([
        "",
        cause["interpretation"],
        "",
        "## Emergency Stop Semantics",
        "",
    ])
    for key, value in report["emergency_stop_semantics"].items():
        lines.append(f"- `{key}`: `{str(value).lower() if isinstance(value, bool) else value}`")
    lines.extend([
        "",
        "## Private Metadata Classification",
        "",
    ])
    for row in private["categories"]:
        lines.append(
            f"- `{row['category']}`: detected=`{str(row['detected']).lower()}`, occurrences=`{row['occurrence_count']}`"
        )
    lines.extend([
        "",
        "## Current Safety Invariants",
        "",
    ])
    for key, value in safety.items():
        lines.append(f"- `{key}`: `{str(value).lower()}`")
    lines.extend([
        "",
        "## Missing Evidence",
        "",
    ])
    for item in report["known_missing_evidence"]:
        lines.append(f"- {item}")
    lines.extend([
        "",
        "Freshness and apply details are maintained in their dedicated reports to avoid duplicating full tables here.",
    ])
    return "\n".join(lines) + "\n"


def render_consistency_index(report: Dict[str, Any]) -> str:
    return f"""# Sentinel Master Report Consistency

- status: `{report['status']}`
- freshness: `{report['subreport_freshness']['status']}`
- apply semantics: `{report['apply_semantics']['status']}`
- owner priority: `{report['owner_priority']['selected_priority']}`
- public summary: `{report['public_summary_sanitization']['status']}`
- new WAF rule recommended: `{str(report['waf_decision']['new_waf_rule_recommended']).lower()}`

This private index links the compact executive view, technical appendix, freshness table, apply semantics and sanitized public summary. Runtime reports, state and audit outputs are local-only and are not Git checkpoint candidates.
"""


def logical_validation(report: Dict[str, Any], public_text: str) -> Dict[str, Any]:
    checks = {
        "freshness_status_ok": report["subreport_freshness"]["status"] == "SUBREPORT_FRESHNESS_OK",
        "stale_excluded_not_included": all(
            not row["included_in_master_status"]
            for row in report["subreport_freshness"]["reports"]
            if row["freshness_status"] == STALE_EXCLUDED
        ),
        "apply_semantics_consistent": report["apply_semantics"]["status"] == "APPLY_SEMANTICS_CONSISTENT",
        "all_not_applied_not_claimed_with_manual_apply": not (
            report["apply_semantics"]["owner_approved_manual_applies"] > 0
            and report["apply_semantics"]["all_not_applied"]
        ),
        "website_priority_precedes_seo": (
            report["source_master"].get("website_status") != "CRITICAL"
            or report["owner_priority"]["selected_priority"] == "WEBSITE_ORIGIN_STABILITY"
        ),
        "public_summary_sanitized": not public_scan(public_text),
        "no_new_waf_rule": report["waf_decision"]["new_waf_rule_recommended"] is False,
        "live_apply_false": report["safety"]["live_apply"] is False,
        "emergency_stop_true": report["safety"]["emergency_stop"] is True,
        "allowed_apply_now_false": report["safety"]["allowed_apply_now"] is False,
        "high_blocked_true": report["safety"]["high_blocked"] is True,
        "medium_not_executable": report["safety"]["medium_executable"] is False,
        "low_live_not_executable": report["safety"]["low_live_executable"] is False,
        "breach_false": report["safety"]["breach"] is False,
        "safety_evidence_no_drift": report["safety_evidence"]["status"] == "SAFETY_FLAGS_CONFIRMED",
        "git_recommendation_safe": not any(
            item.startswith(("reports/", "state/", "audit/", "exports/"))
            for item in report["git_checkpoint"]["recommended_files"]
        ),
    }
    findings = [name for name, passed in checks.items() if not passed]
    return {
        "status": "MASTER_CONSISTENCY_VALIDATION_OK" if not findings else "MASTER_CONSISTENCY_VALIDATION_FAILED",
        "checks": checks,
        "findings": findings,
    }


def validate_written_outputs() -> Dict[str, Any]:
    findings: List[str] = []
    for path in OUTPUT_JSONS:
        data, status = read_json(path)
        if status != "ok":
            findings.append(f"{rel(path)}:{status}")
        elif path in PLAYBOOKS and not isinstance(data, dict):
            findings.append(f"{rel(path)}:invalid_root")
    for path in OUTPUT_MARKDOWN:
        if not path.exists() or not path.read_text(encoding="utf-8", errors="replace").strip():
            findings.append(f"{rel(path)}:empty_or_missing")
    if PUBLIC_MD.exists():
        for finding in public_scan(PUBLIC_MD.read_text(encoding="utf-8", errors="replace")):
            findings.append(f"{rel(PUBLIC_MD)}:{finding}")
    return {
        "status": "OUTPUT_VALIDATION_OK" if not findings else "OUTPUT_VALIDATION_FAILED",
        "findings": findings,
    }


def write_outputs(report: Dict[str, Any], public_text: str, record: bool = False) -> None:
    ensure_dirs()
    write_json(REPORT_JSON, report)
    write_text(REPORT_MD, render_consistency_index(report))
    write_text(EXECUTIVE_MD, render_executive_summary(report))
    write_text(TECHNICAL_MD, render_technical_appendix(report))
    write_text(PUBLIC_MD, public_text)
    write_text(FRESHNESS_MD, render_freshness(report))
    write_text(APPLY_MD, render_apply_semantics(report))
    write_text(PRIORITY_MD, render_priority(report))
    write_json(STATE_JSON, report)
    write_json(LATEST_STATE_JSON, report)
    history, status = read_json(HISTORY_JSON)
    if status != "ok" or not isinstance(history, list):
        history = []
    if record:
        history.append({
            "generated_at_utc": report["generated_at_utc"],
            "status": report["status"],
            "website_status": report["source_master"].get("website_status"),
            "selected_priority": report["owner_priority"]["selected_priority"],
            "manual_applies": report["apply_semantics"]["owner_approved_manual_applies"],
            "excluded_stale_reports": len(report["subreport_freshness"]["excluded_from_master_status"]),
            "breach": report["safety"]["breach"],
        })
        history = history[-200:]
    write_json(HISTORY_JSON, history)
    if record:
        append_jsonl(AUDIT_JSONL, {
            "timestamp_utc": report["generated_at_utc"],
            "event": "master_report_consistency_collected",
            "status": report["status"],
            "selected_priority": report["owner_priority"]["selected_priority"],
            "live_apply": False,
            "breach": False,
        })


def run_pipeline(record: bool = False) -> Dict[str, Any]:
    report = build_report()
    public_text = build_public_summary(report)
    report["validation"] = logical_validation(report, public_text)
    report["status"] = report["validation"]["status"]
    write_outputs(report, public_text, record=record)
    output_validation = validate_written_outputs()
    report["validation"]["output_validation"] = output_validation
    if output_validation["status"] != "OUTPUT_VALIDATION_OK":
        report["validation"]["status"] = "MASTER_CONSISTENCY_VALIDATION_FAILED"
        report["validation"]["findings"].extend(output_validation["findings"])
        report["status"] = "MASTER_CONSISTENCY_VALIDATION_FAILED"
    write_outputs(report, public_text, record=False)
    return report


def self_test() -> Dict[str, Any]:
    now = datetime(2026, 7, 15, 12, 0, tzinfo=timezone.utc)
    test_a = freshness_from_timestamp("website", now - timedelta(hours=2), now)
    test_a2 = freshness_from_timestamp("informational", now - timedelta(days=2), now)
    test_b = freshness_from_timestamp("source_map_prevention", now - timedelta(days=8), now)
    test_c = classify_productive_action(
        {
            "uploaded": True,
            "owner_approval": True,
            "autonomous": False,
            "generated_at_utc": "2026-07-15T10:00:00Z",
            "changed_files": ["one-file"],
            "healthcheck_status": "ok",
        },
        {"approved": True, "timestamp_utc": "2026-07-15T09:55:00Z"},
    )
    test_d = choose_owner_priority({
        "website_status": "CRITICAL",
        "origin_5xx": 668,
        "root_504": 401,
        "recent_significant_growth": True,
        "24h_low_growth_evidence": False,
        "breach": False,
    })
    test_e = dict(EMERGENCY_STOP_SEMANTICS)
    synthetic_public = sanitize_public_text(
        "198.51.100.7 origin.internal.example /srv/private/report /api/internal/node-7"
    )
    test_g = waf_decision({
        "top_5xx_failure_modes": [
            {"failure_mode": "cloudflare_to_origin_timeout", "count": 510},
            {"failure_mode": "origin_php_or_upstream_error", "count": 155},
        ]
    })

    source = Path(__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported: List[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)
    forbidden_imports = {
        "requests", "urllib", "http.client", "socket", "smtplib", "paramiko", "cloudflare"
    }
    network_imports = sorted(
        name for name in imported if any(name == item or name.startswith(item + ".") for item in forbidden_imports)
    )
    function_names = {node.name for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    free_command_calls = [
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"Popen", "run", "call", "check_call", "check_output"}
    ]
    unsafe_git = [
        item for item in RECOMMENDED_GIT_FILES
        if item.startswith(("reports/", "state/", "audit/", "exports/"))
    ]
    synthetic_json = json.dumps({"freshness": test_a, "priority": test_d})
    checks = {
        "test_a_current": test_a["freshness_status"] == CURRENT,
        "test_a2_stale_informational": (
            test_a2["freshness_status"] == STALE_INFORMATIONAL
            and test_a2["included_in_master_status"] is True
        ),
        "test_b_stale_excluded": (
            test_b["freshness_status"] == STALE_EXCLUDED
            and test_b["included_in_master_status"] is False
        ),
        "test_c_manual_apply": (
            test_c["execution_type"] == "owner_approved_manual_apply"
            and test_c["autonomous"] is False
        ),
        "test_d_website_priority": (
            test_d["selected_priority"] == "WEBSITE_ORIGIN_STABILITY"
            and "SEO_TITLE_REVIEW" in test_d["suppressed_lower_priorities"]
        ),
        "test_e_emergency_stop_semantics": (
            test_e["production_apply_lock"]
            and test_e["remote_write_lock"]
            and test_e["scheduler_install_lock"]
            and test_e["timer_execution_lock"]
            and test_e["local_analysis_allowed"]
            and test_e["local_draft_generation_allowed"]
        ),
        "test_f_public_sanitization": (
            not public_scan(synthetic_public)
            and "198.51.100.7" not in synthetic_public
            and "/srv/private/report" not in synthetic_public
            and "origin.internal.example" not in synthetic_public
            and "node-7" not in synthetic_public
        ),
        "test_g_no_waf_automation": test_g["new_waf_rule_recommended"] is False,
        "no_network_imports": not network_imports,
        "no_free_command_execution": not free_command_calls,
        "no_shell_true": ("shell" + "=True") not in source and ("shell" + " = True") not in source,
        "no_apply_executor": not any(name in function_names for name in {"apply", "execute_apply", "live_apply"}),
        "no_remote_write_functions": not any(
            name in function_names
            for name in {"sftp_write", "wordpress_write", "cloudflare_write", "database_write", "nginx_write"}
        ),
        "no_scheduler_installers": not any(
            name in function_names for name in {"install_timer", "install_cron", "enable_systemd"}
        ),
        "no_git_remote_actions": not any(
            name in function_names for name in {"git_push", "git_tag", "remote_write"}
        ),
        "risk_invariants": (
            SAFETY_FLAGS["breach"] is False
            and SAFETY_FLAGS["high_blocked"] is True
            and SAFETY_FLAGS["medium_executable"] is False
            and SAFETY_FLAGS["low_live_executable"] is False
        ),
        "git_recommendation_safe": not unsafe_git,
        "json_serializable": isinstance(json.loads(synthetic_json), dict),
    }
    findings = [name for name, passed in checks.items() if not passed]
    return {
        "status": "MASTER_CONSISTENCY_SELF_TEST_OK" if not findings else "MASTER_CONSISTENCY_SELF_TEST_FAILED",
        "checks": checks,
        "findings": findings,
        "network_imports": network_imports,
        "free_command_calls": free_command_calls,
        "breach": False,
    }


def print_status(report: Dict[str, Any]) -> None:
    print(report.get("status", "MASTER_CONSISTENCY_NOT_BUILT"))
    if not report:
        return
    print(report["subreport_freshness"]["status"])
    print(report["apply_semantics"]["status"])
    print(report["owner_priority"]["status"])
    print(report["public_summary_sanitization"]["status"])
    print(report["waf_decision"]["status"])
    print("LIVE_APPLY_FALSE")
    print("EMERGENCY_STOP_TRUE")
    print("BREACH_FALSE")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Sentinel master-report consistency layer")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--collect", action="store_true")
    group.add_argument("--evaluate-freshness", action="store_true")
    group.add_argument("--evaluate-apply-semantics", action="store_true")
    group.add_argument("--select-owner-priority", action="store_true")
    group.add_argument("--build-executive-summary", action="store_true")
    group.add_argument("--build-technical-appendix", action="store_true")
    group.add_argument("--build-public-summary", action="store_true")
    group.add_argument("--validate", action="store_true")
    group.add_argument("--status", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        result = self_test()
        print(result["status"])
        if result["findings"]:
            print(json.dumps(result["findings"]))
        return 0 if result["status"] == "MASTER_CONSISTENCY_SELF_TEST_OK" else 1
    if args.status:
        report = load_dict(REPORT_JSON)
        print_status(report)
        return 0 if report else 1

    report = run_pipeline(record=args.collect)
    if args.collect:
        print("MASTER_CONSISTENCY_COLLECT_OK")
    elif args.evaluate_freshness:
        print(report["subreport_freshness"]["status"])
    elif args.evaluate_apply_semantics:
        print(report["apply_semantics"]["status"])
    elif args.select_owner_priority:
        print(report["owner_priority"]["status"])
    elif args.build_executive_summary:
        print("MASTER_EXECUTIVE_SUMMARY_READY")
    elif args.build_technical_appendix:
        print("MASTER_TECHNICAL_APPENDIX_READY")
    elif args.build_public_summary:
        print(report["public_summary_sanitization"]["status"])
    elif args.validate:
        print(report["validation"]["status"])
    return 0 if report["status"] == "MASTER_CONSISTENCY_VALIDATION_OK" else 1


if __name__ == "__main__":
    raise SystemExit(main())
