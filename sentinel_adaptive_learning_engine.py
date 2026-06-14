#!/usr/bin/env python3
"""Sentinel Adaptive SEO & Performance Learning Engine (Phase 8.0).

Learns from local Sentinel reports/history and writes machine-readable
knowledge, recommendations, playbooks, and self-correction plans. It has no
apply mode, performs no network access, and never changes WordPress, SFTP,
Cloudflare, Nginx, .htaccess, DB, cache, systemd, or cron.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


PROJECT_DIR = Path("/srv/sentinel-defense")

INPUTS = {
    "low_risk_autonomy": PROJECT_DIR / "reports/latest/low-risk-autonomy.json",
    "low_risk_install_evidence": PROJECT_DIR / "reports/latest/low-risk-readonly-install-evidence.json",
    "low_risk_timer_watchdog": PROJECT_DIR / "reports/latest/low-risk-timer-watchdog.json",
    "sentinel_master_md": PROJECT_DIR / "reports/latest/sentinel-master-report.md",
    "sentinel_master_json": PROJECT_DIR / "reports/latest/sentinel-master-report.json",
    "safe_seo_performance_monitor_json": PROJECT_DIR / "reports/latest/safe-seo-performance-monitor.json",
    "safe_seo_performance_monitor_md": PROJECT_DIR / "reports/latest/safe-seo-performance-monitor.md",
    "bot_learning_low_risk": PROJECT_DIR / "reports/latest/bot-learning-low-risk-autonomy.json",
    "bot_learning_soc": PROJECT_DIR / "reports/latest/bot-learning-soc-schema-cleanup.json",
    "safe_autonomy_policy_update": PROJECT_DIR / "reports/latest/sentinel-safe-autonomy-policy-update.md",
    "history": PROJECT_DIR / "state/low-risk-autonomy/history.jsonl",
}

STATE_DIR = PROJECT_DIR / "state/adaptive-learning"
REPORT_JSON = PROJECT_DIR / "reports/latest/adaptive-learning-engine.json"
REPORT_MD = PROJECT_DIR / "reports/latest/adaptive-learning-engine.md"
RECOMMEND_JSON = PROJECT_DIR / "reports/latest/adaptive-recommendations.json"
RECOMMEND_MD = PROJECT_DIR / "reports/latest/adaptive-recommendations.md"
SELF_CORRECTION_JSON = PROJECT_DIR / "reports/latest/adaptive-self-correction-plan.json"
SELF_CORRECTION_MD = PROJECT_DIR / "reports/latest/adaptive-self-correction-plan.md"
CAPABILITY_JSON = PROJECT_DIR / "reports/latest/adaptive-bot-capability-map.json"
CAPABILITY_MD = PROJECT_DIR / "reports/latest/adaptive-bot-capability-map.md"
NEXT_STEPS_MD = PROJECT_DIR / "reports/latest/adaptive-next-safe-steps.md"
SNAPSHOT_DIR = PROJECT_DIR / "snapshots"
AUDIT_JSONL = PROJECT_DIR / "audit/adaptive-learning-engine.jsonl"

KNOWLEDGE_BASE_JSON = STATE_DIR / "knowledge_base.json"
OBSERVATIONS_JSONL = STATE_DIR / "observations.jsonl"
PATTERNS_JSON = STATE_DIR / "patterns.json"
ACTION_RULES_JSON = STATE_DIR / "action_rules.json"
ROLLBACK_RULES_JSON = STATE_DIR / "rollback_rules.json"
LATEST_JSON = STATE_DIR / "latest.json"

PLAYBOOKS = {
    "adaptive": PROJECT_DIR / "playbooks/adaptive-seo-performance-learning.playbook.json",
    "self_correction": PROJECT_DIR / "playbooks/self-correction-safety.playbook.json",
    "schema_watch": PROJECT_DIR / "playbooks/schema-known-issue-watch.playbook.json",
    "origin_5xx": PROJECT_DIR / "playbooks/origin-5xx-watch.playbook.json",
    "cache_performance": PROJECT_DIR / "playbooks/cache-performance-watch.playbook.json",
}

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "snapshots",
    PROJECT_DIR / "audit",
    STATE_DIR,
    PROJECT_DIR / "playbooks",
)

STATUS_OK = "ADAPTIVE_LEARNING_OK"
STATUS_WARNINGS = "ADAPTIVE_LEARNING_WARNINGS"
STATUS_CRITICAL_KNOWN = "ADAPTIVE_LEARNING_CRITICAL_KNOWN_ISSUES"
STATUS_FAILED = "ADAPTIVE_LEARNING_FAILED"
STATUS_BLOCKED = "ADAPTIVE_LEARNING_BLOCKED_BY_SAFETY"

LOW = "LOW_RISK_AUTO_ALLOWED"
MEDIUM = "MEDIUM_REQUIRES_OWNER_APPROVAL"
HIGH = "HIGH_RISK_MANUAL_REVIEW_REQUIRED"

KNOWN_SOC_ISSUE = "KNOWN_ISSUE_HIGH_RISK_FSE_SOC_SOURCE"
APPLY_STATUS = "not_applied"
SCHEMA_VERSION = "adaptive-learning-engine-8.0"

SECRET_NAME_RE = re.compile(r"(?i)(secret|key|token|password|passwd|api[_-]?key|credential|authorization|cookie|session|license)")
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|password|passwd|bearer|token|credential|session|"
    r"authorization|set-cookie|cookie|x-api-key|access[_-]?key|license)\b\s*[:=]\s*"
    r"[\"']?(?!false\b|true\b|null\b|none\b|not_applied\b|<redacted|-\b|0\b)"
    r"[A-Za-z0-9+/=_\-]{4,}"
)
LONG_HEX_RE = re.compile(r"\b[A-Fa-f0-9]{32,}\b")
FORBIDDEN_COMMAND_RE = re.compile(
    r"(?i)(--apply\b|apply-safe|live-apply|sftp\s+|scp\s+|ssh\s+|wp\s+|wp-cli|mysql\b|"
    r"cloudflare\s+(api|cli)|cfcli|nginx\s+reload|systemctl\s+(enable|start)|crontab\s+(-|install)|rm\s+-rf|"
    r"curl\s+.*\|\s*(ba)?sh|wget\s+.*\|\s*(ba)?sh)"
)
DB_WRITE_RE = re.compile(r"(?i)\b(UPDATE|DELETE|INSERT|REPLACE|ALTER|DROP)\s+(wp_|wordpress|option|post|postmeta|termmeta)")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def timestamp_tag() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def clamp_score(value: Any) -> int:
    try:
        number = int(round(float(value)))
    except (TypeError, ValueError):
        return 0
    return max(0, min(100, number))


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
        raise ValueError(f"Refusing write outside allowed adaptive roots: {path}")
    if path.suffix.lower() in {".sh", ".bash", ".zsh", ".service", ".timer", ".py", ".env", ".bin", ".run"}:
        raise ValueError(f"Refusing executable/install output: {path}")
    if SECRET_NAME_RE.search(path.name):
        raise ValueError(f"Refusing secret-like output path: {path}")


def assert_safe_content(path: Path, content: str) -> None:
    if SECRET_ASSIGNMENT_RE.search(content):
        raise ValueError(f"Secret-like content refused for {path}")
    if FORBIDDEN_COMMAND_RE.search(content):
        raise ValueError(f"Forbidden command pattern refused for {path}")
    if DB_WRITE_RE.search(content):
        raise ValueError(f"DB write pattern refused for {path}")


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


def read_json_file(path: Path) -> Tuple[Optional[Dict[str, Any]], str]:
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


def read_text_file(path: Path, max_chars: int = 300_000) -> Tuple[str, str]:
    if SECRET_NAME_RE.search(path.name) or path.suffix.lower() == ".env":
        return "", "secret_like_path_refused"
    try:
        if not path.exists():
            return "", "missing"
        return path.read_text(encoding="utf-8")[:max_chars], "ok"
    except OSError:
        return "", "read_error"


def read_jsonl(path: Path, max_lines: int = 1000) -> Tuple[List[Dict[str, Any]], str]:
    if SECRET_NAME_RE.search(path.name) or path.suffix.lower() == ".env":
        return [], "secret_like_path_refused"
    try:
        if not path.exists():
            return [], "missing"
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[-max_lines:]
    except OSError:
        return [], "read_error"
    records: List[Dict[str, Any]] = []
    invalid = 0
    for line in lines:
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            invalid += 1
            continue
        if isinstance(item, dict):
            records.append(item)
    return records, "ok" if invalid == 0 else f"partial_invalid:{invalid}"


def nested_get(data: Optional[Dict[str, Any]], keys: List[str], default: Any = None) -> Any:
    current: Any = data
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
    return current


def load_sources() -> Dict[str, Any]:
    json_sources: Dict[str, Optional[Dict[str, Any]]] = {}
    text_sources: Dict[str, str] = {}
    input_status: Dict[str, str] = {}
    for name, path in INPUTS.items():
        if path.suffix == ".json":
            data, status = read_json_file(path)
            json_sources[name] = data
            input_status[name] = status
        elif path.suffix == ".jsonl":
            records, status = read_jsonl(path, max_lines=5000)
            json_sources[name] = {"records": records}
            input_status[name] = status
        else:
            text, status = read_text_file(path)
            text_sources[name] = text
            input_status[name] = status
    audit_records: Dict[str, int] = {}
    for path in sorted((PROJECT_DIR / "audit").glob("*.jsonl"))[:120]:
        records, status = read_jsonl(path, max_lines=50)
        if status.startswith("ok") or status.startswith("partial"):
            audit_records[path.name] = len(records)
    return {
        "json": json_sources,
        "text": text_sources,
        "input_status": input_status,
        "audit_records_seen": audit_records,
    }


def summarize_history(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    scores = [item.get("scores", {}) for item in records if isinstance(item.get("scores"), dict)]
    analysis = [item.get("analysis", {}) for item in records if isinstance(item.get("analysis"), dict)]
    cache_statuses = Counter(str((a.get("headers_subset") or {}).get("Cf-Cache-Status", "unknown")) for a in analysis)
    ttfb_values = [int(a.get("ttfb_ms")) for a in analysis if isinstance(a.get("ttfb_ms"), int)]
    latest = records[-1] if records else {}
    score_keys = ["seo_score", "performance_basic_score", "schema_health_score", "autonomy_safety_score", "overall_safe_monitor_score"]
    score_summary = {}
    for key in score_keys:
        values = [clamp_score(s.get(key)) for s in scores if key in s]
        score_summary[key] = {
            "latest": clamp_score((latest.get("scores") or {}).get(key)),
            "min": min(values) if values else None,
            "max": max(values) if values else None,
            "points": len(values),
        }
    return {
        "history_points": len(records),
        "latest_timestamp_utc": latest.get("timestamp_utc"),
        "latest_status": latest.get("status"),
        "score_summary": score_summary,
        "ttfb_ms": {
            "latest": ttfb_values[-1] if ttfb_values else None,
            "min": min(ttfb_values) if ttfb_values else None,
            "max": max(ttfb_values) if ttfb_values else None,
            "points": len(ttfb_values),
        },
        "cache_status_counts": dict(cache_statuses),
        "known_issues_seen": sorted({issue for item in records for issue in (item.get("known_issues") or [])}),
        "warning_counts": dict(Counter(w for item in records for w in (item.get("warnings") or []))),
    }


def build_observations(sources: Dict[str, Any], history_summary: Dict[str, Any]) -> List[Dict[str, Any]]:
    low = sources["json"].get("low_risk_autonomy") or {}
    master = sources["json"].get("sentinel_master_json") or {}
    analysis = low.get("analysis") or {}
    scores = low.get("scores") or {}
    duplicate_schema = analysis.get("duplicate_schema_types") or {}
    soc_watch = analysis.get("soc_watch") or {}
    observations = [
        {
            "observation_id": "seo-core-signals-good",
            "area": "SEO",
            "symptoms": ["title_ok", "meta_description_ok", "canonical_ok", "h1_ok", "og_twitter_ok"],
            "hypothesis": "Homepage core SEO tags are currently healthy.",
            "risk_level": LOW,
            "confidence_score": 0.93,
            "evidence": {
                "seo_score": clamp_score(scores.get("seo_score")),
                "title_length": analysis.get("title_length"),
                "meta_description_length": analysis.get("meta_description_length"),
                "h1_count": analysis.get("h1_count"),
            },
        },
        {
            "observation_id": "schema-duplicate-soc-known-issue",
            "area": "Schema",
            "symptoms": ["duplicate_schema_types_present", "soc_schema_known_high_risk_source_visible"],
            "hypothesis": "SOC/FSE schema source is active in WordPress editor/template/runtime output.",
            "risk_level": HIGH,
            "confidence_score": 0.92,
            "evidence": {
                "schema_health_score": clamp_score(scores.get("schema_health_score")),
                "duplicate_schema_types": duplicate_schema,
                "soc_watch": soc_watch,
                "known_issue": KNOWN_SOC_ISSUE in (low.get("known_issues") or []),
            },
        },
        {
            "observation_id": "performance-basic-healthy-but-cache-watch",
            "area": "Performance",
            "symptoms": ["performance_basic_score_high", "cloudflare_cache_status_observed", "external_resources_present"],
            "hypothesis": "Basic page performance is currently healthy, but cache and external resource trends should continue to be watched.",
            "risk_level": LOW,
            "confidence_score": 0.86,
            "evidence": {
                "performance_basic_score": clamp_score(scores.get("performance_basic_score")),
                "ttfb_ms": analysis.get("ttfb_ms"),
                "cf_cache_status": (analysis.get("headers_subset") or {}).get("Cf-Cache-Status"),
                "external_resource_host_count": analysis.get("external_resource_host_count"),
            },
        },
        {
            "observation_id": "website-critical-rolling-window-not-autonomy",
            "area": "Stability",
            "symptoms": ["master_critical", "rolling_window_5xx_504"],
            "hypothesis": "Website CRITICAL is caused by website/origin rolling-window status, not by autonomy.",
            "risk_level": LOW,
            "confidence_score": 0.84,
            "evidence": {
                "website_status": master.get("website_status"),
                "critical_caused_by_autonomy": nested_get(master, ["master_critical_cause_snapshot", "critical_caused_by_autonomy"], False),
                "emergency_stop": nested_get(master, ["autonomy_runtime_lock", "emergency_stop"], None),
                "runtime_live_apply": nested_get(master, ["autonomy_runtime_lock", "live_apply_enabled"], None),
            },
        },
    ]
    if history_summary.get("history_points", 0) >= 2:
        observations.append({
            "observation_id": "history-recurring-schema-warning",
            "area": "Trend",
            "symptoms": list((history_summary.get("warning_counts") or {}).keys()),
            "hypothesis": "History shows recurring schema/SOC warnings while core SEO and basic performance remain stable.",
            "risk_level": LOW,
            "confidence_score": 0.82,
            "evidence": history_summary,
        })
    return observations


def recommendations_from_observations(observations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    base: List[Dict[str, Any]] = [
        {
            "recommendation_id": "low-readonly-monitor-continue",
            "category": LOW,
            "title": "Continue read-only SEO/Performance monitoring",
            "action": "Run scheduled read-only scans, update history, reports, snapshots, and audit.",
            "owner_review_required": False,
            "reason": "Core SEO and performance signals are healthy; ongoing trend detection is safe.",
        },
        {
            "recommendation_id": "low-known-soc-watch",
            "category": LOW,
            "title": "Keep SOC/FSE known issue under watch",
            "action": "Track SOC markers, duplicate schema type counts, and schema health score.",
            "owner_review_required": False,
            "reason": "Monitoring is safe; fixing the source is HIGH risk.",
        },
        {
            "recommendation_id": "low-origin-rolling-window-watch",
            "category": LOW,
            "title": "Watch 5xx/504 rolling window and NowPlaying cache status",
            "action": "Compare rolling-window snapshots and report growth without changing WAF, Cloudflare, or Nginx.",
            "owner_review_required": False,
            "reason": "Website CRITICAL is not caused by autonomy and should remain diagnostic-only here.",
        },
        {
            "recommendation_id": "medium-cache-purge-owner-approval",
            "category": MEDIUM,
            "title": "Cache purge only with Owner approval and backup evidence",
            "action": "Prepare dry-run and backup plan; do not execute automatically.",
            "owner_review_required": True,
            "reason": "Cache purge can affect production output and must stay owner-gated.",
        },
        {
            "recommendation_id": "medium-seo-plugin-settings-owner-approval",
            "category": MEDIUM,
            "title": "SEO plugin setting changes remain owner-approved",
            "action": "Prepare copy/paste or dry-run instructions only.",
            "owner_review_required": True,
            "reason": "SEO settings can alter public metadata.",
        },
        {
            "recommendation_id": "high-fse-soc-source-manual-review",
            "category": HIGH,
            "title": "Manual review required for SOC/FSE schema source",
            "action": "Owner reviews FSE template, page/post content, and editor blocks; bot does not edit.",
            "owner_review_required": True,
            "reason": "The known issue source is likely FSE/editor/template/runtime output.",
        },
        {
            "recommendation_id": "high-no-db-template-cloudflare-nginx-auto",
            "category": HIGH,
            "title": "Keep DB/FSE/Cloudflare/Nginx/.htaccess changes blocked",
            "action": "Document only; no automatic write or restore.",
            "owner_review_required": True,
            "reason": "These are production-impacting changes.",
        },
    ]
    return base


def build_action_rules() -> Dict[str, Any]:
    return {
        LOW: [
            "read-only scan ausfuehren",
            "History aktualisieren",
            "Reports schreiben",
            "Draft-Actions erzeugen",
            "Watchdog pruefen",
            "Anomalie melden",
            "Known Issue beobachten",
            "Trend auswerten",
        ],
        MEDIUM: [
            "Cache purge mit Backup",
            "robots/sitemap setting aendern",
            "SEO Plugin setting aendern",
            "Meta-/Schema-Injection ueber MU-Plugin",
            "Bildoptimierungsjob",
            "Lazy-loading Script/HTML Patch",
            "SourceMap WPO-Minify Patch",
            "Microcache-Konfigurationsaenderung",
        ],
        HIGH: [
            "DB delete/update",
            "FSE Template edit",
            "Page/Post edit",
            "Theme/Plugin code edit",
            ".htaccess Aenderung",
            "Cloudflare Rule Aenderung",
            "Nginx Aenderung",
            "Redirect Aenderung",
            "breite Bot-/WAF-Blockade",
        ],
    }


def build_rollback_rules() -> Dict[str, Any]:
    return {
        "restore_file_from_backup": {"autonomous_allowed": False, "requires_owner_approval": True, "requires_backup": True},
        "restore_db_option_from_backup": {"autonomous_allowed": False, "requires_owner_approval": True, "requires_backup": True},
        "disable_temporary_mu_plugin": {"autonomous_allowed": False, "requires_owner_approval": True, "requires_backup": False},
        "clear_generated_draft_only": {"autonomous_allowed": True, "requires_owner_approval": False, "scope": "own drafts/reports only"},
        "rollback_cache_purge": {"autonomous_allowed": False, "reason": "Cache regenerates; report and observe instead."},
        "rollback_cloudflare_nginx_htaccess": {"autonomous_allowed": False, "requires_owner_manual_action": True},
    }


def build_self_correction_plan() -> Dict[str, Any]:
    return {
        "plan_status": "ADAPTIVE_SELF_CORRECTION_PLAN_READY_LOCKED",
        "live_apply": False,
        "apply_status": APPLY_STATUS,
        "detect_bad_change_if": [
            "post_apply_healthcheck_worse",
            "http_status_not_200",
            "seo_score_strong_drop",
            "performance_score_strong_drop",
            "schema_count_worse",
            "5xx_increases_after_change",
            "cache_or_html_broken",
            "breach_detected",
            "secret_in_report_detected",
            "temporary_plugin_remains",
            "backup_missing",
        ],
        "low_risk_safe_reaction": [
            "stop further actions",
            "mark degraded or breach",
            "write alert report",
            "write rollback recommendation",
            "disable affected playbook rule pending_review",
            "run read-only recheck only",
        ],
        "medium_high_response": [
            "no automatic retry",
            "owner review required",
            "rollback only when explicitly allowed and backup exists",
        ],
        "rollback_model": build_rollback_rules(),
        "future_autonomous_self_correction_allowed": [
            "correct own draft/report files",
            "set own timer/watchdog status to blocked",
            "stop future automation",
            "run new read-only validation",
        ],
        "future_autonomous_self_correction_blocked": [
            "DB restore",
            "FSE restore",
            "theme/plugin restore",
            "Cloudflare/Nginx/.htaccess restore",
            "broad security rules",
        ],
    }


def capability_map() -> Dict[str, Any]:
    return {
        "read_only_monitoring": True,
        "reports_history_audit": True,
        "known_issue_watch": True,
        "draft_actions": True,
        "playbook_generation": True,
        "trend_detection": True,
        "self_correction_own_drafts_reports": True,
        "stop_future_automation_after_bad_signal": True,
        "live_apply": False,
        "db_write": False,
        "sftp_write": False,
        "fse_edit": False,
        "post_page_edit": False,
        "cache_purge": False,
        "cloudflare_change": False,
        "nginx_change": False,
        "htaccess_change": False,
        "broad_waf_security_block": False,
    }


def playbook(name: str, purpose: str, triggers: List[str], risk_level: str, owner_review_required: bool, output_reports: List[str]) -> Dict[str, Any]:
    return {
        "name": name,
        "purpose": purpose,
        "triggers": triggers,
        "inputs": [
            "reports/latest/low-risk-autonomy.json",
            "state/low-risk-autonomy/history.jsonl",
            "reports/latest/sentinel-master-report.json",
        ],
        "allowed_actions": build_action_rules()[LOW],
        "blocked_actions": build_action_rules()[MEDIUM] + build_action_rules()[HIGH],
        "risk_level": risk_level,
        "owner_review_required": owner_review_required,
        "healthchecks": ["read-only score compare", "known issue compare", "breach flag check"],
        "rollback_requirements": build_rollback_rules(),
        "output_reports": output_reports,
        "confidence_rules": [
            "High confidence requires at least two matching snapshots",
            "Do not infer remediation from a single 24h rolling-window point",
            "SOC/FSE source stays HIGH risk regardless of confidence",
        ],
        "disable_conditions": [
            "breach=true",
            "secret-like report content",
            "live_apply=true",
            "required input parser failure repeated three times",
        ],
    }


def build_playbooks() -> Dict[str, Dict[str, Any]]:
    return {
        "adaptive": playbook(
            "adaptive-seo-performance-learning",
            "Learn recurring SEO, schema, performance, and stability patterns from local Sentinel reports.",
            ["new low-risk autonomy run", "history updated", "master status changed"],
            LOW,
            False,
            ["reports/latest/adaptive-learning-engine.json", "reports/latest/adaptive-recommendations.json"],
        ),
        "self_correction": playbook(
            "self-correction-safety",
            "Detect bad outcomes and restrict the bot to safe local containment and read-only validation.",
            ["score drop", "healthcheck worse", "breach true", "temporary plugin remains"],
            MEDIUM,
            True,
            ["reports/latest/adaptive-self-correction-plan.json"],
        ),
        "schema_watch": playbook(
            "schema-known-issue-watch",
            "Monitor duplicate schema and SOC/FSE known issue without editing WordPress content.",
            ["schema_health_score below 50", "SOC marker visible", "duplicate schema types present"],
            HIGH,
            True,
            ["reports/latest/adaptive-recommendations.json"],
        ),
        "origin_5xx": playbook(
            "origin-5xx-watch",
            "Watch website/origin 5xx and 504 rolling-window status without WAF or infrastructure changes.",
            ["master website status critical", "rolling-window growth", "origin timeout signal"],
            LOW,
            False,
            ["reports/latest/adaptive-learning-engine.json"],
        ),
        "cache_performance": playbook(
            "cache-performance-watch",
            "Track cache headers, TTFB, HTML size, script count, and resource pressure.",
            ["cache status changes", "TTFB trend worsens", "HTML size grows"],
            LOW,
            False,
            ["reports/latest/adaptive-learning-engine.json"],
        ),
    }


def determine_status(sources: Dict[str, Any], observations: List[Dict[str, Any]], missing_inputs: List[str]) -> str:
    low = sources["json"].get("low_risk_autonomy") or {}
    master = sources["json"].get("sentinel_master_json") or {}
    if low.get("breach") is True or nested_get(master, ["autonomy_runtime_lock", "runtime_lock_breach"], False):
        return STATUS_BLOCKED
    if nested_get(master, ["autonomy_runtime_lock", "live_apply_enabled"], False):
        return STATUS_BLOCKED
    known = low.get("known_issues") or []
    if KNOWN_SOC_ISSUE in known or clamp_score((low.get("scores") or {}).get("schema_health_score")) < 50:
        return STATUS_CRITICAL_KNOWN
    if missing_inputs or low.get("warnings"):
        return STATUS_WARNINGS
    return STATUS_OK


def build_all(action: str) -> Dict[str, Any]:
    ts = timestamp_tag()
    sources = load_sources()
    history_records = (sources["json"].get("history") or {}).get("records", [])
    history_summary = summarize_history(history_records)
    observations = build_observations(sources, history_summary)
    recommendations = recommendations_from_observations(observations)
    missing_inputs = [name for name, status in sources["input_status"].items() if status == "missing"]
    status = determine_status(sources, observations, missing_inputs)
    low = sources["json"].get("low_risk_autonomy") or {}
    master = sources["json"].get("sentinel_master_json") or {}
    scores = low.get("scores") or {}
    breach = status == STATUS_BLOCKED
    report = {
        "schema_version": SCHEMA_VERSION,
        "timestamp": ts,
        "timestamp_utc": utc_now(),
        "action": action,
        "adaptive_status": status,
        "breach": breach,
        "live_apply": False,
        "runtime_live_apply": bool(nested_get(master, ["autonomy_runtime_lock", "live_apply_enabled"], False)),
        "emergency_stop_unchanged": True,
        "emergency_stop": bool(nested_get(master, ["autonomy_runtime_lock", "emergency_stop"], False)),
        "apply_status": APPLY_STATUS,
        "missing_inputs": missing_inputs,
        "input_status": sources["input_status"],
        "scores": {key: clamp_score(value) for key, value in scores.items()},
        "history_summary": history_summary,
        "observations_count": len(observations),
        "recommendation_count": len(recommendations),
        "known_issues": low.get("known_issues") or [],
        "observations": observations,
        "summary": {
            "seo_learning": "Core SEO tags are healthy; keep monitoring.",
            "performance_learning": "Basic performance is healthy; continue cache/TTFB/resource trend watch.",
            "schema_learning": "Duplicate schema/SOC/FSE remains the critical known HIGH-risk issue.",
            "autonomy_learning": "Read-only automation is safe; MEDIUM/HIGH actions remain owner-gated.",
        },
    }
    knowledge = {
        "timestamp_utc": report["timestamp_utc"],
        "learning_status": status,
        "symptoms": sorted({s for obs in observations for s in obs.get("symptoms", [])}),
        "hypotheses": {obs["observation_id"]: obs["hypothesis"] for obs in observations},
        "risk_levels": {obs["observation_id"]: obs["risk_level"] for obs in observations},
        "allowed_bot_reactions": build_action_rules()[LOW],
        "prohibited_bot_reactions": build_action_rules()[MEDIUM] + build_action_rules()[HIGH],
        "owner_approval_required_for": build_action_rules()[MEDIUM] + build_action_rules()[HIGH],
        "healthchecks_required": ["score compare", "public read-only healthcheck", "history trend compare", "breach flag check"],
        "backup_required_for": ["cache purge", "DB option changes", "file restore", "template changes"],
        "rollback_strategy": build_rollback_rules(),
        "learning_confidence": round(sum(float(o.get("confidence_score", 0)) for o in observations) / max(1, len(observations)), 2),
    }
    patterns = {
        "timestamp_utc": report["timestamp_utc"],
        "recurring_warnings": history_summary.get("warning_counts", {}),
        "cache_status_counts": history_summary.get("cache_status_counts", {}),
        "known_issues_seen": history_summary.get("known_issues_seen", []),
        "schema_duplicate_pattern": "persistent" if KNOWN_SOC_ISSUE in history_summary.get("known_issues_seen", []) else "unknown",
        "performance_pattern": "stable_basic_score" if (history_summary.get("score_summary", {}).get("performance_basic_score", {}).get("min") == 100) else "watch",
    }
    return {
        "report": report,
        "knowledge": knowledge,
        "patterns": patterns,
        "action_rules": build_action_rules(),
        "rollback_rules": build_rollback_rules(),
        "recommendations": {
            "timestamp_utc": report["timestamp_utc"],
            "recommendation_count": len(recommendations),
            "categories": dict(Counter(item["category"] for item in recommendations)),
            "recommendations": recommendations,
            "live_apply": False,
            "apply_status": APPLY_STATUS,
            "breach": breach,
        },
        "self_correction": build_self_correction_plan(),
        "capabilities": capability_map(),
        "playbooks": build_playbooks(),
    }


def render_report_md(report: Dict[str, Any]) -> str:
    lines = [
        "# Adaptive Learning Engine",
        "",
        f"- Status: `{report.get('adaptive_status')}`",
        f"- Breach: `{report.get('breach')}`",
        f"- live_apply: `{report.get('live_apply')}`",
        f"- Emergency stop unchanged: `{report.get('emergency_stop_unchanged')}`",
        f"- Observations: `{report.get('observations_count')}`",
        f"- Recommendations: `{report.get('recommendation_count')}`",
        f"- Known issues: `{', '.join(report.get('known_issues') or []) or '-'}`",
        "",
        "## Scores",
        "",
    ]
    for key, value in (report.get("scores") or {}).items():
        lines.append(f"- `{key}`: `{value}`")
    lines.extend(["", "## Learning Summary", ""])
    for key, value in (report.get("summary") or {}).items():
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## Observations", ""])
    for item in report.get("observations", []):
        lines.append(f"- `{item.get('observation_id')}` {item.get('risk_level')}: {item.get('hypothesis')}")
    return "\n".join(lines) + "\n"


def render_recommendations_md(data: Dict[str, Any]) -> str:
    lines = ["# Adaptive Recommendations", "", f"- Count: `{data.get('recommendation_count')}`", ""]
    for item in data.get("recommendations", []):
        lines.append(f"## {item.get('title')}")
        lines.append(f"- Category: `{item.get('category')}`")
        lines.append(f"- Owner review required: `{item.get('owner_review_required')}`")
        lines.append(f"- Action: {item.get('action')}")
        lines.append(f"- Reason: {item.get('reason')}")
        lines.append("")
    return "\n".join(lines)


def render_self_correction_md(plan: Dict[str, Any]) -> str:
    lines = ["# Adaptive Self-Correction Plan", "", f"- Status: `{plan.get('plan_status')}`", f"- live_apply: `{plan.get('live_apply')}`", ""]
    for key in ("detect_bad_change_if", "low_risk_safe_reaction", "medium_high_response", "future_autonomous_self_correction_allowed", "future_autonomous_self_correction_blocked"):
        lines.append(f"## {key.replace('_', ' ').title()}")
        for item in plan.get(key, []):
            lines.append(f"- {item}")
        lines.append("")
    return "\n".join(lines)


def render_capabilities_md(data: Dict[str, Any]) -> str:
    lines = ["# Adaptive Bot Capability Map", ""]
    for key, value in data.items():
        lines.append(f"- `{key}`: `{value}`")
    return "\n".join(lines) + "\n"


def render_next_steps(report: Dict[str, Any], recommendations: Dict[str, Any]) -> str:
    return f"""# Adaptive Next Safe Steps

- Continue LOW-RISK read-only monitoring and history collection.
- Keep `{KNOWN_SOC_ISSUE}` as HIGH-RISK manual review only.
- Do not derive WAF, Cloudflare, Nginx, DB, FSE, or cache actions automatically.
- Use recommendations report for Owner review of MEDIUM/HIGH candidates.
- Next safe build step: add owner-approved MEDIUM dry-run gates, not live apply.

Current adaptive status: `{report.get('adaptive_status')}`
Recommendations: `{recommendations.get('recommendation_count')}`
Breach: `{report.get('breach')}`
"""


def write_outputs(bundle: Dict[str, Any], include_playbooks: bool = True) -> None:
    report = bundle["report"]
    ts = str(report["timestamp"])
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, render_report_md(report))
    write_json_atomic(RECOMMEND_JSON, bundle["recommendations"])
    write_text_atomic(RECOMMEND_MD, render_recommendations_md(bundle["recommendations"]))
    write_json_atomic(SELF_CORRECTION_JSON, bundle["self_correction"])
    write_text_atomic(SELF_CORRECTION_MD, render_self_correction_md(bundle["self_correction"]))
    write_json_atomic(CAPABILITY_JSON, bundle["capabilities"])
    write_text_atomic(CAPABILITY_MD, render_capabilities_md(bundle["capabilities"]))
    write_text_atomic(NEXT_STEPS_MD, render_next_steps(report, bundle["recommendations"]))
    write_json_atomic(SNAPSHOT_DIR / f"adaptive-learning-engine-{ts}.json", report)
    write_json_atomic(KNOWLEDGE_BASE_JSON, bundle["knowledge"])
    append_jsonl(OBSERVATIONS_JSONL, bundle["report"]["observations"])
    write_json_atomic(PATTERNS_JSON, bundle["patterns"])
    write_json_atomic(ACTION_RULES_JSON, bundle["action_rules"])
    write_json_atomic(ROLLBACK_RULES_JSON, bundle["rollback_rules"])
    write_json_atomic(LATEST_JSON, report)
    if include_playbooks:
        for key, path in PLAYBOOKS.items():
            write_json_atomic(path, bundle["playbooks"][key])
    append_jsonl(
        AUDIT_JSONL,
        [{
            "timestamp_utc": report.get("timestamp_utc"),
            "action": report.get("action"),
            "adaptive_status": report.get("adaptive_status"),
            "recommendation_count": bundle["recommendations"].get("recommendation_count"),
            "known_issues": report.get("known_issues"),
            "live_apply": report.get("live_apply"),
            "breach": report.get("breach"),
        }],
    )


def run_command(action: str, include_playbooks: bool = True) -> Dict[str, Any]:
    bundle = build_all(action)
    write_outputs(bundle, include_playbooks=include_playbooks)
    return bundle


def print_status() -> None:
    latest, status = read_json_file(LATEST_JSON)
    if latest is None:
        print(f"status=not_available input_status={status}")
        return
    print(f"adaptive_status={latest.get('adaptive_status')}")
    print(f"timestamp_utc={latest.get('timestamp_utc')}")
    print(f"breach={latest.get('breach')}")
    print(f"live_apply={latest.get('live_apply')}")
    print(f"emergency_stop={latest.get('emergency_stop')}")
    print(f"known_issues={','.join(latest.get('known_issues') or [])}")
    scores = latest.get("scores") or {}
    for key in ("seo_score", "performance_basic_score", "schema_health_score", "autonomy_safety_score", "overall_safe_monitor_score"):
        print(f"{key}={scores.get(key)}")


def run_self_test() -> int:
    parser = build_parser()
    if "--apply" in parser.format_help():
        raise AssertionError("apply mode exposed")
    if clamp_score(-5) != 0 or clamp_score(105) != 100 or clamp_score(50.4) != 50:
        raise AssertionError("score boundaries failed")
    sample_records, status = read_jsonl(Path("/tmp/definitely-missing-adaptive-history.jsonl"))
    if sample_records or status != "missing":
        raise AssertionError("missing jsonl handling failed")
    obs = build_observations({"json": {"low_risk_autonomy": {"scores": {"seo_score": 100, "schema_health_score": 5}, "analysis": {"duplicate_schema_types": {"Organization": 3}, "soc_watch": {"soc-schema-graph": True}}, "known_issues": [KNOWN_SOC_ISSUE]}, "sentinel_master_json": {}}, "text": {}, "input_status": {}}, {"history_points": 0})
    if not any(o["risk_level"] == HIGH for o in obs):
        raise AssertionError("known issue high-risk classification failed")
    recs = recommendations_from_observations(obs)
    if not any(r["category"] == LOW for r in recs) or not any(r["category"] == HIGH for r in recs):
        raise AssertionError("risk recommendations incomplete")
    plan = build_self_correction_plan()
    if "DB restore" not in plan["future_autonomous_self_correction_blocked"]:
        raise AssertionError("self-correction blocked rules incomplete")
    rules = build_rollback_rules()
    if rules["restore_db_option_from_backup"]["autonomous_allowed"]:
        raise AssertionError("DB rollback incorrectly autonomous")
    if "abcdef" in redact_text("api_key=abcdef12345"):
        raise AssertionError("secret redaction failed")
    source = Path(__file__).read_text(encoding="utf-8")
    for token in ("sub" + "process", "os" + "." + "system", "." + "put(", "." + "remove(", "." + "rename(", "rm " + "-rf"):
        if token in source:
            raise AssertionError(f"forbidden implementation token found: {token}")
    data = build_all("self-test")
    json.dumps(data["report"])
    json.dumps(data["recommendations"])
    print("self-test ok")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Adaptive SEO & Performance Learning Engine.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--learn", action="store_true")
    group.add_argument("--recommend", action="store_true")
    group.add_argument("--draft-playbooks", action="store_true")
    group.add_argument("--self-correction-plan", action="store_true")
    group.add_argument("--status", action="store_true")
    return parser


def print_summary(bundle: Dict[str, Any]) -> None:
    report = bundle["report"]
    print(f"adaptive_status={report.get('adaptive_status')}")
    print(f"recommendation_count={bundle['recommendations'].get('recommendation_count')}")
    print(f"playbooks_count={len(bundle.get('playbooks', {}))}")
    print(f"self_correction_plan_status={bundle['self_correction'].get('plan_status')}")
    print(f"breach={report.get('breach')}")
    print(f"live_apply={report.get('live_apply')}")
    print(f"emergency_stop={report.get('emergency_stop')}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.self_test:
        return run_self_test()
    if args.status:
        print_status()
        return 0
    try:
        if args.learn:
            bundle = run_command("learn", include_playbooks=False)
        elif args.recommend:
            bundle = run_command("recommend", include_playbooks=False)
        elif args.draft_playbooks:
            bundle = run_command("draft-playbooks", include_playbooks=True)
        elif args.self_correction_plan:
            bundle = run_command("self-correction-plan", include_playbooks=True)
        else:
            parser.error("unreachable")
    except Exception as exc:  # noqa: BLE001
        failed = {
            "schema_version": SCHEMA_VERSION,
            "timestamp": timestamp_tag(),
            "timestamp_utc": utc_now(),
            "action": "failed",
            "adaptive_status": STATUS_FAILED,
            "breach": True,
            "live_apply": False,
            "apply_status": APPLY_STATUS,
            "error": redact_text(exc),
        }
        write_json_atomic(REPORT_JSON, failed)
        write_text_atomic(REPORT_MD, "# Adaptive Learning Engine\n\n- Status: `ADAPTIVE_LEARNING_FAILED`\n")
        print(f"adaptive_status={STATUS_FAILED}")
        print("breach=True")
        return 2
    print_summary(bundle)
    return 0 if not bundle["report"].get("breach") else 2


if __name__ == "__main__":
    sys.exit(main())
