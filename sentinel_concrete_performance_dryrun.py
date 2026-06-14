#!/usr/bin/env python3
"""Concrete Performance Trend Watch & Dry-run (Phase 8.4).

Collects local Sentinel and external-checker performance signals, stores a
repeatable trend watch, creates MEDIUM-risk dry-run optimization packages, and
updates adaptive bot learning. It has no apply mode and performs no live
changes, remote writes, cache purge, DB write, Cloudflare/Nginx/.htaccess
change, FSE/Post/Page/Theme/Plugin edit, systemd activation, cron install, or
destructive command.
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

REPORT_JSON = PROJECT_DIR / "reports/latest/concrete-performance-dryrun.json"
REPORT_MD = PROJECT_DIR / "reports/latest/concrete-performance-dryrun.md"
OWNER_PACK_MD = PROJECT_DIR / "reports/latest/concrete-performance-owner-review-pack.md"
TRENDS_JSON = PROJECT_DIR / "reports/latest/concrete-performance-trends.json"
TRENDS_MD = PROJECT_DIR / "reports/latest/concrete-performance-trends.md"
SNAPSHOT_DIR = PROJECT_DIR / "snapshots"
AUDIT_JSONL = PROJECT_DIR / "audit/concrete-performance-dryrun.jsonl"

STATE_DIR = PROJECT_DIR / "state/performance-dryrun"
HISTORY_JSONL = STATE_DIR / "history.jsonl"
LATEST_JSON = STATE_DIR / "latest.json"
STATE_TRENDS_JSON = STATE_DIR / "trends.json"

ADAPTIVE_DIR = PROJECT_DIR / "state/adaptive-learning"
KNOWLEDGE_BASE_JSON = ADAPTIVE_DIR / "knowledge_base.json"
OBSERVATIONS_JSONL = ADAPTIVE_DIR / "observations.jsonl"
PATTERNS_JSON = ADAPTIVE_DIR / "patterns.json"
ACTION_RULES_JSON = ADAPTIVE_DIR / "action_rules.json"
ADAPTIVE_LATEST_JSON = ADAPTIVE_DIR / "latest.json"

ADAPTIVE_REPORT_MD = PROJECT_DIR / "reports/latest/adaptive-learning-engine.md"
ADAPTIVE_RECOMMEND_MD = PROJECT_DIR / "reports/latest/adaptive-recommendations.md"
ADAPTIVE_CAPABILITY_MD = PROJECT_DIR / "reports/latest/adaptive-bot-capability-map.md"

PLAYBOOKS = {
    "images": PROJECT_DIR / "playbooks/performance-images-dryrun.playbook.json",
    "inline-css": PROJECT_DIR / "playbooks/performance-inline-css-dryrun.playbook.json",
    "scripts": PROJECT_DIR / "playbooks/performance-scripts-dryrun.playbook.json",
    "cache-expires": PROJECT_DIR / "playbooks/performance-cache-expires-review.playbook.json",
    "html-size": PROJECT_DIR / "playbooks/performance-html-size-dryrun.playbook.json",
}

INPUTS = {
    "external_seo_ingest": PROJECT_DIR / "reports/latest/external-seo-report-ingest.json",
    "external_seo_recommendations": PROJECT_DIR / "reports/latest/external-seo-report-recommendations.json",
    "low_risk_autonomy": PROJECT_DIR / "reports/latest/low-risk-autonomy.json",
    "low_risk_latest": PROJECT_DIR / "state/low-risk-autonomy/latest.json",
    "global_checker": PROJECT_DIR / "reports/latest/global-checker-ingest.json",
    "adaptive_learning": PROJECT_DIR / "reports/latest/adaptive-learning-engine.json",
    "knowledge_base": KNOWLEDGE_BASE_JSON,
    "patterns": PATTERNS_JSON,
    "adaptive_latest": ADAPTIVE_LATEST_JSON,
}

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "snapshots",
    PROJECT_DIR / "audit",
    STATE_DIR,
    ADAPTIVE_DIR,
    PROJECT_DIR / "playbooks",
)

STATUS_OK = "CONCRETE_PERFORMANCE_DRYRUN_OK"
STATUS_WARNINGS = "CONCRETE_PERFORMANCE_DRYRUN_WARNINGS"
STATUS_INSUFFICIENT = "CONCRETE_PERFORMANCE_DRYRUN_INSUFFICIENT_HISTORY"
STATUS_BLOCKED = "CONCRETE_PERFORMANCE_DRYRUN_BLOCKED_BY_SAFETY"
STATUS_FAILED = "CONCRETE_PERFORMANCE_DRYRUN_FAILED"

TREND_IMPROVING = "IMPROVING"
TREND_STABLE = "STABLE"
TREND_WATCH = "WATCH"
TREND_REGRESSION = "REGRESSION"
TREND_INSUFFICIENT = "INSUFFICIENT_HISTORY"

LOW = "LOW_RISK_AUTO_ALLOWED"
MEDIUM = "MEDIUM_REQUIRES_OWNER_APPROVAL"
HIGH = "HIGH_RISK_MANUAL_REVIEW_REQUIRED"
APPLY_STATUS = "not_applied"
SCHEMA_VERSION = "concrete-performance-dryrun-8.4"
GATES = ("images", "inline-css", "scripts", "cache-expires", "html-size")

SECRET_NAME_RE = re.compile(r"(?i)(secret|key|token|password|passwd|api[_-]?key|credential|authorization|cookie|session|license)")
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|password|passwd|bearer|token|credential|session|"
    r"authorization|set-cookie|cookie|x-api-key|access[_-]?key|license)\b\s*[:=]\s*"
    r"[\"']?(?!false\b|true\b|null\b|none\b|not_applied\b|<redacted|-\b|0\b)"
    r"[A-Za-z0-9+/=_\-]{4,}"
)
LONG_HEX_RE = re.compile(r"\b[A-Fa-f0-9]{32,}\b")
FORBIDDEN_COMMAND_RE = re.compile(
    r"(?i)(--apply\b|apply-safe|live-apply|sftp\s+(put|remove|rename|rm|mkdir|rmdir)|scp\s+|ssh\s+|wp\s+|wp-cli|mysql\b|"
    r"sftp\.(put|remove|rename)|cloudflare\s+(api|cli)|nginx\s+reload|systemctl\s+(enable|start)|"
    r"crontab\s+(-|install)|rm\s+-rf|curl\s+.*\|\s*(ba)?sh|wget\s+.*\|\s*(ba)?sh)"
)
DB_WRITE_RE = re.compile(r"(?i)\b(UPDATE|DELETE|INSERT|REPLACE|ALTER|DROP)\s+(wp_|wordpress|option|post|postmeta|termmeta)")


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


def redact_text(value: Any, default: str = "-", max_len: int = 1200) -> str:
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
        raise ValueError(f"Refusing write outside allowed performance dry-run roots: {path}")
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


def read_history(path: Path) -> Tuple[List[Dict[str, Any]], str]:
    if not path.exists():
        return [], "missing"
    records: List[Dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            item = json.loads(line)
            if isinstance(item, dict):
                records.append(item)
    except (OSError, json.JSONDecodeError):
        return records, "read_error"
    return records, "ok"


def nested_get(data: Dict[str, Any], keys: List[str], default: Any = None) -> Any:
    current: Any = data
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
    return current


def to_number(value: Any) -> Optional[float]:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def to_int(value: Any) -> Optional[int]:
    number = to_number(value)
    if number is None:
        return None
    return int(round(number))


def load_inputs() -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    status: Dict[str, str] = {}
    for name, path in INPUTS.items():
        item, st = read_json(path)
        data[name] = item or {}
        status[name] = st
    return {"data": data, "status": status}


def finding_value(report: Dict[str, Any], finding_id: str) -> Any:
    for item in report.get("findings", []) or []:
        if item.get("finding_id") == finding_id:
            return item.get("parsed_value")
    return None


def finding_exists(report: Dict[str, Any], finding_id: str) -> bool:
    return any(item.get("finding_id") == finding_id for item in report.get("findings", []) or [])


def collect_metrics(inputs: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    inputs = inputs or load_inputs()
    data = inputs["data"]
    external = data.get("external_seo_ingest", {})
    low = data.get("low_risk_autonomy") or data.get("low_risk_latest") or {}
    analysis = low.get("analysis") or {}
    global_metrics = (data.get("global_checker", {}) or {}).get("metrics") or {}
    image_kb = to_int(finding_value(external, "image_bytes_high"))
    image_bytes = image_kb * 1024 if image_kb is not None and image_kb < 10000 else image_kb
    cache_headers = analysis.get("headers_subset") or {}
    return {
        "timestamp_utc": utc_now(),
        "total_transfer_bytes": to_int(finding_value(external, "total_transfer_bytes_high")),
        "image_bytes": image_bytes,
        "image_kb_reported": image_kb,
        "inline_css_count": to_int(finding_value(external, "inline_css_count_high")),
        "internal_scripts_count": to_int(finding_value(external, "internal_scripts_count_high")),
        "html_bytes": to_int(finding_value(external, "html_bytes_high")) or to_int(analysis.get("html_size_bytes")),
        "external_html_bytes": to_int(finding_value(external, "html_bytes_high")),
        "sentinel_html_size_bytes": to_int(analysis.get("html_size_bytes")),
        "sentinel_response_size_bytes": to_int(analysis.get("response_size_bytes")),
        "expires_tag_missing": finding_exists(external, "expires_tag_missing"),
        "ttfb_ms": to_int(analysis.get("ttfb_ms")),
        "script_tag_count": to_int(analysis.get("script_tag_count")),
        "stylesheet_count": to_int(analysis.get("stylesheet_count")),
        "image_count": to_int(analysis.get("image_count")),
        "lazy_image_count": to_int(analysis.get("lazy_image_count")),
        "webp_hint_count": to_int(analysis.get("webp_hint_count")),
        "large_inline_script_count": to_int(analysis.get("large_inline_script_count")),
        "external_resource_host_count": to_int(analysis.get("external_resource_host_count")),
        "cf_cache_status": cache_headers.get("Cf-Cache-Status"),
        "cache_control": cache_headers.get("Cache-Control"),
        "global_avg_latency_ms": to_number(global_metrics.get("avg_latency_ms")),
        "global_p90_latency_ms": to_number(global_metrics.get("p90_latency_ms")),
        "global_avg_ttfb_ms": to_number(global_metrics.get("avg_ttfb_ms")),
        "global_p90_ttfb_ms": to_number(global_metrics.get("p90_ttfb_ms")),
        "global_success_rate_percent": to_number(global_metrics.get("success_rate_percent")),
        "global_slowest_regions": global_metrics.get("slowest_regions") or [],
        "global_fastest_regions": global_metrics.get("fastest_regions") or [],
        "global_warning_statuses": (data.get("global_checker", {}) or {}).get("warning_statuses") or [],
        "source_status": inputs["status"],
    }


def metric_delta(current: Dict[str, Any], previous: Dict[str, Any], key: str) -> Optional[float]:
    cur = to_number(current.get(key))
    prev = to_number(previous.get(key))
    if cur is None or prev is None:
        return None
    return round(cur - prev, 2)


def compare_history(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    if len(records) < 2:
        latest = records[-1] if records else {}
        return {
            "trend": TREND_INSUFFICIENT,
            "history_points": len(records),
            "reason": "Need at least two local performance dry-run points for trend comparison.",
            "latest_metrics": latest,
            "deltas": {},
        }
    current = records[-1]
    previous = records[-2]
    watched = [
        "total_transfer_bytes",
        "image_bytes",
        "inline_css_count",
        "internal_scripts_count",
        "html_bytes",
        "ttfb_ms",
        "script_tag_count",
        "global_p90_latency_ms",
        "global_p90_ttfb_ms",
    ]
    deltas = {key: metric_delta(current, previous, key) for key in watched}
    numeric_deltas = [value for value in deltas.values() if value is not None]
    if not numeric_deltas:
        trend = TREND_WATCH
        reason = "Comparable numeric history is limited; continue observation."
    else:
        regression = any(value > 0 for value in numeric_deltas if abs(value) >= 3)
        improving = any(value < 0 for value in numeric_deltas if abs(value) >= 3) and not regression
        stable = all(abs(value) < 3 for value in numeric_deltas)
        if regression:
            trend = TREND_REGRESSION
            reason = "At least one watched performance metric increased versus previous run."
        elif improving:
            trend = TREND_IMPROVING
            reason = "Watched performance metrics are decreasing or stable versus previous run."
        elif stable:
            trend = TREND_STABLE
            reason = "Watched performance metrics are broadly stable."
        else:
            trend = TREND_WATCH
            reason = "Mixed performance movement; keep collecting snapshots."
    return {
        "trend": trend,
        "history_points": len(records),
        "reason": reason,
        "latest_metrics": current,
        "previous_metrics": previous,
        "deltas": deltas,
    }


def recommendations(metrics: Dict[str, Any]) -> List[Dict[str, Any]]:
    recs = [
        {
            "recommendation_id": "performance:repeat-measurement",
            "category": LOW,
            "title": "Repeat local performance measurement and store trend history.",
            "reason": "A single checker finding is not enough for apply decisions.",
            "apply_status": APPLY_STATUS,
            "live_apply": False,
        },
        {
            "recommendation_id": "performance:trend-report",
            "category": LOW,
            "title": "Update concrete performance trend reports.",
            "reason": "Trend data lets the bot distinguish persistent regression from one-off findings.",
            "apply_status": APPLY_STATUS,
            "live_apply": False,
        },
        {
            "recommendation_id": "performance:known-issue-watch",
            "category": LOW,
            "title": "Keep SOC/schema known issue separate from performance apply decisions.",
            "reason": "Schema health remains HIGH-risk manual review and should not trigger performance changes.",
            "apply_status": APPLY_STATUS,
            "live_apply": False,
        },
    ]
    medium_specs = [
        ("performance:image-compression-review", "Prepare image compression and responsive image review.", metrics.get("image_bytes")),
        ("performance:lazyload-review", "Review lazy-loading coverage for non-lazy images.", metrics.get("lazy_image_count")),
        ("performance:inline-css-reduction", "Prepare inline CSS reduction owner review.", metrics.get("inline_css_count")),
        ("performance:script-defer-review", "Prepare script defer/lazy-load owner review.", metrics.get("script_tag_count")),
        ("performance:cache-expires-review", "Prepare cache/expires header owner review.", metrics.get("cache_control")),
        ("performance:html-size-reduction", "Prepare HTML payload reduction owner review.", metrics.get("html_bytes")),
    ]
    for rec_id, title, evidence in medium_specs:
        recs.append({
            "recommendation_id": rec_id,
            "category": MEDIUM,
            "title": title,
            "reason": f"Evidence: {redact_text(evidence)}",
            "owner_review_required": True,
            "apply_status": APPLY_STATUS,
            "live_apply": False,
        })
    high_specs = [
        ("performance:no-fse-auto-edit", "Do not automatically edit FSE/Post/Page content."),
        ("performance:no-theme-plugin-auto-edit", "Do not automatically edit Theme or Plugin code."),
        ("performance:no-db-performance-write", "Do not automatically write database performance settings."),
        ("performance:no-htaccess-auto-change", "Do not automatically change .htaccess."),
        ("performance:no-cdn-rule-auto-change", "Do not automatically change CDN/security rules."),
        ("performance:no-nginx-auto-change", "Do not automatically change Nginx configuration."),
        ("performance:no-url-rewrite-auto-change", "Do not automatically change redirects or URL rewrites."),
    ]
    for rec_id, title in high_specs:
        recs.append({
            "recommendation_id": rec_id,
            "category": HIGH,
            "title": title,
            "reason": "This could alter production behavior and requires explicit Owner review.",
            "owner_review_required": True,
            "apply_status": APPLY_STATUS,
            "live_apply": False,
        })
    return recs


def dryrun_images(metrics: Dict[str, Any]) -> Dict[str, Any]:
    image_count = to_int(metrics.get("image_count")) or 0
    lazy_count = to_int(metrics.get("lazy_image_count")) or 0
    return {
        "gate": "images",
        "risk": MEDIUM,
        "dryrun_status": "DRY_RUN_REVIEW_READY",
        "would_change": False,
        "checks": {
            "image_bytes": metrics.get("image_bytes"),
            "image_kb_reported": metrics.get("image_kb_reported"),
            "image_count": image_count,
            "lazy_image_count": lazy_count,
            "non_lazy_image_estimate": max(0, image_count - lazy_count),
            "webp_hint_count": metrics.get("webp_hint_count"),
        },
        "optimization_plan": [
            "Inventory largest visual assets manually from page source or media library.",
            "Prioritize hero, cover-art, shop, player, and radio visuals.",
            "Prepare WebP/AVIF and responsive size review without uploading files.",
            "Confirm lazy-loading remains active for below-fold images.",
        ],
        "blocked_actions": ["image rewrite", "upload optimized files", "media library changes"],
    }


def dryrun_inline_css(metrics: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "gate": "inline-css",
        "risk": MEDIUM,
        "dryrun_status": "DRY_RUN_REVIEW_READY",
        "would_change": False,
        "checks": {
            "inline_css_count": metrics.get("inline_css_count"),
            "stylesheet_count": metrics.get("stylesheet_count"),
            "suspected_sources": ["WordPress blocks", "FSE templates", "page builder/plugin output"],
        },
        "optimization_plan": [
            "Identify repeated inline style blocks in read-only HTML snapshots.",
            "Group candidates by likely source before any owner-approved edit.",
            "Prefer plugin/theme setting review over code edits when possible.",
        ],
        "blocked_actions": ["FSE edit", "theme code edit", "plugin code edit"],
    }


def dryrun_scripts(metrics: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "gate": "scripts",
        "risk": MEDIUM,
        "dryrun_status": "DRY_RUN_REVIEW_READY",
        "would_change": False,
        "checks": {
            "internal_scripts_count_external": metrics.get("internal_scripts_count"),
            "script_tag_count_sentinel": metrics.get("script_tag_count"),
            "large_inline_script_count": metrics.get("large_inline_script_count"),
            "external_resource_host_count": metrics.get("external_resource_host_count"),
        },
        "optimization_plan": [
            "Create script inventory grouped by source and criticality.",
            "Review defer/delay candidates only after visual/player behavior checks.",
            "Keep radio/player/shop scripts out of automatic modification.",
        ],
        "blocked_actions": ["script rewrite", "theme/plugin edit", "player code change"],
    }


def dryrun_cache_expires(metrics: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "gate": "cache-expires",
        "risk": MEDIUM,
        "dryrun_status": "DRY_RUN_REVIEW_READY",
        "would_change": False,
        "checks": {
            "cache_control": metrics.get("cache_control"),
            "cf_cache_status": metrics.get("cf_cache_status"),
            "expires_tag_missing": metrics.get("expires_tag_missing"),
            "global_success_rate_percent": metrics.get("global_success_rate_percent"),
            "global_p90_latency_ms": metrics.get("global_p90_latency_ms"),
            "global_p90_ttfb_ms": metrics.get("global_p90_ttfb_ms"),
        },
        "optimization_plan": [
            "Compare cache headers across repeated read-only runs.",
            "Prepare owner review for cache/expires policy only if warnings persist.",
            "Do not infer WAF/security rules from cache or latency findings.",
        ],
        "blocked_actions": ["cache purge", "CDN rule change", "Nginx change", ".htaccess change"],
    }


def dryrun_html_size(metrics: Dict[str, Any]) -> Dict[str, Any]:
    total = to_number(metrics.get("total_transfer_bytes")) or 0
    image = to_number(metrics.get("image_bytes")) or 0
    html = to_number(metrics.get("html_bytes")) or 0
    return {
        "gate": "html-size",
        "risk": MEDIUM,
        "dryrun_status": "DRY_RUN_REVIEW_READY",
        "would_change": False,
        "checks": {
            "html_bytes": metrics.get("html_bytes"),
            "total_transfer_bytes": metrics.get("total_transfer_bytes"),
            "image_share_percent_estimate": round((image / total) * 100, 2) if total else None,
            "html_share_percent_estimate": round((html / total) * 100, 2) if total else None,
            "script_tag_count": metrics.get("script_tag_count"),
            "inline_css_count": metrics.get("inline_css_count"),
        },
        "optimization_plan": [
            "Split payload drivers into image, inline CSS, scripts, and generated HTML.",
            "Keep WordPress editor/FSE payload reductions manual because content output can change.",
            "Use repeated trend watch before prioritizing a payload reduction task.",
        ],
        "blocked_actions": ["FSE edit", "Post/Page edit", "DB update", "theme/plugin code edit"],
    }


DRYRUN_BUILDERS = {
    "images": dryrun_images,
    "inline-css": dryrun_inline_css,
    "scripts": dryrun_scripts,
    "cache-expires": dryrun_cache_expires,
    "html-size": dryrun_html_size,
}


def build_playbook(gate: str, result: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "name": f"performance-{gate}-dryrun",
        "purpose": f"Prepare concrete performance dry-run review for {gate}; no production changes.",
        "risk_level": MEDIUM,
        "owner_review_required": True,
        "triggers": ["external checker high-value performance signal", "trend regression", "Owner asks for review pack"],
        "inputs": [str(path) for path in INPUTS.values()],
        "allowed_actions": ["read local reports", "write trend state", "write reports", "write snapshots", "write audit", "prepare owner review"],
        "blocked_actions": [
            "live apply",
            "remote write",
            "DB write",
            "cache purge",
            "CDN rule change",
            "Nginx change",
            ".htaccess change",
            "FSE/Post/Page/Theme/Plugin edit",
        ],
        "checks": result.get("checks", {}),
        "healthchecks": ["before/after score compare if future owner-approved action exists", "public read-only HTML check", "cache header check"],
        "rollback_requirements": ["No rollback needed for dry-run; future MEDIUM actions need backup and Owner approval."],
        "output_reports": ["reports/latest/concrete-performance-dryrun.json", "reports/latest/concrete-performance-owner-review-pack.md"],
        "disable_conditions": ["breach=true", "forbidden command pattern", "secret-like output", "unexpected apply mode"],
    }


def aggregate_status(breach: bool, trend: str, input_status: Dict[str, str], dryruns: Dict[str, Any]) -> str:
    if breach:
        return STATUS_BLOCKED
    if trend == TREND_INSUFFICIENT:
        return STATUS_INSUFFICIENT
    if trend in {TREND_WATCH, TREND_REGRESSION}:
        return STATUS_WARNINGS
    if any(status not in {"ok", "missing"} for status in input_status.values()):
        return STATUS_WARNINGS
    if any(status == "missing" for status in input_status.values()):
        return STATUS_WARNINGS
    if not dryruns:
        return STATUS_WARNINGS
    return STATUS_OK


def build_base_report(action: str, selected_gate: Optional[str] = None) -> Dict[str, Any]:
    ts = timestamp_tag()
    inputs = load_inputs()
    metrics = collect_metrics(inputs)
    existing_state, _ = read_json(LATEST_JSON)
    existing_dryruns = (existing_state or {}).get("dryrun_results_by_gate") or {}
    history, _ = read_history(HISTORY_JSONL)
    trend_state, _ = read_json(STATE_TRENDS_JSON)
    trend = (trend_state or {}).get("trend", TREND_INSUFFICIENT)
    recs = recommendations(metrics)
    breach = False
    breach_reasons: List[str] = []
    if selected_gate and selected_gate not in DRYRUN_BUILDERS:
        breach = True
        breach_reasons.append(f"unknown dry-run gate: {selected_gate}")
    return {
        "schema_version": SCHEMA_VERSION,
        "timestamp": ts,
        "timestamp_utc": utc_now(),
        "action": action,
        "status": aggregate_status(breach, trend, inputs["status"], existing_dryruns),
        "breach": breach,
        "breach_reasons": breach_reasons,
        "live_apply": False,
        "emergency_stop_unchanged": True,
        "apply_status": APPLY_STATUS,
        "selected_gate": selected_gate,
        "input_status": inputs["status"],
        "missing_inputs": [name for name, status in inputs["status"].items() if status == "missing"],
        "metrics": metrics,
        "trend": trend,
        "history_points": len(history),
        "dryrun_results_by_gate": existing_dryruns,
        "dryrun_results_count": len(existing_dryruns),
        "recommendations": recs,
        "recommendation_count": len(recs),
        "recommendation_categories": dict(Counter(item["category"] for item in recs)),
        "owner_review_pack_written": False,
        "bot_learning_updated": False,
        "recommended_next_step": "Continue trend watch and review MEDIUM packages manually; do not apply changes from this phase.",
    }


def render_report_md(report: Dict[str, Any]) -> str:
    metrics = report.get("metrics") or {}
    lines = [
        "# Concrete Performance Dry-run",
        "",
        f"- Status: `{report.get('status')}`",
        f"- Breach: `{report.get('breach')}`",
        f"- live_apply: `{report.get('live_apply')}`",
        f"- Emergency stop unchanged: `{report.get('emergency_stop_unchanged')}`",
        f"- Trend: `{report.get('trend')}`",
        f"- Recommendations: `{report.get('recommendation_count')}`",
        "",
        "## Current Metrics",
        "",
    ]
    for key in [
        "total_transfer_bytes",
        "image_bytes",
        "inline_css_count",
        "internal_scripts_count",
        "html_bytes",
        "ttfb_ms",
        "script_tag_count",
        "stylesheet_count",
        "image_count",
        "lazy_image_count",
        "webp_hint_count",
        "cf_cache_status",
        "cache_control",
        "global_avg_latency_ms",
        "global_p90_latency_ms",
        "global_avg_ttfb_ms",
        "global_p90_ttfb_ms",
    ]:
        lines.append(f"- `{key}`: `{metrics.get(key)}`")
    lines.extend(["", "## Dry-run Packages", ""])
    dryruns = report.get("dryrun_results_by_gate") or {}
    if not dryruns:
        lines.append("- No package generated yet.")
    for gate, result in dryruns.items():
        lines.append(f"- `{gate}`: `{result.get('dryrun_status')}` risk=`{result.get('risk')}` would_change=`{result.get('would_change')}`")
    return "\n".join(lines) + "\n"


def render_trends_md(trends: Dict[str, Any]) -> str:
    lines = [
        "# Concrete Performance Trends",
        "",
        f"- Trend: `{trends.get('trend')}`",
        f"- History points: `{trends.get('history_points')}`",
        f"- Reason: {trends.get('reason')}",
        "",
        "## Deltas",
        "",
    ]
    for key, value in (trends.get("deltas") or {}).items():
        lines.append(f"- `{key}`: `{value}`")
    return "\n".join(lines) + "\n"


def render_owner_pack(report: Dict[str, Any]) -> str:
    lines = [
        "# Concrete Performance Owner Review Pack",
        "",
        "This pack is dry-run only. It does not authorize live apply, cache purge, remote writes, or website changes.",
        "",
    ]
    for gate in GATES:
        result = (report.get("dryrun_results_by_gate") or {}).get(gate)
        if not result:
            continue
        lines.append(f"## {gate}")
        lines.append(f"- Risk: `{result.get('risk')}`")
        lines.append(f"- Status: `{result.get('dryrun_status')}`")
        lines.append(f"- Would change: `{result.get('would_change')}`")
        lines.append("- Checks:")
        for key, value in (result.get("checks") or {}).items():
            lines.append(f"  - `{key}`: `{value}`")
        lines.append("- Optimization plan:")
        for item in result.get("optimization_plan") or []:
            lines.append(f"  - {item}")
        lines.append("- Blocked actions:")
        for item in result.get("blocked_actions") or []:
            lines.append(f"  - {item}")
        lines.append("")
    return "\n".join(lines)


def append_markdown_section(path: Path, title: str, body: str) -> None:
    if not path.exists():
        return
    text = path.read_text(encoding="utf-8")
    marker = f"<!-- sentinel:{title.lower().replace(' ', '-')} -->"
    block = f"\n{marker}\n## {title}\n\n{body.rstrip()}\n"
    if marker in text:
        text = text.split(marker, 1)[0].rstrip() + block
    else:
        text = text.rstrip() + "\n" + block
    write_text_atomic(path, text)


def write_report(report: Dict[str, Any], write_owner_pack: bool = False, write_playbooks: bool = True) -> None:
    ts = str(report.get("timestamp") or timestamp_tag())
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, render_report_md(report))
    write_json_atomic(LATEST_JSON, report)
    write_json_atomic(SNAPSHOT_DIR / f"concrete-performance-dryrun-{ts}.json", report)
    if write_owner_pack:
        write_text_atomic(OWNER_PACK_MD, render_owner_pack(report))
    if write_playbooks:
        for gate, result in (report.get("dryrun_results_by_gate") or {}).items():
            if gate in PLAYBOOKS:
                write_json_atomic(PLAYBOOKS[gate], build_playbook(gate, result))
    append_jsonl(AUDIT_JSONL, [{
        "timestamp_utc": report.get("timestamp_utc"),
        "action": report.get("action"),
        "status": report.get("status"),
        "trend": report.get("trend"),
        "selected_gate": report.get("selected_gate"),
        "dryrun_results_count": report.get("dryrun_results_count"),
        "recommendation_count": report.get("recommendation_count"),
        "breach": report.get("breach"),
        "live_apply": report.get("live_apply"),
    }])


def update_bot_learning(report: Dict[str, Any], trends: Optional[Dict[str, Any]] = None) -> None:
    metrics = report.get("metrics") or {}
    trends = trends or {}
    learning = {
        "timestamp_utc": report.get("timestamp_utc"),
        "status": report.get("status"),
        "trend": report.get("trend"),
        "metrics": {
            "total_transfer_bytes": metrics.get("total_transfer_bytes"),
            "image_bytes": metrics.get("image_bytes"),
            "inline_css_count": metrics.get("inline_css_count"),
            "internal_scripts_count": metrics.get("internal_scripts_count"),
            "html_bytes": metrics.get("html_bytes"),
            "cache_control": metrics.get("cache_control"),
            "cf_cache_status": metrics.get("cf_cache_status"),
            "global_p90_latency_ms": metrics.get("global_p90_latency_ms"),
            "global_p90_ttfb_ms": metrics.get("global_p90_ttfb_ms"),
        },
        "learning": {
            "do_not_apply_from_single_report": True,
            "performance_levers_are_real": ["images", "inline_css", "scripts", "html_size", "cache_expires"],
            "productive_output_changes_remain_medium": True,
            "bot_can_prepare_owner_review": True,
            "regression_can_block_future_automation": True,
            "no_live_apply_without_owner_gate": True,
        },
    }
    knowledge, _ = read_json(KNOWLEDGE_BASE_JSON)
    knowledge = knowledge or {}
    knowledge["concrete_performance_dryrun"] = learning
    write_json_atomic(KNOWLEDGE_BASE_JSON, knowledge)
    append_jsonl(OBSERVATIONS_JSONL, [{
        "timestamp_utc": report.get("timestamp_utc"),
        "observation_id": "concrete-performance-dryrun-watch",
        "area": "Performance",
        "risk_level": MEDIUM,
        "confidence_score": 0.82,
        "symptoms": ["large_transfer", "image_payload", "inline_css", "script_count", "html_size", "expires_missing"],
        "hypothesis": "Performance optimization candidates are real but require trend confirmation and Owner approval before changing output.",
        "evidence": learning.get("metrics"),
        "allowed_bot_reaction": ["trend watch", "report", "owner review pack", "playbook"],
        "forbidden_bot_reaction": ["live apply", "cache purge", "remote write", "template/code edit"],
    }])
    patterns, _ = read_json(PATTERNS_JSON)
    patterns = patterns or {}
    patterns["concrete_performance_dryrun"] = {
        "timestamp_utc": report.get("timestamp_utc"),
        "trend": report.get("trend"),
        "history_points": report.get("history_points"),
        "high_value_metrics_present": True,
        "dryrun_gates": sorted((report.get("dryrun_results_by_gate") or {}).keys()),
        "trend_deltas": trends.get("deltas") or {},
    }
    write_json_atomic(PATTERNS_JSON, patterns)
    rules, _ = read_json(ACTION_RULES_JSON)
    rules = rules or {}
    rules["concrete_performance_dryrun"] = {
        "low_auto_allowed": ["measure again", "write trend", "write report", "write draft actions", "watch known issues"],
        "medium_owner_approval": ["image optimization review", "inline CSS reduction", "script defer review", "cache/expires review", "HTML reduction"],
        "high_manual_review": ["FSE/Post/Page edit", "Theme/Plugin code edit", "DB update", ".htaccess change", "CDN rule change", "Nginx config"],
        "block_on": ["breach=true", "regression after future owner-approved action", "secret-like output", "forbidden command pattern"],
    }
    write_json_atomic(ACTION_RULES_JSON, rules)
    latest, _ = read_json(ADAPTIVE_LATEST_JSON)
    latest = latest or {}
    latest["concrete_performance_dryrun"] = {
        "status": report.get("status"),
        "trend": report.get("trend"),
        "recommendation_count": report.get("recommendation_count"),
        "dryrun_results_count": report.get("dryrun_results_count"),
        "breach": report.get("breach"),
    }
    write_json_atomic(ADAPTIVE_LATEST_JSON, latest)
    section = (
        f"- Status: `{report.get('status')}`\n"
        f"- Trend: `{report.get('trend')}`\n"
        f"- History points: `{report.get('history_points')}`\n"
        f"- Recommendation count: `{report.get('recommendation_count')}`\n"
        "- Learning: images, inline CSS, scripts, HTML size and cache/expires are real levers, but remain owner-gated.\n"
    )
    append_markdown_section(ADAPTIVE_REPORT_MD, "Concrete Performance Dry-run Learning", section)
    append_markdown_section(ADAPTIVE_RECOMMEND_MD, "Concrete Performance Dry-run Recommendations", render_recommendations_md(report))
    append_markdown_section(
        ADAPTIVE_CAPABILITY_MD,
        "Concrete Performance Dry-run Capability",
        "- `performance_trend_watch`: `True`\n- `performance_owner_review_pack`: `True`\n- `performance_live_apply`: `False`\n",
    )


def render_recommendations_md(report: Dict[str, Any]) -> str:
    lines = ["# Concrete Performance Dry-run Recommendations", ""]
    for item in report.get("recommendations", []):
        lines.append(f"- `{item.get('category')}` `{item.get('recommendation_id')}`: {item.get('title')}")
    return "\n".join(lines) + "\n"


def collect_action() -> Dict[str, Any]:
    report = build_base_report("collect")
    report["bot_learning_updated"] = True
    update_bot_learning(report)
    write_report(report, write_playbooks=False)
    return report


def trend_watch_action() -> Tuple[Dict[str, Any], Dict[str, Any]]:
    report = build_base_report("trend-watch")
    metrics = report["metrics"]
    append_jsonl(HISTORY_JSONL, [metrics])
    history, _ = read_history(HISTORY_JSONL)
    trends = compare_history(history)
    report["trend"] = trends["trend"]
    report["history_points"] = trends["history_points"]
    report["status"] = aggregate_status(report["breach"], report["trend"], report["input_status"], report["dryrun_results_by_gate"])
    write_json_atomic(STATE_TRENDS_JSON, trends)
    write_json_atomic(TRENDS_JSON, trends)
    write_text_atomic(TRENDS_MD, render_trends_md(trends))
    report["bot_learning_updated"] = True
    update_bot_learning(report, trends)
    write_report(report, write_playbooks=False)
    return report, trends


def dryrun_action(gate: str) -> Dict[str, Any]:
    report = build_base_report("dry-run", selected_gate=gate)
    if report["breach"]:
        write_report(report, write_playbooks=False)
        return report
    result = DRYRUN_BUILDERS[gate](report["metrics"])
    dryruns = dict(report.get("dryrun_results_by_gate") or {})
    dryruns[gate] = result
    report["dryrun_results_by_gate"] = dryruns
    report["dryrun_results_count"] = len(dryruns)
    report["status"] = aggregate_status(report["breach"], report["trend"], report["input_status"], dryruns)
    report["bot_learning_updated"] = True
    update_bot_learning(report)
    write_report(report, write_playbooks=True)
    return report


def owner_review_pack_action() -> Dict[str, Any]:
    report = build_base_report("owner-review-pack")
    dryruns = dict(report.get("dryrun_results_by_gate") or {})
    for gate in GATES:
        dryruns.setdefault(gate, DRYRUN_BUILDERS[gate](report["metrics"]))
    report["dryrun_results_by_gate"] = dryruns
    report["dryrun_results_count"] = len(dryruns)
    report["owner_review_pack_written"] = True
    report["status"] = aggregate_status(report["breach"], report["trend"], report["input_status"], dryruns)
    report["bot_learning_updated"] = True
    update_bot_learning(report)
    write_report(report, write_owner_pack=True, write_playbooks=True)
    return report


def print_status() -> None:
    data, status = read_json(LATEST_JSON)
    if not data:
        print(f"status=not_available input_status={status}")
        return
    print(f"status={data.get('status')}")
    print(f"trend={data.get('trend')}")
    print(f"history_points={data.get('history_points')}")
    print(f"recommendation_count={data.get('recommendation_count')}")
    print(f"dryrun_results_count={data.get('dryrun_results_count')}")
    print(f"breach={data.get('breach')}")
    print(f"live_apply={data.get('live_apply')}")
    print(f"emergency_stop_unchanged={data.get('emergency_stop_unchanged')}")
    metrics = data.get("metrics") or {}
    for key in ("total_transfer_bytes", "image_bytes", "inline_css_count", "internal_scripts_count", "html_bytes"):
        print(f"{key}={metrics.get(key)}")


def print_summary(report: Dict[str, Any]) -> None:
    print(f"status={report.get('status')}")
    print(f"action={report.get('action')}")
    print(f"trend={report.get('trend')}")
    print(f"selected_gate={report.get('selected_gate') or '-'}")
    print(f"dryrun_results_count={report.get('dryrun_results_count')}")
    print(f"recommendation_count={report.get('recommendation_count')}")
    print(f"breach={report.get('breach')}")
    print(f"live_apply={report.get('live_apply')}")
    print(f"emergency_stop_unchanged={report.get('emergency_stop_unchanged')}")


def run_self_test() -> int:
    parser = build_parser()
    if "--apply" in parser.format_help():
        raise AssertionError("apply mode exposed")
    missing, st = read_json(PROJECT_DIR / "reports/latest/definitely-missing-performance-input.json")
    if missing is not None or st != "missing":
        raise AssertionError("optional missing input not handled")
    one = compare_history([{"total_transfer_bytes": 1000}])
    if one["trend"] != TREND_INSUFFICIENT:
        raise AssertionError("single point trend should be insufficient")
    two = compare_history([{"total_transfer_bytes": 1000}, {"total_transfer_bytes": 1100}])
    if two["trend"] != TREND_REGRESSION:
        raise AssertionError("regression trend not detected")
    report = build_base_report("self-test", selected_gate="unknown")
    if not report["breach"]:
        raise AssertionError("unknown gate not blocked")
    sample = dryrun_images({"image_count": 3, "lazy_image_count": 2, "image_bytes": 2048})
    if sample["risk"] != MEDIUM or sample["would_change"] is not False:
        raise AssertionError("risk classification failed")
    if "abcdef" in redact_text("password=abcdef12345"):
        raise AssertionError("secret redaction failed")
    source = Path(__file__).read_text(encoding="utf-8")
    for token in (
        "sub" + "process",
        "os" + "." + "system",
        "sftp" + "." + "put",
        "sftp" + "." + "remove",
        "sftp" + "." + "rename",
        "rm " + "-rf",
    ):
        if token in source:
            raise AssertionError(f"forbidden implementation token found: {token}")
    for path in (
        REPORT_JSON,
        REPORT_MD,
        OWNER_PACK_MD,
        TRENDS_JSON,
        LATEST_JSON,
        STATE_TRENDS_JSON,
        HISTORY_JSONL,
        SNAPSHOT_DIR / "x.json",
        AUDIT_JSONL,
        PLAYBOOKS["images"],
    ):
        assert_allowed_write(path)
    json.dumps({"report": report, "sample": sample})
    print("self-test ok")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Concrete performance trend watch and dry-run packages.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--collect", action="store_true")
    group.add_argument("--trend-watch", action="store_true")
    group.add_argument("--dry-run", choices=GATES)
    group.add_argument("--owner-review-pack", action="store_true")
    group.add_argument("--status", action="store_true")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.self_test:
        return run_self_test()
    if args.status:
        print_status()
        return 0
    try:
        if args.collect:
            report = collect_action()
        elif args.trend_watch:
            report, _ = trend_watch_action()
        elif args.dry_run:
            report = dryrun_action(args.dry_run)
        elif args.owner_review_pack:
            report = owner_review_pack_action()
        else:
            parser.error("unreachable")
    except Exception as exc:  # noqa: BLE001
        failed = {
            "schema_version": SCHEMA_VERSION,
            "timestamp": timestamp_tag(),
            "timestamp_utc": utc_now(),
            "action": "failed",
            "status": STATUS_FAILED,
            "breach": True,
            "breach_reasons": [redact_text(exc)],
            "live_apply": False,
            "emergency_stop_unchanged": True,
            "apply_status": APPLY_STATUS,
        }
        try:
            write_json_atomic(REPORT_JSON, failed)
            write_text_atomic(REPORT_MD, render_report_md(failed))
            append_jsonl(AUDIT_JSONL, [failed])
        except Exception:
            pass
        print(f"status={STATUS_FAILED}")
        print("breach=True")
        print(f"error={redact_text(exc, max_len=300)}")
        return 1
    print_summary(report)
    return 0 if not report.get("breach") else 2


if __name__ == "__main__":
    sys.exit(main())
