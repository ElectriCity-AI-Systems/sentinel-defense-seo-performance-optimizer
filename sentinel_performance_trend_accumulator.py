#!/usr/bin/env python3
"""Performance Trend Accumulator (Phase 8.5).

Builds a read-only trend accumulation layer for concrete performance signals.
It writes only local reports, state, snapshots, audit logs, playbooks, and
review-only timer drafts. It has no apply mode and performs no live changes.
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

REPORT_JSON = PROJECT_DIR / "reports/latest/performance-trend-accumulator.json"
REPORT_MD = PROJECT_DIR / "reports/latest/performance-trend-accumulator.md"
PRIORITY_JSON = PROJECT_DIR / "reports/latest/performance-owner-review-priority.json"
PRIORITY_MD = PROJECT_DIR / "reports/latest/performance-owner-review-priority.md"
SNAPSHOT_DIR = PROJECT_DIR / "snapshots"
AUDIT_JSONL = PROJECT_DIR / "audit/performance-trend-accumulator.jsonl"

STATE_DIR = PROJECT_DIR / "state/performance-dryrun"
SOURCE_HISTORY_JSONL = STATE_DIR / "history.jsonl"
ACCUMULATOR_JSON = STATE_DIR / "accumulator.json"
TREND_DECISION_JSON = STATE_DIR / "trend_decision.json"

ADAPTIVE_DIR = PROJECT_DIR / "state/adaptive-learning"
KNOWLEDGE_BASE_JSON = ADAPTIVE_DIR / "knowledge_base.json"
OBSERVATIONS_JSONL = ADAPTIVE_DIR / "observations.jsonl"
PATTERNS_JSON = ADAPTIVE_DIR / "patterns.json"
ACTION_RULES_JSON = ADAPTIVE_DIR / "action_rules.json"
ADAPTIVE_LATEST_JSON = ADAPTIVE_DIR / "latest.json"
ADAPTIVE_REPORT_MD = PROJECT_DIR / "reports/latest/adaptive-learning-engine.md"
ADAPTIVE_RECOMMEND_MD = PROJECT_DIR / "reports/latest/adaptive-recommendations.md"
ADAPTIVE_CAPABILITY_MD = PROJECT_DIR / "reports/latest/adaptive-bot-capability-map.md"

PLAYBOOK_JSON = PROJECT_DIR / "playbooks/performance-trend-accumulator.playbook.json"
SERVICE_DRAFT = PROJECT_DIR / "deploy/systemd/sentinel-performance-trend-accumulator.service"
TIMER_DRAFT = PROJECT_DIR / "deploy/systemd/sentinel-performance-trend-accumulator.timer"
INSTALL_REVIEW_DRAFT = PROJECT_DIR / "deploy/systemd/install-sentinel-performance-trend-accumulator.review.sh"

INPUTS = {
    "concrete_dryrun": PROJECT_DIR / "reports/latest/concrete-performance-dryrun.json",
    "concrete_trends": PROJECT_DIR / "reports/latest/concrete-performance-trends.json",
    "source_history": SOURCE_HISTORY_JSONL,
    "source_latest": STATE_DIR / "latest.json",
    "source_trends": STATE_DIR / "trends.json",
    "low_risk_autonomy": PROJECT_DIR / "reports/latest/low-risk-autonomy.json",
    "global_checker": PROJECT_DIR / "reports/latest/global-checker-ingest.json",
    "external_seo_ingest": PROJECT_DIR / "reports/latest/external-seo-report-ingest.json",
}

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "snapshots",
    PROJECT_DIR / "audit",
    STATE_DIR,
    ADAPTIVE_DIR,
    PROJECT_DIR / "playbooks",
    PROJECT_DIR / "deploy/systemd",
)

ALLOWED_TIMER_DRAFTS = {SERVICE_DRAFT, TIMER_DRAFT, INSTALL_REVIEW_DRAFT}

STATUS_OK = "PERFORMANCE_TREND_ACCUMULATOR_OK"
STATUS_INSUFFICIENT = "PERFORMANCE_TREND_ACCUMULATOR_INSUFFICIENT_HISTORY"
STATUS_WATCH = "PERFORMANCE_TREND_ACCUMULATOR_WATCH"
STATUS_REGRESSION = "PERFORMANCE_TREND_ACCUMULATOR_REGRESSION"
STATUS_BLOCKED = "PERFORMANCE_TREND_ACCUMULATOR_BLOCKED_BY_SAFETY"
STATUS_FAILED = "PERFORMANCE_TREND_ACCUMULATOR_FAILED"

TREND_INSUFFICIENT = "INSUFFICIENT_HISTORY"
TREND_STABLE = "STABLE"
TREND_IMPROVING = "IMPROVING"
TREND_WATCH = "WATCH"
TREND_REGRESSION = "REGRESSION"

MEDIUM = "MEDIUM_REQUIRES_OWNER_APPROVAL"
APPLY_STATUS = "not_applied"
SCHEMA_VERSION = "performance-trend-accumulator-8.5"

TREND_FIELDS = (
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
    "global_p90_latency_ms",
    "global_p90_ttfb_ms",
)

MAIN_FIELDS = (
    "total_transfer_bytes",
    "image_bytes",
    "inline_css_count",
    "internal_scripts_count",
    "html_bytes",
    "ttfb_ms",
    "script_tag_count",
    "global_p90_latency_ms",
    "global_p90_ttfb_ms",
)

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
        raise ValueError(f"Refusing write outside allowed trend accumulator roots: {path}")
    if path.suffix.lower() in {".sh", ".bash", ".zsh", ".service", ".timer"} and path not in ALLOWED_TIMER_DRAFTS:
        raise ValueError(f"Refusing non-approved executable/timer draft output: {path}")
    if path.suffix.lower() in {".py", ".env", ".bin", ".run"}:
        raise ValueError(f"Refusing executable/config output: {path}")
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


def read_jsonl(path: Path) -> Tuple[List[Dict[str, Any]], str, int]:
    if not path.exists():
        return [], "missing", 0
    rows: List[Dict[str, Any]] = []
    bad = 0
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                bad += 1
                continue
            if isinstance(item, dict):
                rows.append(item)
            else:
                bad += 1
    except OSError:
        return rows, "read_error", bad
    return rows, "ok", bad


def to_float(value: Any) -> Optional[float]:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def number_or_none(value: Any) -> Optional[float]:
    number = to_float(value)
    if number is None:
        return None
    return round(number, 2)


def load_inputs() -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    status: Dict[str, str] = {}
    malformed_history = 0
    for name, path in INPUTS.items():
        if path.suffix == ".jsonl":
            rows, st, bad = read_jsonl(path)
            data[name] = rows
            status[name] = st
            malformed_history += bad
        else:
            item, st = read_json(path)
            data[name] = item or {}
            status[name] = st
    return {"data": data, "status": status, "malformed_history_lines": malformed_history}


def extract_metrics(inputs: Dict[str, Any]) -> Dict[str, Any]:
    data = inputs["data"]
    concrete = data.get("concrete_dryrun", {}) or {}
    metrics = concrete.get("metrics") or {}
    low = data.get("low_risk_autonomy", {}) or {}
    analysis = low.get("analysis") or {}
    global_metrics = (data.get("global_checker", {}) or {}).get("metrics") or {}
    result = {
        "timestamp_utc": utc_now(),
        "source": "performance-trend-accumulator",
        "total_transfer_bytes": number_or_none(metrics.get("total_transfer_bytes")),
        "image_bytes": number_or_none(metrics.get("image_bytes")),
        "inline_css_count": number_or_none(metrics.get("inline_css_count")),
        "internal_scripts_count": number_or_none(metrics.get("internal_scripts_count")),
        "html_bytes": number_or_none(metrics.get("html_bytes") or analysis.get("html_size_bytes")),
        "ttfb_ms": number_or_none(metrics.get("ttfb_ms") or analysis.get("ttfb_ms")),
        "script_tag_count": number_or_none(metrics.get("script_tag_count") or analysis.get("script_tag_count")),
        "stylesheet_count": number_or_none(metrics.get("stylesheet_count") or analysis.get("stylesheet_count")),
        "image_count": number_or_none(metrics.get("image_count") or analysis.get("image_count")),
        "lazy_image_count": number_or_none(metrics.get("lazy_image_count") or analysis.get("lazy_image_count")),
        "webp_hint_count": number_or_none(metrics.get("webp_hint_count") or analysis.get("webp_hint_count")),
        "global_p90_latency_ms": number_or_none(metrics.get("global_p90_latency_ms") or global_metrics.get("p90_latency_ms")),
        "global_p90_ttfb_ms": number_or_none(metrics.get("global_p90_ttfb_ms") or global_metrics.get("p90_ttfb_ms")),
        "cache_control": metrics.get("cache_control") or (analysis.get("headers_subset") or {}).get("Cache-Control"),
        "cf_cache_status": metrics.get("cf_cache_status") or (analysis.get("headers_subset") or {}).get("Cf-Cache-Status"),
        "live_apply": False,
        "apply_status": APPLY_STATUS,
        "breach": False,
        "input_status": inputs["status"],
    }
    return result


def pct_change(previous: Any, current: Any) -> Optional[float]:
    prev = to_float(previous)
    cur = to_float(current)
    if prev is None or cur is None:
        return None
    if prev == 0:
        if cur == 0:
            return 0.0
        return None
    return round(((cur - prev) / abs(prev)) * 100.0, 2)


def values_stable(changes: Dict[str, Optional[float]], limit: float = 5.0) -> bool:
    usable = [value for value in changes.values() if value is not None]
    return bool(usable) and all(abs(value) <= limit for value in usable)


def analyze_history(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    clean = [row for row in records if isinstance(row, dict)]
    latest = clean[-1] if clean else {}
    if len(clean) < 3:
        return {
            "trend_status": TREND_INSUFFICIENT,
            "history_points": len(clean),
            "reason": "Need at least three accumulator history points.",
            "latest_metrics": latest,
            "field_changes_percent": {},
            "improved_main_fields": [],
            "watch_fields": [],
            "regression_fields": [],
            "breach": bool(latest.get("breach") or latest.get("live_apply") or latest.get("apply_status") not in {None, APPLY_STATUS}),
        }
    current = clean[-1]
    previous = clean[-2]
    changes = {field: pct_change(previous.get(field), current.get(field)) for field in TREND_FIELDS}
    main_changes = {field: changes.get(field) for field in MAIN_FIELDS}
    improved = [field for field, value in main_changes.items() if value is not None and value < -5.0]
    watch = [field for field, value in main_changes.items() if value is not None and value > 10.0]
    regress = [field for field, value in main_changes.items() if value is not None and value > 15.0]
    safety_breach = any(row.get("breach") for row in clean[-3:]) or any(row.get("live_apply") for row in clean[-3:])
    unsafe_apply = any(row.get("apply_status") not in {None, APPLY_STATUS} for row in clean[-3:])
    if safety_breach or unsafe_apply or len(regress) >= 3:
        trend = TREND_REGRESSION
        reason = "Regression or unsafe signal detected; block further automation and require review."
    elif len(watch) >= 2:
        trend = TREND_WATCH
        reason = "At least two main performance fields worsened by more than 10 percent."
    elif len(improved) >= 3:
        trend = TREND_IMPROVING
        reason = "At least three main performance fields improved by more than 5 percent."
    elif values_stable(main_changes, 5.0):
        trend = TREND_STABLE
        reason = "Main performance fields are within plus/minus 5 percent."
    else:
        trend = TREND_WATCH
        reason = "Mixed trend movement; continue read-only collection."
    return {
        "trend_status": trend,
        "history_points": len(clean),
        "reason": reason,
        "latest_metrics": current,
        "previous_metrics": previous,
        "field_changes_percent": changes,
        "improved_main_fields": improved,
        "watch_fields": watch,
        "regression_fields": regress,
        "breach": bool(safety_breach or unsafe_apply),
    }


def status_for_trend(trend_status: str, breach: bool) -> str:
    if breach:
        return STATUS_BLOCKED
    if trend_status == TREND_REGRESSION:
        return STATUS_REGRESSION
    if trend_status == TREND_WATCH:
        return STATUS_WATCH
    if trend_status == TREND_INSUFFICIENT:
        return STATUS_INSUFFICIENT
    return STATUS_OK


def priority_items(metrics: Dict[str, Any], trend: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [
        {
            "priority": 1,
            "priority_id": "images",
            "title": "Bilder reduzieren/komprimieren",
            "risk": MEDIUM,
            "evidence": {
                "image_bytes": metrics.get("image_bytes"),
                "image_count": metrics.get("image_count"),
                "lazy_image_count": metrics.get("lazy_image_count"),
                "webp_hint_count": metrics.get("webp_hint_count"),
            },
            "owner_action": "Manuell groesste Bilder identifizieren, Varianten pruefen, keine automatische Medienaenderung.",
        },
        {
            "priority": 2,
            "priority_id": "inline-css",
            "title": "Inline CSS reduzieren",
            "risk": MEDIUM,
            "evidence": {"inline_css_count": metrics.get("inline_css_count")},
            "owner_action": "Wiederholte Inline-Style-Bloecke gruppieren und Quelle manuell pruefen.",
        },
        {
            "priority": 3,
            "priority_id": "scripts",
            "title": "Scripts pruefen/defer/lazy-load",
            "risk": MEDIUM,
            "evidence": {
                "internal_scripts_count": metrics.get("internal_scripts_count"),
                "script_tag_count": metrics.get("script_tag_count"),
            },
            "owner_action": "Script-Inventar nach kritisch/nicht-kritisch sortieren; Player/Shop/Radio nicht automatisch aendern.",
        },
        {
            "priority": 4,
            "priority_id": "cache-expires",
            "title": "Cache/Expires Header Review",
            "risk": MEDIUM,
            "evidence": {
                "cache_control": metrics.get("cache_control"),
                "cf_cache_status": metrics.get("cf_cache_status"),
                "global_p90_latency_ms": metrics.get("global_p90_latency_ms"),
                "global_p90_ttfb_ms": metrics.get("global_p90_ttfb_ms"),
            },
            "owner_action": "Header ueber mehrere Laeufe vergleichen; keine CDN/Nginx/.htaccess-Aenderung aus diesem Modul.",
        },
        {
            "priority": 5,
            "priority_id": "html-size",
            "title": "HTML-Groesse reduzieren",
            "risk": MEDIUM,
            "evidence": {
                "html_bytes": metrics.get("html_bytes"),
                "total_transfer_bytes": metrics.get("total_transfer_bytes"),
            },
            "owner_action": "Payload-Treiber trennen; FSE/Post/Page-Aenderungen bleiben manuelle Review.",
        },
    ]


def build_report(action: str, trend: Optional[Dict[str, Any]] = None, priorities: Optional[List[Dict[str, Any]]] = None, timer_written: bool = False) -> Dict[str, Any]:
    inputs = load_inputs()
    source_rows = inputs["data"].get("source_history") if isinstance(inputs["data"].get("source_history"), list) else []
    accumulator, _ = read_json(ACCUMULATOR_JSON)
    history = (accumulator or {}).get("history") or []
    metrics = extract_metrics(inputs)
    trend = trend or analyze_history(history)
    if priorities is None:
        priority_doc, _ = read_json(PRIORITY_JSON)
        if priority_doc and isinstance(priority_doc.get("priorities"), list):
            priorities = priority_doc.get("priorities")
    breach = bool(trend.get("breach") or metrics.get("live_apply") or metrics.get("apply_status") != APPLY_STATUS)
    return {
        "schema_version": SCHEMA_VERSION,
        "timestamp": timestamp_tag(),
        "timestamp_utc": utc_now(),
        "action": action,
        "status": status_for_trend(trend.get("trend_status", TREND_INSUFFICIENT), breach),
        "trend_status": trend.get("trend_status", TREND_INSUFFICIENT),
        "history_points": trend.get("history_points", len(history)),
        "breach": breach,
        "breach_reasons": ["unsafe trend breach"] if breach else [],
        "live_apply": False,
        "emergency_stop_unchanged": True,
        "apply_status": APPLY_STATUS,
        "metrics": metrics,
        "trend_decision": trend,
        "priority_count": len(priorities or []),
        "owner_review_priorities": priorities or [],
        "source_history_points": len(source_rows),
        "malformed_history_lines": inputs.get("malformed_history_lines", 0),
        "input_status": inputs["status"],
        "timer_draft_written": timer_written,
        "recommended_owner_action": recommended_owner_action(trend.get("trend_status", TREND_INSUFFICIENT), breach),
    }


def recommended_owner_action(trend_status: str, breach: bool) -> str:
    if breach or trend_status == TREND_REGRESSION:
        return "Stop further automation, keep read-only checks only, and review regression before any owner-approved action."
    if trend_status == TREND_INSUFFICIENT:
        return "Collect more read-only performance trend points before prioritizing action."
    if trend_status == TREND_WATCH:
        return "Continue read-only observation and review owner priority pack; do not apply changes."
    if trend_status == TREND_IMPROVING:
        return "Trend is improving; continue observation and avoid unnecessary changes."
    return "Trend is stable; owner may review MEDIUM priorities, no apply from this module."


def render_report_md(report: Dict[str, Any]) -> str:
    metrics = report.get("metrics") or {}
    trend = report.get("trend_decision") or {}
    lines = [
        "# Performance Trend Accumulator",
        "",
        f"- Status: `{report.get('status')}`",
        f"- Trend: `{report.get('trend_status')}`",
        f"- History points: `{report.get('history_points')}`",
        f"- Breach: `{report.get('breach')}`",
        f"- live_apply: `{report.get('live_apply')}`",
        f"- Emergency stop unchanged: `{report.get('emergency_stop_unchanged')}`",
        f"- Recommended owner action: {report.get('recommended_owner_action')}",
        "",
        "## Latest Metrics",
        "",
    ]
    for field in TREND_FIELDS:
        lines.append(f"- `{field}`: `{metrics.get(field)}`")
    lines.extend(["", "## Trend Decision", "", f"- Reason: {trend.get('reason')}", ""])
    for field, value in (trend.get("field_changes_percent") or {}).items():
        lines.append(f"- `{field}`: `{value}` percent")
    return "\n".join(lines) + "\n"


def render_priority_md(data: Dict[str, Any]) -> str:
    lines = [
        "# Performance Owner Review Priority",
        "",
        f"- Priority count: `{data.get('priority_count')}`",
        f"- Breach: `{data.get('breach')}`",
        f"- live_apply: `{data.get('live_apply')}`",
        "",
    ]
    for item in data.get("priorities", []):
        lines.append(f"## {item.get('priority')}. {item.get('title')}")
        lines.append(f"- Risk: `{item.get('risk')}`")
        lines.append(f"- Owner action: {item.get('owner_action')}")
        lines.append("- Evidence:")
        for key, value in (item.get("evidence") or {}).items():
            lines.append(f"  - `{key}`: `{value}`")
        lines.append("")
    return "\n".join(lines)


def render_playbook() -> Dict[str, Any]:
    return {
        "name": "performance-trend-accumulator",
        "purpose": "Collect read-only performance trend points and prioritize MEDIUM owner-review actions.",
        "risk_level": "LOW_RISK_READ_ONLY_MONITORING",
        "owner_review_required_for_actions": True,
        "allowed_actions": ["read reports", "append local history", "analyze trends", "write reports", "write snapshots", "write audit", "write timer draft"],
        "blocked_actions": [
            "live apply",
            "DB write",
            "SFTP write",
            "cache purge",
            "CDN change",
            "Nginx change",
            ".htaccess change",
            "FSE/Post/Page/Theme/Plugin edit",
            "unit activation",
            "cron install",
        ],
        "trend_fields": list(TREND_FIELDS),
        "trend_logic": {
            "insufficient": "history_points < 3",
            "stable": "main values within plus/minus 5 percent",
            "improving": "at least 3 main values improve by more than 5 percent",
            "watch": "at least 2 main values worsen by more than 10 percent",
            "regression": "at least 3 main values worsen by more than 15 percent or unsafe signal appears",
        },
        "outputs": [str(REPORT_JSON), str(PRIORITY_JSON), str(TREND_DECISION_JSON)],
    }


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


def update_bot_learning(report: Dict[str, Any]) -> None:
    learning = {
        "timestamp_utc": report.get("timestamp_utc"),
        "status": report.get("status"),
        "trend_status": report.get("trend_status"),
        "history_points": report.get("history_points"),
        "learning": {
            "bot_may_collect_performance_trends": True,
            "single_measurement_is_not_apply_evidence": True,
            "regression_blocks_further_automation": True,
            "performance_output_changes_remain_medium": True,
            "owner_review_priorities_allowed": True,
            "no_live_change_without_owner_gate": True,
        },
    }
    knowledge, _ = read_json(KNOWLEDGE_BASE_JSON)
    knowledge = knowledge or {}
    knowledge["performance_trend_accumulator"] = learning
    write_json_atomic(KNOWLEDGE_BASE_JSON, knowledge)
    append_jsonl(OBSERVATIONS_JSONL, [{
        "timestamp_utc": report.get("timestamp_utc"),
        "observation_id": "performance-trend-accumulator",
        "area": "Performance",
        "risk_level": "LOW_RISK_AUTO_ALLOWED",
        "confidence_score": 0.84,
        "symptoms": list(TREND_FIELDS),
        "hypothesis": "Repeated read-only performance trend points are required before MEDIUM owner-review actions are prioritized.",
        "trend_status": report.get("trend_status"),
        "history_points": report.get("history_points"),
    }])
    patterns, _ = read_json(PATTERNS_JSON)
    patterns = patterns or {}
    patterns["performance_trend_accumulator"] = {
        "timestamp_utc": report.get("timestamp_utc"),
        "trend_status": report.get("trend_status"),
        "history_points": report.get("history_points"),
        "priority_count": report.get("priority_count"),
    }
    write_json_atomic(PATTERNS_JSON, patterns)
    rules, _ = read_json(ACTION_RULES_JSON)
    rules = rules or {}
    rules["performance_trend_accumulator"] = {
        "low_auto_allowed": ["collect trend", "analyze trend", "write report", "write owner priority draft", "write timer draft"],
        "medium_owner_approval": ["image compression", "inline CSS reduction", "script defer review", "cache/expires review", "HTML reduction"],
        "block_on": ["REGRESSION", "breach=true", "live_apply=true", "secret-like output"],
    }
    write_json_atomic(ACTION_RULES_JSON, rules)
    latest, _ = read_json(ADAPTIVE_LATEST_JSON)
    latest = latest or {}
    latest["performance_trend_accumulator"] = {
        "status": report.get("status"),
        "trend_status": report.get("trend_status"),
        "history_points": report.get("history_points"),
        "breach": report.get("breach"),
    }
    write_json_atomic(ADAPTIVE_LATEST_JSON, latest)
    section = (
        f"- Status: `{report.get('status')}`\n"
        f"- Trend: `{report.get('trend_status')}`\n"
        f"- History points: `{report.get('history_points')}`\n"
        "- Learning: repeated read-only measurements can prioritize review, but do not authorize apply.\n"
    )
    append_markdown_section(ADAPTIVE_REPORT_MD, "Performance Trend Accumulator Learning", section)
    append_markdown_section(
        ADAPTIVE_RECOMMEND_MD,
        "Performance Trend Accumulator Recommendations",
        "- Continue read-only trend collection.\n- Keep all output-changing optimizations as MEDIUM owner-review tasks.\n",
    )
    append_markdown_section(
        ADAPTIVE_CAPABILITY_MD,
        "Performance Trend Accumulator Capability",
        "- `performance_trend_collection`: `True`\n- `owner_priority_generation`: `True`\n- `performance_live_apply`: `False`\n",
    )


def write_common_outputs(report: Dict[str, Any]) -> None:
    ts = str(report.get("timestamp") or timestamp_tag())
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, render_report_md(report))
    write_json_atomic(SNAPSHOT_DIR / f"performance-trend-accumulator-{ts}.json", report)
    write_json_atomic(PLAYBOOK_JSON, render_playbook())
    append_jsonl(AUDIT_JSONL, [{
        "timestamp_utc": report.get("timestamp_utc"),
        "action": report.get("action"),
        "status": report.get("status"),
        "trend_status": report.get("trend_status"),
        "history_points": report.get("history_points"),
        "breach": report.get("breach"),
        "live_apply": report.get("live_apply"),
    }])
    update_bot_learning(report)


def collect_now() -> Dict[str, Any]:
    inputs = load_inputs()
    metrics = extract_metrics(inputs)
    accumulator, _ = read_json(ACCUMULATOR_JSON)
    history = (accumulator or {}).get("history") or []
    history.append(metrics)
    trend = analyze_history(history)
    accumulator_data = {
        "schema_version": SCHEMA_VERSION,
        "timestamp_utc": utc_now(),
        "history": history,
        "history_points": len(history),
        "latest_metrics": metrics,
        "malformed_history_lines": inputs.get("malformed_history_lines", 0),
        "source_input_status": inputs["status"],
        "live_apply": False,
        "apply_status": APPLY_STATUS,
        "breach": bool(trend.get("breach")),
    }
    write_json_atomic(ACCUMULATOR_JSON, accumulator_data)
    write_json_atomic(TREND_DECISION_JSON, trend)
    report = build_report("collect-now", trend=trend)
    write_common_outputs(report)
    return report


def analyze_trends() -> Dict[str, Any]:
    accumulator, _ = read_json(ACCUMULATOR_JSON)
    history = (accumulator or {}).get("history") or []
    trend = analyze_history(history)
    write_json_atomic(TREND_DECISION_JSON, trend)
    report = build_report("analyze-trends", trend=trend)
    write_common_outputs(report)
    return report


def owner_review_priority() -> Dict[str, Any]:
    accumulator, _ = read_json(ACCUMULATOR_JSON)
    history = (accumulator or {}).get("history") or []
    trend = analyze_history(history)
    metrics = trend.get("latest_metrics") or extract_metrics(load_inputs())
    priorities = priority_items(metrics, trend)
    priority_doc = {
        "schema_version": SCHEMA_VERSION,
        "timestamp_utc": utc_now(),
        "priority_count": len(priorities),
        "priorities": priorities,
        "risk": MEDIUM,
        "breach": False,
        "live_apply": False,
        "apply_status": APPLY_STATUS,
        "recommended_owner_action": "Review priorities manually; do not apply from this module.",
    }
    write_json_atomic(PRIORITY_JSON, priority_doc)
    write_text_atomic(PRIORITY_MD, render_priority_md(priority_doc))
    report = build_report("owner-review-priority", trend=trend, priorities=priorities)
    write_common_outputs(report)
    return report


def service_draft_text() -> str:
    return """[Unit]
Description=Sentinel Performance Trend Accumulator (read-only review draft)
After=network-online.target

[Service]
Type=oneshot
WorkingDirectory=/srv/sentinel-defense
ExecStart=/usr/bin/python3 /srv/sentinel-defense/sentinel_performance_trend_accumulator.py --collect-now
ExecStart=/usr/bin/python3 /srv/sentinel-defense/sentinel_performance_trend_accumulator.py --analyze-trends
"""


def timer_draft_text() -> str:
    return """[Unit]
Description=Sentinel Performance Trend Accumulator Timer (review draft)

[Timer]
OnBootSec=15min
OnUnitActiveSec=6h
Persistent=true

[Install]
WantedBy=timers.target
"""


def install_review_text() -> str:
    return """#!/bin/sh
# REVIEW ONLY - DO NOT RUN WITHOUT OWNER FINAL CONFIRMATION.
# This draft is read-only monitoring only.
# It does not enable live apply and does not change production systems.
# Inspect the service and timer draft files manually before any separate future owner decision.

cd /srv/sentinel-defense || exit 1
python3 sentinel_performance_trend_accumulator.py --collect-now
python3 sentinel_performance_trend_accumulator.py --analyze-trends
python3 sentinel_performance_trend_accumulator.py --status
"""


def draft_timer() -> Dict[str, Any]:
    write_text_atomic(SERVICE_DRAFT, service_draft_text())
    write_text_atomic(TIMER_DRAFT, timer_draft_text())
    write_text_atomic(INSTALL_REVIEW_DRAFT, install_review_text())
    report = build_report("draft-timer", timer_written=True)
    write_common_outputs(report)
    return report


def print_status() -> None:
    data, status = read_json(REPORT_JSON)
    if not data:
        print(f"status=not_available input_status={status}")
        return
    print(f"status={data.get('status')}")
    print(f"trend_status={data.get('trend_status')}")
    print(f"history_points={data.get('history_points')}")
    print(f"priority_count={data.get('priority_count')}")
    print(f"timer_draft_written={data.get('timer_draft_written')}")
    print(f"breach={data.get('breach')}")
    print(f"live_apply={data.get('live_apply')}")
    print(f"emergency_stop_unchanged={data.get('emergency_stop_unchanged')}")


def print_summary(report: Dict[str, Any]) -> None:
    print(f"status={report.get('status')}")
    print(f"action={report.get('action')}")
    print(f"trend_status={report.get('trend_status')}")
    print(f"history_points={report.get('history_points')}")
    print(f"priority_count={report.get('priority_count')}")
    print(f"timer_draft_written={report.get('timer_draft_written')}")
    print(f"breach={report.get('breach')}")
    print(f"live_apply={report.get('live_apply')}")
    print(f"emergency_stop_unchanged={report.get('emergency_stop_unchanged')}")


def run_self_test() -> int:
    parser = build_parser()
    if "--apply" in parser.format_help():
        raise AssertionError("apply mode exposed")
    one = analyze_history([{"total_transfer_bytes": 1000, "apply_status": APPLY_STATUS}])
    if one["trend_status"] != TREND_INSUFFICIENT:
        raise AssertionError("one point should be insufficient")
    stable = analyze_history([
        {"total_transfer_bytes": 1000, "image_bytes": 800, "inline_css_count": 100, "internal_scripts_count": 20, "html_bytes": 180, "apply_status": APPLY_STATUS},
        {"total_transfer_bytes": 1010, "image_bytes": 804, "inline_css_count": 101, "internal_scripts_count": 20, "html_bytes": 181, "apply_status": APPLY_STATUS},
        {"total_transfer_bytes": 1005, "image_bytes": 802, "inline_css_count": 99, "internal_scripts_count": 20, "html_bytes": 180, "apply_status": APPLY_STATUS},
    ])
    if stable["trend_status"] != TREND_STABLE:
        raise AssertionError("stable trend not detected")
    improving = analyze_history([
        {"total_transfer_bytes": 1000, "image_bytes": 800, "inline_css_count": 100, "internal_scripts_count": 30, "html_bytes": 200, "apply_status": APPLY_STATUS},
        {"total_transfer_bytes": 950, "image_bytes": 760, "inline_css_count": 95, "internal_scripts_count": 28, "html_bytes": 190, "apply_status": APPLY_STATUS},
        {"total_transfer_bytes": 850, "image_bytes": 650, "inline_css_count": 80, "internal_scripts_count": 24, "html_bytes": 170, "apply_status": APPLY_STATUS},
    ])
    if improving["trend_status"] != TREND_IMPROVING:
        raise AssertionError("improving trend not detected")
    watch = analyze_history([
        {"total_transfer_bytes": 1000, "image_bytes": 800, "inline_css_count": 100, "internal_scripts_count": 20, "html_bytes": 180, "apply_status": APPLY_STATUS},
        {"total_transfer_bytes": 1000, "image_bytes": 800, "inline_css_count": 100, "internal_scripts_count": 20, "html_bytes": 180, "apply_status": APPLY_STATUS},
        {"total_transfer_bytes": 1120, "image_bytes": 900, "inline_css_count": 100, "internal_scripts_count": 20, "html_bytes": 180, "apply_status": APPLY_STATUS},
    ])
    if watch["trend_status"] != TREND_WATCH:
        raise AssertionError("watch trend not detected")
    regression = analyze_history([
        {"total_transfer_bytes": 1000, "image_bytes": 800, "inline_css_count": 100, "internal_scripts_count": 20, "html_bytes": 180, "apply_status": APPLY_STATUS},
        {"total_transfer_bytes": 1000, "image_bytes": 800, "inline_css_count": 100, "internal_scripts_count": 20, "html_bytes": 180, "apply_status": APPLY_STATUS},
        {"total_transfer_bytes": 1200, "image_bytes": 960, "inline_css_count": 118, "internal_scripts_count": 24, "html_bytes": 180, "apply_status": APPLY_STATUS},
    ])
    if regression["trend_status"] != TREND_REGRESSION:
        raise AssertionError("regression trend not detected")
    rows, _, bad = read_jsonl(PROJECT_DIR / "missing-history.jsonl")
    if rows or bad:
        raise AssertionError("missing history should be empty")
    if "abcdef" in redact_text("api_key=abcdef12345"):
        raise AssertionError("secret redaction failed")
    for content in (service_draft_text(), timer_draft_text(), install_review_text()):
        if FORBIDDEN_COMMAND_RE.search(content):
            raise AssertionError("timer draft contains forbidden command")
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
        PRIORITY_JSON,
        PRIORITY_MD,
        ACCUMULATOR_JSON,
        TREND_DECISION_JSON,
        SNAPSHOT_DIR / "x.json",
        AUDIT_JSONL,
        PLAYBOOK_JSON,
        SERVICE_DRAFT,
        TIMER_DRAFT,
        INSTALL_REVIEW_DRAFT,
    ):
        assert_allowed_write(path)
    json.dumps({"stable": stable, "regression": regression})
    print("self-test ok")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read-only performance trend accumulator.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--collect-now", action="store_true")
    group.add_argument("--analyze-trends", action="store_true")
    group.add_argument("--owner-review-priority", action="store_true")
    group.add_argument("--status", action="store_true")
    group.add_argument("--draft-timer", action="store_true")
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
        if args.collect_now:
            report = collect_now()
        elif args.analyze_trends:
            report = analyze_trends()
        elif args.owner_review_priority:
            report = owner_review_priority()
        elif args.draft_timer:
            report = draft_timer()
        else:
            parser.error("unreachable")
    except Exception as exc:  # noqa: BLE001
        failed = {
            "schema_version": SCHEMA_VERSION,
            "timestamp": timestamp_tag(),
            "timestamp_utc": utc_now(),
            "action": "failed",
            "status": STATUS_FAILED,
            "trend_status": TREND_REGRESSION,
            "history_points": 0,
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
