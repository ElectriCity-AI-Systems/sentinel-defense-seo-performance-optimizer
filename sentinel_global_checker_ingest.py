#!/usr/bin/env python3
"""Global Performance Checker Ingestion (Phase 8.2).

Ingests a local CSV export of global checker results, derives read-only
performance learning, updates adaptive learning state, and writes reports,
snapshots, audit, and a playbook. It performs no live changes and has no apply
mode.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


PROJECT_DIR = Path("/srv/sentinel-defense")

REPORT_JSON = PROJECT_DIR / "reports/latest/global-checker-ingest.json"
REPORT_MD = PROJECT_DIR / "reports/latest/global-checker-ingest.md"
RECOMMEND_JSON = PROJECT_DIR / "reports/latest/global-checker-recommendations.json"
RECOMMEND_MD = PROJECT_DIR / "reports/latest/global-checker-recommendations.md"
SNAPSHOT_DIR = PROJECT_DIR / "snapshots"
AUDIT_JSONL = PROJECT_DIR / "audit/global-checker-ingest.jsonl"
PLAYBOOK_JSON = PROJECT_DIR / "playbooks/global-performance-checker-ingest.playbook.json"

STATE_DIR = PROJECT_DIR / "state/adaptive-learning"
KNOWLEDGE_BASE_JSON = STATE_DIR / "knowledge_base.json"
OBSERVATIONS_JSONL = STATE_DIR / "observations.jsonl"
PATTERNS_JSON = STATE_DIR / "patterns.json"
LATEST_JSON = STATE_DIR / "latest.json"

ADAPTIVE_REPORT_JSON = PROJECT_DIR / "reports/latest/adaptive-learning-engine.json"
ADAPTIVE_REPORT_MD = PROJECT_DIR / "reports/latest/adaptive-learning-engine.md"
ADAPTIVE_RECOMMEND_JSON = PROJECT_DIR / "reports/latest/adaptive-recommendations.json"
ADAPTIVE_RECOMMEND_MD = PROJECT_DIR / "reports/latest/adaptive-recommendations.md"
ADAPTIVE_CAPABILITY_MD = PROJECT_DIR / "reports/latest/adaptive-bot-capability-map.md"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "snapshots",
    PROJECT_DIR / "audit",
    STATE_DIR,
    PROJECT_DIR / "playbooks",
)

REQUIRED_COLUMNS = (
    "Region Code",
    "Location",
    "Provider",
    "Latency (ms)",
    "Status",
    "DNS (ms)",
    "Connect (ms)",
    "TLS (ms)",
    "TTFB (ms)",
    "Transfer (ms)",
)

NUMERIC_COLUMNS = (
    "Latency (ms)",
    "DNS (ms)",
    "Connect (ms)",
    "TLS (ms)",
    "TTFB (ms)",
    "Transfer (ms)",
)

STATUS_OK = "GLOBAL_CHECKER_INGEST_OK"
STATUS_WARNINGS = "GLOBAL_CHECKER_INGEST_WARNINGS"
STATUS_FAILED = "GLOBAL_CHECKER_INGEST_FAILED"
STATUS_BLOCKED = "GLOBAL_CHECKER_INGEST_BLOCKED_BY_SAFETY"

LOW = "LOW_RISK_AUTO_ALLOWED"
MEDIUM = "MEDIUM_REQUIRES_OWNER_APPROVAL"
HIGH = "HIGH_RISK_MANUAL_REVIEW_REQUIRED"
APPLY_STATUS = "not_applied"
SCHEMA_VERSION = "global-checker-ingest-8.2"

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
        raise ValueError(f"Refusing write outside allowed global checker roots: {path}")
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


def safe_number(value: Any) -> Tuple[Optional[float], bool]:
    text = "" if value is None else str(value).strip()
    if text == "":
        return None, False
    text = text.replace(",", ".")
    try:
        return float(text), True
    except ValueError:
        return None, False


def percentile(values: List[float], p: float) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = int((p / 100.0) * len(ordered) + 0.999999)
    index = min(max(rank - 1, 0), len(ordered) - 1)
    return ordered[index]


def average(values: List[float]) -> Optional[float]:
    if not values:
        return None
    return sum(values) / len(values)


def median(values: List[float]) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2


def round_or_none(value: Optional[float], digits: int = 2) -> Optional[float]:
    if value is None:
        return None
    return round(value, digits)


def parse_csv_text(text: str) -> Dict[str, Any]:
    reader = csv.DictReader(io.StringIO(text))
    fieldnames = [name.strip() for name in (reader.fieldnames or [])]
    missing = [column for column in REQUIRED_COLUMNS if column not in fieldnames]
    rows: List[Dict[str, Any]] = []
    row_errors: List[Dict[str, Any]] = []
    if missing:
        return {"rows": rows, "missing_columns": missing, "row_errors": [{"row": 0, "error": "missing_required_columns"}]}
    for index, row in enumerate(reader, start=1):
        normalized = {key.strip(): (value.strip() if isinstance(value, str) else value) for key, value in row.items() if key is not None}
        parsed: Dict[str, Any] = {
            "region_code": normalized.get("Region Code", ""),
            "location": normalized.get("Location", ""),
            "provider": normalized.get("Provider", ""),
            "status": normalized.get("Status", ""),
            "numeric": {},
            "missing_numeric_fields": [],
            "invalid_numeric_fields": [],
        }
        for column in NUMERIC_COLUMNS:
            value, ok = safe_number(normalized.get(column))
            key = column.replace(" (ms)", "").lower().replace(" ", "_") + "_ms"
            parsed["numeric"][key] = value
            if normalized.get(column, "") == "":
                parsed["missing_numeric_fields"].append(column)
            elif not ok:
                parsed["invalid_numeric_fields"].append(column)
        if parsed["missing_numeric_fields"] or parsed["invalid_numeric_fields"]:
            row_errors.append({
                "row": index,
                "region_code": parsed["region_code"],
                "location": parsed["location"],
                "missing_numeric_fields": parsed["missing_numeric_fields"],
                "invalid_numeric_fields": parsed["invalid_numeric_fields"],
            })
        rows.append(parsed)
    return {"rows": rows, "missing_columns": [], "row_errors": row_errors}


def is_status_200(status: Any) -> bool:
    text = str(status).strip().lower()
    return text in {"200", "200 ok", "ok", "success"}


def metric(values: List[float]) -> Dict[str, Optional[float]]:
    return {
        "avg": round_or_none(average(values)),
        "median": round_or_none(median(values)),
        "p90": round_or_none(percentile(values, 90)),
        "max": round_or_none(max(values) if values else None),
    }


def compute_metrics(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(rows)
    status_200 = sum(1 for row in rows if is_status_200(row.get("status")))
    errors = total - status_200
    values_by_key: Dict[str, List[float]] = defaultdict(list)
    for row in rows:
        for key, value in (row.get("numeric") or {}).items():
            if isinstance(value, (int, float)):
                values_by_key[key].append(float(value))
    provider_rows: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in rows:
        provider_rows[row.get("provider") or "unknown"].append(row)
    provider_summary: Dict[str, Dict[str, Any]] = {}
    for provider, items in provider_rows.items():
        lat = [float(item["numeric"]["latency_ms"]) for item in items if isinstance(item.get("numeric", {}).get("latency_ms"), (int, float))]
        ttfb = [float(item["numeric"]["ttfb_ms"]) for item in items if isinstance(item.get("numeric", {}).get("ttfb_ms"), (int, float))]
        ok_count = sum(1 for item in items if is_status_200(item.get("status")))
        provider_summary[provider] = {
            "count": len(items),
            "avg_latency_ms": round_or_none(average(lat)),
            "avg_ttfb_ms": round_or_none(average(ttfb)),
            "max_latency_ms": round_or_none(max(lat) if lat else None),
            "success_rate_percent": round_or_none(ok_count * 100 / len(items) if items else None),
        }
    sorted_by_latency = sorted(
        [row for row in rows if isinstance(row.get("numeric", {}).get("latency_ms"), (int, float))],
        key=lambda row: float(row["numeric"]["latency_ms"]),
    )
    high_dns = [region_summary(row) for row in rows if isinstance(row.get("numeric", {}).get("dns_ms"), (int, float)) and row["numeric"]["dns_ms"] > 150]
    high_ttfb = [region_summary(row) for row in rows if isinstance(row.get("numeric", {}).get("ttfb_ms"), (int, float)) and row["numeric"]["ttfb_ms"] > 300]
    return {
        "total_checks": total,
        "status_200_count": status_200,
        "error_count": errors,
        "success_rate_percent": round_or_none(status_200 * 100 / total if total else None),
        "avg_latency_ms": round_or_none(average(values_by_key["latency_ms"])),
        "median_latency_ms": round_or_none(median(values_by_key["latency_ms"])),
        "p90_latency_ms": round_or_none(percentile(values_by_key["latency_ms"], 90)),
        "max_latency_ms": round_or_none(max(values_by_key["latency_ms"]) if values_by_key["latency_ms"] else None),
        "avg_ttfb_ms": round_or_none(average(values_by_key["ttfb_ms"])),
        "median_ttfb_ms": round_or_none(median(values_by_key["ttfb_ms"])),
        "p90_ttfb_ms": round_or_none(percentile(values_by_key["ttfb_ms"], 90)),
        "max_ttfb_ms": round_or_none(max(values_by_key["ttfb_ms"]) if values_by_key["ttfb_ms"] else None),
        "avg_dns_ms": round_or_none(average(values_by_key["dns_ms"])),
        "max_dns_ms": round_or_none(max(values_by_key["dns_ms"]) if values_by_key["dns_ms"] else None),
        "provider_summary": provider_summary,
        "fastest_regions": [region_summary(row) for row in sorted_by_latency[:5]],
        "slowest_regions": [region_summary(row) for row in list(reversed(sorted_by_latency[-5:]))],
        "high_dns_regions": high_dns,
        "high_ttfb_regions": high_ttfb,
    }


def region_summary(row: Dict[str, Any]) -> Dict[str, Any]:
    numeric = row.get("numeric") or {}
    return {
        "region_code": row.get("region_code"),
        "location": row.get("location"),
        "provider": row.get("provider"),
        "status": row.get("status"),
        "latency_ms": round_or_none(numeric.get("latency_ms")),
        "dns_ms": round_or_none(numeric.get("dns_ms")),
        "ttfb_ms": round_or_none(numeric.get("ttfb_ms")),
    }


def evaluate(metrics: Dict[str, Any]) -> Dict[str, Any]:
    statuses: List[str] = []
    if metrics.get("total_checks", 0) and metrics.get("error_count") == 0:
        statuses.append("GLOBAL_REACHABILITY_OK")
    if (metrics.get("p90_latency_ms") or 0) > 500:
        statuses.append("GLOBAL_LATENCY_WARNING")
    if (metrics.get("p90_ttfb_ms") or 0) > 300:
        statuses.append("GLOBAL_TTFB_WARNING")
    if len(metrics.get("high_dns_regions") or []) > 1:
        statuses.append("GLOBAL_DNS_WATCH")
    if not statuses:
        statuses.append("GLOBAL_CHECKER_NO_DATA")
    if any(status.endswith("WARNING") or status.endswith("WATCH") for status in statuses):
        ingest_status = STATUS_WARNINGS
    elif "GLOBAL_REACHABILITY_OK" in statuses:
        ingest_status = STATUS_OK
    else:
        ingest_status = STATUS_WARNINGS
    return {"warning_statuses": statuses, "ingest_status": ingest_status}


def recommendations() -> Dict[str, Any]:
    recs = [
        {"category": LOW, "title": "Re-ingest global checker CSV regularly", "action": "Build trend from repeated CSV snapshots."},
        {"category": LOW, "title": "Watch DNS/TTFB spikes by region", "action": "Track high DNS and high TTFB regions over time."},
        {"category": LOW, "title": "Report global reachability separately from outage status", "action": "Treat far-region latency as performance signal, not outage by itself."},
        {"category": LOW, "title": "Update bot learning after each checker run", "action": "Append observations and update adaptive patterns."},
        {"category": MEDIUM, "title": "CDN/cache rule review", "action": "Owner-reviewed rule comparison only; no automatic Cloudflare changes."},
        {"category": MEDIUM, "title": "DNS provider review", "action": "Owner-reviewed DNS performance analysis over repeated runs."},
        {"category": MEDIUM, "title": "Origin cache tuning", "action": "Prepare dry-run plan only; no Nginx or Cloudflare change."},
        {"category": MEDIUM, "title": "Image/embed optimization job", "action": "Owner-approved optimization plan after repeated performance evidence."},
        {"category": MEDIUM, "title": "Regional performance comparison", "action": "Repeat checker runs before recommending any tuning."},
        {"category": HIGH, "title": "Cloudflare rule changes", "action": "Manual review only."},
        {"category": HIGH, "title": "Nginx config changes", "action": "Manual review only."},
        {"category": HIGH, "title": "DNS migration", "action": "Manual review only."},
        {"category": HIGH, "title": "Origin migration", "action": "Manual review only."},
        {"category": HIGH, "title": "Broad WAF/security action", "action": "Manual review only."},
    ]
    return {
        "timestamp_utc": utc_now(),
        "recommendations_count": len(recs),
        "categories": dict(Counter(item["category"] for item in recs)),
        "recommendations": recs,
        "live_apply": False,
        "apply_status": APPLY_STATUS,
        "breach": False,
    }


def playbook() -> Dict[str, Any]:
    return {
        "name": "global-performance-checker-ingest",
        "purpose": "Ingest local global performance checker CSV and learn geography-dependent reachability/performance patterns.",
        "input_csv_schema": list(REQUIRED_COLUMNS),
        "allowed_actions": ["read local CSV", "validate rows", "compute metrics", "write reports", "write state", "write audit", "write snapshots", "update bot learning"],
        "blocked_actions": ["live apply", "SFTP write", "DB write", "cache purge", "Cloudflare change", "Nginx change", ".htaccess change", "systemctl/crontab changes"],
        "risk_classification": {"ingestion": LOW, "cdn_dns_origin_tuning": MEDIUM, "cloudflare_nginx_dns_migration": HIGH},
        "thresholds": {"p90_latency_warning_ms": 500, "p90_ttfb_warning_ms": 300, "dns_watch_ms": 150},
        "trend_logic": ["single snapshot is not proof of outage", "compare repeated CSV snapshots", "separate far-region latency from availability failure"],
        "owner_review_boundaries": ["No WAF/CDN/DNS/Nginx action from one CSV", "MEDIUM/HIGH recommendations require Owner review"],
        "output_reports": [str(REPORT_JSON), str(RECOMMEND_JSON), str(PLAYBOOK_JSON)],
    }


def build_report(csv_path: Path) -> Dict[str, Any]:
    ts = timestamp_tag()
    if SECRET_NAME_RE.search(csv_path.name) or csv_path.suffix.lower() == ".env":
        return failure_report(ts, csv_path, "secret_like_input_path_refused", STATUS_BLOCKED, breach=True)
    try:
        text = csv_path.read_text(encoding="utf-8-sig")
    except OSError:
        return failure_report(ts, csv_path, "csv_missing_or_unreadable", STATUS_FAILED, breach=False)
    parsed = parse_csv_text(text)
    if parsed["missing_columns"]:
        return failure_report(ts, csv_path, "missing_required_columns:" + ",".join(parsed["missing_columns"]), STATUS_FAILED, breach=False)
    metrics = compute_metrics(parsed["rows"])
    evaluation = evaluate(metrics)
    report = {
        "schema_version": SCHEMA_VERSION,
        "timestamp": ts,
        "timestamp_utc": utc_now(),
        "source_csv": str(csv_path),
        "status": evaluation["ingest_status"],
        "warning_statuses": evaluation["warning_statuses"],
        "breach": False,
        "live_apply": False,
        "apply_status": APPLY_STATUS,
        "row_errors_count": len(parsed["row_errors"]),
        "row_errors_sample": parsed["row_errors"][:20],
        "metrics": metrics,
        "learning": {
            "global_reachability_is_healthy": metrics.get("error_count") == 0 and metrics.get("total_checks", 0) > 0,
            "performance_degradation_is_geography_dependent": bool(metrics.get("slowest_regions")),
            "far_region_latency_is_not_outage": True,
            "dns_ttfb_are_watch_signals": True,
            "no_waf_security_rule_from_csv": True,
            "no_cloudflare_nginx_change_from_single_snapshot": True,
        },
    }
    return report


def failure_report(ts: str, csv_path: Path, reason: str, status: str, breach: bool) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "timestamp": ts,
        "timestamp_utc": utc_now(),
        "source_csv": str(csv_path),
        "status": status,
        "warning_statuses": [],
        "breach": breach,
        "live_apply": False,
        "apply_status": APPLY_STATUS,
        "error": reason,
        "metrics": {
            "total_checks": 0,
            "status_200_count": 0,
            "error_count": 0,
            "success_rate_percent": None,
        },
        "learning": {
            "global_reachability_is_healthy": False,
            "performance_degradation_is_geography_dependent": False,
            "far_region_latency_is_not_outage": True,
            "dns_ttfb_are_watch_signals": True,
            "no_waf_security_rule_from_csv": True,
            "no_cloudflare_nginx_change_from_single_snapshot": True,
        },
    }


def update_adaptive_state(report: Dict[str, Any]) -> None:
    observation = {
        "timestamp_utc": report.get("timestamp_utc"),
        "observation_id": "global-checker-performance-learning",
        "area": "Global Performance",
        "risk_level": LOW,
        "confidence_score": 0.8 if report.get("metrics", {}).get("total_checks") else 0.2,
        "symptoms": report.get("warning_statuses", []),
        "hypothesis": "Global reachability is healthy; geography-dependent DNS/TTFB/latency should be trended before any owner-reviewed tuning.",
        "evidence": report.get("metrics", {}),
    }
    append_jsonl(OBSERVATIONS_JSONL, [observation])
    knowledge, _status = read_json(KNOWLEDGE_BASE_JSON)
    knowledge = knowledge or {}
    knowledge["global_checker_performance_learning"] = {
        "timestamp_utc": report.get("timestamp_utc"),
        "learning": report.get("learning"),
        "warning_statuses": report.get("warning_statuses"),
        "metrics": report.get("metrics"),
        "allowed_bot_reaction": ["report", "trend", "watch DNS/TTFB regions", "update learning"],
        "forbidden_bot_reaction": ["derive WAF/security rule", "Cloudflare change", "Nginx change", "DNS migration"],
    }
    write_json_atomic(KNOWLEDGE_BASE_JSON, knowledge)
    patterns, _status = read_json(PATTERNS_JSON)
    patterns = patterns or {}
    patterns["global_checker"] = {
        "timestamp_utc": report.get("timestamp_utc"),
        "warning_statuses": report.get("warning_statuses"),
        "slowest_regions": report.get("metrics", {}).get("slowest_regions"),
        "high_dns_regions": report.get("metrics", {}).get("high_dns_regions"),
        "high_ttfb_regions": report.get("metrics", {}).get("high_ttfb_regions"),
    }
    write_json_atomic(PATTERNS_JSON, patterns)
    latest, _status = read_json(LATEST_JSON)
    latest = latest or {}
    latest["global_checker_performance_learning"] = {
        "status": report.get("status"),
        "warning_statuses": report.get("warning_statuses"),
        "success_rate_percent": report.get("metrics", {}).get("success_rate_percent"),
        "p90_latency_ms": report.get("metrics", {}).get("p90_latency_ms"),
        "p90_ttfb_ms": report.get("metrics", {}).get("p90_ttfb_ms"),
    }
    write_json_atomic(LATEST_JSON, latest)


def update_adaptive_reports(report: Dict[str, Any], recs: Dict[str, Any]) -> None:
    adaptive, _status = read_json(ADAPTIVE_REPORT_JSON)
    if adaptive:
        adaptive["global_checker_performance_learning"] = {
            "status": report.get("status"),
            "warning_statuses": report.get("warning_statuses"),
            "metrics": report.get("metrics"),
            "learning": report.get("learning"),
        }
        write_json_atomic(ADAPTIVE_REPORT_JSON, adaptive)
    adapt_rec, _status = read_json(ADAPTIVE_RECOMMEND_JSON)
    if adapt_rec:
        adapt_rec["global_checker_recommendations"] = recs
        write_json_atomic(ADAPTIVE_RECOMMEND_JSON, adapt_rec)
    append_markdown_section(ADAPTIVE_REPORT_MD, "Global Checker Performance Learning", render_adaptive_md_section(report))
    append_markdown_section(ADAPTIVE_RECOMMEND_MD, "Global Checker Recommendations", render_recommendations_md(recs))
    append_markdown_section(ADAPTIVE_CAPABILITY_MD, "Global Checker Capability", "- `global_checker_csv_ingest`: `True`\n- `global_checker_live_apply`: `False`\n")


def append_markdown_section(path: Path, title: str, body: str) -> None:
    if not path.exists():
        return
    text = path.read_text(encoding="utf-8")
    start = f"\n## {title}\n"
    marker = f"<!-- sentinel:{title.lower().replace(' ', '-')} -->"
    block = f"\n{marker}\n## {title}\n\n{body.rstrip()}\n"
    if marker in text:
        text = text.split(marker, 1)[0].rstrip() + block
    else:
        text = text.rstrip() + "\n" + block
    write_text_atomic(path, text)


def render_report_md(report: Dict[str, Any]) -> str:
    metrics = report.get("metrics", {})
    lines = [
        "# Global Checker Ingest",
        "",
        f"- Status: `{report.get('status')}`",
        f"- Breach: `{report.get('breach')}`",
        f"- live_apply: `{report.get('live_apply')}`",
        f"- Source CSV: `{report.get('source_csv')}`",
        f"- Total checks: `{metrics.get('total_checks')}`",
        f"- Success rate: `{metrics.get('success_rate_percent')}`",
        f"- Avg latency ms: `{metrics.get('avg_latency_ms')}`",
        f"- P90 latency ms: `{metrics.get('p90_latency_ms')}`",
        f"- Avg TTFB ms: `{metrics.get('avg_ttfb_ms')}`",
        f"- P90 TTFB ms: `{metrics.get('p90_ttfb_ms')}`",
        f"- Warning statuses: `{', '.join(report.get('warning_statuses') or [])}`",
        "",
        "## Slowest Regions",
        "",
    ]
    for region in metrics.get("slowest_regions", [])[:5]:
        lines.append(f"- {region.get('location')} ({region.get('provider')}): latency `{region.get('latency_ms')}` ms, DNS `{region.get('dns_ms')}` ms, TTFB `{region.get('ttfb_ms')}` ms")
    lines.extend(["", "## Learning", ""])
    for key, value in (report.get("learning") or {}).items():
        lines.append(f"- `{key}`: `{value}`")
    return "\n".join(lines) + "\n"


def render_adaptive_md_section(report: Dict[str, Any]) -> str:
    metrics = report.get("metrics", {})
    return (
        f"- Status: `{report.get('status')}`\n"
        f"- Warning statuses: `{', '.join(report.get('warning_statuses') or [])}`\n"
        f"- Total checks: `{metrics.get('total_checks')}`\n"
        f"- Success rate: `{metrics.get('success_rate_percent')}`\n"
        f"- P90 latency ms: `{metrics.get('p90_latency_ms')}`\n"
        f"- P90 TTFB ms: `{metrics.get('p90_ttfb_ms')}`\n"
        "- Interpretation: far-region latency is a performance watch signal, not an outage by itself.\n"
    )


def render_recommendations_md(data: Dict[str, Any]) -> str:
    lines = ["# Global Checker Recommendations", "", f"- Count: `{data.get('recommendations_count')}`", ""]
    for item in data.get("recommendations", []):
        lines.append(f"- `{item.get('category')}` {item.get('title')}: {item.get('action')}")
    return "\n".join(lines) + "\n"


def write_outputs(report: Dict[str, Any], recs: Dict[str, Any]) -> None:
    ts = str(report["timestamp"])
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, render_report_md(report))
    write_json_atomic(RECOMMEND_JSON, recs)
    write_text_atomic(RECOMMEND_MD, render_recommendations_md(recs))
    write_json_atomic(SNAPSHOT_DIR / f"global-checker-ingest-{ts}.json", report)
    write_json_atomic(PLAYBOOK_JSON, playbook())
    append_jsonl(AUDIT_JSONL, [{
        "timestamp_utc": report.get("timestamp_utc"),
        "status": report.get("status"),
        "total_checks": report.get("metrics", {}).get("total_checks"),
        "success_rate_percent": report.get("metrics", {}).get("success_rate_percent"),
        "warning_statuses": report.get("warning_statuses"),
        "breach": report.get("breach"),
        "live_apply": report.get("live_apply"),
    }])
    if report.get("status") not in {STATUS_FAILED, STATUS_BLOCKED}:
        update_adaptive_state(report)
        update_adaptive_reports(report, recs)


def run_ingest(csv_path: Path) -> Dict[str, Any]:
    report = build_report(csv_path)
    recs = recommendations()
    write_outputs(report, recs)
    return report


def run_recommend() -> Dict[str, Any]:
    report, _status = read_json(REPORT_JSON)
    if not report:
        report = failure_report(timestamp_tag(), Path("-"), "no_previous_ingest", STATUS_FAILED, breach=False)
    recs = recommendations()
    write_json_atomic(RECOMMEND_JSON, recs)
    write_text_atomic(RECOMMEND_MD, render_recommendations_md(recs))
    return recs


def print_status() -> None:
    report, status = read_json(REPORT_JSON)
    if not report:
        print(f"status=not_available input_status={status}")
        return
    metrics = report.get("metrics", {})
    print(f"status={report.get('status')}")
    print(f"breach={report.get('breach')}")
    print(f"live_apply={report.get('live_apply')}")
    print(f"total_checks={metrics.get('total_checks')}")
    print(f"success_rate_percent={metrics.get('success_rate_percent')}")
    print(f"avg_latency_ms={metrics.get('avg_latency_ms')}")
    print(f"p90_latency_ms={metrics.get('p90_latency_ms')}")
    print(f"avg_ttfb_ms={metrics.get('avg_ttfb_ms')}")
    print(f"p90_ttfb_ms={metrics.get('p90_ttfb_ms')}")
    print(f"warning_statuses={','.join(report.get('warning_statuses') or [])}")


def run_self_test() -> int:
    parser = build_parser()
    if "--apply" in parser.format_help():
        raise AssertionError("apply mode exposed")
    sample = """Region Code,Location,Provider,Latency (ms),Status,DNS (ms),Connect (ms),TLS (ms),TTFB (ms),Transfer (ms)
us,New York,Koyeb,120,200,20,30,40,80,40
au,Sydney,Fly,640,200,180,80,90,360,100
za,Johannesburg,Railway,580,200,160,70,80,330,100
"""
    parsed = parse_csv_text(sample)
    if parsed["missing_columns"] or len(parsed["rows"]) != 3:
        raise AssertionError("csv parser failed")
    missing = parse_csv_text("A,B\n1,2\n")
    if not missing["missing_columns"]:
        raise AssertionError("missing columns not detected")
    bad = parse_csv_text("""Region Code,Location,Provider,Latency (ms),Status,DNS (ms),Connect (ms),TLS (ms),TTFB (ms),Transfer (ms)
xx,Nowhere,Koyeb,abc,200,,1,2,3,4
""")
    if not bad["row_errors"]:
        raise AssertionError("numeric parse errors not captured")
    if percentile([1, 2, 3, 4, 5], 90) != 5:
        raise AssertionError("p90 calculation failed")
    metrics = compute_metrics(parsed["rows"])
    if "Koyeb" not in metrics["provider_summary"] or metrics["total_checks"] != 3:
        raise AssertionError("provider grouping failed")
    ev = evaluate(metrics)
    if "GLOBAL_LATENCY_WARNING" not in ev["warning_statuses"] or "GLOBAL_TTFB_WARNING" not in ev["warning_statuses"]:
        raise AssertionError("risk classification failed")
    if "abcdef" in redact_text("api_key=abcdef12345"):
        raise AssertionError("secret redaction failed")
    source = Path(__file__).read_text(encoding="utf-8")
    for token in ("sub" + "process", "os" + "." + "system", "." + "put(", "." + "remove(", "." + "rename(", "rm " + "-rf"):
        if token in source:
            raise AssertionError(f"forbidden implementation token found: {token}")
    json.dumps(build_report_from_text_for_test(sample))
    print("self-test ok")
    return 0


def build_report_from_text_for_test(text: str) -> Dict[str, Any]:
    parsed = parse_csv_text(text)
    metrics = compute_metrics(parsed["rows"])
    evaluation = evaluate(metrics)
    return {
        "schema_version": SCHEMA_VERSION,
        "timestamp": timestamp_tag(),
        "timestamp_utc": utc_now(),
        "status": evaluation["ingest_status"],
        "warning_statuses": evaluation["warning_statuses"],
        "breach": False,
        "live_apply": False,
        "metrics": metrics,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Ingest local global checker CSV into adaptive learning.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--ingest", metavar="CSV_PATH")
    group.add_argument("--status", action="store_true")
    group.add_argument("--recommend", action="store_true")
    return parser


def print_summary(report: Dict[str, Any]) -> None:
    metrics = report.get("metrics", {})
    print(f"status={report.get('status')}")
    print(f"breach={report.get('breach')}")
    print(f"live_apply={report.get('live_apply')}")
    print(f"total_checks={metrics.get('total_checks')}")
    print(f"success_rate_percent={metrics.get('success_rate_percent')}")
    print(f"avg_latency_ms={metrics.get('avg_latency_ms')}")
    print(f"p90_latency_ms={metrics.get('p90_latency_ms')}")
    print(f"avg_ttfb_ms={metrics.get('avg_ttfb_ms')}")
    print(f"p90_ttfb_ms={metrics.get('p90_ttfb_ms')}")
    print(f"warning_statuses={','.join(report.get('warning_statuses') or [])}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.self_test:
        return run_self_test()
    if args.status:
        print_status()
        return 0
    try:
        if args.ingest:
            report = run_ingest(Path(args.ingest))
            print_summary(report)
            return 0 if not report.get("breach") else 2
        recs = run_recommend()
        print(f"recommendations_count={recs.get('recommendations_count')}")
        print(f"breach={recs.get('breach')}")
        print(f"live_apply={recs.get('live_apply')}")
        return 0
    except Exception as exc:  # noqa: BLE001
        failed = failure_report(timestamp_tag(), Path(args.ingest or "-"), redact_text(exc), STATUS_FAILED, breach=True)
        write_json_atomic(REPORT_JSON, failed)
        write_text_atomic(REPORT_MD, render_report_md(failed))
        print(f"status={STATUS_FAILED}")
        print("breach=True")
        return 2


if __name__ == "__main__":
    sys.exit(main())
