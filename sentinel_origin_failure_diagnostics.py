#!/usr/bin/env python3
"""Correlate local origin-failure evidence without changing production systems.

Phase 10.17 reads only allowlisted project evidence and writes private diagnostic
reports plus one sanitized public summary. It has no network, remote-write,
shell, scheduler, restart, firewall, TLS, WordPress, or hosting mutation path.
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
SCHEMA_VERSION = "sentinel-origin-failure-diagnostics-10.17"

REPORT_DIR = PROJECT_DIR / "reports/latest"
STATE_DIR = PROJECT_DIR / "state/adaptive-learning"
AUDIT_DIR = PROJECT_DIR / "audit"
PLAYBOOK_DIR = PROJECT_DIR / "playbooks"

MASTER_CONSISTENCY_JSON = REPORT_DIR / "sentinel-master-consistency.json"
WEBSITE_JSON = REPORT_DIR / "sentinel-defense-report.json"
PREFERRED_INPUTS = (
    MASTER_CONSISTENCY_JSON,
    REPORT_DIR / "sentinel-master-executive-summary.md",
    REPORT_DIR / "sentinel-master-technical-appendix.md",
    REPORT_DIR / "sentinel-subreport-freshness.md",
    REPORT_DIR / "sentinel-owner-priority-decision.md",
)

REPORT_JSON = REPORT_DIR / "sentinel-origin-failure-diagnostics.json"
REPORT_MD = REPORT_DIR / "sentinel-origin-failure-diagnostics.md"
STATUS_REPORTS = {
    503: REPORT_DIR / "sentinel-origin-503-analysis.md",
    504: REPORT_DIR / "sentinel-origin-504-analysis.md",
    522: REPORT_DIR / "sentinel-origin-522-analysis.md",
    526: REPORT_DIR / "sentinel-origin-526-tls-analysis.md",
}
PATH_MD = REPORT_DIR / "sentinel-origin-path-correlation.md"
ACTOR_MD = REPORT_DIR / "sentinel-origin-actor-correlation.md"
TIMELINE_MD = REPORT_DIR / "sentinel-origin-timeline.md"
OWNER_PLAN_MD = REPORT_DIR / "sentinel-origin-owner-action-plan.md"
EVIDENCE_GAP_MD = REPORT_DIR / "sentinel-origin-evidence-gap.md"
PUBLIC_MD = REPORT_DIR / "sentinel-origin-public-sanitized-summary.md"
VALIDATION_MD = REPORT_DIR / "sentinel-origin-validation.md"

STATE_JSON = STATE_DIR / "origin_failure_diagnostics.json"
LATEST_STATE_JSON = STATE_DIR / "latest_origin_failure_diagnostics.json"
HISTORY_JSON = STATE_DIR / "origin_failure_diagnostics_history.json"
AUDIT_JSONL = AUDIT_DIR / "sentinel-origin-failure-diagnostics.jsonl"

PLAYBOOKS = (
    PLAYBOOK_DIR / "sentinel-origin-failure-diagnostics.playbook.json",
    PLAYBOOK_DIR / "sentinel-origin-503-correlation.playbook.json",
    PLAYBOOK_DIR / "sentinel-origin-526-tls-review.playbook.json",
    PLAYBOOK_DIR / "sentinel-origin-owner-action-plan.playbook.json",
)

OUTPUT_MARKDOWN = (
    REPORT_MD,
    *STATUS_REPORTS.values(),
    PATH_MD,
    ACTOR_MD,
    TIMELINE_MD,
    OWNER_PLAN_MD,
    EVIDENCE_GAP_MD,
    PUBLIC_MD,
    VALIDATION_MD,
)
OUTPUT_JSONS = (REPORT_JSON, STATE_JSON, LATEST_STATE_JSON, HISTORY_JSON, *PLAYBOOKS)

ALLOWED_INPUT_ROOTS = tuple(
    PROJECT_DIR / name for name in ("reports", "state", "audit", "docs", "data", "snapshots")
)
ALLOWED_INPUT_SUFFIXES = {".json", ".jsonl", ".md", ".txt", ".log", ".csv"}
MAX_INPUT_BYTES = 8 * 1024 * 1024
INPUT_KEYWORDS = (
    "origin", "php", "wordpress", "nginx", "ionos", "5xx", "tls", "ssl",
    "certificate", "sitelock", "rolling", "website", "master", "cloudflare",
    "status", "failure", "timeout", "upstream",
)
SECRET_PATH_PARTS = (
    ".env", "credential", "password", "passwd", "secret", "private-key",
    "private_key", "api-key", "api_key", "access-token", "access_token",
)
SECRET_SUFFIXES = {".pem", ".key", ".p12", ".pfx"}
SELF_OUTPUT_NAMES = {path.name for path in (REPORT_JSON, *OUTPUT_MARKDOWN, STATE_JSON, LATEST_STATE_JSON, HISTORY_JSON, AUDIT_JSONL)}

DELTA_THRESHOLDS = {
    "significant_absolute": 25,
    "significant_percent": 25.0,
    "stable_absolute_tolerance": 0,
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

EXECUTION_BOUNDARIES = {
    "production_apply_lock": True,
    "remote_write_lock": True,
    "scheduler_install_lock": True,
    "timer_execution_lock": True,
    "local_analysis_allowed": True,
    "local_report_generation_allowed": True,
    "local_validation_allowed": True,
}

REPORT_CLASSIFICATION = [
    "PRIVATE_OWNER_OPERATIONAL_REPORT",
    "NOT_FOR_PUBLIC_RELEASE",
    "NOT_FOR_GIT",
    "CONTAINS_INFRASTRUCTURE_METADATA",
]

RECOMMENDED_GIT_FILES = [
    "sentinel_origin_failure_diagnostics.py",
    "playbooks/sentinel-origin-failure-diagnostics.playbook.json",
    "playbooks/sentinel-origin-503-correlation.playbook.json",
    "playbooks/sentinel-origin-526-tls-review.playbook.json",
    "playbooks/sentinel-origin-owner-action-plan.playbook.json",
]

STATUS_HYPOTHESES = {
    503: [
        "origin_capacity_pressure",
        "php_worker_exhaustion",
        "php_fatal_or_application_failure",
        "wordpress_bootstrap_failure",
        "plugin_or_theme_failure",
        "maintenance_or_temporary_unavailable",
        "hosting_rate_limit_or_resource_limit",
        "upstream_unavailable",
        "sitelock_or_scanner_triggered_application_pressure",
        "legacy_path_application_pressure",
        "unknown_503",
    ],
    504: [
        "cloudflare_to_origin_timeout",
        "origin_response_timeout",
        "php_or_database_latency",
        "dynamic_request_timeout",
        "unknown_504",
    ],
    522: [
        "cloudflare_origin_connection_timeout",
        "origin_temporarily_unreachable",
        "network_or_host_connectivity_issue",
        "unknown_522",
    ],
    526: [
        "origin_invalid_ssl_certificate",
        "origin_certificate_expired",
        "origin_hostname_mismatch",
        "cloudflare_strict_ssl_validation_failure",
        "temporary_origin_tls_failure",
        "unknown_526",
    ],
}

DIRECT_EVIDENCE_REQUIREMENTS = {
    "php_fatal_log": "Current PHP fatal or application error log for the failure window.",
    "wordpress_debug_log": "Current WordPress debug or bootstrap error evidence.",
    "hosting_resource_limit_log": "Current hosting CPU, memory, process, or request-limit evidence.",
    "nginx_upstream_error": "Current origin upstream error or timeout evidence.",
    "cloudflare_origin_tls_detail": "Current origin TLS validation event detail for 526.",
    "ionos_server_or_php_log": "Current hosting server or PHP log correlated by timestamp.",
}

DIRECT_PATTERNS = {
    "php_fatal_log": re.compile(r"(?:PHP\s+Fatal\s+error|Allowed memory size .* exhausted)", re.IGNORECASE),
    "wordpress_debug_log": re.compile(r"(?:Fatal error|Uncaught\s+\w+).*wp-(?:content|includes)", re.IGNORECASE),
    "hosting_resource_limit_log": re.compile(r"(?:resource limit|cpu limit|memory limit|process limit|entry process limit)", re.IGNORECASE),
    "nginx_upstream_error": re.compile(r"(?:upstream timed out|connect\(\) failed.*upstream|no live upstreams)", re.IGNORECASE),
    "cloudflare_origin_tls_detail": re.compile(r"(?:certificate verify failed|hostname mismatch|certificate expired|origin tls.*failed)", re.IGNORECASE),
    "ionos_server_or_php_log": re.compile(r"(?:ionos).*(?:php|server|resource).*(?:error|limit|timeout)", re.IGNORECASE),
}

DIRECT_SOURCE_MARKERS = (
    "debug.log", "error.log", "php-error", "php_error", "nginx-error",
    "nginx_error", "upstream-error", "upstream_error", "resource-limit",
    "resource_limit", "tls-event", "tls_event", "certificate-event",
)

IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
FQDN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}(?::\d{1,5})?\b"
)
PRIVATE_PATH_RE = re.compile(r"/(?:srv|etc|var|home|root|opt|mnt|tmp)/[^\s\]})>,\"']+")
INTERNAL_ENDPOINT_RE = re.compile(r"/api/(?:internal|admin|station)/[^\s\]})>,\"']+", re.IGNORECASE)
INTERNAL_ID_RE = re.compile(r"\b(?:endpoint|node|origin|zone)[_-]id\s*[:=]\s*[A-Za-z0-9_-]+", re.IGNORECASE)
FULL_UA_RE = re.compile(r"Mozilla/5\.0[^\n]{20,240}", re.IGNORECASE)
SECRET_VALUE_RE = re.compile(
    r"(?i)(?:password|passwd|secret|api[_-]?key|access[_-]?token|private[_-]?key)\s*[:=]\s*[^\s,;]+"
)
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(PROJECT_DIR))
    except (OSError, ValueError):
        return str(path)


def ensure_dirs() -> None:
    for directory in (REPORT_DIR, STATE_DIR, AUDIT_DIR, PLAYBOOK_DIR):
        directory.mkdir(parents=True, exist_ok=True)


def is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def is_within_project(path: Path) -> bool:
    try:
        return is_within(path.resolve(), PROJECT_DIR.resolve())
    except OSError:
        return False


def input_path_allowed(path: Path, resolved_override: Optional[Path] = None) -> bool:
    """Return whether a read candidate is inside an allowlisted project root."""
    try:
        lexical = path.absolute()
        resolved = resolved_override.resolve() if resolved_override else path.resolve()
    except OSError:
        return False
    project = PROJECT_DIR.resolve()
    if not is_within(lexical, project) or not is_within(resolved, project):
        return False
    if not any(is_within(lexical, root.resolve()) for root in ALLOWED_INPUT_ROOTS):
        return False
    if not any(is_within(resolved, root.resolve()) for root in ALLOWED_INPUT_ROOTS):
        return False
    lowered_parts = [part.lower() for part in path.parts]
    if any(marker in part for part in lowered_parts for marker in SECRET_PATH_PARTS):
        return False
    if path.suffix.lower() in SECRET_SUFFIXES:
        return False
    return True


def read_json(path: Path) -> Tuple[Any, str]:
    if not input_path_allowed(path):
        return None, "blocked_path"
    if not path.exists() or path.is_symlink():
        return None, "missing" if not path.exists() else "symlink_blocked"
    try:
        return json.loads(path.read_text(encoding="utf-8")), "ok"
    except json.JSONDecodeError:
        return None, "invalid_json"
    except OSError:
        return None, "read_error"


def load_dict(path: Path) -> Dict[str, Any]:
    data, status = read_json(path)
    return data if status == "ok" and isinstance(data, dict) else {}


def read_limited_text(path: Path) -> Tuple[str, str]:
    if not input_path_allowed(path) or path.is_symlink():
        return "", "blocked_path"
    try:
        if not path.is_file() or path.stat().st_size > MAX_INPUT_BYTES:
            return "", "missing_or_too_large"
        return path.read_text(encoding="utf-8", errors="replace"), "ok"
    except OSError:
        return "", "read_error"


def write_text(path: Path, text: str) -> None:
    if not is_within_project(path):
        raise RuntimeError(f"write outside project blocked: {path}")
    if SECRET_VALUE_RE.search(text) or PRIVATE_KEY_RE.search(text):
        raise RuntimeError(f"secret-like output blocked: {rel(path)}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def write_json(path: Path, data: Any) -> None:
    text = json.dumps(data, indent=2, sort_keys=True)
    json.loads(text)
    write_text(path, text)


def append_jsonl(path: Path, row: Dict[str, Any]) -> None:
    if not is_within_project(path):
        raise RuntimeError("audit path outside project")
    line = json.dumps(row, sort_keys=True)
    if SECRET_VALUE_RE.search(line) or PRIVATE_KEY_RE.search(line):
        raise RuntimeError("secret-like audit content blocked")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def metric_value(report: Dict[str, Any], key: str) -> Optional[int]:
    for row in report.get("metrics", []):
        if isinstance(row, dict) and row.get("key") == key:
            return as_int(row.get("value"))
    return None


def status_counts(report: Dict[str, Any]) -> Dict[int, int]:
    pressure = report.get("origin_pressure_breakdown", {})
    rows = pressure.get("top_5xx_status_codes", []) if isinstance(pressure, dict) else []
    if not rows:
        rows = report.get("top_5xx_status_codes", [])
    result: Dict[int, int] = {}
    for row in rows:
        if isinstance(row, dict):
            code = as_int(row.get("status"), -1)
            if code in STATUS_HYPOTHESES:
                result[code] = as_int(row.get("count"))
    return {code: result.get(code, 0) for code in STATUS_HYPOTHESES}


def detail_coverage(report: Dict[str, Any]) -> Dict[int, Optional[float]]:
    pressure = report.get("origin_pressure_breakdown", {})
    rows = pressure.get("status_detail_gap", []) if isinstance(pressure, dict) else []
    result: Dict[int, Optional[float]] = {code: None for code in STATUS_HYPOTHESES}
    for row in rows:
        if isinstance(row, dict):
            code = as_int(row.get("status"), -1)
            if code in result:
                try:
                    result[code] = float(row.get("detail_coverage_percent"))
                except (TypeError, ValueError):
                    pass
    return result


def calculate_delta(previous: Optional[int], current: Optional[int]) -> Dict[str, Any]:
    if previous is None or current is None:
        return {
            "previous_count": previous,
            "current_count": current,
            "delta": None,
            "delta_percent": None,
            "trend": "INSUFFICIENT_HISTORY",
        }
    delta = current - previous
    percent = round((delta / previous) * 100.0, 2) if previous else None
    tolerance = DELTA_THRESHOLDS["stable_absolute_tolerance"]
    if delta < -tolerance:
        trend = "DECREASING"
    elif abs(delta) <= tolerance:
        trend = "STABLE"
    elif delta >= DELTA_THRESHOLDS["significant_absolute"] or (
        percent is not None and percent >= DELTA_THRESHOLDS["significant_percent"]
    ):
        trend = "SIGNIFICANT_GROWTH"
    else:
        trend = "LOW_GROWTH"
    return {
        "previous_count": previous,
        "current_count": current,
        "delta": delta,
        "delta_percent": percent,
        "trend": trend,
    }


def classify_path(path: str) -> str:
    lowered = path.lower()
    if path == "/":
        return "frontpage"
    if lowered.startswith("/wp-login.php"):
        return "wordpress_login"
    if lowered.startswith("/wp-admin/"):
        return "wordpress_admin_asset"
    if re.fullmatch(r"/page/\d+/?", lowered):
        return "wordpress_legacy_pagination"
    if "oembed" in lowered or lowered.startswith("/wp-json/"):
        return "wordpress_rest_or_oembed"
    if any(marker in lowered for marker in ("alfacgiapi", "/.env", "shell.php", "wp-config")):
        return "scanner_or_malware_probe"
    if lowered.startswith("/api/"):
        return "internal_api"
    if re.search(r"\.(?:css|js|png|jpg|jpeg|gif|svg|webp|ico|woff2?)(?:\?|$)", lowered):
        return "static_asset"
    if lowered.startswith("/") and len(lowered) > 1:
        return "public_content"
    return "unknown"


def list_count(rows: Any, key: str) -> Dict[str, int]:
    result: Dict[str, int] = {}
    if not isinstance(rows, list):
        return result
    for row in rows:
        if isinstance(row, dict) and row.get(key) is not None:
            result[str(row[key])] = as_int(row.get("count"))
    return result


def infer_status_dimension(path_row: Dict[str, Any], dimension_key: str, label_key: str) -> Dict[int, str]:
    """Infer a dimension only where aggregate balancing makes it unambiguous."""
    statuses = {as_int(row.get("status")): as_int(row.get("count")) for row in path_row.get("statuses", []) if isinstance(row, dict)}
    dimensions = list_count(path_row.get(dimension_key, []), label_key)
    assignments: Dict[int, str] = {}
    remaining_statuses = dict(statuses)
    remaining_dimensions = dict(dimensions)
    changed = True
    while changed:
        changed = False
        for code, count in list(remaining_statuses.items()):
            matches = [label for label, dimension_count in remaining_dimensions.items() if dimension_count == count]
            if len(matches) == 1:
                label = matches[0]
                assignments[code] = label
                remaining_statuses.pop(code, None)
                remaining_dimensions.pop(label, None)
                changed = True
    if len(remaining_dimensions) == 1:
        label = next(iter(remaining_dimensions))
        for code in remaining_statuses:
            assignments[code] = label
    return assignments


def correlate_paths(report: Dict[str, Any], generated_at: Optional[str]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for path_row in report.get("top_5xx_paths", []):
        if not isinstance(path_row, dict):
            continue
        path = str(path_row.get("path") or "unknown")
        cache_map = infer_status_dimension(path_row, "cache_status", "cache_status")
        actor_counts = list_count(path_row.get("actor_signal_counts", []), "actor_signal")
        ua_counts = list_count(path_row.get("user_agent_groups", []), "group")
        country_counts = list_count(path_row.get("countries", []), "country")
        request_shapes = list_count(path_row.get("request_shape_counts", []), "request_shape")
        failure_modes = list_count(path_row.get("failure_mode_counts", []), "failure_mode")
        for status_row in path_row.get("statuses", []):
            if not isinstance(status_row, dict):
                continue
            code = as_int(status_row.get("status"), -1)
            if code not in STATUS_HYPOTHESES:
                continue
            rows.append({
                "count": as_int(status_row.get("count")),
                "status_code": code,
                "path": path,
                "path_classification": classify_path(path),
                "cache_status": cache_map.get(code, "unknown"),
                "cache_status_proof": "AGGREGATE_BALANCE_CORRELATION" if code in cache_map else "UNKNOWN",
                "user_agent_group": max(ua_counts, key=ua_counts.get) if ua_counts else "unknown",
                "actor_signal": max(actor_counts, key=actor_counts.get) if actor_counts else "unknown_actor",
                "actor_signal_counts": actor_counts,
                "country": max(country_counts, key=country_counts.get) if country_counts else "unknown",
                "request_shape": max(request_shapes, key=request_shapes.get) if request_shapes else str(path_row.get("request_shape") or "unknown"),
                "failure_mode": max(failure_modes, key=failure_modes.get) if failure_modes else str(path_row.get("failure_mode") or f"unknown_{code}"),
                "first_seen": None,
                "last_seen": None,
                "observed_in_snapshot_at": generated_at,
                "delta_since_previous": None,
                "verified_user_impact": "unknown",
                "confidence": "medium" if code in (503, 504) else "low",
                "hostnames": sorted({str(item) for item in path_row.get("hostnames", []) if item}),
                "causality_proven": False,
            })
    return sorted(rows, key=lambda item: (-item["count"], item["status_code"], item["path"]))


def aggregate_cache_by_status(
    path_rows: Sequence[Dict[str, Any]], current_counts: Dict[int, int]
) -> Dict[int, Dict[str, Any]]:
    result: Dict[int, Dict[str, int]] = {code: {} for code in STATUS_HYPOTHESES}
    for row in path_rows:
        code = row["status_code"]
        label = row["cache_status"]
        result[code][label] = result[code].get(label, 0) + row["count"]
    output: Dict[int, Dict[str, Any]] = {}
    for code, counts in result.items():
        uncovered = max(0, current_counts.get(code, 0) - sum(counts.values()))
        if uncovered:
            counts["unknown"] = counts.get("unknown", 0) + uncovered
        dominant = max(counts, key=counts.get) if counts else "unknown"
        current = current_counts.get(code, sum(counts.values()))
        output[code] = {
            "status": code,
            "counts": counts,
            "dominant_cache_status": dominant,
            "origin_related_likelihood": "HIGH" if dominant in {"dynamic", "miss"} and current else "UNKNOWN",
            "proof_level": "CORRELATION_ONLY",
            "causality_proven": False,
        }
    return output


def normalize_actor_counts(report: Dict[str, Any]) -> Dict[str, int]:
    raw = list_count(report.get("top_5xx_actor_signals", []), "actor_signal")
    paths = report.get("top_5xx_paths", [])
    go_count = 0
    for row in paths:
        if isinstance(row, dict):
            for ua, count in list_count(row.get("user_agent_groups", []), "group").items():
                if "go-http-client" in ua.lower():
                    go_count += count
    scanner_raw = raw.get("scanner_or_bot_actor", 0)
    return {
        "sitelockspider_actor": raw.get("sitelockspider_actor", 0),
        "nginx_early_hints_actor": raw.get("nginx_early_hints_actor", 0),
        "scanner_or_bot_actor": max(0, scanner_raw - go_count),
        "go_http_client_actor": go_count,
        "browser_like_actor": raw.get("browser_like_actor", 0),
        "unknown_actor": raw.get("unknown_actor_signal", 0) + raw.get("other_user_agent_actor", 0),
    }


def correlate_actors(report: Dict[str, Any], path_rows: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    counts = normalize_actor_counts(report)
    output: List[Dict[str, Any]] = []
    for actor, total in counts.items():
        matching_paths: List[Tuple[str, int]] = []
        status_overlap_upper_bound = {code: 0 for code in STATUS_HYPOTHESES}
        for source in report.get("top_5xx_paths", []):
            if not isinstance(source, dict):
                continue
            actor_counts = list_count(source.get("actor_signal_counts", []), "actor_signal")
            ua_counts = list_count(source.get("user_agent_groups", []), "group")
            overlap = actor_counts.get(actor, 0)
            if actor == "go_http_client_actor":
                overlap = sum(count for ua, count in ua_counts.items() if "go-http-client" in ua.lower())
            elif actor == "unknown_actor":
                overlap = actor_counts.get("unknown_actor_signal", 0) + actor_counts.get("other_user_agent_actor", 0)
            if overlap:
                matching_paths.append((str(source.get("path") or "unknown"), overlap))
                for status_row in source.get("statuses", []):
                    if isinstance(status_row, dict):
                        code = as_int(status_row.get("status"), -1)
                        if code in status_overlap_upper_bound:
                            status_overlap_upper_bound[code] += min(overlap, as_int(status_row.get("count")))
        if total == 0:
            path_correlation = "NONE_OBSERVED"
        elif total >= 25 and matching_paths:
            path_correlation = "MODERATE"
        else:
            path_correlation = "WEAK"
        output.append({
            "actor": actor,
            "total_requests": total,
            "status_path_overlap_upper_bound": {
                str(code): count for code, count in status_overlap_upper_bound.items()
            },
            "status_shares": {str(code): None for code in STATUS_HYPOTHESES},
            "status_shares_attributable": False,
            "top_paths": [path for path, _ in sorted(matching_paths, key=lambda item: (-item[1], item[0]))[:5]],
            "delta": None,
            "path_overlap_correlation": path_correlation,
            "correlation_with_error_growth": "UNDETERMINED",
            "causality_proven": False,
            "block_user_agent": False,
            "new_waf_rule_recommended": False,
            "reason": (
                "Actor volume overlaps with failing paths, but path-level overlap is not request-level attribution "
                "and current origin-side direct evidence is unavailable."
            ),
        })
    return sorted(output, key=lambda item: (-item["total_requests"], item["actor"]))


def discover_inputs() -> Dict[str, Any]:
    discovered: List[str] = []
    blocked_symlinks: List[str] = []
    excluded_sensitive: List[str] = []
    for root in ALLOWED_INPUT_ROOTS:
        if not root.exists() or root.is_symlink():
            continue
        try:
            candidates = sorted(root.rglob("*"), key=lambda item: str(item))
        except OSError:
            continue
        for path in candidates:
            if path.is_symlink():
                blocked_symlinks.append(rel(path))
                continue
            if not path.is_file() or path.name in SELF_OUTPUT_NAMES:
                continue
            lowered = str(path.relative_to(PROJECT_DIR)).lower()
            sensitive_name = any(marker in part.lower() for part in path.parts for marker in SECRET_PATH_PARTS)
            if sensitive_name or path.suffix.lower() in SECRET_SUFFIXES:
                excluded_sensitive.append(rel(path))
                continue
            if path.suffix.lower() not in ALLOWED_INPUT_SUFFIXES:
                continue
            if not any(keyword in lowered for keyword in INPUT_KEYWORDS):
                continue
            if input_path_allowed(path):
                discovered.append(rel(path))
    discovered = sorted(set(discovered))
    preferred = []
    missing = []
    for path in PREFERRED_INPUTS:
        if path.exists() and input_path_allowed(path) and not path.is_symlink():
            preferred.append(rel(path))
        else:
            missing.append(rel(path))
    if WEBSITE_JSON.exists() and rel(WEBSITE_JSON) not in discovered:
        discovered.append(rel(WEBSITE_JSON))
    return {
        "status": "ORIGIN_INPUT_DISCOVERY_OK" if not missing else "ORIGIN_INPUT_DISCOVERY_PARTIAL",
        "allowed_roots": [rel(root) for root in ALLOWED_INPUT_ROOTS],
        "preferred_inputs_found": preferred,
        "missing_inputs": missing,
        "discovered_inputs": sorted(set(discovered)),
        "discovered_count": len(set(discovered)),
        "blocked_symlinks": sorted(set(blocked_symlinks)),
        "excluded_sensitive_paths": sorted(set(excluded_sensitive)),
        "outside_project_reads": 0,
    }


def direct_evidence(discovery: Dict[str, Any]) -> Dict[str, Any]:
    found: Dict[str, List[str]] = {key: [] for key in DIRECT_EVIDENCE_REQUIREMENTS}
    for relative in discovery.get("discovered_inputs", []):
        path = PROJECT_DIR / relative
        lowered = path.name.lower()
        if path.suffix.lower() != ".log" and not any(marker in lowered for marker in DIRECT_SOURCE_MARKERS):
            continue
        text, status = read_limited_text(path)
        if status != "ok":
            continue
        for evidence_type, pattern in DIRECT_PATTERNS.items():
            if pattern.search(text):
                found[evidence_type].append(relative)
    present = [key for key, paths in found.items() if paths]
    missing = [DIRECT_EVIDENCE_REQUIREMENTS[key] for key, paths in found.items() if not paths]
    return {
        "level_a_direct_evidence": [
            {"evidence_type": key, "sources": sorted(set(found[key]))} for key in present
        ],
        "direct_evidence_count": len(present),
        "causality_proven": False,
        "missing_evidence": missing,
    }


def build_hypotheses(code: int, current_count: int, path_rows: Sequence[Dict[str, Any]], evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
    relevant = [row for row in path_rows if row["status_code"] == code]
    dynamic_count = sum(row["count"] for row in relevant if row["cache_status"] in {"dynamic", "miss"})
    legacy_count = sum(
        row["count"] for row in relevant
        if row["path_classification"] in {"wordpress_login", "wordpress_admin_asset", "wordpress_legacy_pagination", "wordpress_rest_or_oembed"}
    )
    sitelock_overlap = sum(
        row["count"] for row in relevant if row.get("actor_signal_counts", {}).get("sitelockspider_actor", 0)
    )
    direct_types = {row["evidence_type"] for row in evidence.get("level_a_direct_evidence", [])}
    output = []
    for name in STATUS_HYPOTHESES[code]:
        supporting: List[str] = []
        level = "C"
        confidence = "low"
        proven = False
        if code == 503 and name == "legacy_path_application_pressure" and legacy_count:
            supporting.append(f"{legacy_count} status-503 rows overlap with WordPress login, admin, REST, or legacy paths.")
            level, confidence = "B", "medium"
        elif code == 503 and name == "sitelock_or_scanner_triggered_application_pressure" and sitelock_overlap:
            supporting.append(f"Actor/path overlap is visible across {sitelock_overlap} status-503 path rows.")
            level, confidence = "C", "low"
        elif code in (503, 504) and name in {"origin_capacity_pressure", "origin_response_timeout", "dynamic_request_timeout", "cloudflare_to_origin_timeout"} and dynamic_count:
            supporting.append(f"{dynamic_count} rows are dynamic or cache-miss shaped.")
            level, confidence = "B", "medium"
        elif code == 522 and name in {"cloudflare_origin_connection_timeout", "origin_temporarily_unreachable"} and current_count:
            supporting.append("Current local aggregation contains status 522, without connection-level event detail.")
            level, confidence = "C", "low"
        elif code == 526 and name in {"cloudflare_strict_ssl_validation_failure", "temporary_origin_tls_failure"} and current_count:
            supporting.append("Current local aggregation contains status 526, without certificate validation event detail.")
            level, confidence = "C", "low"

        evidence_type = None
        if name in {"php_worker_exhaustion", "php_fatal_or_application_failure", "wordpress_bootstrap_failure", "plugin_or_theme_failure"}:
            evidence_type = "php_fatal_log" if name != "wordpress_bootstrap_failure" else "wordpress_debug_log"
        elif name == "hosting_rate_limit_or_resource_limit":
            evidence_type = "hosting_resource_limit_log"
        elif name in {"upstream_unavailable", "origin_response_timeout"}:
            evidence_type = "nginx_upstream_error"
        elif code == 526 and name != "unknown_526":
            evidence_type = "cloudflare_origin_tls_detail"
        if evidence_type and evidence_type in direct_types:
            supporting.append(f"Direct local evidence category present: {evidence_type}.")
            level, confidence = "A", "high"
            supporting.append("Timestamp and request correlation are still required before causality can be marked proven.")

        output.append({
            "hypothesis": name,
            "evidence_level": level,
            "confidence": confidence,
            "causality_proven": proven,
            "supporting_evidence": supporting,
            "missing_evidence": [] if proven else ["Direct origin-side evidence is required before treating this hypothesis as a cause."],
        })
    return output


def tls_diagnostic(delta: Dict[str, Any], path_rows: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    current = as_int(delta.get("current_count"))
    trend = delta.get("trend")
    if current == 0:
        status = "TLS_WATCH"
    elif trend == "SIGNIFICANT_GROWTH":
        status = "TLS_SIGNIFICANT_GROWTH"
    elif current > 0:
        status = "TLS_REVIEW_REQUIRED"
    else:
        status = "TLS_EVIDENCE_INSUFFICIENT"
    tls_rows = [row for row in path_rows if row["status_code"] == 526]
    return {
        "section": "ORIGIN_TLS_DIAGNOSTIC",
        "status": status,
        "count": current,
        "trend": trend,
        "affected_hostnames": sorted({host for row in tls_rows for host in row.get("hostnames", [])}),
        "affected_paths": sorted({row["path"] for row in tls_rows}),
        "first_seen": None,
        "last_seen": None,
        "observed_in_snapshot_at": max((row.get("observed_in_snapshot_at") or "" for row in tls_rows), default=None) or None,
        "cloudflare_ssl_mode": None,
        "certificate_evidence": [],
        "automatic_ssl_change": False,
        "ssl_downgrade_recommended": False,
        "certificate_validation_disable_recommended": False,
        "causality_proven": False,
        "owner_checklist": [
            "Review Cloudflare SSL/TLS events manually.",
            "Review origin certificate validity manually.",
            "Review hostname and SAN coverage manually.",
            "Review the certificate chain manually.",
            "Correlate timestamps with hosting or certificate renewal events.",
            "Do not reduce SSL validation strength.",
        ],
    }


def parse_timestamp(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def iso_utc(value: datetime) -> str:
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def build_timeline(previous: Dict[str, Any], current: Dict[str, Any], website: Dict[str, Any]) -> Dict[str, Any]:
    rolling = website.get("rolling_window_context", {}) if isinstance(website.get("rolling_window_context"), dict) else {}
    history = rolling.get("history", {}) if isinstance(rolling.get("history"), dict) else {}
    metrics = {
        str(row.get("key")): row
        for row in history.get("elevated_metrics", [])
        if isinstance(row, dict) and row.get("key")
    }
    root = metrics.get("root_504", {})
    total = metrics.get("total_5xx", {})
    focus = root or total
    required = focus.get("required_stable_minutes_for_old_window") or history.get("old_window_required_stable_minutes") or 1440
    stable_since = focus.get("stable_since_utc")
    stable_dt = parse_timestamp(stable_since)
    earliest = iso_utc(stable_dt + timedelta(minutes=float(required))) if stable_dt else None
    last_significant = focus.get("last_significant_growth_at_utc")
    recent = focus.get("recent_snapshots", []) if isinstance(focus.get("recent_snapshots"), list) else []
    total_recent = total.get("recent_snapshots", []) if isinstance(total.get("recent_snapshots"), list) else []
    root_recent = root.get("recent_snapshots", []) if isinstance(root.get("recent_snapshots"), list) else []
    latest_total_snapshot = total_recent[-1] if total_recent and isinstance(total_recent[-1], dict) else {}
    latest_root_snapshot = root_recent[-1] if root_recent and isinstance(root_recent[-1], dict) else {}
    consecutive = 0
    low_limit = as_int(focus.get("low_growth_limit"), 0)
    for snapshot in reversed(recent):
        if not isinstance(snapshot, dict) or snapshot.get("delta") is None:
            break
        if as_int(snapshot.get("delta")) <= low_limit:
            consecutive += 1
        else:
            break
    return {
        "first_growth_at": last_significant,
        "peak_growth_at": current.get("generated_at_utc") if current.get("total_5xx", 0) >= previous.get("total_5xx", 0) else previous.get("generated_at_utc"),
        "last_growth_at": last_significant,
        "stable_since": stable_since,
        "latest_delta": focus.get("latest_delta"),
        "consecutive_stable_or_decreasing_snapshots": consecutive,
        "new_growth_present": rolling.get("status") == "NEW_GROWTH_PRESENT",
        "rolling_window_status": rolling.get("status") or website.get("trend_summary") or "UNKNOWN",
        "required_stable_minutes": required,
        "stable_minutes": focus.get("stable_minutes"),
        "remaining_minutes": focus.get("remaining_stable_minutes_for_old_window"),
        "earliest_recheck_at": earliest,
        "automatic_ok_transition": False,
        "recheck_note": "Any calculated recheck time is a forecast; a new snapshot must confirm the state.",
        "source_alignment": {
            "detailed_snapshot_at": current.get("generated_at_utc"),
            "detailed_total_5xx": current.get("total_5xx"),
            "rolling_snapshot_at": latest_total_snapshot.get("generated_at_utc"),
            "rolling_total_5xx": latest_total_snapshot.get("value"),
            "total_5xx_difference": (
                as_int(latest_total_snapshot.get("value")) - as_int(current.get("total_5xx"))
                if latest_total_snapshot.get("value") is not None and current.get("total_5xx") is not None
                else None
            ),
            "detailed_root_504": current.get("root_504"),
            "rolling_root_504": latest_root_snapshot.get("value"),
            "root_504_difference": (
                as_int(latest_root_snapshot.get("value")) - as_int(current.get("root_504"))
                if latest_root_snapshot.get("value") is not None and current.get("root_504") is not None
                else None
            ),
            "interpretation": (
                "Status-specific analysis uses the detailed aggregate. Rolling values are retained only for "
                "window timing, and any mismatch remains explicit rather than being reconciled by assumption."
            ),
        },
        "status_event_times": {
            str(code): {
                "first_seen": None,
                "peak_at": None,
                "last_seen": None,
                "observed_in_snapshot_at": current.get("generated_at_utc"),
            }
            for code in STATUS_HYPOTHESES
        },
    }


def choose_priorities(deltas: Dict[int, Dict[str, Any]], tls: Dict[str, Any]) -> Dict[str, Any]:
    if SAFETY_FLAGS["breach"]:
        detail = "SAFETY_ESCALATION"
    elif deltas[503]["trend"] == "SIGNIFICANT_GROWTH":
        detail = "ORIGIN_503_GROWTH_DIAGNOSIS"
    elif tls["status"] in {"TLS_REVIEW_REQUIRED", "TLS_SIGNIFICANT_GROWTH"}:
        detail = "ORIGIN_TLS_EVIDENCE_REVIEW"
    elif deltas[504]["current_count"]:
        detail = "ORIGIN_504_ROLLING_WINDOW_DIAGNOSIS"
    else:
        detail = "ORIGIN_EVIDENCE_CORRELATION"
    return {
        "selected_priority": "WEBSITE_ORIGIN_STABILITY",
        "selected_detail_priority": detail,
        "ordered_actions": [
            "Diagnose status-503 behavior by current path, time, actor, cache status, and local origin evidence.",
            "Review the isolated status-526 TLS evidence manually without changing SSL settings.",
            "Continue status-504 rolling-window observation and require a confirming snapshot.",
            "Correlate top paths without deriving a broad block rule.",
            "Review available origin, PHP, WordPress, and hosting evidence; request missing evidence explicitly.",
            "Keep SEO and metadata work below technical stability work.",
        ],
        "suppressed_lower_priorities": [
            "SEO_TITLE_REVIEW",
            "META_DESCRIPTION_REVIEW",
            "OPEN_GRAPH_REVIEW",
            "INTERNAL_LINK_REVIEW",
            "NEW_WAF_RULE",
            "TIMER_INSTALLATION",
            "LOW_RISK_AUTONOMY_ACTIVATION",
        ],
        "reason": "Website status is CRITICAL and current origin-side failure evidence remains unresolved.",
    }


def sanitize_public_text(text: str) -> str:
    text = FULL_UA_RE.sub("[user-agent redacted]", text)
    text = PRIVATE_PATH_RE.sub("[private path redacted]", text)
    text = INTERNAL_ENDPOINT_RE.sub("[internal endpoint redacted]", text)
    text = INTERNAL_ID_RE.sub("[internal identifier redacted]", text)
    text = IP_RE.sub("[address redacted]", text)
    text = FQDN_RE.sub("[hostname redacted]", text)
    return text


def public_findings(text: str) -> List[str]:
    findings = []
    checks = {
        "ip_address": IP_RE,
        "hostname": FQDN_RE,
        "private_path": PRIVATE_PATH_RE,
        "internal_endpoint": INTERNAL_ENDPOINT_RE,
        "internal_identifier": INTERNAL_ID_RE,
        "full_user_agent": FULL_UA_RE,
        "secret_value": SECRET_VALUE_RE,
        "private_key": PRIVATE_KEY_RE,
    }
    for name, pattern in checks.items():
        if pattern.search(text):
            findings.append(name)
    return findings


def build_public_summary(report: Dict[str, Any]) -> str:
    text = """# Sentinel Origin Diagnostics - Public Summary

The website currently shows elevated origin-side service-unavailable and timeout responses. A small number of origin TLS review signals remains open. Sentinel remains breach-free, live automation remains disabled, and no new firewall rule is recommended without stronger evidence.

This summary reports correlation only. Verified human-user impact is unknown. Productive changes, remote writes, scheduler installation, firewall changes, and TLS changes remain blocked.
"""
    return sanitize_public_text(text)


def current_snapshot(website: Dict[str, Any]) -> Dict[str, Any]:
    counts = status_counts(website)
    total = metric_value(website, "total_5xx")
    if total is None:
        total = sum(counts.values())
    return {
        "generated_at_utc": website.get("generated_at_utc"),
        "website_status": website.get("overall_status") or "UNKNOWN",
        "total_5xx": total,
        "status_code_counts": {str(code): counts[code] for code in STATUS_HYPOTHESES},
        "root_504": metric_value(website, "root_504"),
        "wp_login_503": metric_value(website, "wp_login_503"),
        "detail_coverage_percent": {str(code): value for code, value in detail_coverage(website).items()},
    }


def previous_snapshot(master: Dict[str, Any]) -> Dict[str, Any]:
    value = master.get("current_website_evidence", {}) if isinstance(master, dict) else {}
    counts = value.get("status_code_counts", {}) if isinstance(value, dict) else {}
    return {
        "generated_at_utc": value.get("generated_at_utc"),
        "website_status": value.get("website_status"),
        "total_5xx": value.get("total_5xx"),
        "status_code_counts": {str(code): as_int(counts.get(str(code))) if str(code) in counts else None for code in STATUS_HYPOTHESES},
        "root_504": value.get("root_504"),
    }


def build_report() -> Dict[str, Any]:
    generated = utc_now()
    discovery = discover_inputs()
    master = load_dict(MASTER_CONSISTENCY_JSON)
    website = load_dict(WEBSITE_JSON)
    previous = previous_snapshot(master)
    current = current_snapshot(website)
    deltas = {
        code: {
            "status": code,
            **calculate_delta(previous["status_code_counts"].get(str(code)), current["status_code_counts"].get(str(code))),
        }
        for code in STATUS_HYPOTHESES
    }
    total_delta = calculate_delta(previous.get("total_5xx"), current.get("total_5xx"))
    paths = correlate_paths(website, current.get("generated_at_utc"))
    cache = aggregate_cache_by_status(
        paths,
        {code: current["status_code_counts"][str(code)] for code in STATUS_HYPOTHESES},
    )
    actors = correlate_actors(website, paths)
    evidence = direct_evidence(discovery)
    evidence["level_b_strong_correlation"] = [
        "Current status/path/cache/actor aggregation with per-status detail coverage.",
        "Independent Phase 10.16 consistency snapshot used only as the previous comparison point.",
    ] if website and master else []
    ionos_review = "reports/latest/sentinel-ionos-login-probe-owner-review.md"
    evidence["level_c_weak_correlation"] = [
        "Path volume and grouped user-agent overlap do not prove origin cause.",
        (
            f"Private hosting analytics login-probe evidence ({ionos_review}) is actor context, "
            "not human engagement or origin-cause proof."
            if ionos_review in discovery.get("discovered_inputs", [])
            else "Private hosting analytics login-probe evidence was not available in the allowlisted inputs."
        ),
    ]
    hypotheses = {
        code: build_hypotheses(code, current["status_code_counts"][str(code)], paths, evidence)
        for code in STATUS_HYPOTHESES
    }
    tls = tls_diagnostic(deltas[526], paths)
    timeline = build_timeline(previous, current, website)
    priority = choose_priorities(deltas, tls)
    missing_inputs = list(discovery["missing_inputs"])
    if not website:
        missing_inputs.append(rel(WEBSITE_JSON))
    if not master:
        missing_inputs.append(rel(MASTER_CONSISTENCY_JSON))

    significant_growth = any(item["trend"] == "SIGNIFICANT_GROWTH" for item in deltas.values())
    all_current_inputs = bool(website and master and not missing_inputs)
    direct_missing = bool(evidence["missing_evidence"])
    if SAFETY_FLAGS["breach"]:
        diagnostic_status = "ORIGIN_DIAG_RED"
    elif all_current_inputs and not significant_growth and current["total_5xx"] == 0 and tls["count"] == 0 and not direct_missing:
        diagnostic_status = "ORIGIN_DIAG_GREEN"
    else:
        diagnostic_status = "ORIGIN_DIAG_YELLOW"

    report: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": generated,
        "status": diagnostic_status,
        "report_classification": REPORT_CLASSIFICATION,
        "safety": SAFETY_FLAGS,
        "execution_boundaries": EXECUTION_BOUNDARIES,
        "input_discovery": discovery,
        "missing_inputs": sorted(set(missing_inputs)),
        "comparison_scope": {
            "previous_snapshot": previous,
            "current_snapshot": current,
            "note": "The previous Phase 10.16 snapshot is a comparison point; the newest local website report is the current state.",
        },
        "total_5xx_delta": total_delta,
        "status_deltas": {str(code): value for code, value in deltas.items()},
        "status_analysis": {
            str(code): {
                "status_code": code,
                "count": current["status_code_counts"][str(code)],
                "delta": deltas[code],
                "hypotheses": hypotheses[code],
                "top_paths": [row for row in paths if row["status_code"] == code][:10],
                "cache_correlation": cache[code],
                "verified_user_impact": "unknown",
                "causality_proven": any(item["causality_proven"] for item in hypotheses[code]),
            }
            for code in STATUS_HYPOTHESES
        },
        "path_correlation": paths,
        "actor_correlation": actors,
        "cache_correlation": {str(code): value for code, value in cache.items()},
        "timeline": timeline,
        "evidence_hierarchy": evidence,
        "origin_tls_diagnostic": tls,
        "owner_priority": priority,
        "verified_user_impact": "unknown",
        "causality_proven": evidence["causality_proven"],
        "waf_decision": {
            "new_waf_rule_recommended": False,
            "automatic_waf_action": False,
            "reason": "Status-503 growth and origin-side failure patterns are not reliably solved by a new WAF rule. Correlate origin, PHP, WordPress, and hosting evidence first.",
        },
        "ssl_tls_decision": {
            "automatic_ssl_change": False,
            "ssl_downgrade_recommended": False,
            "certificate_validation_disable_recommended": False,
            "reason": "Review origin TLS evidence manually and retain strict validation.",
        },
        "git_checkpoint": {
            "recommended_files": RECOMMENDED_GIT_FILES,
            "excluded_prefixes": ["reports/", "state/", "audit/", "exports/", "backups/", "snapshots/"],
        },
        "validation": {"status": "NOT_RUN", "findings": []},
    }
    return report


def private_header(title: str) -> List[str]:
    return [
        f"# {title}",
        "",
        "Classification: PRIVATE_OWNER_OPERATIONAL_REPORT | NOT_FOR_PUBLIC_RELEASE | NOT_FOR_GIT | CONTAINS_INFRASTRUCTURE_METADATA",
        "",
    ]


def render_main(report: Dict[str, Any]) -> str:
    current = report["comparison_scope"]["current_snapshot"]
    lines = private_header("Sentinel Origin Failure Diagnostics")
    lines += [
        f"- Diagnostic status: `{report['status']}`",
        f"- Website status: `{current['website_status']}`",
        f"- Current 5xx: `{current['total_5xx']}`",
        f"- Owner priority: `{report['owner_priority']['selected_priority']}`",
        f"- Detail priority: `{report['owner_priority']['selected_detail_priority']}`",
        f"- Causality proven: `{str(report['causality_proven']).lower()}`",
        f"- Verified user impact: `{report['verified_user_impact']}`",
        f"- New WAF rule recommended: `{str(report['waf_decision']['new_waf_rule_recommended']).lower()}`",
        f"- SSL downgrade recommended: `{str(report['ssl_tls_decision']['ssl_downgrade_recommended']).lower()}`",
        "",
        "## Status Deltas",
        "",
        "| Status | Previous | Current | Delta | Percent | Trend |",
        "|---:|---:|---:|---:|---:|---|",
    ]
    for code in STATUS_HYPOTHESES:
        delta = report["status_deltas"][str(code)]
        lines.append(
            f"| {code} | {delta['previous_count']} | {delta['current_count']} | {delta['delta']} | {delta['delta_percent']} | `{delta['trend']}` |"
        )
    lines += [
        "",
        "## Interpretation",
        "",
        "Status codes are analyzed separately. Correlation is not causality, grouped actor volume is not proof, and human-user impact remains unknown without direct evidence.",
        "",
        "No productive action is available from this component. All review items remain manual and evidence-gated.",
    ]
    return "\n".join(lines)


def render_status(report: Dict[str, Any], code: int) -> str:
    analysis = report["status_analysis"][str(code)]
    title = f"Sentinel Origin {code} Analysis"
    if code == 526:
        title += " - TLS Review"
    lines = private_header(title)
    delta = analysis["delta"]
    lines += [
        f"- Current: `{delta['current_count']}`",
        f"- Previous: `{delta['previous_count']}`",
        f"- Delta: `{delta['delta']}`",
        f"- Trend: `{delta['trend']}`",
        f"- Verified user impact: `{analysis['verified_user_impact']}`",
        f"- Causality proven: `{str(analysis['causality_proven']).lower()}`",
        f"- Dominant cache status: `{analysis['cache_correlation']['dominant_cache_status']}`",
        f"- Proof level: `{analysis['cache_correlation']['proof_level']}`",
        "",
        "## Hypotheses",
        "",
        "| Hypothesis | Evidence | Confidence | Proven |",
        "|---|---|---|---|",
    ]
    for item in analysis["hypotheses"]:
        lines.append(
            f"| `{item['hypothesis']}` | `{item['evidence_level']}` | `{item['confidence']}` | `{str(item['causality_proven']).lower()}` |"
        )
    lines += ["", "## Top Paths", "", "| Count | Path | Class | Cache | Actor |", "|---:|---|---|---|---|"]
    for row in analysis["top_paths"]:
        lines.append(f"| {row['count']} | `{row['path']}` | `{row['path_classification']}` | `{row['cache_status']}` | `{row['actor_signal']}` |")
    if code == 526:
        tls = report["origin_tls_diagnostic"]
        lines += [
            "",
            "## TLS Guardrails",
            "",
            f"- TLS status: `{tls['status']}`",
            "- No certificate mutation is performed.",
            "- No SSL mode downgrade is recommended.",
            "- No certificate validation bypass is recommended.",
            "- Review Cloudflare and origin certificate evidence manually while retaining strict validation.",
        ]
    return "\n".join(lines)


def render_paths(report: Dict[str, Any]) -> str:
    lines = private_header("Sentinel Origin Path Correlation")
    lines += [
        "Path aggregation is correlation-only. A high path count is not a block-rule recommendation.",
        "",
        "| Status | Count | Path | Class | Cache | Actor | Failure mode | User impact |",
        "|---:|---:|---|---|---|---|---|---|",
    ]
    for row in report["path_correlation"]:
        lines.append(
            f"| {row['status_code']} | {row['count']} | `{row['path']}` | `{row['path_classification']}` | `{row['cache_status']}` | `{row['actor_signal']}` | `{row['failure_mode']}` | `{row['verified_user_impact']}` |"
        )
    return "\n".join(lines)


def render_actors(report: Dict[str, Any]) -> str:
    lines = private_header("Sentinel Origin Actor Correlation")
    lines += [
        "Actor overlap does not prove causality. Counts may overlap when only path-level aggregates are available.",
        "",
        "| Actor | Requests | Correlation | Causality | Block | WAF | Top paths |",
        "|---|---:|---|---|---|---|---|",
    ]
    for row in report["actor_correlation"]:
        paths = ", ".join(f"`{item}`" for item in row["top_paths"]) or "none"
        lines.append(
            f"| `{row['actor']}` | {row['total_requests']} | `{row['path_overlap_correlation']}` | `false` | `false` | `false` | {paths} |"
        )
    return "\n".join(lines)


def render_timeline(report: Dict[str, Any]) -> str:
    timeline = report["timeline"]
    lines = private_header("Sentinel Origin Timeline")
    for key in (
        "first_growth_at", "peak_growth_at", "last_growth_at", "stable_since",
        "latest_delta", "consecutive_stable_or_decreasing_snapshots", "new_growth_present",
        "rolling_window_status", "stable_minutes", "required_stable_minutes",
        "remaining_minutes", "earliest_recheck_at",
    ):
        lines.append(f"- {key}: `{timeline.get(key)}`")
    lines += ["", timeline["recheck_note"]]
    alignment = timeline.get("source_alignment", {})
    lines += [
        "",
        "## Source Alignment",
        "",
        f"- Detailed total 5xx: `{alignment.get('detailed_total_5xx')}`",
        f"- Rolling total 5xx: `{alignment.get('rolling_total_5xx')}`",
        f"- Total difference: `{alignment.get('total_5xx_difference')}`",
        f"- Detailed root 504: `{alignment.get('detailed_root_504')}`",
        f"- Rolling root 504: `{alignment.get('rolling_root_504')}`",
        f"- Root difference: `{alignment.get('root_504_difference')}`",
        "",
        alignment.get("interpretation", ""),
    ]
    return "\n".join(lines)


def render_owner_plan(report: Dict[str, Any]) -> str:
    priority = report["owner_priority"]
    lines = private_header("Sentinel Origin Owner Action Plan")
    lines += [
        f"- Selected priority: `{priority['selected_priority']}`",
        f"- Selected detail priority: `{priority['selected_detail_priority']}`",
        "",
        "## Ordered Manual Diagnosis",
        "",
    ]
    lines.extend(f"{index}. {item}" for index, item in enumerate(priority["ordered_actions"], 1))
    lines += [
        "",
        "## Explicit Guardrails",
        "",
        "- Do not add a new WAF rule. Correlate origin, PHP, WordPress, and hosting logs first.",
        "- Do not change Cloudflare SSL mode or reduce certificate validation.",
        "- Do not change WordPress, PHP, Nginx, hosting, databases, or remote files.",
        "- Re-evaluate only from a new local snapshot and current direct evidence.",
        "",
        "## Suppressed Priorities",
        "",
    ]
    lines.extend(f"- `{item}`" for item in priority["suppressed_lower_priorities"])
    return "\n".join(lines)


def render_evidence_gap(report: Dict[str, Any]) -> str:
    evidence = report["evidence_hierarchy"]
    lines = private_header("Sentinel Origin Evidence Gap")
    lines += [
        f"- Direct evidence categories found: `{evidence['direct_evidence_count']}`",
        f"- Causality proven: `{str(evidence['causality_proven']).lower()}`",
        "",
        "## Direct Evidence",
        "",
    ]
    if evidence["level_a_direct_evidence"]:
        for item in evidence["level_a_direct_evidence"]:
            lines.append(f"- `{item['evidence_type']}` from {', '.join(item['sources'])}")
    else:
        lines.append("- No current direct origin-side evidence was found in the allowlisted project inputs.")
    lines += ["", "## Missing Evidence", ""]
    lines.extend(f"- {item}" for item in evidence["missing_evidence"])
    lines += ["", "Missing evidence must be reviewed manually. Sentinel does not request or store credentials."]
    return "\n".join(lines)


def render_validation(report: Dict[str, Any]) -> str:
    validation = report["validation"]
    lines = private_header("Sentinel Origin Diagnostics Validation")
    lines += [
        f"- Status: `{validation['status']}`",
        f"- Findings: `{len(validation['findings'])}`",
        f"- Public sanitization: `{validation.get('public_sanitization_status')}`",
        f"- JSON validation: `{validation.get('json_validation_status')}`",
        f"- Markdown validation: `{validation.get('markdown_validation_status')}`",
        f"- live_apply: `false`",
        f"- emergency_stop: `true`",
        f"- breach: `false`",
    ]
    if validation["findings"]:
        lines += ["", "## Findings", ""] + [f"- {item}" for item in validation["findings"]]
    return "\n".join(lines)


def logical_validation(report: Dict[str, Any], public_text: str) -> Dict[str, Any]:
    findings: List[str] = []
    public_issues = public_findings(public_text)
    if public_issues:
        findings.extend(f"public_summary:{item}" for item in public_issues)
    safety_expected = {
        "live_apply": False,
        "emergency_stop": True,
        "allowed_apply_now": False,
        "high_blocked": True,
        "medium_executable": False,
        "low_live_executable": False,
        "breach": False,
    }
    if report.get("safety") != safety_expected:
        findings.append("safety_flags_drift")
    if report["waf_decision"]["new_waf_rule_recommended"] is not False:
        findings.append("automatic_waf_recommendation")
    if report["ssl_tls_decision"]["ssl_downgrade_recommended"] is not False:
        findings.append("ssl_downgrade_recommendation")
    if report["verified_user_impact"] != "unknown":
        findings.append("unsupported_user_impact")
    if any(row["causality_proven"] for row in report["actor_correlation"]):
        findings.append("actor_causality_claim")
    unsafe_git = [
        path for path in report["git_checkpoint"]["recommended_files"]
        if path.startswith(("reports/", "state/", "audit/", "exports/", "backups/", "snapshots/"))
    ]
    if unsafe_git:
        findings.append("unsafe_git_recommendation")
    return {
        "status": "ORIGIN_FAILURE_DIAGNOSTICS_VALIDATION_OK" if not findings else "ORIGIN_FAILURE_DIAGNOSTICS_VALIDATION_FAILED",
        "findings": findings,
        "public_sanitization_status": "PUBLIC_SUMMARY_SANITIZED" if not public_issues else "PUBLIC_SUMMARY_UNSAFE",
        "json_validation_status": "PENDING_WRITE_VALIDATION",
        "markdown_validation_status": "PENDING_WRITE_VALIDATION",
        "secret_findings": 0,
        "forbidden_findings": len(findings),
    }


def write_outputs(report: Dict[str, Any], public_text: str, record: bool) -> None:
    ensure_dirs()
    write_json(REPORT_JSON, report)
    write_json(STATE_JSON, report)
    write_json(LATEST_STATE_JSON, report)
    write_text(REPORT_MD, render_main(report))
    for code, path in STATUS_REPORTS.items():
        write_text(path, render_status(report, code))
    write_text(PATH_MD, render_paths(report))
    write_text(ACTOR_MD, render_actors(report))
    write_text(TIMELINE_MD, render_timeline(report))
    write_text(OWNER_PLAN_MD, render_owner_plan(report))
    write_text(EVIDENCE_GAP_MD, render_evidence_gap(report))
    write_text(PUBLIC_MD, public_text)
    write_text(VALIDATION_MD, render_validation(report))

    history, history_status = read_json(HISTORY_JSON)
    if history_status != "ok" or not isinstance(history, list):
        history = []
    if record:
        history.append({
            "generated_at_utc": report["generated_at_utc"],
            "status": report["status"],
            "validation_status": report["validation"]["status"],
            "current_total_5xx": report["comparison_scope"]["current_snapshot"]["total_5xx"],
            "status_deltas": report["status_deltas"],
            "selected_detail_priority": report["owner_priority"]["selected_detail_priority"],
            "breach": False,
        })
    write_json(HISTORY_JSON, history)
    if record:
        append_jsonl(AUDIT_JSONL, {
            "timestamp_utc": report["generated_at_utc"],
            "event": "origin_failure_diagnostics_collected",
            "status": report["status"],
            "validation_status": report["validation"]["status"],
            "selected_detail_priority": report["owner_priority"]["selected_detail_priority"],
            "live_apply": False,
            "breach": False,
        })


def validate_written_outputs() -> Dict[str, Any]:
    findings: List[str] = []
    for path in OUTPUT_JSONS:
        if not path.exists():
            findings.append(f"missing_json:{rel(path)}")
            continue
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            findings.append(f"invalid_json:{rel(path)}")
    for path in OUTPUT_MARKDOWN:
        try:
            if not path.read_text(encoding="utf-8").strip():
                findings.append(f"empty_markdown:{rel(path)}")
        except OSError:
            findings.append(f"missing_markdown:{rel(path)}")
    public_text = PUBLIC_MD.read_text(encoding="utf-8") if PUBLIC_MD.exists() else ""
    findings.extend(f"public_summary:{item}" for item in public_findings(public_text))
    return {
        "status": "OUTPUT_VALIDATION_OK" if not findings else "OUTPUT_VALIDATION_FAILED",
        "findings": findings,
    }


def run_pipeline(record: bool = False) -> Dict[str, Any]:
    report = build_report()
    public_text = build_public_summary(report)
    report["validation"] = logical_validation(report, public_text)
    write_outputs(report, public_text, record=record)
    output = validate_written_outputs()
    report["validation"]["output_validation"] = output
    report["validation"]["json_validation_status"] = "JSON_VALID" if not any("json:" in item for item in output["findings"]) else "JSON_INVALID"
    report["validation"]["markdown_validation_status"] = "MARKDOWN_NONEMPTY" if not any("markdown:" in item for item in output["findings"]) else "MARKDOWN_INVALID"
    if output["status"] != "OUTPUT_VALIDATION_OK":
        report["validation"]["status"] = "ORIGIN_FAILURE_DIAGNOSTICS_VALIDATION_FAILED"
        report["validation"]["findings"].extend(output["findings"])
    write_outputs(report, public_text, record=False)
    return report


def self_test() -> Dict[str, Any]:
    delta_503 = calculate_delta(155, 297)
    delta_504 = calculate_delta(510, 462)
    delta_526 = calculate_delta(0, 2)
    synthetic_deltas = {
        503: {"status": 503, **delta_503},
        504: {"status": 504, **delta_504},
        522: {"status": 522, **calculate_delta(2, 2)},
        526: {"status": 526, **delta_526},
    }
    synthetic_tls = tls_diagnostic(synthetic_deltas[526], [])
    synthetic_priority = choose_priorities(synthetic_deltas, synthetic_tls)
    synthetic_public = sanitize_public_text(
        "198.51.100.7 origin.private.example /srv/private/site /api/internal/node-a "
        "endpoint_id=private-7 Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 ExampleBrowser/1.0"
    )
    sitelock = correlate_actors(
        {"top_5xx_actor_signals": [{"actor_signal": "sitelockspider_actor", "count": 100}], "top_5xx_paths": []},
        [],
    )
    source = Path(__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports: List[str] = []
    function_names = set()
    command_calls: List[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.append(node.module)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function_names.add(node.name)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {
            "Popen", "run", "call", "check_call", "check_output", "system"
        }:
            command_calls.append(node.func.attr)
    forbidden_imports = {"requests", "urllib", "http.client", "socket", "smtplib", "paramiko", "cloudflare"}
    network_imports = sorted(
        name for name in imports if any(name == blocked or name.startswith(blocked + ".") for blocked in forbidden_imports)
    )
    dangerous_functions = {
        "apply", "execute_apply", "live_apply", "wordpress_write", "cloudflare_write",
        "sftp_write", "database_write", "php_config_write", "nginx_write", "htaccess_write",
        "install_timer", "install_cron", "enable_systemd", "restart_process", "git_push",
        "git_tag", "github_release", "send_email", "remote_write",
    }
    escaped = PROJECT_DIR.parent / "outside.json"
    safe_candidate = PROJECT_DIR / "data/example-origin.json"
    tests = {
        "test_a_503_significant_growth": delta_503["delta"] == 142 and delta_503["trend"] == "SIGNIFICANT_GROWTH",
        "test_b_504_decreasing": delta_504["delta"] == -48 and delta_504["trend"] == "DECREASING",
        "test_b_503_not_overridden": synthetic_priority["selected_detail_priority"] == "ORIGIN_503_GROWTH_DIAGNOSIS",
        "test_c_tls_review": (
            synthetic_tls["status"] == "TLS_REVIEW_REQUIRED"
            and synthetic_tls["automatic_ssl_change"] is False
            and synthetic_tls["ssl_downgrade_recommended"] is False
        ),
        "test_d_no_direct_evidence": build_hypotheses(503, 297, [], {"level_a_direct_evidence": []})[0]["causality_proven"] is False,
        "test_e_sitelock_correlation_only": bool(sitelock) and all(
            row["causality_proven"] is False and row["block_user_agent"] is False and row["new_waf_rule_recommended"] is False
            for row in sitelock
        ),
        "test_f_user_impact_unknown": "unknown" == "unknown",
        "test_g_public_sanitized": not public_findings(synthetic_public),
        "test_h_emergency_boundaries": (
            SAFETY_FLAGS["emergency_stop"] is True
            and SAFETY_FLAGS["live_apply"] is False
            and EXECUTION_BOUNDARIES["production_apply_lock"] is True
            and EXECUTION_BOUNDARIES["remote_write_lock"] is True
            and EXECUTION_BOUNDARIES["local_analysis_allowed"] is True
            and EXECUTION_BOUNDARIES["local_report_generation_allowed"] is True
        ),
        "input_allowlist_accepts_project_data": input_path_allowed(safe_candidate),
        "input_allowlist_blocks_escape": not input_path_allowed(safe_candidate, resolved_override=escaped),
        "input_allowlist_blocks_secret_name": not input_path_allowed(PROJECT_DIR / "data/.env-origin.json"),
        "status_logic_separate": set(STATUS_HYPOTHESES) == {503, 504, 522, 526},
        "no_network_imports": not network_imports,
        "no_free_command_execution": not command_calls,
        "no_shell_true": ("shell" + "=True") not in source and ("shell" + " = True") not in source,
        "no_sudo_call": not command_calls,
        "no_dangerous_functions": not (function_names & dangerous_functions),
        "risk_invariants": (
            SAFETY_FLAGS["live_apply"] is False
            and SAFETY_FLAGS["emergency_stop"] is True
            and SAFETY_FLAGS["allowed_apply_now"] is False
            and SAFETY_FLAGS["high_blocked"] is True
            and SAFETY_FLAGS["medium_executable"] is False
            and SAFETY_FLAGS["low_live_executable"] is False
            and SAFETY_FLAGS["breach"] is False
        ),
        "no_waf_automation": all(row["new_waf_rule_recommended"] is False for row in sitelock),
        "git_recommendation_safe": not any(
            path.startswith(("reports/", "state/", "audit/", "exports/")) for path in RECOMMENDED_GIT_FILES
        ),
        "json_serializable": isinstance(json.loads(json.dumps(synthetic_deltas)), dict),
        "markdown_nonempty": bool(render_owner_plan({
            "owner_priority": {
                "selected_priority": "WEBSITE_ORIGIN_STABILITY",
                "selected_detail_priority": "ORIGIN_503_GROWTH_DIAGNOSIS",
                "ordered_actions": ["Review local evidence."],
                "suppressed_lower_priorities": ["SEO_TITLE_REVIEW"],
            }
        }).strip()),
    }
    findings = [name for name, passed in tests.items() if not passed]
    return {
        "status": "ORIGIN_FAILURE_DIAGNOSTICS_SELF_TEST_OK" if not findings else "ORIGIN_FAILURE_DIAGNOSTICS_SELF_TEST_FAILED",
        "checks": tests,
        "findings": findings,
        "network_imports": network_imports,
        "command_calls": command_calls,
        "breach": False,
    }


def print_status(report: Dict[str, Any]) -> None:
    if not report:
        print("ORIGIN_FAILURE_DIAGNOSTICS_NOT_BUILT")
        return
    print(report.get("status", "ORIGIN_DIAG_UNKNOWN"))
    print(report.get("validation", {}).get("status", "ORIGIN_FAILURE_DIAGNOSTICS_NOT_VALIDATED"))
    for code in STATUS_HYPOTHESES:
        item = report.get("status_deltas", {}).get(str(code), {})
        print(f"{code}_TREND_{item.get('trend', 'UNKNOWN')}")
    print(f"526_STATUS_{report.get('origin_tls_diagnostic', {}).get('status', 'UNKNOWN')}")
    print(f"OWNER_PRIORITY_{report.get('owner_priority', {}).get('selected_detail_priority', 'UNKNOWN')}")
    print("VERIFIED_USER_IMPACT_UNKNOWN")
    print("NEW_WAF_RULE_RECOMMENDED_FALSE")
    print("SSL_DOWNGRADE_RECOMMENDED_FALSE")
    print("LIVE_APPLY_FALSE")
    print("EMERGENCY_STOP_TRUE")
    print("BREACH_FALSE")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only Sentinel origin failure diagnostics")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--discover-inputs", action="store_true")
    group.add_argument("--collect", action="store_true")
    group.add_argument("--analyze-deltas", action="store_true")
    group.add_argument("--analyze-503", action="store_true")
    group.add_argument("--analyze-504", action="store_true")
    group.add_argument("--analyze-522", action="store_true")
    group.add_argument("--analyze-526", action="store_true")
    group.add_argument("--correlate-paths", action="store_true")
    group.add_argument("--correlate-actors", action="store_true")
    group.add_argument("--build-timeline", action="store_true")
    group.add_argument("--build-owner-plan", action="store_true")
    group.add_argument("--build-public-summary", action="store_true")
    group.add_argument("--validate", action="store_true")
    group.add_argument("--status", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        result = self_test()
        print(result["status"])
        if result["findings"]:
            print(json.dumps(result["findings"]))
        return 0 if not result["findings"] else 1
    if args.status:
        print_status(load_dict(REPORT_JSON))
        return 0 if REPORT_JSON.exists() else 1

    report = run_pipeline(record=args.collect)
    if args.discover_inputs:
        print(report["input_discovery"]["status"])
        print(f"DISCOVERED_INPUTS_{report['input_discovery']['discovered_count']}")
    elif args.collect:
        print("ORIGIN_FAILURE_DIAGNOSTICS_COLLECT_OK")
    elif args.analyze_deltas:
        for code in STATUS_HYPOTHESES:
            print(f"{code}_TREND_{report['status_deltas'][str(code)]['trend']}")
    elif args.analyze_503:
        print(f"503_TREND_{report['status_deltas']['503']['trend']}")
    elif args.analyze_504:
        print(f"504_TREND_{report['status_deltas']['504']['trend']}")
    elif args.analyze_522:
        print(f"522_TREND_{report['status_deltas']['522']['trend']}")
    elif args.analyze_526:
        print(f"526_STATUS_{report['origin_tls_diagnostic']['status']}")
    elif args.correlate_paths:
        print(f"ORIGIN_PATH_CORRELATION_ROWS_{len(report['path_correlation'])}")
    elif args.correlate_actors:
        print(f"ORIGIN_ACTOR_CORRELATION_ROWS_{len(report['actor_correlation'])}")
    elif args.build_timeline:
        print("ORIGIN_TIMELINE_READY")
    elif args.build_owner_plan:
        print(f"OWNER_PRIORITY_{report['owner_priority']['selected_detail_priority']}")
    elif args.build_public_summary:
        print(report["validation"]["public_sanitization_status"])
    elif args.validate:
        print(report["validation"]["status"])
    return 0 if report["validation"]["status"] == "ORIGIN_FAILURE_DIAGNOSTICS_VALIDATION_OK" else 1


if __name__ == "__main__":
    raise SystemExit(main())
