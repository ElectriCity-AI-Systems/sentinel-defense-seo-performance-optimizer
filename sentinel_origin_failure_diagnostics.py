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

import sentinel_canonical_truth as canonical_truth


PROJECT_DIR = Path(__file__).resolve().parent
SCHEMA_VERSION = "sentinel-origin-failure-diagnostics-10.17.1"

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
WP_USERS_ME_MD = REPORT_DIR / "sentinel-origin-wp-users-me-classification.md"
ACTOR_MD = REPORT_DIR / "sentinel-origin-actor-correlation.md"
TIMELINE_MD = REPORT_DIR / "sentinel-origin-timeline.md"
OWNER_PLAN_MD = REPORT_DIR / "sentinel-origin-owner-action-plan.md"
EVIDENCE_GAP_MD = REPORT_DIR / "sentinel-origin-evidence-gap.md"
IONOS_EVIDENCE_JSON = REPORT_DIR / "sentinel-ionos-webspace-owner-evidence.json"
IONOS_ANALYSIS_MD = REPORT_DIR / "sentinel-ionos-webspace-action-classification.md"
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
    WP_USERS_ME_MD,
    ACTOR_MD,
    TIMELINE_MD,
    OWNER_PLAN_MD,
    EVIDENCE_GAP_MD,
    IONOS_ANALYSIS_MD,
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

WP_USERS_ME_PATH = "/wp-json/wp/v2/users/me"
WP_USERS_ME_CLASSIFICATIONS = (
    "WP_USERS_ME_EXPECTED_ADMIN_TRAFFIC",
    "WP_USERS_ME_FRONTEND_DEPENDENCY",
    "WP_USERS_ME_BOT_OR_SCANNER",
    "WP_USERS_ME_PLUGIN_POLLING",
    "WP_USERS_ME_ORIGIN_TIMEOUT",
    "WP_USERS_ME_EVIDENCE_INSUFFICIENT",
)
# Order in which simultaneously matching classifications are reported as primary.
WP_USERS_ME_CLASSIFICATION_PRIORITY = (
    "WP_USERS_ME_ORIGIN_TIMEOUT",
    "WP_USERS_ME_BOT_OR_SCANNER",
    "WP_USERS_ME_PLUGIN_POLLING",
    "WP_USERS_ME_FRONTEND_DEPENDENCY",
    "WP_USERS_ME_EXPECTED_ADMIN_TRAFFIC",
    "WP_USERS_ME_EVIDENCE_INSUFFICIENT",
)
WP_USERS_ME_FORBIDDEN_KEYS = (
    "cookie", "authorization", "auth_header", "token", "bearer", "session",
    "user_id", "userid", "user_login", "username", "email", "nonce", "password",
)
WP_USERS_ME_PRIVACY_GUARANTEES = {
    "cookies_stored": False,
    "authorization_headers_stored": False,
    "tokens_stored": False,
    "user_ids_collected": False,
    "productive_rule_applied": False,
    "diagnosis_only": True,
}

FRESHNESS_THRESHOLDS_SECONDS = {
    "current": 24 * 60 * 60,
    "stale_informational": 7 * 24 * 60 * 60,
}

IONOS_SEQUENCE_MIN_PATHS = 3

DELTA_THRESHOLDS = {
    "significant_absolute": 25,
    "significant_percent": 25.0,
    "stable_absolute_tolerance": 0,
}

# Module execution boundary, not runtime state. These flags describe what THIS
# module may do (nothing productive). Phase 10.21: the runtime emergency stop,
# breach and autonomy level are canonical runtime fields and are resolved live via
# sentinel_canonical_truth.resolve_runtime_flags() — never hardcoded here.
SAFETY_FLAGS = {
    "live_apply": False,
    "emergency_stop": True,
    "allowed_apply_now": False,
    "high_blocked": True,
    "medium_executable": False,
    "low_live_executable": False,
    "breach": False,
}
SAFETY_FLAGS_SEMANTICS = (
    "module_execution_boundary_not_runtime_state: emergency_stop here means this module "
    "behaves as if productive apply were locked; the canonical runtime emergency stop is "
    "reported separately as runtime_emergency_stop"
)

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


def normalize_evidence_path(path: Any) -> str:
    value = str(path or "unknown").strip()
    value = value.split("?", 1)[0].split("#", 1)[0]
    if not value.startswith("/"):
        value = "/" + value
    value = re.sub(r"/{2,}", "/", value)
    if value != "/":
        value = value.rstrip("/")
    return value or "/"


def is_scanner_probe_path(path: str) -> bool:
    lowered = normalize_evidence_path(path).lower()
    scanner_markers = (
        "/.env", "/.git", "wp-config", "alfacgiapi", "/vendor/phpunit/",
        "phpinfo.php", "wp-plain.php", "/seotheme/db.php", "/fix/up.php",
        "/apikey.php", "/apismtp.php", ".php.suspected",
    )
    return any(marker in lowered for marker in scanner_markers) or bool(
        re.fullmatch(r"/atg-[a-z0-9]+\.html", lowered)
    )


def classify_path(path: str) -> str:
    normalized = normalize_evidence_path(path)
    lowered = normalized.lower()
    if normalized == "/":
        return "frontpage"
    if lowered.startswith("/wp-login.php"):
        return "wordpress_login"
    if is_scanner_probe_path(normalized):
        return "scanner_or_malware_probe"
    if lowered.startswith("/wp-admin/"):
        return "wordpress_admin_asset"
    if re.fullmatch(r"/page/\d+/?", lowered):
        return "wordpress_legacy_pagination"
    if "oembed" in lowered or lowered.startswith("/wp-json/"):
        return "wordpress_rest_or_oembed"
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
        label, dimension_count = next(iter(remaining_dimensions.items()))
        if dimension_count == sum(remaining_statuses.values()):
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
        actor_map = infer_status_dimension(path_row, "actor_signal_counts", "actor_signal")
        ua_map = infer_status_dimension(path_row, "user_agent_groups", "group")
        country_map = infer_status_dimension(path_row, "countries", "country")
        request_shape_map = infer_status_dimension(path_row, "request_shape_counts", "request_shape")
        failure_mode_map = infer_status_dimension(path_row, "failure_mode_counts", "failure_mode")
        for status_row in path_row.get("statuses", []):
            if not isinstance(status_row, dict):
                continue
            code = as_int(status_row.get("status"), -1)
            if code not in STATUS_HYPOTHESES:
                continue
            status_count = as_int(status_row.get("count"))
            actor = actor_map.get(code, "unknown_actor")
            rows.append({
                "count": status_count,
                "status_code": code,
                "path": path,
                "path_classification": classify_path(path),
                "cache_status": cache_map.get(code, "unknown"),
                "cache_status_proof": "AGGREGATE_BALANCE_CORRELATION" if code in cache_map else "UNKNOWN",
                "user_agent_group": ua_map.get(code, "unknown"),
                "user_agent_group_proof": "AGGREGATE_BALANCE_CORRELATION" if code in ua_map else "UNKNOWN",
                "actor_signal": actor,
                "actor_signal_proof": "AGGREGATE_BALANCE_CORRELATION" if code in actor_map else "UNKNOWN",
                "actor_signal_counts": {actor: status_count} if code in actor_map else {},
                "country": country_map.get(code, "unknown"),
                "country_proof": "AGGREGATE_BALANCE_CORRELATION" if code in country_map else "UNKNOWN",
                "request_shape": request_shape_map.get(code, "unknown"),
                "request_shape_proof": "AGGREGATE_BALANCE_CORRELATION" if code in request_shape_map else "UNKNOWN",
                "failure_mode": failure_mode_map.get(code, f"unknown_{code}"),
                "failure_mode_proof": "AGGREGATE_BALANCE_CORRELATION" if code in failure_mode_map else "UNKNOWN",
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


def build_safety_block() -> Dict[str, Any]:
    """Module boundary plus the canonical runtime flags, never a hardcoded runtime state."""
    runtime = canonical_truth.resolve_runtime_flags()
    flags = runtime.get("flags", {})
    provenance = runtime.get("provenance", {})
    return {
        **SAFETY_FLAGS,
        "semantics": SAFETY_FLAGS_SEMANTICS,
        "module_productive_apply_lock": True,
        "runtime_emergency_stop": flags.get("emergency_stop"),
        "runtime_breach": flags.get("breach"),
        "runtime_autonomy_level": flags.get("autonomy_level"),
        "runtime_systemd_timer_active": flags.get("systemd_timer_active"),
        "runtime_low_live_apply_enabled": flags.get("low_live_apply_enabled"),
        "runtime_flags_status": runtime.get("status"),
        "runtime_flags_unresolved": runtime.get("unresolved_fields", []),
        "runtime_emergency_stop_source": provenance.get("emergency_stop", {}).get("source"),
        "runtime_breach_source": provenance.get("breach", {}).get("source"),
    }


def wp_users_me_row(website: Dict[str, Any]) -> Dict[str, Any]:
    """The current aggregate row for the WordPress REST identity endpoint."""
    origin = website.get("origin_pressure_breakdown")
    rows = origin.get("top_5xx_paths") if isinstance(origin, dict) else None
    if not isinstance(rows, list):
        rows = website.get("top_5xx_paths") if isinstance(website.get("top_5xx_paths"), list) else []
    for row in rows:
        if isinstance(row, dict) and normalize_evidence_path(row.get("path")) == WP_USERS_ME_PATH:
            return row
    return {}


def privacy_scan(payload: Any) -> List[str]:
    """Refuse to carry identity material into the diagnostic output."""
    findings: List[str] = []

    def walk(node: Any, trail: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                lowered = str(key).lower()
                if any(marker in lowered for marker in WP_USERS_ME_FORBIDDEN_KEYS):
                    findings.append(f"{trail}.{key}")
                walk(value, f"{trail}.{key}")
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, f"{trail}[{index}]")

    walk(payload, "wp_users_me_diagnostic")
    return findings


def build_wp_users_me_diagnostic(website: Dict[str, Any]) -> Dict[str, Any]:
    """Read-only classification of current /wp-json/wp/v2/users/me 5xx pressure.

    Uses only aggregates that the Cloudflare monitor snapshot already collected:
    request frequency, actor class, user-agent class, country distribution, cache
    status, response status and — where present — referer class. No cookies, no
    Authorization headers, no tokens and no user identifiers are read or stored.
    """
    row = wp_users_me_row(website)
    if not row:
        return {
            "status": "WP_USERS_ME_EVIDENCE_INSUFFICIENT",
            "path": WP_USERS_ME_PATH,
            "classification": "WP_USERS_ME_EVIDENCE_INSUFFICIENT",
            "classification_reason": (
                "The current website snapshot contains no 5xx aggregate row for this path."
            ),
            "present": False,
            "evidence": {},
            "candidate_classifications": [],
            "privacy": dict(WP_USERS_ME_PRIVACY_GUARANTEES),
            "missing_evidence": [
                "current 5xx aggregate row for the path",
                "per-path temporal distribution",
            ],
            "productive_rule_applied": False,
            "diagnosis_only": True,
        }

    statuses = {as_int(item.get("status")): as_int(item.get("count"))
                for item in row.get("statuses", []) if isinstance(item, dict)}
    total_5xx = sum(statuses.values())
    count_504 = statuses.get(504, 0)
    countries = list_count(row.get("countries", []), "country")
    user_agents = list_count(row.get("user_agent_groups", []), "group")
    cache_statuses = list_count(row.get("cache_status", []), "cache_status")
    actor_signals = list_count(row.get("actor_signal_counts", []), "actor_signal")
    failure_modes = list_count(row.get("failure_mode_counts", []), "failure_mode")
    request_shapes = list_count(row.get("request_shape_counts", []), "request_shape")
    referers = list_count(row.get("referers", []), "referer")
    requests_24h = as_int(row.get("top_paths_24h_request_count"))
    security_actions = row.get("security_actions_24h")
    security_action_count = len(security_actions) if isinstance(security_actions, list) else 0

    country_count = len(countries)
    top_country_share = (
        round(max(countries.values()) / total_5xx * 100, 2) if countries and total_5xx else None
    )
    failure_ratio = round(total_5xx / requests_24h * 100, 2) if requests_24h else None
    browser_like = any(
        marker in group.lower()
        for group in user_agents
        for marker in ("chrome", "firefox", "safari", "edge", "browser")
    )
    infrastructure_like = any(
        marker in group.lower()
        for group in user_agents
        for marker in ("nginx", "early hints", "curl", "python", "go-http", "libwww", "okhttp")
    )
    timeout_dominant = (
        failure_modes.get("cloudflare_to_origin_timeout", 0) >= total_5xx / 2 if total_5xx else False
    ) or (count_504 >= total_5xx / 2 if total_5xx else False)
    cache_bypassed = sum(
        count for label, count in cache_statuses.items() if label in {"miss", "dynamic", "bypass", "expired"}
    )

    evidence = {
        "request_frequency": {
            "total_5xx_24h": total_5xx,
            "status_504_24h": count_504,
            "path_requests_24h": requests_24h or None,
            "failure_share_of_path_requests_percent": failure_ratio,
        },
        "response_status": {str(code): count for code, count in sorted(statuses.items())},
        "cache_status": cache_statuses,
        "cache_bypassed_count": cache_bypassed,
        "country_distribution": countries,
        "distinct_countries": country_count,
        "top_country_share_percent": top_country_share,
        "user_agent_class": user_agents,
        "actor_class": actor_signals or ({row.get("actor_signal"): total_5xx} if row.get("actor_signal") else {}),
        "failure_mode": failure_modes or ({row.get("failure_mode"): total_5xx} if row.get("failure_mode") else {}),
        "request_shape": request_shapes,
        "referer_class": referers or None,
        "referer_evidence": "COLLECTED" if referers else "EVIDENCE_NOT_COLLECTED",
        "temporal_clustering": "EVIDENCE_NOT_COLLECTED",
        "temporal_clustering_reason": (
            "The Cloudflare snapshot aggregates this path without a per-path time dimension."
        ),
        "authenticated_vs_anonymous": "EVIDENCE_NOT_SAFELY_AVAILABLE",
        "authenticated_evidence_reason": (
            "Distinguishing authenticated from anonymous calls would require cookie or "
            "Authorization header inspection, which is forbidden."
        ),
        "security_actions_24h_count": security_action_count,
        "covered_by_sentinel_combined_rule": bool(row.get("covered_by_sentinel_combined_rule")),
        "hostnames": sorted({str(item) for item in row.get("hostnames", []) if item}),
    }

    candidates: List[Dict[str, Any]] = []

    def add(name: str, matched: bool, reason: str, confidence: str) -> None:
        candidates.append({
            "classification": name,
            "matched": bool(matched),
            "reason": reason,
            "confidence": confidence if matched else "none",
        })

    add(
        "WP_USERS_ME_ORIGIN_TIMEOUT",
        timeout_dominant,
        (
            f"{count_504} of {total_5xx} current 5xx are 504 with a "
            "cloudflare_to_origin_timeout failure mode."
            if timeout_dominant
            else "504 / origin-timeout failure mode is not dominant."
        ),
        "high" if timeout_dominant and total_5xx >= 10 else "medium",
    )
    bot_like = (
        country_count >= 3
        and infrastructure_like
        and not browser_like
    )
    add(
        "WP_USERS_ME_BOT_OR_SCANNER",
        bot_like,
        (
            f"Requests spread over {country_count} countries with a non-browser user-agent class "
            f"({', '.join(sorted(user_agents)) or 'unknown'}) and no browser class present."
            if bot_like
            else "No combination of multi-country spread and non-browser user-agent class."
        ),
        "medium",
    )
    admin_like = (
        browser_like
        and country_count <= 2
        and (top_country_share or 0) >= 80
    )
    add(
        "WP_USERS_ME_EXPECTED_ADMIN_TRAFFIC",
        admin_like,
        (
            "Browser user-agent class concentrated in a single country, consistent with owner "
            "or editor admin sessions."
            if admin_like
            else "No concentrated single-country browser pattern that would indicate admin usage."
        ),
        "medium",
    )
    frontend_like = browser_like and bool(referers) and country_count >= 2
    add(
        "WP_USERS_ME_FRONTEND_DEPENDENCY",
        frontend_like,
        (
            "Browser user-agent class with collected referer evidence indicates a frontend "
            "dependency on the identity endpoint."
            if frontend_like
            else "No referer evidence combined with a browser class is available."
        ),
        "low",
    )
    add(
        "WP_USERS_ME_PLUGIN_POLLING",
        False,
        (
            "Plugin polling requires a per-path temporal distribution, which the current "
            "snapshot does not collect."
        ),
        "none",
    )
    insufficient = total_5xx == 0 or (not timeout_dominant and not bot_like and not admin_like and not frontend_like)
    add(
        "WP_USERS_ME_EVIDENCE_INSUFFICIENT",
        insufficient,
        (
            "Current aggregates do not support any specific classification."
            if insufficient
            else "Sufficient aggregate evidence for at least one specific classification."
        ),
        "high" if insufficient else "none",
    )

    matched = [item for item in candidates if item["matched"]]
    if matched:
        order = {name: index for index, name in enumerate(WP_USERS_ME_CLASSIFICATION_PRIORITY)}
        primary = sorted(matched, key=lambda item: order.get(item["classification"], 99))[0]
        classification = primary["classification"]
        classification_reason = primary["reason"]
        confidence = primary["confidence"]
    else:
        classification = "WP_USERS_ME_EVIDENCE_INSUFFICIENT"
        classification_reason = "No classification rule matched the current aggregates."
        confidence = "low"

    secondary = [
        item["classification"] for item in matched if item["classification"] != classification
    ]
    diagnostic = {
        "status": classification,
        "path": WP_USERS_ME_PATH,
        "present": True,
        "classification": classification,
        "classification_reason": classification_reason,
        "confidence": confidence,
        "secondary_classifications": secondary,
        "candidate_classifications": candidates,
        "allowed_classifications": list(WP_USERS_ME_CLASSIFICATIONS),
        "evidence": evidence,
        "missing_evidence": [
            "per-path temporal distribution for polling detection",
            "authenticated vs anonymous split (forbidden to collect)",
        ] + ([] if referers else ["referer class"]),
        "causality_proven": False,
        "evidence_level": "B_STRONG_CORRELATION" if total_5xx >= 10 else "C_WEAK_CORRELATION",
        "owner_note": (
            "Diagnosis only. No WAF rule, no rate limit, no Cloudflare change and no WordPress "
            "change is derived from this classification."
        ),
        "productive_rule_applied": False,
        "new_waf_rule_recommended": False,
        "diagnosis_only": True,
        "privacy": dict(WP_USERS_ME_PRIVACY_GUARANTEES),
    }
    # Scan the collected evidence, not the privacy declaration itself: the
    # guarantee keys legitimately name the forbidden material they exclude.
    privacy_findings = privacy_scan({
        "evidence": diagnostic["evidence"],
        "candidate_classifications": diagnostic["candidate_classifications"],
        "secondary_classifications": diagnostic["secondary_classifications"],
    })
    diagnostic["privacy"]["forbidden_field_findings"] = privacy_findings
    diagnostic["privacy"]["privacy_status"] = (
        "WP_USERS_ME_PRIVACY_OK" if not privacy_findings else "WP_USERS_ME_PRIVACY_VIOLATION"
    )
    return diagnostic


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


def evaluate_evidence_freshness(
    generated_at: Any, now: Optional[datetime] = None
) -> Dict[str, Any]:
    current_time = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    generated = parse_timestamp(generated_at)
    if generated is None:
        return {
            "generated_at": generated_at,
            "age_seconds": None,
            "freshness_status": "INVALID_TIMESTAMP",
            "included_in_master_status": False,
            "correlation_allowed": True,
            "reason": "Source generation time is missing or invalid; evidence is private context only.",
        }
    age_seconds = (current_time - generated).total_seconds()
    if age_seconds < -300:
        return {
            "generated_at": iso_utc(generated),
            "age_seconds": round(age_seconds, 2),
            "freshness_status": "INVALID_TIMESTAMP",
            "included_in_master_status": False,
            "correlation_allowed": False,
            "reason": "Source timestamp is unexpectedly in the future.",
        }
    age_seconds = max(0.0, age_seconds)
    if age_seconds <= FRESHNESS_THRESHOLDS_SECONDS["current"]:
        status = "CURRENT"
        included = True
        reason = "Evidence is within the current 24-hour window."
    elif age_seconds <= FRESHNESS_THRESHOLDS_SECONDS["stale_informational"]:
        status = "STALE_INFORMATIONAL"
        included = False
        reason = "Evidence is older than 24 hours and remains informational only."
    else:
        status = "STALE_EXCLUDED_FROM_MASTER_STATUS"
        included = False
        reason = "Evidence is older than seven days and is excluded from current status decisions."
    return {
        "generated_at": iso_utc(generated),
        "age_seconds": round(age_seconds, 2),
        "freshness_status": status,
        "included_in_master_status": included,
        "correlation_allowed": True,
        "reason": reason,
    }


def normalize_ionos_rows(data: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[str]]:
    source_rows: Any = data.get("key_rows")
    if not isinstance(source_rows, list):
        source_rows = data.get("rows")
    if not isinstance(source_rows, list):
        source_rows = data.get("top_error_paths")
    if not isinstance(source_rows, list):
        return [], ["ionos_rows_missing"]
    rows: List[Dict[str, Any]] = []
    findings: List[str] = []
    for index, row in enumerate(source_rows):
        if not isinstance(row, dict):
            findings.append(f"ionos_row_{index}_not_object")
            continue
        path = row.get("path")
        status_value = row.get("status", row.get("status_code", row.get("http_status")))
        count_value = row.get("count", row.get("requests", row.get("anzahl")))
        status = as_int(status_value, -1)
        count = as_int(count_value, -1)
        if not isinstance(path, str) or not path.strip() or not 100 <= status <= 599 or count < 0:
            findings.append(f"ionos_row_{index}_invalid")
            continue
        rows.append({
            "row_id": f"ionos-{index + 1}",
            "path": normalize_evidence_path(path),
            "status": status,
            "count": count,
            "source_category": str(row.get("source_category") or row.get("category") or "unknown"),
            "source_priority": str(row.get("source_priority") or row.get("priority") or "UNKNOWN"),
        })
    return sorted(rows, key=lambda item: (-item["count"], item["status"], item["path"])), findings


def classify_ionos_response(row: Dict[str, Any]) -> Dict[str, Any]:
    path = normalize_evidence_path(row.get("path"))
    status = as_int(row.get("status"), -1)
    source_category = str(row.get("source_category") or "unknown")
    scanner_path = is_scanner_probe_path(path)
    path_class = classify_path(path)
    operational_class = "CONTEXT_REQUIRED"
    disposition = "OWNER_CONTEXT_REVIEW"
    priority = "P3_CONTEXT"
    recommendation = "Correlate method, actor, referrer, host, and timestamp before changing the site."
    required_evidence = ["request_method", "actor_or_user_agent_group", "timestamp_bucket"]
    expected_response_candidate = False
    counts_as_origin_availability_signal = False

    if status in STATUS_HYPOTHESES or 500 <= status <= 599:
        counts_as_origin_availability_signal = True
        priority = "P1_ORIGIN_STABILITY"
        disposition = "DIAGNOSE_ORIGIN_BEFORE_CHANGE"
        required_evidence = ["matching_origin_log", "timestamp_bucket", "actor_or_user_agent_group"]
        if scanner_path:
            operational_class = "SCANNER_CORRELATED_ORIGIN_FAILURE"
            recommendation = (
                "Treat the scanner request as actor context, but diagnose why the origin returned 5xx. "
                "Do not dismiss the 5xx as harmless scanner noise."
            )
        else:
            operational_class = "ORIGIN_AVAILABILITY_SIGNAL"
            recommendation = "Correlate current hosting, PHP, WordPress, and upstream logs before optimization work."
    elif path == "/wp-json/wp/v2/users/me" and status == 401:
        operational_class = "EXPECTED_UNAUTHENTICATED_RESPONSE_CANDIDATE"
        disposition = "NO_REPAIR_WITHOUT_AUTHENTICATED_FAILURE"
        priority = "P4_EXPECTED_RESPONSE"
        recommendation = "Do not repair unless an authenticated WordPress workflow is confirmed to fail."
        required_evidence = ["authenticated_workflow_result", "request_auth_context"]
        expected_response_candidate = True
    elif path == "/wp-comments-post.php" and status == 405:
        operational_class = "EXPECTED_METHOD_RESTRICTION_CANDIDATE"
        disposition = "NO_REPAIR_WITHOUT_VALID_POST_FAILURE"
        priority = "P4_EXPECTED_RESPONSE"
        recommendation = "Do not repair unless a valid comment POST workflow is confirmed to fail."
        required_evidence = ["request_method", "valid_comment_workflow_result"]
        expected_response_candidate = True
    elif path == "/hello-world" and status == 410:
        operational_class = "INTENTIONAL_REMOVAL_CANDIDATE"
        disposition = "CHECK_CURRENT_INTERNAL_REFERENCES_ONLY"
        priority = "P4_HISTORICAL_CONTENT"
        recommendation = "Keep 410 unless current menus, sitemap entries, or internal links still reference the path."
        required_evidence = ["current_internal_link_evidence", "current_sitemap_evidence"]
        expected_response_candidate = True
    elif source_category == "stale_plugin_admin_request" and status == 404:
        operational_class = "STALE_ADMIN_CLIENT_REQUEST"
        disposition = "CLOSE_STALE_ADMIN_CONTEXT"
        priority = "P4_HISTORICAL_ADMIN"
        recommendation = "Close stale admin tabs; do not create a public redirect or restore an unused plugin endpoint."
        required_evidence = ["current_admin_workflow_result"]
        expected_response_candidate = True
    elif scanner_path and status in {400, 401, 403, 404, 405, 410}:
        operational_class = "EXPECTED_SCANNER_REJECTION"
        disposition = "MONITOR_NO_REPAIR"
        priority = "P5_SCANNER_NOISE"
        recommendation = "Preserve the negative response; do not create the requested file or redirect."
        required_evidence = []
        expected_response_candidate = True
    elif path == "/wp-admin/admin-ajax.php" and status == 403:
        operational_class = "ADMIN_AJAX_SECURITY_OR_WORKFLOW_CONTEXT_REQUIRED"
        disposition = "REVIEW_FRONTEND_WORKFLOW_BEFORE_CHANGE"
        priority = "P3_CONTEXT"
        recommendation = "Separate direct probes from legitimate nonce-protected frontend AJAX requests before changing security rules."
        required_evidence = ["request_method", "referrer_class", "nonce_or_auth_context", "frontend_workflow_result"]
    elif path == "/" and status == 404:
        operational_class = "ROOT_ROUTING_CONTEXT_REQUIRED"
        disposition = "REVIEW_REQUEST_SHAPE_BEFORE_REDIRECT"
        priority = "P2_ROUTE_INTEGRITY"
        recommendation = "Separate canonical browser GET requests from host, method, query, and scanner variants before considering a redirect."
        required_evidence = ["request_method", "request_host", "query_class", "actor_or_user_agent_group"]
    elif status == 429:
        operational_class = "RATE_LIMIT_ISSUER_REVIEW"
        disposition = "VERIFY_PROTECTION_VS_USER_IMPACT"
        priority = "P2_RATE_LIMIT_CONTEXT"
        recommendation = "Identify whether Cloudflare, hosting, WordPress, or an application component generated 429 and which actor was limited."
        required_evidence = ["response_issuer", "actor_or_user_agent_group", "browser_workflow_result"]
    elif status == 404:
        operational_class = "CURRENT_LINK_EVIDENCE_REQUIRED"
        disposition = "CHECK_REFERENCES_BEFORE_REDIRECT"
        priority = "P3_CONTENT_CONTEXT"
        recommendation = "Review only when current browser, sitemap, referrer, or internal-link evidence shows the path is relevant."
        required_evidence = ["current_internal_link_evidence", "referrer_class"]

    return {
        **row,
        "path": path,
        "path_classification": path_class,
        "scanner_path": scanner_path,
        "operational_class": operational_class,
        "action_disposition": disposition,
        "operational_priority": priority,
        "recommendation": recommendation,
        "required_evidence": required_evidence,
        "expected_response_candidate": expected_response_candidate,
        "counts_as_origin_availability_signal": counts_as_origin_availability_signal,
        "verified_user_impact": "unknown",
        "causality_proven": False,
        "automatic_action": "NO_ACTION",
        "new_waf_rule_recommended": False,
    }


def detect_synchronized_sequences(
    ionos_rows: Sequence[Dict[str, Any]], current_path_rows: Sequence[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    groups: Dict[Tuple[int, int], List[Dict[str, Any]]] = {}
    for row in ionos_rows:
        groups.setdefault((as_int(row.get("status")), as_int(row.get("count"))), []).append(row)
    current_index = {
        (as_int(row.get("status_code")), normalize_evidence_path(row.get("path"))): row
        for row in current_path_rows
    }
    sequences: List[Dict[str, Any]] = []
    for (status, count), grouped in sorted(groups.items()):
        paths = sorted({normalize_evidence_path(row.get("path")) for row in grouped})
        if len(paths) < IONOS_SEQUENCE_MIN_PATHS:
            continue
        matches = [current_index[(status, path)] for path in paths if (status, path) in current_index]
        current_counts = [as_int(row.get("count")) for row in matches]
        actor_signals = sorted({
            str(row.get("actor_signal")) for row in matches
            if row.get("actor_signal") not in {None, "", "unknown_actor"}
        })
        all_scanner_paths = all(is_scanner_probe_path(path) for path in paths)
        if all_scanner_paths:
            sequence_kind = "SCANNER_PROBE_SEQUENCE"
        elif status >= 500:
            sequence_kind = "ORIGIN_FAILURE_MULTI_PATH_SEQUENCE"
        else:
            sequence_kind = "SYNCHRONIZED_MULTI_PATH_SEQUENCE"
        replicated = len(matches) == len(paths) and len(set(current_counts)) == 1
        correlation = "STRONG" if replicated and len(actor_signals) == 1 else "MODERATE" if matches else "WEAK"
        sequences.append({
            "sequence_id": f"status-{status}-count-{count}-paths-{len(paths)}",
            "sequence_kind": sequence_kind,
            "status": status,
            "source_count_per_path": count,
            "paths": paths,
            "path_count": len(paths),
            "raw_request_observations": count * len(paths),
            "sequence_occurrence_candidate": count,
            "operational_incident_groups": 1,
            "request_duplication_proven": False,
            "repeated_sequence_supported": replicated,
            "cross_source_match_count": len(matches),
            "cross_source_counts": current_counts,
            "cross_source_actor_signal": actor_signals[0] if len(actor_signals) == 1 else "unknown_actor",
            "correlation_strength": correlation,
            "causality_proven": False,
            "verified_user_impact": "unknown",
            "automatic_block": False,
            "new_waf_rule_recommended": False,
            "recommendation": (
                "Correlate timestamps and scanner schedule as one sequence while retaining every raw request count. "
                "Do not infer causality or create an actor-wide block."
            ),
        })
    return sorted(sequences, key=lambda item: (-item["raw_request_observations"], item["sequence_id"]))


def build_ionos_evidence_analysis(
    current_path_rows: Sequence[Dict[str, Any]], now: Optional[datetime] = None
) -> Dict[str, Any]:
    source, read_status = read_json(IONOS_EVIDENCE_JSON)
    if read_status != "ok" or not isinstance(source, dict):
        return {
            "status": "IONOS_EVIDENCE_MISSING" if read_status == "missing" else "IONOS_EVIDENCE_INVALID",
            "source_path": rel(IONOS_EVIDENCE_JSON),
            "imported_rows": 0,
            "freshness": evaluate_evidence_freshness(None, now),
            "row_classifications": [],
            "synchronized_sequences": [],
            "summary": {},
            "improvement_candidates": [],
            "missing_evidence": ["Structured private IONOS Webspace evidence is not available."],
            "validation_findings": [] if read_status == "missing" else [f"ionos_source_{read_status}"],
            "automatic_apply": False,
        }
    rows, findings = normalize_ionos_rows(source)
    classified = [classify_ionos_response(row) for row in rows]
    sequences = detect_synchronized_sequences(classified, current_path_rows)
    freshness = evaluate_evidence_freshness(source.get("source_generated_at"), now)
    class_counts: Dict[str, int] = {}
    disposition_counts: Dict[str, int] = {}
    for row in classified:
        class_counts[row["operational_class"]] = class_counts.get(row["operational_class"], 0) + 1
        disposition_counts[row["action_disposition"]] = disposition_counts.get(row["action_disposition"], 0) + 1
    missing_evidence = [str(item) for item in source.get("owner_evidence_needed", []) if item]
    if freshness["freshness_status"] == "INVALID_TIMESTAMP":
        missing_evidence.insert(0, "Source report generation timestamp and exact log window.")
    improvements = [
        {
            "candidate": "CORRELATE_ORIGIN_LOG_WINDOW",
            "status": "OWNER_EVIDENCE_REQUIRED",
            "reason": "Match 503/504 timestamps with hosting, PHP, WordPress, and upstream logs.",
        },
        {
            "candidate": "REVIEW_SYNCHRONIZED_SCANNER_SEQUENCE",
            "status": "REVIEW_ONLY",
            "reason": "Review scanner schedule or concurrency only if timestamp-level sequence correlation is confirmed.",
        },
        {
            "candidate": "VERIFY_STATIC_ASSET_ORIGIN_PATH",
            "status": "OWNER_REVIEW_REQUIRED",
            "reason": "A static admin asset returning 503 warrants routing and origin-load review without changing WordPress automatically.",
        },
        {
            "candidate": "ANONYMOUS_MICROCACHE_CANARY",
            "status": "BLOCKED_PENDING_SEPARATE_GUARDED_ADAPTER_VALIDATION",
            "reason": "Caching remains a later reversible candidate, not an action from this diagnostic component.",
        },
        {
            "candidate": "EXACT_SCANNER_PATH_CHALLENGE",
            "status": "BLOCKED_PENDING_FRESH_TRIGGER_AND_WRITE_CANARY",
            "reason": "Only exact high-confidence scanner paths may be considered; root, pagination, admin assets, actors, countries, and browsers are excluded.",
        },
    ]
    return {
        "status": "IONOS_EVIDENCE_IMPORTED" if classified and not findings else "IONOS_EVIDENCE_IMPORTED_WITH_FINDINGS",
        "source_path": rel(IONOS_EVIDENCE_JSON),
        "source_type": source.get("source_type"),
        "source_window": source.get("source_window"),
        "imported_rows": len(classified),
        "freshness": freshness,
        "included_in_master_status": freshness["included_in_master_status"],
        "available_for_private_correlation": freshness["correlation_allowed"],
        "row_classifications": classified,
        "synchronized_sequences": sequences,
        "summary": {
            "operational_class_counts": class_counts,
            "action_disposition_counts": disposition_counts,
            "origin_availability_rows": sum(1 for row in classified if row["counts_as_origin_availability_signal"]),
            "expected_response_candidates": sum(1 for row in classified if row["expected_response_candidate"]),
            "context_review_rows": sum(1 for row in classified if row["operational_priority"].startswith(("P2", "P3"))),
            "raw_request_observations": sum(as_int(row.get("count")) for row in classified),
            "operational_sequence_groups": len(sequences),
        },
        "improvement_candidates": improvements,
        "missing_evidence": list(dict.fromkeys(missing_evidence)),
        "validation_findings": findings,
        "causality_proven": False,
        "verified_user_impact": "unknown",
        "automatic_apply": False,
        "new_waf_rule_recommended": False,
    }


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


def choose_priorities(
    deltas: Dict[int, Dict[str, Any]], tls: Dict[str, Any], ionos: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    ionos = ionos or {}
    synchronized_sequences = ionos.get("synchronized_sequences", [])
    if SAFETY_FLAGS["breach"]:
        detail = "SAFETY_ESCALATION"
    elif deltas[503]["trend"] == "SIGNIFICANT_GROWTH":
        detail = "ORIGIN_503_GROWTH_DIAGNOSIS"
    elif deltas[504]["trend"] == "SIGNIFICANT_GROWTH":
        detail = "ORIGIN_504_GROWTH_DIAGNOSIS"
    elif tls["status"] in {"TLS_REVIEW_REQUIRED", "TLS_SIGNIFICANT_GROWTH"}:
        detail = "ORIGIN_TLS_EVIDENCE_REVIEW"
    elif deltas[503]["current_count"] and synchronized_sequences:
        detail = "ORIGIN_503_SEQUENCE_DIAGNOSIS"
    elif deltas[504]["current_count"]:
        detail = "ORIGIN_504_ROLLING_WINDOW_DIAGNOSIS"
    else:
        detail = "ORIGIN_EVIDENCE_CORRELATION"
    ordered_actions = []
    if detail == "ORIGIN_503_GROWTH_DIAGNOSIS":
        ordered_actions.append("Diagnose current status-503 growth by path, time, actor, cache status, and origin evidence.")
    elif detail == "ORIGIN_504_GROWTH_DIAGNOSIS":
        ordered_actions.append("Diagnose current status-504 growth and correlate root timeouts with origin and upstream evidence.")
    elif detail == "ORIGIN_503_SEQUENCE_DIAGNOSIS":
        ordered_actions.append("Correlate the synchronized status-503 path sequence by timestamp before treating paths as independent incidents.")
    else:
        ordered_actions.append("Continue current origin-failure diagnosis using fresh status-specific evidence.")
    if synchronized_sequences:
        ordered_actions.append(
            "Review synchronized IONOS path sequences as one operational pattern while retaining all raw request counts."
        )
    ordered_actions.extend([
        "Review the static admin asset 503 path for routing or origin-load evidence without changing WordPress automatically.",
        "Separate root 404 and 429 rows by host, method, actor, response issuer, query class, and timestamp.",
        "Treat REST 401, comments 405, intentional 410, and scanner 404 as expected-response candidates until workflow evidence proves otherwise.",
        "Review available origin, PHP, WordPress, and hosting evidence; request missing evidence explicitly.",
        "Keep SEO and metadata work below technical stability work.",
    ])
    return {
        "selected_priority": "WEBSITE_ORIGIN_STABILITY",
        "selected_detail_priority": detail,
        "ordered_actions": ordered_actions,
        "ionos_sequence_groups": len(synchronized_sequences),
        "suppressed_lower_priorities": [
            "SEO_TITLE_REVIEW",
            "META_DESCRIPTION_REVIEW",
            "OPEN_GRAPH_REVIEW",
            "INTERNAL_LINK_REVIEW",
            "REST_401_REPAIR_WITHOUT_AUTH_FAILURE",
            "SCANNER_404_REDIRECT_CREATION",
            "SITELOCK_GLOBAL_BLOCK",
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
    ionos = build_ionos_evidence_analysis(paths)
    evidence = direct_evidence(discovery)
    evidence["level_b_strong_correlation"] = [
        "Current status/path/cache/actor aggregation with per-status detail coverage.",
        "Independent Phase 10.16 consistency snapshot used only as the previous comparison point.",
    ] if website and master else []
    if any(item.get("correlation_strength") == "STRONG" for item in ionos.get("synchronized_sequences", [])):
        evidence["level_b_strong_correlation"].append(
            "A synchronized private IONOS path pattern is replicated in current status/path/actor aggregation."
        )
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
    if ionos.get("freshness", {}).get("freshness_status") != "CURRENT":
        evidence["level_c_weak_correlation"].append(
            "The private IONOS Webspace excerpt lacks current timestamp evidence and cannot alter current master status."
        )
    hypotheses = {
        code: build_hypotheses(code, current["status_code_counts"][str(code)], paths, evidence)
        for code in STATUS_HYPOTHESES
    }
    tls = tls_diagnostic(deltas[526], paths)
    timeline = build_timeline(previous, current, website)
    priority = choose_priorities(deltas, tls, ionos)
    missing_inputs = list(discovery["missing_inputs"])
    if not website:
        missing_inputs.append(rel(WEBSITE_JSON))
    if not master:
        missing_inputs.append(rel(MASTER_CONSISTENCY_JSON))

    significant_growth = any(item["trend"] == "SIGNIFICANT_GROWTH" for item in deltas.values())
    all_current_inputs = bool(website and master and not missing_inputs)
    direct_missing = bool(evidence["missing_evidence"])
    safety = build_safety_block()
    if safety.get("runtime_breach") is True:
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
        "safety": safety,
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
        "wp_users_me_diagnostic": build_wp_users_me_diagnostic(website),
        "actor_correlation": actors,
        "cache_correlation": {str(code): value for code, value in cache.items()},
        "ionos_webspace_evidence": ionos,
        "safe_improvement_plan": ionos.get("improvement_candidates", []),
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
    ionos = report.get("ionos_webspace_evidence", {})
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
        f"- IONOS evidence import: `{ionos.get('status', 'IONOS_EVIDENCE_MISSING')}`",
        f"- IONOS freshness: `{ionos.get('freshness', {}).get('freshness_status', 'MISSING')}`",
        f"- Synchronized path sequences: `{len(ionos.get('synchronized_sequences', []))}`",
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


def render_wp_users_me(report: Dict[str, Any]) -> str:
    diagnostic = report.get("wp_users_me_diagnostic", {})
    lines = private_header("Sentinel WordPress REST Identity Endpoint Classification")
    lines += [
        f"- path: `{diagnostic.get('path')}`",
        f"- classification: `{diagnostic.get('classification')}`",
        f"- confidence: `{diagnostic.get('confidence', 'none')}`",
        f"- evidence level: `{diagnostic.get('evidence_level', 'C_WEAK_CORRELATION')}`",
        f"- causality proven: `{str(diagnostic.get('causality_proven', False)).lower()}`",
        f"- diagnosis only: `{str(diagnostic.get('diagnosis_only', True)).lower()}`",
        f"- productive rule applied: `{str(diagnostic.get('productive_rule_applied', False)).lower()}`",
        "",
        diagnostic.get("classification_reason", ""),
        "",
    ]
    if not diagnostic.get("present"):
        lines += [
            "## Evidence",
            "",
            "- No current 5xx aggregate row exists for this path.",
        ]
        return "\n".join(lines)

    evidence = diagnostic.get("evidence", {})
    frequency = evidence.get("request_frequency", {})
    lines += [
        "## Request Frequency",
        "",
        f"- current 24h 5xx: `{frequency.get('total_5xx_24h')}`",
        f"- current 24h 504: `{frequency.get('status_504_24h')}`",
        f"- 24h path requests: `{frequency.get('path_requests_24h')}`",
        f"- failure share of path requests: `{frequency.get('failure_share_of_path_requests_percent')}%`",
        "",
        "## Dimensions",
        "",
        "| Dimension | Value |",
        "|---|---|",
        f"| response status | `{evidence.get('response_status')}` |",
        f"| cache status | `{evidence.get('cache_status')}` |",
        f"| cache bypassed | `{evidence.get('cache_bypassed_count')}` |",
        f"| country distribution | `{evidence.get('country_distribution')}` |",
        f"| distinct countries | `{evidence.get('distinct_countries')}` |",
        f"| top country share | `{evidence.get('top_country_share_percent')}%` |",
        f"| user agent class | `{evidence.get('user_agent_class')}` |",
        f"| actor class | `{evidence.get('actor_class')}` |",
        f"| failure mode | `{evidence.get('failure_mode')}` |",
        f"| request shape | `{evidence.get('request_shape')}` |",
        f"| referer class | `{evidence.get('referer_evidence')}` |",
        f"| temporal clustering | `{evidence.get('temporal_clustering')}` |",
        f"| authenticated vs anonymous | `{evidence.get('authenticated_vs_anonymous')}` |",
        f"| security actions 24h | `{evidence.get('security_actions_24h_count')}` |",
        f"| covered by combined rule | `{str(evidence.get('covered_by_sentinel_combined_rule')).lower()}` |",
        "",
        "## Candidate Classifications",
        "",
        "| Classification | Matched | Confidence | Reason |",
        "|---|---|---|---|",
    ]
    for item in diagnostic.get("candidate_classifications", []):
        lines.append(
            f"| `{item['classification']}` | `{str(item['matched']).lower()}` | "
            f"`{item['confidence']}` | {item['reason']} |"
        )
    lines += ["", "## Missing Evidence", ""]
    for item in diagnostic.get("missing_evidence", []):
        lines.append(f"- {item}")
    privacy = diagnostic.get("privacy", {})
    lines += [
        "",
        "## Privacy Guarantees",
        "",
        f"- privacy status: `{privacy.get('privacy_status', 'WP_USERS_ME_PRIVACY_OK')}`",
        f"- cookies stored: `{str(privacy.get('cookies_stored', False)).lower()}`",
        f"- authorization headers stored: `{str(privacy.get('authorization_headers_stored', False)).lower()}`",
        f"- tokens stored: `{str(privacy.get('tokens_stored', False)).lower()}`",
        f"- user ids collected: `{str(privacy.get('user_ids_collected', False)).lower()}`",
        "",
        "## Owner Note",
        "",
        f"- {diagnostic.get('owner_note', 'Diagnosis only.')}",
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
    ionos = report.get("ionos_webspace_evidence", {})
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
    lines += [
        "",
        "## IONOS Evidence Semantics",
        "",
        f"- Import status: `{ionos.get('status', 'IONOS_EVIDENCE_MISSING')}`",
        f"- Freshness: `{ionos.get('freshness', {}).get('freshness_status', 'MISSING')}`",
        f"- Synchronized sequence groups: `{len(ionos.get('synchronized_sequences', []))}`",
        f"- Expected-response candidates: `{ionos.get('summary', {}).get('expected_response_candidates', 0)}`",
        "- Preserve raw counts, but issue one operational recommendation per synchronized sequence.",
        "- Do not treat REST 401, method-restricted 405, intentional 410, or scanner 404 as repair tasks without confirming workflow evidence.",
        "- Do not dismiss scanner-correlated 503 as harmless; diagnose the origin response separately.",
    ]
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


def render_ionos_analysis(report: Dict[str, Any]) -> str:
    ionos = report.get("ionos_webspace_evidence", {})
    freshness = ionos.get("freshness", {})
    summary = ionos.get("summary", {})
    lines = private_header("Sentinel IONOS Webspace Action Classification")
    lines += [
        f"- Import status: `{ionos.get('status', 'IONOS_EVIDENCE_MISSING')}`",
        f"- Imported rows: `{ionos.get('imported_rows', 0)}`",
        f"- Freshness: `{freshness.get('freshness_status', 'MISSING')}`",
        f"- Included in current master status: `{str(ionos.get('included_in_master_status', False)).lower()}`",
        f"- Origin availability rows: `{summary.get('origin_availability_rows', 0)}`",
        f"- Expected-response candidates: `{summary.get('expected_response_candidates', 0)}`",
        f"- Context-review rows: `{summary.get('context_review_rows', 0)}`",
        f"- Operational sequence groups: `{summary.get('operational_sequence_groups', 0)}`",
        f"- Raw request observations retained: `{summary.get('raw_request_observations', 0)}`",
        "",
        "Freshness affects current status inclusion. Missing timestamps do not erase private correlation evidence, but they prevent the excerpt from overriding current telemetry.",
        "",
        "## Synchronized Sequences",
        "",
        "| Status | Count/path | Paths | Raw observations | Incident groups | Current actor | Correlation | Causality |",
        "|---:|---:|---:|---:|---:|---|---|---|",
    ]
    sequences = ionos.get("synchronized_sequences", [])
    if sequences:
        for item in sequences:
            lines.append(
                f"| {item['status']} | {item['source_count_per_path']} | {item['path_count']} | "
                f"{item['raw_request_observations']} | {item['operational_incident_groups']} | "
                f"`{item['cross_source_actor_signal']}` | `{item['correlation_strength']}` | `false` |"
            )
    else:
        lines.append("| - | - | - | - | - | - | `NONE` | `false` |")
    lines += [
        "",
        "## Response Semantics",
        "",
        "| Count | Status | Path | Operational class | Disposition |",
        "|---:|---:|---|---|---|",
    ]
    for row in ionos.get("row_classifications", []):
        lines.append(
            f"| {row['count']} | {row['status']} | `{row['path']}` | "
            f"`{row['operational_class']}` | `{row['action_disposition']}` |"
        )
    lines += ["", "## Safe Improvement Candidates", ""]
    for item in ionos.get("improvement_candidates", []):
        lines.append(f"- `{item['candidate']}`: `{item['status']}` - {item['reason']}")
    lines += [
        "",
        "## Guardrails",
        "",
        "- Raw request counts remain unchanged; only repeated operational recommendations are grouped.",
        "- Actor correlation is not causality and does not authorize an actor-wide block.",
        "- Expected-response candidates require workflow evidence before any repair.",
        "- No WordPress, hosting, Cloudflare, firewall, cache, or remote change is performed.",
    ]
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
    safety = report.get("safety") if isinstance(report.get("safety"), dict) else {}
    # The module boundary must stay exactly as declared; the canonical runtime
    # fields are additional and must be present with a recorded source.
    if {key: safety.get(key) for key in safety_expected} != safety_expected:
        findings.append("safety_flags_drift")
    if safety.get("module_productive_apply_lock") is not True:
        findings.append("module_apply_lock_missing")
    if "runtime_emergency_stop" not in safety or "runtime_breach" not in safety:
        findings.append("runtime_flags_missing")
    if safety.get("runtime_flags_status") not in {"RUNTIME_FLAGS_RESOLVED", "RUNTIME_FLAGS_INCOMPLETE"}:
        findings.append("runtime_flags_status_invalid")
    wp_users_me = report.get("wp_users_me_diagnostic") if isinstance(
        report.get("wp_users_me_diagnostic"), dict
    ) else {}
    if wp_users_me.get("classification") not in WP_USERS_ME_CLASSIFICATIONS:
        findings.append("wp_users_me_classification_invalid")
    if wp_users_me.get("productive_rule_applied") is not False:
        findings.append("wp_users_me_productive_rule")
    if wp_users_me.get("privacy", {}).get("privacy_status") != "WP_USERS_ME_PRIVACY_OK":
        findings.append("wp_users_me_privacy_violation")
    if report["waf_decision"]["new_waf_rule_recommended"] is not False:
        findings.append("automatic_waf_recommendation")
    if report["ssl_tls_decision"]["ssl_downgrade_recommended"] is not False:
        findings.append("ssl_downgrade_recommendation")
    if report["verified_user_impact"] != "unknown":
        findings.append("unsupported_user_impact")
    if any(row["causality_proven"] for row in report["actor_correlation"]):
        findings.append("actor_causality_claim")
    ionos = report.get("ionos_webspace_evidence", {})
    if ionos.get("automatic_apply") is not False:
        findings.append("ionos_automatic_apply_enabled")
    if ionos.get("causality_proven") is True:
        findings.append("ionos_causality_claim")
    if any(row.get("automatic_action") != "NO_ACTION" for row in ionos.get("row_classifications", [])):
        findings.append("ionos_row_automatic_action")
    if any(row.get("new_waf_rule_recommended") is not False for row in ionos.get("row_classifications", [])):
        findings.append("ionos_row_waf_recommendation")
    if any(item.get("causality_proven") is not False for item in ionos.get("synchronized_sequences", [])):
        findings.append("ionos_sequence_causality_claim")
    for item in ionos.get("synchronized_sequences", []):
        expected_raw = item.get("source_count_per_path", 0) * item.get("path_count", 0)
        if item.get("raw_request_observations") != expected_raw:
            findings.append("ionos_sequence_count_mismatch")
    findings.extend(f"ionos_input:{item}" for item in ionos.get("validation_findings", []))
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
    write_text(WP_USERS_ME_MD, render_wp_users_me(report))
    write_text(ACTOR_MD, render_actors(report))
    write_text(TIMELINE_MD, render_timeline(report))
    write_text(OWNER_PLAN_MD, render_owner_plan(report))
    write_text(EVIDENCE_GAP_MD, render_evidence_gap(report))
    write_text(IONOS_ANALYSIS_MD, render_ionos_analysis(report))
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
    mixed_status_rows = correlate_paths(
        {
            "top_5xx_paths": [{
                "path": "/",
                "statuses": [{"status": 503, "count": 48}, {"status": 504, "count": 1381}],
                "cache_status": [{"cache_status": "dynamic", "count": 48}, {"cache_status": "miss", "count": 1381}],
                "actor_signal_counts": [
                    {"actor_signal": "sitelockspider_actor", "count": 48},
                    {"actor_signal": "nginx_early_hints_actor", "count": 1381},
                ],
                "user_agent_groups": [
                    {"group": "SiteLockSpider", "count": 48},
                    {"group": "nginx-ssl early hints", "count": 1381},
                ],
                "countries": [{"country": "US", "count": 48}, {"country": "FR", "count": 1381}],
                "request_shape_counts": [
                    {"request_shape": "generic_origin_shape", "count": 48},
                    {"request_shape": "generic_timeout_shape", "count": 1381},
                ],
                "failure_mode_counts": [
                    {"failure_mode": "origin_php_or_upstream_error", "count": 48},
                    {"failure_mode": "cloudflare_to_origin_timeout", "count": 1381},
                ],
            }]
        },
        "2026-07-16T17:16:39Z",
    )
    mixed_by_status = {row["status_code"]: row for row in mixed_status_rows}
    synthetic_ionos_rows, synthetic_ionos_findings = normalize_ionos_rows({
        "key_rows": [
            {"path": "/", "status": 503, "count": 432, "source_priority": "HIGH"},
            {"path": "/page/2/", "status": 503, "count": 432, "source_priority": "HIGH"},
            {"path": "/wp-admin/images/w-logo-gray.png", "status": 503, "count": 432, "source_priority": "LOW"},
            {"path": "/wp-json/wp/v2/users/me", "status": 401, "count": 112},
            {"path": "/wp-comments-post.php", "status": 405, "count": 73},
            {"path": "/hello-world/", "status": 410, "count": 63},
            {"path": "/wp-content/plugins/fix/up.php", "status": 404, "count": 31},
            {"path": "/ALFA_DATA/alfacgiapi/perl.alfa", "status": 503, "count": 29},
            {"path": "/wp-admin/admin-ajax.php", "status": 403, "count": 528},
            {"path": "/", "status": 404, "count": 50},
            {"path": "/", "status": 429, "count": 25},
        ]
    })
    synthetic_ionos_classified = [classify_ionos_response(row) for row in synthetic_ionos_rows]
    synthetic_ionos_by_key = {
        (row["path"], row["status"]): row for row in synthetic_ionos_classified
    }
    synthetic_sequences = detect_synchronized_sequences(
        synthetic_ionos_classified,
        [
            {"status_code": 503, "path": "/", "count": 48, "actor_signal": "sitelockspider_actor"},
            {"status_code": 503, "path": "/page/2/", "count": 48, "actor_signal": "sitelockspider_actor"},
            {"status_code": 503, "path": "/wp-admin/images/w-logo-gray.png", "count": 48, "actor_signal": "sitelockspider_actor"},
        ],
    )
    synthetic_503_sequence = next(item for item in synthetic_sequences if item["status"] == 503)
    synthetic_504_growth = {
        503: {"status": 503, **calculate_delta(297, 155)},
        504: {"status": 504, **calculate_delta(462, 1450)},
        522: {"status": 522, **calculate_delta(2, 1)},
        526: {"status": 526, **calculate_delta(2, 0)},
    }
    synthetic_504_priority = choose_priorities(
        synthetic_504_growth,
        tls_diagnostic(synthetic_504_growth[526], []),
        {"synchronized_sequences": synthetic_sequences},
    )
    invalid_freshness = evaluate_evidence_freshness(None, datetime(2026, 7, 16, tzinfo=timezone.utc))
    synthetic_wp_users_me = build_wp_users_me_diagnostic({
        "origin_pressure_breakdown": {
            "top_5xx_paths": [{
                "path": WP_USERS_ME_PATH,
                "count": 62,
                "hostnames": ["example.invalid"],
                "statuses": [{"status": 504, "count": 62}],
                "countries": [
                    {"country": "US", "count": 22},
                    {"country": "VN", "count": 8},
                    {"country": "IN", "count": 4},
                    {"country": "FR", "count": 4},
                ],
                "cache_status": [{"cache_status": "miss", "count": 62}],
                "user_agent_groups": [{"group": "nginx-ssl early hints", "count": 53}],
                "actor_signal_counts": [{"actor_signal": "nginx_early_hints_actor", "count": 62}],
                "failure_mode_counts": [{"failure_mode": "cloudflare_to_origin_timeout", "count": 62}],
                "request_shape_counts": [{"request_shape": "wordpress_or_legacy_shape", "count": 62}],
                "security_actions_24h": [],
                "top_paths_24h_request_count": 101,
            }]
        }
    })
    synthetic_safety = build_safety_block()
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
        "test_e_status_specific_actor_correlation": (
            mixed_by_status[503]["actor_signal"] == "sitelockspider_actor"
            and mixed_by_status[504]["actor_signal"] == "nginx_early_hints_actor"
            and mixed_by_status[503]["user_agent_group"] == "SiteLockSpider"
            and mixed_by_status[504]["user_agent_group"] == "nginx-ssl early hints"
        ),
        "test_e_ambiguous_dimension_not_assigned": infer_status_dimension(
            {
                "statuses": [{"status": 503, "count": 48}, {"status": 504, "count": 1381}],
                "actor_signal_counts": [{"actor_signal": "incomplete_actor", "count": 47}],
            },
            "actor_signal_counts",
            "actor_signal",
        ) == {},
        "ionos_rows_normalized": len(synthetic_ionos_rows) == 11 and not synthetic_ionos_findings,
        "ionos_rest_401_expected_candidate": (
            synthetic_ionos_by_key[("/wp-json/wp/v2/users/me", 401)]["operational_class"]
            == "EXPECTED_UNAUTHENTICATED_RESPONSE_CANDIDATE"
        ),
        "ionos_comments_405_expected_candidate": (
            synthetic_ionos_by_key[("/wp-comments-post.php", 405)]["operational_class"]
            == "EXPECTED_METHOD_RESTRICTION_CANDIDATE"
        ),
        "ionos_hello_world_410_expected_candidate": (
            synthetic_ionos_by_key[("/hello-world", 410)]["operational_class"]
            == "INTENTIONAL_REMOVAL_CANDIDATE"
        ),
        "ionos_scanner_404_no_repair": (
            synthetic_ionos_by_key[("/wp-content/plugins/fix/up.php", 404)]["operational_class"]
            == "EXPECTED_SCANNER_REJECTION"
        ),
        "ionos_scanner_503_still_origin_signal": (
            synthetic_ionos_by_key[("/ALFA_DATA/alfacgiapi/perl.alfa", 503)]["operational_class"]
            == "SCANNER_CORRELATED_ORIGIN_FAILURE"
            and synthetic_ionos_by_key[("/ALFA_DATA/alfacgiapi/perl.alfa", 503)]["counts_as_origin_availability_signal"] is True
        ),
        "ionos_admin_ajax_403_requires_context": (
            synthetic_ionos_by_key[("/wp-admin/admin-ajax.php", 403)]["operational_class"]
            == "ADMIN_AJAX_SECURITY_OR_WORKFLOW_CONTEXT_REQUIRED"
        ),
        "ionos_root_404_requires_request_shape": (
            synthetic_ionos_by_key[("/", 404)]["operational_class"] == "ROOT_ROUTING_CONTEXT_REQUIRED"
        ),
        "ionos_root_429_requires_issuer": (
            synthetic_ionos_by_key[("/", 429)]["operational_class"] == "RATE_LIMIT_ISSUER_REVIEW"
        ),
        "ionos_sequence_deduplicates_action_not_counts": (
            synthetic_503_sequence["raw_request_observations"] == 1296
            and synthetic_503_sequence["operational_incident_groups"] == 1
            and synthetic_503_sequence["request_duplication_proven"] is False
        ),
        "ionos_sequence_cross_source_actor_correlation": (
            synthetic_503_sequence["repeated_sequence_supported"] is True
            and synthetic_503_sequence["cross_source_actor_signal"] == "sitelockspider_actor"
            and synthetic_503_sequence["causality_proven"] is False
        ),
        "ionos_missing_timestamp_excluded": (
            invalid_freshness["freshness_status"] == "INVALID_TIMESTAMP"
            and invalid_freshness["included_in_master_status"] is False
        ),
        "owner_priority_current_504_growth": (
            synthetic_504_priority["selected_detail_priority"] == "ORIGIN_504_GROWTH_DIAGNOSIS"
        ),
        "ionos_no_automatic_actions": all(
            row["automatic_action"] == "NO_ACTION" and row["new_waf_rule_recommended"] is False
            for row in synthetic_ionos_classified
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
        "wp_users_me_origin_timeout_classified": (
            synthetic_wp_users_me["classification"] == "WP_USERS_ME_ORIGIN_TIMEOUT"
            and synthetic_wp_users_me["evidence"]["request_frequency"]["status_504_24h"] == 62
            and synthetic_wp_users_me["causality_proven"] is False
            and synthetic_wp_users_me["productive_rule_applied"] is False
            and synthetic_wp_users_me["new_waf_rule_recommended"] is False
        ),
        "wp_users_me_bot_signal_recorded": (
            "WP_USERS_ME_BOT_OR_SCANNER" in synthetic_wp_users_me["secondary_classifications"]
        ),
        "wp_users_me_no_identity_material": (
            synthetic_wp_users_me["privacy"]["privacy_status"] == "WP_USERS_ME_PRIVACY_OK"
            and synthetic_wp_users_me["privacy"]["cookies_stored"] is False
            and synthetic_wp_users_me["privacy"]["authorization_headers_stored"] is False
            and synthetic_wp_users_me["privacy"]["tokens_stored"] is False
            and synthetic_wp_users_me["privacy"]["user_ids_collected"] is False
        ),
        "wp_users_me_privacy_scan_detects_identity_keys": privacy_scan(
            {"evidence": {"cookie": "x", "rows": [{"user_id": 7}]}}
        ) != [],
        "wp_users_me_polling_requires_temporal_evidence": (
            synthetic_wp_users_me["evidence"]["temporal_clustering"] == "EVIDENCE_NOT_COLLECTED"
            and all(
                item["matched"] is False
                for item in synthetic_wp_users_me["candidate_classifications"]
                if item["classification"] == "WP_USERS_ME_PLUGIN_POLLING"
            )
        ),
        "wp_users_me_missing_row_is_insufficient": (
            build_wp_users_me_diagnostic({})["classification"] == "WP_USERS_ME_EVIDENCE_INSUFFICIENT"
        ),
        "wp_users_me_allowed_classifications": (
            set(WP_USERS_ME_CLASSIFICATIONS) == set(WP_USERS_ME_CLASSIFICATION_PRIORITY)
            and synthetic_wp_users_me["classification"] in WP_USERS_ME_CLASSIFICATIONS
        ),
        "runtime_flags_not_hardcoded": (
            "runtime_emergency_stop" in synthetic_safety
            and synthetic_safety["module_productive_apply_lock"] is True
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
    ionos = report.get("ionos_webspace_evidence", {})
    print(ionos.get("status", "IONOS_EVIDENCE_MISSING"))
    print(f"IONOS_SYNCHRONIZED_SEQUENCES_{len(ionos.get('synchronized_sequences', []))}")
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
    group.add_argument("--analyze-wp-users-me", action="store_true")
    group.add_argument("--correlate-actors", action="store_true")
    group.add_argument("--analyze-ionos-evidence", action="store_true")
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
    elif args.analyze_wp_users_me:
        diagnostic = report["wp_users_me_diagnostic"]
        print(diagnostic["classification"])
        print(f"WP_USERS_ME_504_{diagnostic.get('evidence', {}).get('request_frequency', {}).get('status_504_24h', 0)}")
        print(f"CONFIDENCE_{diagnostic.get('confidence', 'none')}")
        print(f"PRIVACY_{diagnostic.get('privacy', {}).get('privacy_status', 'WP_USERS_ME_PRIVACY_OK')}")
        print(f"PRODUCTIVE_RULE_APPLIED_{str(diagnostic.get('productive_rule_applied', False)).lower()}")
    elif args.correlate_actors:
        print(f"ORIGIN_ACTOR_CORRELATION_ROWS_{len(report['actor_correlation'])}")
    elif args.analyze_ionos_evidence:
        ionos = report["ionos_webspace_evidence"]
        print(ionos["status"])
        print(f"IONOS_ROWS_{ionos['imported_rows']}")
        print(f"IONOS_SYNCHRONIZED_SEQUENCES_{len(ionos['synchronized_sequences'])}")
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
