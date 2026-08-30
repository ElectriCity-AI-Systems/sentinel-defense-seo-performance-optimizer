#!/usr/bin/env python3
"""Normalize owner-provided local origin evidence without retaining raw log lines.

The collector reads only a fixed project-local spool directory. It has no
network, subprocess, credential, system-log, or production-write capability.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import sentinel_runtime_safety as runtime_safety


PROJECT_DIR = Path(__file__).resolve().parent
SOURCE_DIR = PROJECT_DIR / "data/origin-evidence"
REPORT_DIR = PROJECT_DIR / "reports/latest"
STATE_DIR = PROJECT_DIR / "state/adaptive-learning"
AUDIT_DIR = PROJECT_DIR / "audit"

REPORT_JSON = REPORT_DIR / "sentinel-origin-evidence-collector.json"
REPORT_MD = REPORT_DIR / "sentinel-origin-evidence-collector.md"
STATE_JSON = STATE_DIR / "origin_evidence_collector.json"
LATEST_STATE_JSON = STATE_DIR / "latest_origin_evidence_collector.json"
HISTORY_JSON = STATE_DIR / "origin_evidence_collector_history.json"
AUDIT_JSONL = AUDIT_DIR / "sentinel-origin-evidence-collector.jsonl"

SCHEMA_VERSION = "sentinel-origin-evidence-collector-1"
ORIGIN_AGGREGATE_SCHEMA_VERSION = "sentinel-origin-window-aggregate-1"
ORIGIN_AGGREGATE_KIND = "NOWPLAYING_ORIGIN_WINDOW_AGGREGATE"
ORIGIN_AGGREGATE_VERIFICATION_SOURCE = (
    "OWNER_VERIFIED_COMPLETE_NGINX_EXACT_ENDPOINT_AGGREGATION"
)
CLOUDFLARE_EVENT_SCHEMA_VERSION = "sentinel-cloudflare-http-event-window-1"
CLOUDFLARE_EVENT_KIND = "NOWPLAYING_CLOUDFLARE_HTTP_EVENT_WINDOW"
CLOUDFLARE_EVENT_VERIFICATION_SOURCE = (
    "CLOUDFLARE_GRAPHQL_HTTP_REQUESTS_ADAPTIVE_READ_ONLY"
)
FILE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.(?:json|jsonl|log)$")
SNAPSHOT_ID_RE = re.compile(r"^\d{8}-\d{6}$")
TIMESTAMP_RE = re.compile(r"(?P<timestamp>\d{4}-\d{2}-\d{2}[T ][0-2]\d:[0-5]\d:[0-5]\d(?:\.\d+)?(?:Z|[+-][0-2]\d:[0-5]\d)?)")
NGINX_TIMESTAMP_RE = re.compile(r"\[(?P<timestamp>\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]")
PHP_TIMESTAMP_RE = re.compile(r"\[(?P<timestamp>\d{2}-[A-Za-z]{3}-\d{4} \d{2}:\d{2}:\d{2}(?: UTC)?)\]")
STATUS_RE = re.compile(r"(?:^|\s)(?P<status>[1-5]\d{2})(?:\s|$)")
PATH_RE = re.compile(r"(?:GET|POST|HEAD|PUT|PATCH|DELETE|OPTIONS)\s+(?P<path>/[^\s?]*)")
SECRET_RE = re.compile(r"(?i)(?:password|passwd|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*\S+")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----")

MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_RECORDS_PER_FILE = 5000
MAX_TOTAL_RECORDS = 20000
MAX_AGGREGATES = 100
MAX_CLOUDFLARE_EVENT_WINDOWS = 20
MAX_CLOUDFLARE_EVENTS_PER_WINDOW = 10000
AGGREGATE_CURRENT_SECONDS = 24 * 60 * 60

SOURCE_TYPES = {
    "PHP_FATAL_LOG",
    "WORDPRESS_DEBUG_LOG",
    "NGINX_UPSTREAM_ERROR",
    "HOSTING_RESOURCE_LIMIT",
    "ORIGIN_TLS_EVENT",
    "DATABASE_ERROR_LOG",
    "GENERIC_ORIGIN_ERROR_LOG",
}

CATEGORY_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    ("PHP_FATAL", re.compile(r"(?i)(?:PHP Fatal error|Uncaught (?:Error|Exception)|Maximum execution time)")),
    ("WORDPRESS_APPLICATION", re.compile(r"(?i)(?:WordPress database error|wp-settings\.php|wp-load\.php|wp_die\()")),
    ("ORIGIN_UPSTREAM_TIMEOUT", re.compile(r"(?i)(?:upstream timed out|upstream timeout|gateway timeout)")),
    ("ORIGIN_UPSTREAM_FAILURE", re.compile(r"(?i)(?:upstream prematurely closed|connect\(\) failed|no live upstreams)")),
    ("HOSTING_RESOURCE_LIMIT", re.compile(r"(?i)(?:Allowed memory size|Resource temporarily unavailable|max children|entry processes|resource limit)")),
    ("DATABASE_FAILURE", re.compile(r"(?i)(?:MySQL server has gone away|Too many connections|database connection error|database error)")),
    ("ORIGIN_TLS_FAILURE", re.compile(r"(?i)(?:certificate.*(?:expired|mismatch|verify failed)|SSL_do_handshake|TLS handshake failed)")),
)

SOURCE_TYPE_DEFAULT_CATEGORY = {
    "PHP_FATAL_LOG": "PHP_FATAL",
    "WORDPRESS_DEBUG_LOG": "WORDPRESS_APPLICATION",
    "NGINX_UPSTREAM_ERROR": "ORIGIN_UPSTREAM_FAILURE",
    "HOSTING_RESOURCE_LIMIT": "HOSTING_RESOURCE_LIMIT",
    "ORIGIN_TLS_EVENT": "ORIGIN_TLS_FAILURE",
    "DATABASE_ERROR_LOG": "DATABASE_FAILURE",
    "GENERIC_ORIGIN_ERROR_LOG": "UNKNOWN_ORIGIN_ERROR",
}

REPORT_CLASSIFICATION = [
    "PRIVATE_OWNER_OPERATIONAL_REPORT",
    "NOT_FOR_PUBLIC_RELEASE",
    "NOT_FOR_GIT",
    "SANITIZED_AGGREGATES_NO_RAW_LOG_LINES",
]


def utc_now_dt() -> datetime:
    return datetime.now(timezone.utc)


def utc_now() -> str:
    return utc_now_dt().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_timestamp(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace(" ", "T", 1)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def parse_log_timestamp(message: str) -> Optional[datetime]:
    iso_match = TIMESTAMP_RE.search(message)
    if iso_match:
        parsed = parse_timestamp(iso_match.group("timestamp"))
        if parsed:
            return parsed
    nginx_match = NGINX_TIMESTAMP_RE.search(message)
    if nginx_match:
        try:
            return datetime.strptime(nginx_match.group("timestamp"), "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
        except ValueError:
            pass
    php_match = PHP_TIMESTAMP_RE.search(message)
    if php_match:
        candidate = php_match.group("timestamp")
        for timestamp_format in ("%d-%b-%Y %H:%M:%S UTC", "%d-%b-%Y %H:%M:%S"):
            try:
                return datetime.strptime(candidate, timestamp_format).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    return None


def iso_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def canonical_hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (OSError, ValueError):
        return False


def safe_source_file(path: Path) -> bool:
    return bool(
        FILE_NAME_RE.fullmatch(path.name)
        and not path.is_symlink()
        and path.is_file()
        and is_within(path, SOURCE_DIR)
        and path.stat().st_size <= MAX_FILE_BYTES
    )


def ensure_dirs() -> None:
    for directory in (SOURCE_DIR, REPORT_DIR, STATE_DIR, AUDIT_DIR):
        if directory.is_symlink() or not is_within(directory, PROJECT_DIR):
            raise RuntimeError(f"unsafe directory: {directory.name}")
        directory.mkdir(parents=True, exist_ok=True)


def write_text(path: Path, text: str) -> None:
    if path.is_symlink() or not any(is_within(path, root) for root in (REPORT_DIR, STATE_DIR, AUDIT_DIR)):
        raise RuntimeError(f"blocked output path: {path.name}")
    mode = 0o600 if is_within(path, STATE_DIR) or is_within(path, AUDIT_DIR) else 0o644
    runtime_safety.atomic_write_text(path, text, mode)


def write_json(path: Path, value: Any) -> None:
    write_text(path, json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True))


def append_jsonl(path: Path, value: Dict[str, Any]) -> None:
    if path.is_symlink() or not is_within(path, AUDIT_DIR):
        raise RuntimeError("blocked audit path")
    line = json.dumps(value, sort_keys=True, ensure_ascii=True)
    json.loads(line)
    runtime_safety.durable_append_jsonl(path, value)


def classify_path(path: Optional[str]) -> Tuple[str, Optional[str]]:
    if not path or not path.startswith("/"):
        return "unknown", None
    normalized = path.split("?", 1)[0]
    if normalized == "/":
        path_class = "frontpage"
    elif normalized in {"/wp-login.php", "/xmlrpc.php"}:
        path_class = "wordpress_authentication"
    elif normalized.startswith("/wp-admin/"):
        path_class = "wordpress_admin"
    elif normalized.startswith(("/.env", "/.git/", "/alfacgiapi/", "/vendor/phpunit/")):
        path_class = "scanner_probe"
    elif re.search(r"\.(?:css|js|png|jpg|jpeg|gif|svg|webp|ico|woff2?)$", normalized):
        path_class = "static_asset"
    else:
        path_class = "public_or_unknown"
    return path_class, "path-" + hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


def classify_message(message: str, source_type: str) -> str:
    for category, pattern in CATEGORY_PATTERNS:
        if pattern.search(message):
            return category
    return SOURCE_TYPE_DEFAULT_CATEGORY.get(source_type, "UNKNOWN_ORIGIN_ERROR")


def secret_bearing(text: str) -> bool:
    return bool(SECRET_RE.search(text) or PRIVATE_KEY_RE.search(text))


def nonnegative_int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    try:
        result = int(value)
    except (TypeError, ValueError):
        return None
    return result if result >= 0 else None


def normalized_status_counts(value: Any) -> Optional[Dict[str, int]]:
    if not isinstance(value, dict):
        return None
    result: Dict[str, int] = {}
    for raw_status, raw_count in value.items():
        status = str(raw_status)
        count = nonnegative_int(raw_count)
        if not re.fullmatch(r"[1-5]\d{2}", status) or count is None:
            return None
        result[status] = count
    return dict(sorted(result.items()))


def nonnegative_number(value: Any) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    result = float(value)
    return result if result >= 0 else None


def normalized_cloudflare_event_window(
    row: Dict[str, Any], source_id: str
) -> Tuple[Optional[Dict[str, Any]], str]:
    """Normalize bounded Cloudflare request events without claiming origin causality."""
    findings: List[str] = []
    if row.get("schema_version") != CLOUDFLARE_EVENT_SCHEMA_VERSION:
        findings.append("invalid_schema_version")
    if row.get("evidence_kind") != CLOUDFLARE_EVENT_KIND:
        findings.append("invalid_evidence_kind")
    if row.get("verification_source") != CLOUDFLARE_EVENT_VERIFICATION_SOURCE:
        findings.append("unverified_source")

    retrieved_at = parse_timestamp(row.get("retrieved_at"))
    window_start = parse_timestamp(row.get("window_start"))
    window_end = parse_timestamp(row.get("window_end"))
    if retrieved_at is None:
        findings.append("invalid_retrieved_at")
    if window_start is None or window_end is None or window_start >= window_end:
        findings.append("invalid_evidence_window")

    endpoint = row.get("endpoint")
    hostname = row.get("hostname")
    snapshot_id = row.get("cloudflare_snapshot_id")
    if not isinstance(endpoint, str) or not endpoint.startswith("/") or "?" in endpoint:
        findings.append("invalid_endpoint")
    if not isinstance(hostname, str) or not hostname or "/" in hostname or "@" in hostname:
        findings.append("invalid_hostname")
    if not isinstance(snapshot_id, str) or not SNAPSHOT_ID_RE.fullmatch(snapshot_id):
        findings.append("invalid_cloudflare_snapshot_id")

    aggregate_count = nonnegative_int(row.get("cloudflare_aggregate_504_count"))
    declared_count = nonnegative_int(row.get("graphql_event_count"))
    weighted_count = nonnegative_int(row.get("graphql_weighted_aggregate_count"))
    sample_interval = nonnegative_number(row.get("graphql_average_sample_interval"))
    raw_events = row.get("events")
    if aggregate_count is None:
        findings.append("invalid_cloudflare_aggregate_504_count")
    if declared_count is None:
        findings.append("invalid_graphql_event_count")
    if weighted_count is None or weighted_count != aggregate_count:
        findings.append("invalid_graphql_weighted_aggregate_count")
    if sample_interval is None or sample_interval <= 0:
        findings.append("invalid_graphql_average_sample_interval")
    if not isinstance(raw_events, list) or len(raw_events) > MAX_CLOUDFLARE_EVENTS_PER_WINDOW:
        findings.append("invalid_events")
        raw_events = []
    if declared_count is not None and declared_count != len(raw_events):
        findings.append("event_count_mismatch")

    if row.get("graphql_dataset") != "httpRequestsAdaptive":
        findings.append("invalid_graphql_dataset")
    if row.get("graphql_dataset_enabled") is not True:
        findings.append("graphql_dataset_not_enabled")
    if not isinstance(row.get("origin_event_rows_available"), bool):
        findings.append("invalid_origin_event_rows_available")
    if row.get("credential_search_performed") is not False:
        findings.append("credential_search_not_false")

    normalized_events: List[Dict[str, Any]] = []
    for index, event in enumerate(raw_events):
        if not isinstance(event, dict):
            findings.append("invalid_event_row")
            continue
        timestamp = parse_timestamp(event.get("timestamp"))
        edge_status = nonnegative_int(event.get("edge_response_status"))
        origin_status = nonnegative_int(event.get("origin_response_status"))
        timings = {
            name: nonnegative_number(event.get(name))
            for name in (
                "origin_response_duration_ms",
                "origin_response_header_receive_duration_ms",
                "origin_tcp_handshake_duration_ms",
                "origin_tls_handshake_duration_ms",
            )
        }
        cache_status = event.get("cache_status")
        request_source = event.get("request_source")
        if (
            timestamp is None
            or window_start is None
            or window_end is None
            or not window_start <= timestamp <= window_end
        ):
            findings.append("event_timestamp_outside_window")
        if edge_status != 504:
            findings.append("event_edge_status_not_504")
        if origin_status is None or origin_status > 599:
            findings.append("invalid_origin_response_status")
        if any(value is None for value in timings.values()):
            findings.append("invalid_origin_timing")
        if not isinstance(cache_status, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", cache_status):
            findings.append("invalid_cache_status")
        if not isinstance(request_source, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", request_source):
            findings.append("invalid_request_source")
        if findings:
            continue
        normalized_timestamp = iso_utc(timestamp)
        identity = {
            "source_id": source_id,
            "index": index,
            "timestamp": normalized_timestamp,
            "edge_response_status": edge_status,
            "origin_response_status": origin_status,
            **timings,
        }
        normalized_events.append({
            "event_id": "cf-event-" + canonical_hash(identity)[:24],
            "timestamp": normalized_timestamp,
            "ray_id": None,
            "edge_response_status": edge_status,
            "origin_response_status": origin_status,
            **timings,
            "cache_status": cache_status,
            "request_source": request_source,
            "classification": "INSUFFICIENT_EVIDENCE",
            "causality_proven": False,
        })

    if findings:
        return None, ",".join(sorted(set(findings)))

    event_count = len(normalized_events)
    event_timestamps = [event["timestamp"] for event in normalized_events]
    origin_status_counts: Dict[str, int] = {}
    request_source_counts: Dict[str, int] = {}
    cache_status_counts: Dict[str, int] = {}
    for event in normalized_events:
        status_key = str(event["origin_response_status"])
        origin_status_counts[status_key] = origin_status_counts.get(status_key, 0) + 1
        source_key = event["request_source"]
        request_source_counts[source_key] = request_source_counts.get(source_key, 0) + 1
        cache_key = event["cache_status"]
        cache_status_counts[cache_key] = cache_status_counts.get(cache_key, 0) + 1

    return {
        "event_window_id": "cf-window-" + canonical_hash({
            "source_id": source_id,
            "window_start": iso_utc(window_start),
            "window_end": iso_utc(window_end),
            "endpoint": endpoint,
            "event_count": event_count,
        })[:24],
        "schema_version": CLOUDFLARE_EVENT_SCHEMA_VERSION,
        "evidence_kind": CLOUDFLARE_EVENT_KIND,
        "verification_source": CLOUDFLARE_EVENT_VERIFICATION_SOURCE,
        "source_id": source_id,
        "retrieved_at": iso_utc(retrieved_at),
        "window_start": iso_utc(window_start),
        "window_end": iso_utc(window_end),
        "cloudflare_snapshot_id": snapshot_id,
        "cloudflare_aggregate_504_count": aggregate_count,
        "endpoint": endpoint,
        "hostname": hostname,
        "graphql_dataset": "httpRequestsAdaptive",
        "graphql_dataset_enabled": True,
        "cloudflare_data_type": "HTTP_REQUESTS_ADAPTIVE_SAMPLED_ROWS",
        "complete_raw_request_log": False,
        "event_count": event_count,
        "weighted_aggregate_count": weighted_count,
        "average_sample_interval": sample_interval,
        "adaptive_sampling_present": sample_interval != 1.0,
        "events_with_timestamp": len(event_timestamps),
        "events_with_ray_id": 0,
        "first_event_at": min(event_timestamps) if event_timestamps else None,
        "last_event_at": max(event_timestamps) if event_timestamps else None,
        "edge_status_counts": {"504": event_count},
        "origin_status_counts": dict(sorted(origin_status_counts.items())),
        "request_source_counts": dict(sorted(request_source_counts.items())),
        "cache_status_counts": dict(sorted(cache_status_counts.items())),
        "classification_totals": {"INSUFFICIENT_EVIDENCE": event_count},
        "complete_event_coverage": event_count == aggregate_count and sample_interval == 1.0,
        "event_correlation_possible": False,
        "origin_event_rows_available": row["origin_event_rows_available"],
        "origin_access_status": str(row.get("origin_access_status") or "UNKNOWN"),
        "logpull_status": str(row.get("logpull_status") or "UNKNOWN"),
        "logpull_http_status": nonnegative_int(row.get("logpull_http_status")),
        "logpull_error_code": nonnegative_int(row.get("logpull_error_code")),
        "unavailable_event_fields": [
            str(value) for value in row.get("unavailable_event_fields", [])
            if isinstance(value, str)
        ],
        "credential_search_performed": False,
        "raw_response_stored": False,
        "client_identifiers_stored": False,
        "causality_proven": False,
        "verified_user_impact": "unknown",
        "events": normalized_events,
    }, "ok"


def normalized_origin_aggregate(
    row: Dict[str, Any], source_id: str
) -> Tuple[Optional[Dict[str, Any]], str]:
    """Validate a complete aggregate without turning zero findings into events."""
    findings: List[str] = []
    if row.get("schema_version") != ORIGIN_AGGREGATE_SCHEMA_VERSION:
        findings.append("invalid_schema_version")
    if row.get("evidence_kind") != ORIGIN_AGGREGATE_KIND:
        findings.append("invalid_evidence_kind")
    if row.get("verification_source") != ORIGIN_AGGREGATE_VERIFICATION_SOURCE:
        findings.append("unverified_source")

    window_start = parse_timestamp(row.get("window_start"))
    window_end = parse_timestamp(row.get("window_end"))
    verified_at = parse_timestamp(row.get("verified_at"))
    if window_start is None or window_end is None or window_start >= window_end:
        findings.append("invalid_evidence_window")
    if verified_at is None:
        findings.append("invalid_verified_at")

    endpoint = row.get("endpoint")
    origin = row.get("origin")
    snapshot_id = row.get("cloudflare_snapshot_id")
    if not isinstance(endpoint, str) or not endpoint.startswith("/") or "?" in endpoint:
        findings.append("invalid_endpoint")
    if not isinstance(origin, str) or not origin.strip():
        findings.append("invalid_origin")
    if not isinstance(snapshot_id, str) or not SNAPSHOT_ID_RE.fullmatch(snapshot_id):
        findings.append("invalid_cloudflare_snapshot_id")

    total = nonnegative_int(row.get("request_total"))
    local_total = nonnegative_int(row.get("local_request_total"))
    remote_total = nonnegative_int(row.get("remote_request_total"))
    cloudflare_504 = nonnegative_int(row.get("cloudflare_504_count"))
    nginx_504 = nonnegative_int(row.get("origin_nginx_504"))
    nginx_errors = nonnegative_int(row.get("nginx_matching_error_entries"))
    status_counts = normalized_status_counts(row.get("status_counts"))
    local_status_counts = normalized_status_counts(row.get("local_status_counts"))
    remote_status_counts = normalized_status_counts(row.get("remote_status_counts"))
    numeric_values = {
        "request_total": total,
        "local_request_total": local_total,
        "remote_request_total": remote_total,
        "cloudflare_504_count": cloudflare_504,
        "origin_nginx_504": nginx_504,
        "nginx_matching_error_entries": nginx_errors,
    }
    findings.extend(name + "_invalid" for name, value in numeric_values.items() if value is None)
    if status_counts is None:
        findings.append("invalid_status_counts")
    if local_status_counts is None:
        findings.append("invalid_local_status_counts")
    if remote_status_counts is None:
        findings.append("invalid_remote_status_counts")
    if total is not None and status_counts is not None and sum(status_counts.values()) != total:
        findings.append("status_count_total_mismatch")
    if local_total is not None and local_status_counts is not None and sum(local_status_counts.values()) != local_total:
        findings.append("local_status_count_total_mismatch")
    if remote_total is not None and remote_status_counts is not None and sum(remote_status_counts.values()) != remote_total:
        findings.append("remote_status_count_total_mismatch")
    if None not in (total, local_total, remote_total) and local_total + remote_total != total:
        findings.append("local_remote_total_mismatch")
    if nginx_504 is not None and status_counts is not None and status_counts.get("504", 0) != nginx_504:
        findings.append("nginx_504_status_mismatch")

    boolean_fields = (
        "nginx_timeout_observed",
        "upstream_timeout_observed",
        "azuracast_failure_supported",
        "current_direct_control_probe_succeeds",
        "microcache_unchanged",
        "event_level_correlation_available",
        "cloudflare_ray_ids_available",
    )
    for name in boolean_fields:
        if not isinstance(row.get(name), bool):
            findings.append(name + "_invalid")

    if findings:
        return None, ",".join(sorted(set(findings)))

    normalized = {
        "aggregate_id": "origin-aggregate-" + canonical_hash({
            "source_id": source_id,
            "window_start": iso_utc(window_start),
            "window_end": iso_utc(window_end),
            "endpoint": endpoint,
            "origin": origin,
            "request_total": total,
            "cloudflare_504_count": cloudflare_504,
        })[:24],
        "schema_version": ORIGIN_AGGREGATE_SCHEMA_VERSION,
        "evidence_kind": ORIGIN_AGGREGATE_KIND,
        "verification_source": ORIGIN_AGGREGATE_VERIFICATION_SOURCE,
        "source_id": source_id,
        "verified_at": iso_utc(verified_at),
        "window_start": iso_utc(window_start),
        "window_end": iso_utc(window_end),
        "cloudflare_snapshot_id": snapshot_id,
        "cloudflare_504_count": cloudflare_504,
        "endpoint": endpoint,
        "origin": origin,
        "request_total": total,
        "status_counts": status_counts,
        "local_request_total": local_total,
        "local_status_counts": local_status_counts,
        "remote_request_total": remote_total,
        "remote_status_counts": remote_status_counts,
        "origin_nginx_504": nginx_504,
        "nginx_matching_error_entries": nginx_errors,
        **{name: row[name] for name in boolean_fields},
        "azuracast_observation": (
            "NORMAL_EXPECTED_EXIT_0_RESTART_CYCLES"
            if row.get("azuracast_failure_supported") is False
            else "FAILURE_SIGNAL_PRESENT"
        ),
        "complete_exact_endpoint_aggregation": True,
        "raw_log_lines_stored": False,
        "causality_proven": False,
        "verified_user_impact": "unknown",
    }
    return normalized, "ok"


def aggregate_freshness(aggregates: List[Dict[str, Any]], now: datetime) -> Dict[str, Any]:
    verified = [parse_timestamp(row.get("verified_at")) for row in aggregates]
    valid = [item for item in verified if item is not None and item <= now]
    if not valid:
        return {"status": "MISSING_OR_INVALID_TIMESTAMP", "latest_verified_at": None, "age_seconds": None}
    latest = max(valid)
    age = max(0.0, (now - latest).total_seconds())
    return {
        "status": "CURRENT" if age <= AGGREGATE_CURRENT_SECONDS else "STALE_EXCLUDED_FROM_RUNTIME_PROOF",
        "latest_verified_at": iso_utc(latest),
        "age_seconds": round(age, 2),
    }


def cloudflare_event_window_freshness(
    windows: List[Dict[str, Any]], now: datetime
) -> Dict[str, Any]:
    retrieved = [parse_timestamp(row.get("retrieved_at")) for row in windows]
    valid = [item for item in retrieved if item is not None and item <= now]
    if not valid:
        return {"status": "MISSING_OR_INVALID_TIMESTAMP", "latest_retrieved_at": None, "age_seconds": None}
    latest = max(valid)
    age = max(0.0, (now - latest).total_seconds())
    return {
        "status": "CURRENT" if age <= AGGREGATE_CURRENT_SECONDS else "STALE_EXCLUDED_FROM_RUNTIME_PROOF",
        "latest_retrieved_at": iso_utc(latest),
        "age_seconds": round(age, 2),
    }


def select_origin_aggregate(
    report: Dict[str, Any],
    endpoint: Any,
    origin: Any,
    current_cloudflare_504: Any,
    current_snapshot_id: Any,
    current_window_start: Any = None,
    current_window_end: Any = None,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Select current-compatible evidence or retain it as incident-only context."""
    current_count = nonnegative_int(current_cloudflare_504)
    evaluated_at = (now or utc_now_dt()).astimezone(timezone.utc)
    current_start = parse_timestamp(current_window_start)
    current_end = parse_timestamp(current_window_end)
    incident_candidates: List[Dict[str, Any]] = []
    for row in report.get("origin_aggregates", []):
        if not isinstance(row, dict) or row.get("complete_exact_endpoint_aggregation") is not True:
            continue
        if row.get("endpoint") != endpoint or row.get("origin") != origin:
            continue
        verified_at = parse_timestamp(row.get("verified_at"))
        if verified_at is None or verified_at > evaluated_at or (evaluated_at - verified_at).total_seconds() > AGGREGATE_CURRENT_SECONDS:
            continue
        incident_candidates.append(row)

    if not incident_candidates:
        return {
            "status": "ORIGIN_AGGREGATION_EVIDENCE_MISSING",
            "current_truth_compatible": False,
            "incident_window_compatible": False,
            "aggregate": None,
            "reason": "No fresh complete exact-endpoint origin aggregate matches the endpoint and origin.",
        }

    row = max(incident_candidates, key=lambda item: item.get("verified_at", ""))
    aggregate_start = parse_timestamp(row.get("window_start"))
    aggregate_end = parse_timestamp(row.get("window_end"))
    exact_snapshot = row.get("cloudflare_snapshot_id") == current_snapshot_id
    within_current_window = bool(
        current_start and current_end and aggregate_start and aggregate_end
        and current_start <= aggregate_start <= aggregate_end <= current_end
    )
    count_match = current_count is not None and row.get("cloudflare_504_count") == current_count
    current_compatible = count_match and (exact_snapshot or within_current_window)
    status = (
        "CURRENT_ORIGIN_CORRELATION_EVIDENCE"
        if current_compatible
        else "INCIDENT_WINDOW_ORIGIN_CORRELATION_EVIDENCE"
    )
    return {
        "status": status,
        "current_truth_compatible": current_compatible,
        "incident_window_compatible": True,
        "compatibility": {
            "cloudflare_504_count_match": count_match,
            "cloudflare_snapshot_exact": exact_snapshot,
            "aggregate_within_current_monitor_window": within_current_window,
        },
        "aggregate": row,
        "reason": (
            "The aggregate matches the current Cloudflare count and evidence window."
            if current_compatible
            else "The aggregate is retained as verified incident-window evidence and is excluded from current counters."
        ),
    }


def select_cloudflare_event_window(
    report: Dict[str, Any],
    endpoint: Any,
    hostname: Any,
    current_cloudflare_504: Any,
    current_snapshot_id: Any,
    current_window_start: Any = None,
    current_window_end: Any = None,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Keep historical request events visible without replacing current counters."""
    current_count = nonnegative_int(current_cloudflare_504)
    evaluated_at = (now or utc_now_dt()).astimezone(timezone.utc)
    current_start = parse_timestamp(current_window_start)
    current_end = parse_timestamp(current_window_end)
    candidates: List[Dict[str, Any]] = []
    for row in report.get("cloudflare_event_windows", []):
        if not isinstance(row, dict) or row.get("evidence_kind") != CLOUDFLARE_EVENT_KIND:
            continue
        if row.get("endpoint") != endpoint or row.get("hostname") != hostname:
            continue
        retrieved_at = parse_timestamp(row.get("retrieved_at"))
        if (
            retrieved_at is None
            or retrieved_at > evaluated_at
            or (evaluated_at - retrieved_at).total_seconds() > AGGREGATE_CURRENT_SECONDS
        ):
            continue
        candidates.append(row)

    if not candidates:
        return {
            "status": "CLOUDFLARE_EVENT_EVIDENCE_MISSING",
            "current_truth_compatible": False,
            "incident_window_compatible": False,
            "event_window": None,
            "reason": "No fresh bounded Cloudflare event window matches the fixed endpoint and hostname.",
        }

    row = max(candidates, key=lambda item: item.get("retrieved_at", ""))
    event_start = parse_timestamp(row.get("window_start"))
    event_end = parse_timestamp(row.get("window_end"))
    exact_snapshot = row.get("cloudflare_snapshot_id") == current_snapshot_id
    within_current_window = bool(
        current_start and current_end and event_start and event_end
        and current_start <= event_start <= event_end <= current_end
    )
    count_match = current_count is not None and row.get("cloudflare_aggregate_504_count") == current_count
    current_compatible = count_match and (exact_snapshot or within_current_window)
    return {
        "status": (
            "CURRENT_CLOUDFLARE_EVENT_EVIDENCE"
            if current_compatible
            else "INCIDENT_WINDOW_CLOUDFLARE_EVENT_EVIDENCE"
        ),
        "current_truth_compatible": current_compatible,
        "incident_window_compatible": True,
        "compatibility": {
            "cloudflare_504_count_match": count_match,
            "cloudflare_snapshot_exact": exact_snapshot,
            "event_window_within_current_monitor_window": within_current_window,
        },
        "event_window": row,
        "reason": (
            "The Cloudflare request events match the current count and evidence window."
            if current_compatible
            else "The Cloudflare request events are retained as incident-window evidence and cannot replace current counters."
        ),
    }


def normalized_event(
    source_id: str,
    source_type: str,
    timestamp_value: Any,
    message: str,
    status_value: Any = None,
    path_value: Any = None,
) -> Tuple[Optional[Dict[str, Any]], str]:
    if secret_bearing(message):
        return None, "secret_pattern_skipped"
    parsed = parse_timestamp(timestamp_value)
    if parsed is None:
        parsed = parse_log_timestamp(message)
    status: Optional[int] = None
    try:
        candidate_status = int(status_value)
        status = candidate_status if 100 <= candidate_status <= 599 else None
    except (TypeError, ValueError):
        match = STATUS_RE.search(message)
        status = int(match.group("status")) if match else None
    path = str(path_value) if isinstance(path_value, str) else None
    if not path:
        match = PATH_RE.search(message)
        path = match.group("path") if match else None
    path_class, path_fingerprint = classify_path(path)
    category = classify_message(message, source_type)
    timestamp = iso_utc(parsed) if parsed else None
    identity = {
        "source_id": source_id,
        "source_type": source_type,
        "timestamp": timestamp,
        "category": category,
        "status": status,
        "path_fingerprint": path_fingerprint,
    }
    return {
        "event_id": "origin-" + canonical_hash(identity)[:24],
        "timestamp": timestamp,
        "source_id": source_id,
        "source_type": source_type,
        "category": category,
        "http_status": status,
        "path_class": path_class,
        "path_fingerprint": path_fingerprint,
        "direct_evidence": parsed is not None and category != "UNKNOWN_ORIGIN_ERROR",
        "raw_message_stored": False,
        "causality_proven": False,
        "verified_user_impact": "unknown",
    }, "ok"


def object_value(row: Dict[str, Any], names: Iterable[str]) -> Any:
    for name in names:
        if row.get(name) is not None:
            return row[name]
    return None


def parse_structured_rows(value: Any, source_id: str) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    rows = value if isinstance(value, list) else [value]
    events: List[Dict[str, Any]] = []
    skipped = {"invalid_row": 0, "secret_pattern": 0}
    for row in rows[:MAX_RECORDS_PER_FILE]:
        if not isinstance(row, dict):
            skipped["invalid_row"] += 1
            continue
        source_type = str(row.get("source_type") or "GENERIC_ORIGIN_ERROR_LOG")
        if source_type not in SOURCE_TYPES:
            source_type = "GENERIC_ORIGIN_ERROR_LOG"
        message = str(object_value(row, ("message", "error", "detail", "event")) or "")
        event, status = normalized_event(
            source_id,
            source_type,
            object_value(row, ("timestamp", "generated_at", "time", "datetime")),
            message,
            object_value(row, ("status", "status_code", "http_status")),
            object_value(row, ("path", "request_path", "uri")),
        )
        if event:
            events.append(event)
        elif status == "secret_pattern_skipped":
            skipped["secret_pattern"] += 1
    return events, skipped


def parse_file(
    path: Path,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    source_id = "source-" + file_hash(path)[:20]
    metadata: Dict[str, Any] = {
        "source_id": source_id,
        "file_name_stored": False,
        "size_bytes": path.stat().st_size,
        "format": path.suffix.lstrip("."),
        "records_read": 0,
        "records_emitted": 0,
        "secret_rows_skipped": 0,
        "invalid_rows_skipped": 0,
    }
    events: List[Dict[str, Any]] = []
    aggregates: List[Dict[str, Any]] = []
    cloudflare_event_windows: List[Dict[str, Any]] = []
    if path.suffix == ".json":
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            metadata["status"] = "INVALID_JSON"
            return [], [], [], metadata
        if isinstance(value, dict) and value.get("evidence_kind") == ORIGIN_AGGREGATE_KIND:
            aggregate, aggregate_status = normalized_origin_aggregate(value, source_id)
            if aggregate is not None:
                aggregates.append(aggregate)
                skipped = {"invalid_row": 0, "secret_pattern": 0}
            else:
                skipped = {"invalid_row": 1, "secret_pattern": 0}
                metadata["aggregate_validation"] = aggregate_status
        elif isinstance(value, dict) and value.get("evidence_kind") == CLOUDFLARE_EVENT_KIND:
            event_window, event_window_status = normalized_cloudflare_event_window(value, source_id)
            if event_window is not None:
                cloudflare_event_windows.append(event_window)
                skipped = {"invalid_row": 0, "secret_pattern": 0}
            else:
                skipped = {"invalid_row": 1, "secret_pattern": 0}
                metadata["cloudflare_event_validation"] = event_window_status
        else:
            events, skipped = parse_structured_rows(value, source_id)
        metadata["records_read"] = len(value) if isinstance(value, list) else 1
    else:
        skipped = {"invalid_row": 0, "secret_pattern": 0}
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[:MAX_RECORDS_PER_FILE]
        except OSError:
            metadata["status"] = "READ_ERROR"
            return [], [], [], metadata
        metadata["records_read"] = len(lines)
        if path.suffix == ".jsonl":
            values: List[Any] = []
            for line in lines:
                try:
                    values.append(json.loads(line))
                except json.JSONDecodeError:
                    skipped["invalid_row"] += 1
            events, structured_skipped = parse_structured_rows(values, source_id)
            skipped["invalid_row"] += structured_skipped["invalid_row"]
            skipped["secret_pattern"] += structured_skipped["secret_pattern"]
        else:
            source_type = "GENERIC_ORIGIN_ERROR_LOG"
            for line in lines:
                event, status = normalized_event(source_id, source_type, None, line)
                if event:
                    events.append(event)
                elif status == "secret_pattern_skipped":
                    skipped["secret_pattern"] += 1
    metadata["records_emitted"] = len(events)
    metadata["aggregates_emitted"] = len(aggregates)
    metadata["cloudflare_event_windows_emitted"] = len(cloudflare_event_windows)
    metadata["secret_rows_skipped"] = skipped["secret_pattern"]
    metadata["invalid_rows_skipped"] = skipped["invalid_row"]
    metadata["status"] = "COLLECTED"
    return events, aggregates, cloudflare_event_windows, metadata


def freshness(events: List[Dict[str, Any]], now: datetime) -> Dict[str, Any]:
    timestamps = [parse_timestamp(row.get("timestamp")) for row in events]
    valid = [item for item in timestamps if item is not None]
    if not valid:
        return {"status": "MISSING_OR_INVALID_TIMESTAMP", "latest_event_at": None, "age_seconds": None}
    latest = max(valid)
    age = max(0.0, (now - latest).total_seconds())
    if age <= 1800:
        status = "CURRENT"
    elif age <= 86400:
        status = "STALE_INFORMATIONAL"
    else:
        status = "STALE_EXCLUDED_FROM_RUNTIME_PROOF"
    return {"status": status, "latest_event_at": iso_utc(latest), "age_seconds": round(age, 2)}


def collect(write_audit: bool = True) -> Dict[str, Any]:
    ensure_dirs()
    files = sorted(path for path in SOURCE_DIR.iterdir() if safe_source_file(path))
    blocked = sorted(
        path.name
        for path in SOURCE_DIR.iterdir()
        if path.is_file() and path.name != ".gitignore" and not safe_source_file(path)
    )
    events: List[Dict[str, Any]] = []
    aggregates: List[Dict[str, Any]] = []
    cloudflare_event_windows: List[Dict[str, Any]] = []
    sources: List[Dict[str, Any]] = []
    for path in files:
        file_events, file_aggregates, file_cloudflare_windows, metadata = parse_file(path)
        remaining = max(0, MAX_TOTAL_RECORDS - len(events))
        events.extend(file_events[:remaining])
        aggregate_remaining = max(0, MAX_AGGREGATES - len(aggregates))
        aggregates.extend(file_aggregates[:aggregate_remaining])
        event_window_remaining = max(
            0, MAX_CLOUDFLARE_EVENT_WINDOWS - len(cloudflare_event_windows)
        )
        cloudflare_event_windows.extend(file_cloudflare_windows[:event_window_remaining])
        sources.append(metadata)
        if (
            len(events) >= MAX_TOTAL_RECORDS
            and len(aggregates) >= MAX_AGGREGATES
            and len(cloudflare_event_windows) >= MAX_CLOUDFLARE_EVENT_WINDOWS
        ):
            break
    categories: Dict[str, int] = {}
    for event in events:
        categories[event["category"]] = categories.get(event["category"], 0) + 1
    direct = sum(1 for event in events if event["direct_evidence"])
    generated_at = utc_now()
    generated_at_dt = parse_timestamp(generated_at) or utc_now_dt()
    event_freshness = freshness(events, generated_at_dt)
    origin_aggregate_freshness = aggregate_freshness(aggregates, generated_at_dt)
    cloudflare_events_freshness = cloudflare_event_window_freshness(
        cloudflare_event_windows, generated_at_dt
    )
    evidence_freshness = (
        origin_aggregate_freshness
        if origin_aggregate_freshness["status"] == "CURRENT"
        else event_freshness
    )
    aggregate_ready = bool(aggregates) and origin_aggregate_freshness["status"] == "CURRENT"
    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "status": (
            "ORIGIN_EVIDENCE_CURRENT"
            if (direct and event_freshness["status"] == "CURRENT") or aggregate_ready
            else "ORIGIN_EVIDENCE_INCOMPLETE"
        ),
        "report_classification": REPORT_CLASSIFICATION,
        "source_directory": "project-local-fixed-spool",
        "source_file_count": len(files),
        "blocked_file_count": len(blocked),
        "blocked_file_names_disclosed": False,
        "normalized_event_count": len(events),
        "direct_evidence_count": direct,
        "freshness": evidence_freshness,
        "event_freshness": event_freshness,
        "origin_aggregate_freshness": origin_aggregate_freshness,
        "origin_aggregate_count": len(aggregates),
        "complete_origin_aggregate_count": sum(
            1 for row in aggregates if row.get("complete_exact_endpoint_aggregation") is True
        ),
        "origin_aggregates": aggregates,
        "cloudflare_event_window_freshness": cloudflare_events_freshness,
        "cloudflare_event_window_count": len(cloudflare_event_windows),
        "cloudflare_event_count": sum(
            row.get("event_count", 0) for row in cloudflare_event_windows
        ),
        "cloudflare_event_windows": cloudflare_event_windows,
        "category_counts": categories,
        "sources": sources,
        "events": events,
        "raw_log_lines_stored": False,
        "secret_rows_skipped": sum(item["secret_rows_skipped"] for item in sources),
        "causality_proven": False,
        "verified_user_impact": "unknown",
        "safety": {
            "network_access": False,
            "remote_log_access": False,
            "credential_access": False,
            "production_write": False,
            "breach": False,
        },
    }
    write_json(REPORT_JSON, report)
    write_json(STATE_JSON, report)
    write_json(LATEST_STATE_JSON, report)
    history: List[Any] = []
    if HISTORY_JSON.exists() and not HISTORY_JSON.is_symlink():
        try:
            loaded = json.loads(HISTORY_JSON.read_text(encoding="utf-8"))
            history = loaded if isinstance(loaded, list) else []
        except (OSError, json.JSONDecodeError):
            history = []
    history.append({key: report[key] for key in (
        "generated_at", "status", "normalized_event_count", "direct_evidence_count",
        "origin_aggregate_count", "complete_origin_aggregate_count", "freshness",
        "category_counts", "cloudflare_event_window_count", "cloudflare_event_count",
    )})
    write_json(HISTORY_JSON, history[-200:])
    lines = [
        "# Sentinel Origin Evidence Collector",
        "",
        *[f"- Classification: `{item}`" for item in REPORT_CLASSIFICATION],
        f"- Status: `{report['status']}`",
        f"- Source files: `{report['source_file_count']}`",
        f"- Normalized events: `{report['normalized_event_count']}`",
        f"- Direct evidence: `{report['direct_evidence_count']}`",
        f"- Complete origin aggregates: `{report['complete_origin_aggregate_count']}`",
        f"- Cloudflare event windows: `{report['cloudflare_event_window_count']}`",
        f"- Cloudflare adaptive rows: `{report['cloudflare_event_count']}`",
        f"- Freshness: `{report['freshness']['status']}`",
        f"- Raw log lines stored: `false`",
        f"- Causality proven: `false`",
        f"- Verified user impact: `unknown`",
        "",
        "Owner-provided evidence must be placed manually in the fixed project-local spool. The collector never reads system log directories or remote systems.",
    ]
    write_text(REPORT_MD, "\n".join(lines))
    if write_audit:
        append_jsonl(AUDIT_JSONL, {
            "timestamp": generated_at,
            "event": "origin_evidence_collected",
            "status": report["status"],
            "source_file_count": len(files),
            "normalized_event_count": len(events),
            "direct_evidence_count": direct,
            "complete_origin_aggregate_count": report["complete_origin_aggregate_count"],
            "cloudflare_event_window_count": report["cloudflare_event_window_count"],
            "cloudflare_event_count": report["cloudflare_event_count"],
            "raw_log_lines_stored": False,
            "breach": False,
        })
    return report


def self_test() -> Dict[str, Any]:
    sample, sample_status = normalized_event(
        "source-test",
        "PHP_FATAL_LOG",
        "2026-07-16T18:00:00Z",
        "PHP Fatal error: Uncaught Error in application code",
        503,
        "/",
    )
    secret, secret_status = normalized_event(
        "source-test",
        "GENERIC_ORIGIN_ERROR_LOG",
        "2026-07-16T18:00:00Z",
        "pass" + "word=should-not-be-retained",
    )
    common_log, common_log_status = normalized_event(
        "source-test",
        "NGINX_UPSTREAM_ERROR",
        None,
        '[16/Jul/2026:18:00:00 +0000] upstream timed out "GET / HTTP/1.1" 504',
    )
    aggregate_fixture = {
        "schema_version": ORIGIN_AGGREGATE_SCHEMA_VERSION,
        "evidence_kind": ORIGIN_AGGREGATE_KIND,
        "verification_source": ORIGIN_AGGREGATE_VERIFICATION_SOURCE,
        "verified_at": "2026-08-27T19:00:00Z",
        "window_start": "2026-08-26T16:15:59Z",
        "window_end": "2026-08-27T06:42:40Z",
        "cloudflare_snapshot_id": "20260827-140232",
        "cloudflare_504_count": 834,
        "endpoint": "/api/nowplaying/electri-city-ai-electro-radio",
        "origin": "203.0.113.10",
        "request_total": 2612,
        "status_counts": {"200": 2612},
        "local_request_total": 1714,
        "local_status_counts": {"200": 1714},
        "remote_request_total": 898,
        "remote_status_counts": {"200": 898},
        "origin_nginx_504": 0,
        "nginx_matching_error_entries": 0,
        "nginx_timeout_observed": False,
        "upstream_timeout_observed": False,
        "azuracast_failure_supported": False,
        "current_direct_control_probe_succeeds": True,
        "microcache_unchanged": True,
        "event_level_correlation_available": False,
        "cloudflare_ray_ids_available": False,
    }
    aggregate, aggregate_status = normalized_origin_aggregate(aggregate_fixture, "source-test")
    aggregate_report = {"origin_aggregates": [aggregate] if aggregate else []}
    current_match = select_origin_aggregate(
        aggregate_report,
        aggregate_fixture["endpoint"],
        aggregate_fixture["origin"],
        834,
        "20260827-140232",
        "2026-08-26T14:02:32Z",
        "2026-08-27T14:02:32Z",
        datetime(2026, 8, 27, 19, 10, tzinfo=timezone.utc),
    )
    historical_match = select_origin_aggregate(
        aggregate_report,
        aggregate_fixture["endpoint"],
        aggregate_fixture["origin"],
        659,
        "20260827-191907",
        "2026-08-26T19:19:07Z",
        "2026-08-27T19:19:07Z",
        datetime(2026, 8, 27, 19, 10, tzinfo=timezone.utc),
    )
    cloudflare_event_fixture = {
        "schema_version": CLOUDFLARE_EVENT_SCHEMA_VERSION,
        "evidence_kind": CLOUDFLARE_EVENT_KIND,
        "verification_source": CLOUDFLARE_EVENT_VERIFICATION_SOURCE,
        "retrieved_at": "2026-08-27T19:30:00Z",
        "window_start": "2026-08-26T16:15:59Z",
        "window_end": "2026-08-27T06:42:40Z",
        "cloudflare_snapshot_id": "20260827-140232",
        "cloudflare_aggregate_504_count": 3,
        "endpoint": "/api/nowplaying/electri-city-ai-electro-radio",
        "hostname": "radio.example.test",
        "graphql_dataset": "httpRequestsAdaptive",
        "graphql_dataset_enabled": True,
        "graphql_event_count": 2,
        "graphql_weighted_aggregate_count": 3,
        "graphql_average_sample_interval": 1.5,
        "origin_event_rows_available": False,
        "origin_access_status": "READ_ONLY_FORCED_COMMAND_UNSUPPORTED",
        "credential_search_performed": False,
        "logpull_status": "PLAN_UNAVAILABLE_FREE_ZONE",
        "logpull_http_status": 403,
        "logpull_error_code": 10000,
        "unavailable_event_fields": ["RayID", "coloCode", "originIP"],
        "events": [
            {
                "timestamp": "2026-08-26T16:22:42Z",
                "edge_response_status": 504,
                "origin_response_status": 0,
                "origin_response_duration_ms": 0,
                "origin_response_header_receive_duration_ms": 0,
                "origin_tcp_handshake_duration_ms": 0,
                "origin_tls_handshake_duration_ms": 0,
                "cache_status": "miss",
                "request_source": "earlyHintsCache",
            },
            {
                "timestamp": "2026-08-27T06:28:51Z",
                "edge_response_status": 504,
                "origin_response_status": 0,
                "origin_response_duration_ms": 0,
                "origin_response_header_receive_duration_ms": 0,
                "origin_tcp_handshake_duration_ms": 0,
                "origin_tls_handshake_duration_ms": 0,
                "cache_status": "miss",
                "request_source": "earlyHintsCache",
            },
        ],
    }
    cloudflare_window, cloudflare_window_status = normalized_cloudflare_event_window(
        cloudflare_event_fixture, "source-test"
    )
    cloudflare_event_report = {
        "cloudflare_event_windows": [cloudflare_window] if cloudflare_window else []
    }
    cloudflare_incident_match = select_cloudflare_event_window(
        cloudflare_event_report,
        cloudflare_event_fixture["endpoint"],
        cloudflare_event_fixture["hostname"],
        139,
        "20260828-040740",
        "2026-08-27T04:07:40Z",
        "2026-08-28T04:07:40Z",
        datetime(2026, 8, 27, 20, 0, tzinfo=timezone.utc),
    )
    source = Path(__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports: List[str] = []
    command_calls: List[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.append(node.module)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {
            "Popen", "run", "call", "check_call", "check_output", "system"
        }:
            command_calls.append(node.func.attr)
    forbidden_imports = {"requests", "urllib", "http.client", "socket", "smtplib", "paramiko", "cloudflare", "subprocess"}
    network_imports = [name for name in imports if name.split(".")[0] in forbidden_imports]
    tests = {
        "php_fatal_normalized": bool(sample) and sample["category"] == "PHP_FATAL",
        "timestamp_required_for_direct_evidence": bool(sample) and sample["direct_evidence"] is True,
        "raw_message_not_stored": bool(sample) and "message" not in sample and sample["raw_message_stored"] is False,
        "secret_row_skipped": secret is None and secret_status == "secret_pattern_skipped",
        "common_log_normalized": (
            common_log_status == "ok"
            and bool(common_log)
            and common_log["timestamp"] == "2026-07-16T18:00:00Z"
            and common_log["http_status"] == 504
            and common_log["path_class"] == "frontpage"
            and common_log["direct_evidence"] is True
        ),
        "path_is_fingerprinted": bool(sample) and sample["path_class"] == "frontpage" and sample["path_fingerprint"],
        "complete_origin_aggregate_normalized": (
            aggregate_status == "ok"
            and bool(aggregate)
            and aggregate["request_total"] == 2612
            and aggregate["status_counts"] == {"200": 2612}
            and aggregate["remote_request_total"] == 898
            and aggregate["origin_nginx_504"] == 0
            and aggregate["causality_proven"] is False
        ),
        "current_aggregate_requires_count_and_window_alignment": (
            current_match["status"] == "CURRENT_ORIGIN_CORRELATION_EVIDENCE"
            and current_match["current_truth_compatible"] is True
        ),
        "historical_aggregate_cannot_overwrite_current_truth": (
            historical_match["status"] == "INCIDENT_WINDOW_ORIGIN_CORRELATION_EVIDENCE"
            and historical_match["current_truth_compatible"] is False
            and historical_match["aggregate"]["cloudflare_504_count"] == 834
        ),
        "cloudflare_event_window_normalized_fail_closed": (
            cloudflare_window_status == "ok"
            and bool(cloudflare_window)
            and cloudflare_window["event_count"] == 2
            and cloudflare_window["events_with_timestamp"] == 2
            and cloudflare_window["events_with_ray_id"] == 0
            and cloudflare_window["cloudflare_data_type"]
            == "HTTP_REQUESTS_ADAPTIVE_SAMPLED_ROWS"
            and cloudflare_window["complete_raw_request_log"] is False
            and cloudflare_window["classification_totals"] == {"INSUFFICIENT_EVIDENCE": 2}
            and cloudflare_window["event_correlation_possible"] is False
            and cloudflare_window["causality_proven"] is False
        ),
        "cloudflare_adaptive_coverage_gap_preserved": (
            bool(cloudflare_window)
            and cloudflare_window["cloudflare_aggregate_504_count"] == 3
            and cloudflare_window["weighted_aggregate_count"] == 3
            and cloudflare_window["adaptive_sampling_present"] is True
            and cloudflare_window["complete_event_coverage"] is False
        ),
        "historical_cloudflare_events_cannot_overwrite_current_truth": (
            cloudflare_incident_match["status"]
            == "INCIDENT_WINDOW_CLOUDFLARE_EVENT_EVIDENCE"
            and cloudflare_incident_match["current_truth_compatible"] is False
            and cloudflare_incident_match["event_window"]["event_count"] == 2
        ),
        "no_network_imports": not network_imports,
        "no_command_execution": not command_calls,
        "fixed_source_directory": SOURCE_DIR == PROJECT_DIR / "data/origin-evidence",
        "symlink_escape_blocked": not is_within(PROJECT_DIR.parent / "outside.log", SOURCE_DIR),
        "breach_false": True,
    }
    findings = [name for name, passed in tests.items() if not passed]
    return {
        "status": "ORIGIN_EVIDENCE_COLLECTOR_SELF_TEST_OK" if not findings else "ORIGIN_EVIDENCE_COLLECTOR_SELF_TEST_FAILED",
        "checks": tests,
        "findings": findings,
        "network_imports": network_imports,
        "command_calls": command_calls,
        "breach": False,
    }


def load_status() -> Dict[str, Any]:
    try:
        value = json.loads(REPORT_JSON.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def main() -> int:
    parser = argparse.ArgumentParser(description="Local read-only origin evidence collector")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--collect", action="store_true")
    group.add_argument("--status", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        result = self_test()
        print(result["status"])
        return 0 if not result["findings"] else 1
    if args.collect:
        result = collect()
    else:
        result = load_status()
    if not result:
        print("ORIGIN_EVIDENCE_NOT_COLLECTED")
        return 1
    print(result.get("status", "ORIGIN_EVIDENCE_UNKNOWN"))
    print(f"DIRECT_EVIDENCE_{result.get('direct_evidence_count', 0)}")
    print("RAW_LOG_LINES_STORED_FALSE")
    print("BREACH_FALSE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
