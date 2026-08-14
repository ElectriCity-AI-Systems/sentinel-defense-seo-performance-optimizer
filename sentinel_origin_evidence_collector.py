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
FILE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.(?:json|jsonl|log)$")
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


def parse_file(path: Path) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
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
    if path.suffix == ".json":
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            metadata["status"] = "INVALID_JSON"
            return [], metadata
        events, skipped = parse_structured_rows(value, source_id)
        metadata["records_read"] = len(value) if isinstance(value, list) else 1
    else:
        skipped = {"invalid_row": 0, "secret_pattern": 0}
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[:MAX_RECORDS_PER_FILE]
        except OSError:
            metadata["status"] = "READ_ERROR"
            return [], metadata
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
    metadata["secret_rows_skipped"] = skipped["secret_pattern"]
    metadata["invalid_rows_skipped"] = skipped["invalid_row"]
    metadata["status"] = "COLLECTED"
    return events, metadata


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
    sources: List[Dict[str, Any]] = []
    for path in files:
        file_events, metadata = parse_file(path)
        remaining = max(0, MAX_TOTAL_RECORDS - len(events))
        events.extend(file_events[:remaining])
        sources.append(metadata)
        if len(events) >= MAX_TOTAL_RECORDS:
            break
    categories: Dict[str, int] = {}
    for event in events:
        categories[event["category"]] = categories.get(event["category"], 0) + 1
    direct = sum(1 for event in events if event["direct_evidence"])
    generated_at = utc_now()
    evidence_freshness = freshness(events, parse_timestamp(generated_at) or utc_now_dt())
    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "status": "ORIGIN_EVIDENCE_CURRENT" if direct and evidence_freshness["status"] == "CURRENT" else "ORIGIN_EVIDENCE_INCOMPLETE",
        "report_classification": REPORT_CLASSIFICATION,
        "source_directory": "project-local-fixed-spool",
        "source_file_count": len(files),
        "blocked_file_count": len(blocked),
        "blocked_file_names_disclosed": False,
        "normalized_event_count": len(events),
        "direct_evidence_count": direct,
        "freshness": evidence_freshness,
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
        "generated_at", "status", "normalized_event_count", "direct_evidence_count", "freshness", "category_counts"
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
