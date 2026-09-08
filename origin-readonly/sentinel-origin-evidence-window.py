#!/usr/bin/env python3
"""Bounded read-only NowPlaying evidence export for an SSH forced command.

The caller may select only a finite evidence class and a recent UTC window.
Paths, log files, endpoints, commands, and output fields are fixed in source.
The helper never invokes a shell, subprocess, network client, sudo, or writer.
"""

from __future__ import annotations

import gzip
import hashlib
import ipaddress
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, TextIO, Tuple


SCHEMA_VERSION = "sentinel-origin-evidence-window-1"
COMMAND_ID = "sentinel-origin-evidence-window"
ENDPOINT = "/api/nowplaying/electri-city-ai-electro-radio"
LOG_ROOT = Path("/var/log/nginx")

ALLOWED_EVIDENCE_TYPES = frozenset({
    "nginx-window",
    "nginx-error-window",
    "nowplaying-window",
})
DISABLED_EVIDENCE_TYPES = {
    "azuracast-window": "No owner-reviewed fixed AzuraCast log source is currently known.",
}
MAX_WINDOW_SECONDS = 60 * 60
MAX_LOOKBACK_SECONDS = 48 * 60 * 60
MAX_SOURCE_BYTES = 2 * 1024 * 1024 * 1024
MAX_LINES = 3_000_000
MAX_RECORDS = 5_000
MAX_OUTPUT_BYTES = 4 * 1024 * 1024

ACCESS_SOURCES = (
    LOG_ROOT / "access.log",
    LOG_ROOT / "access.log.1",
    LOG_ROOT / "access.log.2.gz",
    LOG_ROOT / "access.log.3.gz",
    LOG_ROOT / "azuracast.access.log",
    LOG_ROOT / "azuracast.access.log.1",
    LOG_ROOT / "azuracast.access.log.2.gz",
    LOG_ROOT / "azuracast.access.log.3.gz",
)
ERROR_SOURCES = (
    LOG_ROOT / "error.log",
    LOG_ROOT / "error.log.1",
    LOG_ROOT / "error.log.2.gz",
    LOG_ROOT / "error.log.3.gz",
)

UTC_TOKEN = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"
COMMAND_RE = re.compile(
    rf"^{COMMAND_ID} (?P<kind>[a-z-]+) (?P<start>{UTC_TOKEN}) (?P<end>{UTC_TOKEN})$"
)
COMBINED_RE = re.compile(
    r'^(?P<remote>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<target>\S+)\s+HTTP/[^\"]+"\s+'
    r'(?P<status>\d{3})\s+\S+\s+"[^\"]*"\s+"(?P<ua>[^\"]*)"(?P<tail>.*)$'
)
LABELED_TIMING_RE = re.compile(
    r'(?:^|\s)(?P<name>request_time|upstream_response_time|upstream_status)='
    r'"?(?P<value>[^"\s]+)"?'
)
ERROR_TIME_RE = re.compile(r"^(?P<time>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})")
ERROR_REQUEST_RE = re.compile(r'request:\s+"(?P<method>[A-Z]+)\s+(?P<target>\S+)\s+HTTP/')
ERROR_CLIENT_RE = re.compile(r"(?:^|,\s*)client:\s*(?P<remote>[^,\s]+)")


def iso_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_iso_utc(value: str) -> Optional[datetime]:
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def parse_nginx_time(value: str) -> Optional[datetime]:
    for pattern in ("%d/%b/%Y:%H:%M:%S %z", "%Y/%m/%d %H:%M:%S"):
        try:
            parsed = datetime.strptime(value, pattern)
        except ValueError:
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    return None


def parse_log_time(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00" if text.endswith("Z") else text)
    except ValueError:
        return parse_nginx_time(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def parse_request(command: str, now: Optional[datetime] = None) -> Tuple[Optional[Dict[str, Any]], str]:
    if not isinstance(command, str) or "\x00" in command or "\n" in command or "\r" in command:
        return None, "INVALID_COMMAND_ENCODING"
    match = COMMAND_RE.fullmatch(command)
    if match is None:
        return None, "COMMAND_NOT_ALLOWLISTED"
    kind = match.group("kind")
    if kind in DISABLED_EVIDENCE_TYPES:
        return None, "EVIDENCE_TYPE_NOT_REVIEWED"
    if kind not in ALLOWED_EVIDENCE_TYPES:
        return None, "EVIDENCE_TYPE_NOT_ALLOWLISTED"
    start = parse_iso_utc(match.group("start"))
    end = parse_iso_utc(match.group("end"))
    if start is None or end is None:
        return None, "INVALID_UTC_WINDOW"
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if start >= end:
        return None, "NON_POSITIVE_WINDOW"
    if (end - start).total_seconds() > MAX_WINDOW_SECONDS:
        return None, "WINDOW_EXCEEDS_60_MINUTES"
    if end > current:
        return None, "FUTURE_WINDOW_BLOCKED"
    if start < current - timedelta(seconds=MAX_LOOKBACK_SECONDS):
        return None, "WINDOW_TOO_OLD"
    return {
        "evidence_type": kind,
        "window_start": start,
        "window_end": end,
    }, "OK"


def exact_path(target: str) -> Optional[str]:
    if not isinstance(target, str) or not target.startswith("/"):
        return None
    return target.split("?", 1)[0]


def normalize_remote(value: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def actor_class(remote: Optional[str], user_agent: str) -> str:
    if remote is not None:
        try:
            if ipaddress.ip_address(remote).is_loopback:
                return "LOCAL_WARMUP"
        except ValueError:
            pass
    if user_agent == "SentinelDefense-RouteMapper/10.22":
        return "SENTINEL_ROUTE_MAPPER"
    if user_agent == "nginx-ssl early hints":
        return "NGINX_EARLY_HINTS_ACTOR"
    if re.search(r"(?:Mozilla/|Chrome/|Firefox/|Safari/|Edg/)", user_agent):
        return "BROWSER_LIKE_REMOTE"
    return "OTHER_REMOTE" if remote is not None else "UNKNOWN_ACTOR"


def nonnegative_float(value: Optional[str]) -> Optional[float]:
    if value in (None, "", "-"):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return round(number, 6) if number >= 0 else None


def upstream_statuses(value: Optional[str]) -> Optional[List[int]]:
    if value in (None, "", "-"):
        return None
    result: List[int] = []
    for item in re.split(r"[,;:]", str(value)):
        token = item.strip()
        if not token or token == "-":
            continue
        if not token.isdigit() or not 100 <= int(token) <= 599:
            return None
        result.append(int(token))
    return result or None


def parse_access_line(line: str) -> Tuple[Optional[datetime], Optional[Dict[str, Any]]]:
    stripped = line.strip()
    if stripped.startswith("{"):
        try:
            value = json.loads(stripped)
        except json.JSONDecodeError:
            return None, None
        if not isinstance(value, dict):
            return None, None
        timestamp = parse_log_time(
            value.get("time_iso8601") or value.get("timestamp") or value.get("time")
        )
        if timestamp is None:
            return None, None
        path = exact_path(str(value.get("request_uri") or value.get("uri") or value.get("path") or ""))
        if path != ENDPOINT:
            return timestamp, None
        status = value.get("status")
        if isinstance(status, bool):
            return timestamp, None
        try:
            normalized_status = int(status)
        except (TypeError, ValueError):
            return timestamp, None
        if not 100 <= normalized_status <= 599:
            return timestamp, None
        remote = normalize_remote(str(value.get("remote_addr") or value.get("remote_address") or ""))
        user_agent = str(value.get("http_user_agent") or value.get("user_agent") or "")
        method = str(value.get("request_method") or value.get("method") or "UNKNOWN")
        if not re.fullmatch(r"[A-Z]{3,12}", method):
            method = "UNKNOWN"
        upstream = value.get("upstream_status")
        return timestamp, {
            "timestamp": iso_utc(timestamp),
            "remote_address": remote,
            "method": method,
            "status": normalized_status,
            "path": ENDPOINT,
            "actor_class": actor_class(remote, user_agent),
            "request_time": nonnegative_float(
                None if value.get("request_time") is None else str(value.get("request_time"))
            ),
            "upstream_response_time": nonnegative_float(
                None
                if value.get("upstream_response_time") is None
                else str(value.get("upstream_response_time"))
            ),
            "upstream_status": upstream_statuses(None if upstream is None else str(upstream)),
        }

    match = COMBINED_RE.match(stripped)
    if match is None:
        return None, None
    timestamp = parse_nginx_time(match.group("time"))
    if timestamp is None:
        return None, None
    if exact_path(match.group("target")) != ENDPOINT:
        return timestamp, None
    labeled = {
        item.group("name"): item.group("value")
        for item in LABELED_TIMING_RE.finditer(match.group("tail"))
    }
    remote = normalize_remote(match.group("remote"))
    return timestamp, {
        "timestamp": iso_utc(timestamp),
        "remote_address": remote,
        "method": match.group("method"),
        "status": int(match.group("status")),
        "path": ENDPOINT,
        "actor_class": actor_class(remote, match.group("ua")),
        "request_time": nonnegative_float(labeled.get("request_time")),
        "upstream_response_time": nonnegative_float(labeled.get("upstream_response_time")),
        "upstream_status": upstream_statuses(labeled.get("upstream_status")),
    }


def error_category(line: str) -> str:
    lowered = line.lower()
    if "upstream timed out" in lowered and "while connecting to upstream" in lowered:
        return "UPSTREAM_CONNECT_TIMEOUT"
    if "upstream timed out" in lowered:
        return "UPSTREAM_RESPONSE_TIMEOUT"
    if "connect() failed" in lowered and "upstream" in lowered:
        return "UPSTREAM_CONNECT_ERROR"
    if "no live upstreams" in lowered:
        return "UPSTREAM_UNAVAILABLE"
    return "NGINX_ERROR_OTHER"


def parse_error_line(line: str) -> Tuple[Optional[datetime], Optional[Dict[str, Any]]]:
    time_match = ERROR_TIME_RE.match(line)
    request_match = ERROR_REQUEST_RE.search(line)
    if time_match is None:
        return None, None
    timestamp = parse_nginx_time(time_match.group("time"))
    if timestamp is None:
        return None, None
    if request_match is None or exact_path(request_match.group("target")) != ENDPOINT:
        return timestamp, None
    client_match = ERROR_CLIENT_RE.search(line)
    remote = normalize_remote(client_match.group("remote")) if client_match else None
    return timestamp, {
        "timestamp": iso_utc(timestamp),
        "remote_address": remote,
        "method": request_match.group("method"),
        "path": ENDPOINT,
        "category": error_category(line),
        "raw_message_stored": False,
    }


def secure_source(path: Path) -> bool:
    try:
        if path.is_symlink() or not path.is_file():
            return False
        resolved = path.resolve(strict=True)
        if resolved.parent != LOG_ROOT:
            return False
        metadata = resolved.stat()
    except OSError:
        return False
    return metadata.st_size <= MAX_SOURCE_BYTES and metadata.st_mode & 0o022 == 0


def open_source(path: Path) -> TextIO:
    if path.suffix == ".gz":
        return gzip.open(path, mode="rt", encoding="utf-8", errors="replace")
    return path.open(mode="r", encoding="utf-8", errors="replace")


def collect_rows(
    sources: Tuple[Path, ...],
    parser: Any,
    start: datetime,
    end: datetime,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    source_files_seen = 0
    source_files_read = 0
    lines_read = 0
    read_errors = 0
    limit_exceeded = False
    first_observed: Optional[datetime] = None
    last_observed: Optional[datetime] = None
    for path in sources:
        if not path.exists():
            continue
        source_files_seen += 1
        if not secure_source(path):
            read_errors += 1
            continue
        source_files_read += 1
        try:
            with open_source(path) as handle:
                for line in handle:
                    lines_read += 1
                    if lines_read > MAX_LINES:
                        limit_exceeded = True
                        break
                    timestamp, record = parser(line)
                    if timestamp is not None:
                        first_observed = timestamp if first_observed is None else min(first_observed, timestamp)
                        last_observed = timestamp if last_observed is None else max(last_observed, timestamp)
                    if record is None or timestamp is None or not start <= timestamp <= end:
                        continue
                    records.append(record)
                    if len(records) > MAX_RECORDS:
                        limit_exceeded = True
                        break
        except (OSError, EOFError):
            read_errors += 1
        if limit_exceeded:
            break
    records.sort(key=lambda item: item["timestamp"])
    return records, {
        "fixed_source_candidates": len(sources),
        "source_files_seen": source_files_seen,
        "source_files_read": source_files_read,
        "read_errors": read_errors,
        "limit_exceeded": limit_exceeded,
        "lines_read": lines_read,
        "first_observed_at": iso_utc(first_observed) if first_observed else None,
        "last_observed_at": iso_utc(last_observed) if last_observed else None,
        "observed_span_covers_window": bool(
            first_observed and last_observed and first_observed <= start and last_observed >= end
        ),
        "source_paths_exposed": False,
    }


def export_for_request(request: Dict[str, Any], now: Optional[datetime] = None) -> Tuple[Dict[str, Any], int]:
    kind = request["evidence_type"]
    start = request["window_start"]
    end = request["window_end"]
    access: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    access_summary: Dict[str, Any] = {"requested": False}
    error_summary: Dict[str, Any] = {"requested": False}
    if kind in {"nginx-window", "nowplaying-window"}:
        access, access_summary = collect_rows(ACCESS_SOURCES, parse_access_line, start, end)
        access_summary["requested"] = True
    if kind in {"nginx-error-window", "nowplaying-window"}:
        errors, error_summary = collect_rows(ERROR_SOURCES, parse_error_line, start, end)
        error_summary["requested"] = True

    summaries = [row for row in (access_summary, error_summary) if row.get("requested")]
    source_available = all(row.get("source_files_read", 0) > 0 for row in summaries)
    read_errors = sum(int(row.get("read_errors", 0)) for row in summaries)
    limit_exceeded = any(row.get("limit_exceeded") is True for row in summaries)
    status = "ORIGIN_EVIDENCE_WINDOW_READY"
    exit_code = 0
    if limit_exceeded:
        status = "ORIGIN_EVIDENCE_LIMIT_BLOCKED"
        exit_code = 5
        access = []
        errors = []
    elif not source_available:
        status = "ORIGIN_EVIDENCE_SOURCE_UNAVAILABLE"
        exit_code = 3
        access = []
        errors = []
    elif read_errors:
        status = "ORIGIN_EVIDENCE_PARTIAL_BLOCKED"
        exit_code = 4
        access = []
        errors = []

    query_identity = f"{kind}|{iso_utc(start)}|{iso_utc(end)}|{ENDPOINT}"
    report = {
        "schema_version": SCHEMA_VERSION,
        "command_id": COMMAND_ID,
        "query_id": "origin-window-" + hashlib.sha256(query_identity.encode("ascii")).hexdigest()[:20],
        "status": status,
        "generated_at": iso_utc(now or datetime.now(timezone.utc)),
        "evidence_type": kind,
        "window_start": iso_utc(start),
        "window_end": iso_utc(end),
        "maximum_window_seconds": MAX_WINDOW_SECONDS,
        "maximum_lookback_seconds": MAX_LOOKBACK_SECONDS,
        "endpoint": ENDPOINT,
        "read_only": True,
        "fixed_endpoint": True,
        "arbitrary_command_execution": False,
        "arbitrary_path_access": False,
        "sudo_used": False,
        "network_access": False,
        "writes_performed": False,
        "credentials_stored": False,
        "headers_stored": False,
        "cookies_stored": False,
        "query_values_stored": False,
        "raw_user_agents_stored": False,
        "raw_error_messages_stored": False,
        "output_truncated": False,
        "azuracast_evidence_status": "NOT_EXPOSED_NO_REVIEWED_FIXED_SOURCE",
        "access_summary": access_summary,
        "error_summary": error_summary,
        "access_record_count": len(access),
        "error_record_count": len(errors),
        "access_records": access,
        "error_records": errors,
    }
    encoded = json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_OUTPUT_BYTES:
        return {
            "schema_version": SCHEMA_VERSION,
            "command_id": COMMAND_ID,
            "query_id": report["query_id"],
            "status": "ORIGIN_EVIDENCE_OUTPUT_LIMIT_BLOCKED",
            "read_only": True,
            "writes_performed": False,
            "records_disclosed": False,
        }, 5
    return report, exit_code


def self_test() -> Dict[str, Any]:
    now = datetime(2026, 9, 7, 16, 0, 0, tzinfo=timezone.utc)
    valid_command = (
        "sentinel-origin-evidence-window nowplaying-window "
        "2026-09-07T15:15:54Z 2026-09-07T15:30:37Z"
    )
    valid, valid_status = parse_request(valid_command, now)
    access_line = (
        '198.51.100.7 - - [07/Sep/2026:15:20:00 +0000] '
        '"GET /api/nowplaying/electri-city-ai-electro-radio?x=redacted HTTP/1.1" '
        '200 12 "-" "nginx-ssl early hints" request_time=0.012 '
        'upstream_response_time=0.010 upstream_status=200'
    )
    access_time, access = parse_access_line(access_line)
    json_access_time, json_access = parse_access_line(json.dumps({
        "time_iso8601": "2026-09-07T15:20:00Z",
        "remote_addr": "198.51.100.7",
        "request_method": "GET",
        "request_uri": ENDPOINT + "?ignored=value",
        "status": 200,
        "http_user_agent": "nginx-ssl early hints",
        "request_time": "0.012",
        "upstream_response_time": "0.010",
        "upstream_status": "200",
    }))
    unrelated_time, unrelated = parse_access_line(access_line.replace(ENDPOINT, "/unrelated"))
    error_line = (
        '2026/09/07 15:20:01 [error] 1#1: *1 upstream timed out '
        'while reading response header from upstream, client: 198.51.100.7, '
        'request: "GET /api/nowplaying/electri-city-ai-electro-radio HTTP/1.1"'
    )
    error_time, error = parse_error_line(error_line)
    source = Path(__file__).read_text(encoding="utf-8")
    tests = {
        "fixed_current_window_allowed": valid_status == "OK" and valid is not None,
        "maximum_window_enforced": parse_request(
            "sentinel-origin-evidence-window nowplaying-window "
            "2026-09-07T14:00:00Z 2026-09-07T15:30:37Z",
            now,
        )[1] == "WINDOW_EXCEEDS_60_MINUTES",
        "future_window_blocked": parse_request(
            "sentinel-origin-evidence-window nginx-window "
            "2026-09-07T15:30:00Z 2026-09-07T16:00:01Z",
            now,
        )[1] == "FUTURE_WINDOW_BLOCKED",
        "old_window_blocked": parse_request(
            "sentinel-origin-evidence-window nginx-window "
            "2026-09-05T15:00:00Z 2026-09-05T15:30:00Z",
            now,
        )[1] == "WINDOW_TOO_OLD",
        "arbitrary_type_blocked": parse_request(
            "sentinel-origin-evidence-window arbitrary-window "
            "2026-09-07T15:15:54Z 2026-09-07T15:30:37Z",
            now,
        )[1] == "EVIDENCE_TYPE_NOT_ALLOWLISTED",
        "unreviewed_azuracast_source_blocked": parse_request(
            "sentinel-origin-evidence-window azuracast-window "
            "2026-09-07T15:15:54Z 2026-09-07T15:30:37Z",
            now,
        )[1] == "EVIDENCE_TYPE_NOT_REVIEWED",
        "semicolon_blocked": parse_request(valid_command + "; id", now)[0] is None,
        "pipe_blocked": parse_request(valid_command + " | id", now)[0] is None,
        "backticks_blocked": parse_request(valid_command + " `id`", now)[0] is None,
        "command_substitution_blocked": parse_request(valid_command + " $(id)", now)[0] is None,
        "path_traversal_blocked": parse_request(valid_command + " ../../etc/passwd", now)[0] is None,
        "extra_path_blocked": parse_request(valid_command + " /var/log/nginx/access.log", now)[0] is None,
        "newline_blocked": parse_request(valid_command + "\nid", now)[0] is None,
        "invalid_timestamp_blocked": parse_request(
            "sentinel-origin-evidence-window nginx-window invalid 2026-09-07T15:30:37Z",
            now,
        )[0] is None,
        "empty_input_blocked": parse_request("", now)[0] is None,
        "exact_path_access_parsed": (
            access_time is not None
            and access is not None
            and access["path"] == ENDPOINT
            and access["status"] == 200
            and access["upstream_status"] == [200]
            and access["actor_class"] == "NGINX_EARLY_HINTS_ACTOR"
        ),
        "unrelated_access_not_exported": unrelated_time is not None and unrelated is None,
        "json_access_supported_without_query_storage": (
            json_access_time is not None
            and json_access is not None
            and json_access["path"] == ENDPOINT
            and "ignored" not in json.dumps(json_access)
        ),
        "exact_path_error_classified": (
            error_time is not None
            and error is not None
            and error["category"] == "UPSTREAM_RESPONSE_TIMEOUT"
            and error["raw_message_stored"] is False
        ),
        "finite_sources": bool(ACCESS_SOURCES) and bool(ERROR_SOURCES),
        "no_subprocess_or_network_import": all(
            marker not in source
            for marker in (
                "import " + "subprocess",
                "import " + "socket",
                "import " + "requests",
                "import " + "paramiko",
            )
        ),
        "no_eval": ("eval" + "(") not in source,
        "no_shell_true": ("shell" + "=True") not in source,
        "bounded_output": MAX_RECORDS > 0 and MAX_OUTPUT_BYTES <= 4 * 1024 * 1024,
    }
    findings = sorted(name for name, passed in tests.items() if not passed)
    return {
        "status": "ORIGIN_EVIDENCE_WINDOW_SELF_TEST_OK" if not findings else "ORIGIN_EVIDENCE_WINDOW_SELF_TEST_FAILED",
        "checks": tests,
        "findings": findings,
        "read_only": True,
        "breach": False,
    }


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        report = self_test()
        print(report["status"])
        if report["findings"]:
            print(json.dumps(report, sort_keys=True))
        return 0 if not report["findings"] else 1
    if len(sys.argv) != 1:
        print("DENIED: helper accepts no direct arguments", file=sys.stderr)
        return 126
    request, status = parse_request(os.environ.get("SSH_ORIGINAL_COMMAND", ""))
    if request is None:
        print(f"DENIED: {status}", file=sys.stderr)
        return 126
    report, exit_code = export_for_request(request)
    json.dump(report, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
