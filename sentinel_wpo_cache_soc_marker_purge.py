#!/usr/bin/env python3
"""Controlled WP Optimize cache purge for stale SOC schema HTML cache files.

Phase 6.10 removes only remote WP Optimize HTML cache files that still contain
old SOC schema markers. It is intentionally narrow:

- SFTP only, using Paramiko with RejectPolicy and known_hosts.
- No uploads, no renames, no directory deletes.
- No WordPress database, theme, plugin, .htaccess, Cloudflare or Nginx changes.
- Every deleted file is backed up locally before deletion.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import posixpath
import re
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


PROJECT_DIR = Path("/srv/sentinel-defense")

ALLOWED_REMOTE_PREFIX = "/wordpress/wp-content/cache/wpo-cache/electri-c-ity-studios-24-7.com/"
EXPECTED_REMOTE_ROOT = "/wordpress"
MARKERS = ("soc-schema-graph", "data-soc-schema", "#soc-entity", "#soc-logo", "#soc-website")
MAX_DELETE_FILES = 100
READ_CHUNK_SIZE = 128 * 1024
PUBLIC_HEALTHCHECK_BASE = "https://electri-c-ity-studios-24-7.com/"

REPORT_JSON = PROJECT_DIR / "reports/latest/wpo-cache-soc-marker-purge.json"
REPORT_MD = PROJECT_DIR / "reports/latest/wpo-cache-soc-marker-purge.md"
SNAPSHOT_DIR = PROJECT_DIR / "snapshots"
AUDIT_JSONL = PROJECT_DIR / "audit/wpo-cache-soc-marker-purge.jsonl"
BACKUP_ROOT = PROJECT_DIR / "backups/wpo-cache-soc-purge"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "snapshots",
    PROJECT_DIR / "audit",
    BACKUP_ROOT,
)

STATUS_DRY_RUN_READY = "WPO_CACHE_SOC_PURGE_DRY_RUN_READY"
STATUS_APPLIED = "WPO_CACHE_SOC_PURGE_APPLIED"
STATUS_NO_MATCHES = "WPO_CACHE_SOC_PURGE_NO_MATCHES"
STATUS_BLOCKED_BY_SAFETY = "WPO_CACHE_SOC_PURGE_BLOCKED_BY_SAFETY"
STATUS_FAILED = "WPO_CACHE_SOC_PURGE_FAILED"

SCHEMA_VERSION = "wpo-cache-soc-marker-purge-6.10"

SECRET_NAME_RE = re.compile(r"(?i)(secret|key|token|password|passwd|api[_-]?key|credential|authorization|cookie|session)")
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|password|passwd|bearer|token|credential|session|"
    r"authorization|set-cookie|cookie|x-api-key|access[_-]?key)\b\s*[:=]\s*"
    r"[\"']?(?!false\b|true\b|null\b|none\b|not_applied\b|<redacted|-\b|0\b)"
    r"[A-Za-z0-9+/=_\-]{4,}"
)
LONG_HEX_RE = re.compile(r"\b[A-Fa-f0-9]{32,}\b")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def timestamp_tag() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def redact_text(value: Any, default: str = "-", max_len: int = 1000) -> str:
    if value is None:
        return default
    text = str(value).replace("\r", " ").strip()
    text = SECRET_ASSIGNMENT_RE.sub("<redacted>", text)
    text = LONG_HEX_RE.sub("<redacted-hex>", text)
    if SECRET_NAME_RE.search(text) and "=" in text:
        return "[redacted]"
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text or default


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError):
        return False


def assert_allowed_write(path: Path) -> None:
    if not any(is_within(path, root) for root in ALLOWED_WRITE_ROOTS):
        raise ValueError(f"Refusing to write outside allowed purge roots: {path}")
    if path.suffix.lower() in {".sh", ".bash", ".zsh", ".service", ".timer", ".php", ".py", ".env", ".bin", ".run"}:
        raise ValueError(f"Refusing executable/config output path: {path}")
    if SECRET_NAME_RE.search(path.name):
        raise ValueError(f"Refusing secret-like output path: {path}")


def write_text_atomic(path: Path, content: str) -> None:
    assert_allowed_write(path)
    if SECRET_ASSIGNMENT_RE.search(content):
        raise ValueError(f"Refusing secret-like content in {path}")
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
            if SECRET_ASSIGNMENT_RE.search(text):
                raise ValueError("Refusing secret-like audit output")
            handle.write(text + "\n")


def parse_port(value: str) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return 22
    return port if 0 < port < 65536 else 22


def normalize_remote_root(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    if not value.startswith("/"):
        value = "/" + value
    return value.rstrip("/") or "/"


def sftp_env_presence() -> Dict[str, bool]:
    return {
        "SENTINEL_SFTP_HOST": bool(os.environ.get("SENTINEL_SFTP_HOST")),
        "SENTINEL_SFTP_PORT": bool(os.environ.get("SENTINEL_SFTP_PORT")),
        "SENTINEL_SFTP_USER": bool(os.environ.get("SENTINEL_SFTP_USER")),
        "SENTINEL_SFTP_REMOTE_ROOT": bool(os.environ.get("SENTINEL_SFTP_REMOTE_ROOT")),
        "SENTINEL_SFTP_PASSWORD": bool(os.environ.get("SENTINEL_SFTP_PASSWORD")),
    }


def read_sftp_config() -> Tuple[Optional[Dict[str, Any]], str]:
    presence = sftp_env_presence()
    if not all(presence.values()):
        missing = [name for name, present in presence.items() if not present]
        return None, "missing_env:" + ",".join(missing)
    remote_root = normalize_remote_root(os.environ.get("SENTINEL_SFTP_REMOTE_ROOT", ""))
    if remote_root != EXPECTED_REMOTE_ROOT:
        return None, "remote_root_must_be_/wordpress"
    return {
        "host": os.environ["SENTINEL_SFTP_HOST"].strip(),
        "port": parse_port(os.environ.get("SENTINEL_SFTP_PORT", "22")),
        "user": os.environ["SENTINEL_SFTP_USER"].strip(),
        "password": os.environ["SENTINEL_SFTP_PASSWORD"],
        "remote_root": remote_root,
    }, "ok"


def validate_remote_path(remote_path: str) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    normalized = posixpath.normpath(remote_path)
    if remote_path.endswith("/"):
        reasons.append("directory path is not allowed")
    if not normalized.startswith(ALLOWED_REMOTE_PREFIX.rstrip("/") + "/"):
        reasons.append("outside allowed WPO cache prefix")
    suffix = posixpath.splitext(normalized)[1].lower()
    if suffix not in (".html", ".htm"):
        reasons.append("remote file is not .html/.htm")
    low = normalized.lower()
    if low.endswith(".php") or "/wp-content/mu-plugins/" in low or "/wp-content/plugins/" in low or "/wp-content/themes/" in low:
        reasons.append("remote PHP/plugin/theme/MU-plugin path is forbidden")
    if ".." in normalized.split("/"):
        reasons.append("remote path traversal is forbidden")
    return not reasons, reasons


def matched_markers_from_text(text: str) -> List[str]:
    return [marker for marker in MARKERS if marker in text]


def matched_markers_from_bytes(content: bytes) -> List[str]:
    return matched_markers_from_text(content.decode("utf-8", errors="replace"))


def remote_relative_path(remote_path: str) -> Path:
    if not remote_path.startswith(ALLOWED_REMOTE_PREFIX):
        raise ValueError("remote path outside allowed prefix")
    rel = remote_path[len(ALLOWED_REMOTE_PREFIX) :]
    parts = [part for part in rel.split("/") if part]
    if not parts or any(part in (".", "..") for part in parts):
        raise ValueError("unsafe remote relative path")
    return Path(*parts)


def backup_path_for_remote(remote_path: str, backup_dir: Path) -> Path:
    return backup_dir / remote_relative_path(remote_path)


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def read_remote_file_bytes(sftp: Any, remote_path: str) -> bytes:
    chunks: List[bytes] = []
    with sftp.open(remote_path, "rb") as handle:
        while True:
            chunk = handle.read(READ_CHUNK_SIZE)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks)


def remote_file_metadata(sftp: Any, remote_path: str, content: bytes) -> Dict[str, Any]:
    attrs = sftp.stat(remote_path)
    markers = matched_markers_from_bytes(content)
    return {
        "remote_path": remote_path,
        "size_bytes": int(getattr(attrs, "st_size", len(content)) or len(content)),
        "sha256": sha256_bytes(content),
        "matched_markers": markers,
        "eligible": bool(markers),
    }


def scan_remote_cache(sftp: Any) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    files_seen = 0
    files_scanned = 0
    files_skipped = 0
    scan_errors: List[Dict[str, str]] = []
    matches: List[Dict[str, Any]] = []
    stack = [ALLOWED_REMOTE_PREFIX.rstrip("/")]
    while stack:
        current_dir = stack.pop()
        try:
            entries = sftp.listdir_attr(current_dir)
        except OSError as exc:
            scan_errors.append({"path": current_dir, "error": redact_text(exc, max_len=300)})
            continue
        for entry in entries:
            name = getattr(entry, "filename", "")
            if not name or name in (".", ".."):
                continue
            remote_path = current_dir.rstrip("/") + "/" + name
            mode = int(getattr(entry, "st_mode", 0) or 0)
            if stat.S_ISDIR(mode):
                stack.append(remote_path)
                continue
            if not stat.S_ISREG(mode):
                files_skipped += 1
                continue
            files_seen += 1
            valid, _reasons = validate_remote_path(remote_path)
            if not valid:
                files_skipped += 1
                continue
            files_scanned += 1
            try:
                content = read_remote_file_bytes(sftp, remote_path)
                meta = remote_file_metadata(sftp, remote_path, content)
            except OSError as exc:
                scan_errors.append({"path": remote_path, "error": redact_text(exc, max_len=300)})
                continue
            if meta["eligible"]:
                matches.append(meta)
    matches.sort(key=lambda item: str(item.get("remote_path", "")))
    stats = {
        "files_seen": files_seen,
        "files_scanned": files_scanned,
        "files_skipped": files_skipped,
        "scan_errors": scan_errors,
    }
    return matches, stats


def open_sftp(config: Dict[str, Any]) -> Tuple[Any, Any]:
    import paramiko

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    client.load_system_host_keys()
    known_hosts = Path.home() / ".ssh" / "known_hosts"
    if known_hosts.exists():
        client.load_host_keys(str(known_hosts))
    client.connect(
        hostname=config["host"],
        port=int(config["port"]),
        username=config["user"],
        password=config["password"],
        timeout=30,
        allow_agent=False,
        look_for_keys=False,
    )
    return client, client.open_sftp()


def backup_is_valid(path: Path, expected_sha256: str, expected_size: int) -> bool:
    try:
        if not path.exists() or not path.is_file():
            return False
        content = path.read_bytes()
    except OSError:
        return False
    return len(content) == expected_size and sha256_bytes(content) == expected_sha256


def write_backup(backup_dir: Path, remote_path: str, content: bytes) -> Path:
    backup_path = backup_path_for_remote(remote_path, backup_dir)
    assert_allowed_write(backup_path)
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    backup_path.write_bytes(content)
    return backup_path


def apply_deletes(sftp: Any, matches: List[Dict[str, Any]], backup_dir: Path) -> Tuple[List[Dict[str, Any]], List[str]]:
    deleted: List[Dict[str, Any]] = []
    errors: List[str] = []
    for match in matches:
        remote_path = str(match["remote_path"])
        valid, reasons = validate_remote_path(remote_path)
        if not valid:
            errors.append(f"{remote_path}: " + "; ".join(reasons))
            break
        try:
            content = read_remote_file_bytes(sftp, remote_path)
            markers = matched_markers_from_bytes(content)
            if not markers:
                errors.append(f"{remote_path}: marker missing before delete")
                break
            sha = sha256_bytes(content)
            size = len(content)
            backup_path = write_backup(backup_dir, remote_path, content)
            if not backup_is_valid(backup_path, sha, size):
                errors.append(f"{remote_path}: backup validation failed")
                break
            sftp.remove(remote_path)
            try:
                sftp.stat(remote_path)
                remote_exists_after = True
            except OSError:
                remote_exists_after = False
            deleted.append(
                {
                    "remote_path": remote_path,
                    "size_bytes": size,
                    "sha256": sha,
                    "matched_markers": markers,
                    "backup_path": str(backup_path),
                    "backup_written": True,
                    "remote_exists_after_delete": remote_exists_after,
                    "deleted": not remote_exists_after,
                }
            )
            if remote_exists_after:
                errors.append(f"{remote_path}: remote file still exists after delete")
                break
        except OSError as exc:
            errors.append(f"{remote_path}: {redact_text(exc, max_len=300)}")
            break
    return deleted, errors


def cache_headers(headers: Any) -> Dict[str, str]:
    wanted = (
        "cache-control",
        "cf-cache-status",
        "wpo-cache-status",
        "age",
        "expires",
        "server",
        "x-cache",
        "x-wp-cache",
        "vary",
    )
    result: Dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in wanted:
            result[key] = redact_text(value, max_len=200)
    return result


def public_healthcheck(timestamp: str) -> Dict[str, Any]:
    url = f"{PUBLIC_HEALTHCHECK_BASE}?after_wpo_cache_soc_purge={timestamp}"
    result: Dict[str, Any] = {
        "url": url,
        "http_status": None,
        "jsonld_script_count": 0,
        "soc_schema_graph_present": False,
        "data_soc_schema_present": False,
        "RadioStation_raw_count": 0,
        "MusicGroup_raw_count": 0,
        "Organization_raw_count": 0,
        "WebSite_raw_count": 0,
        "cache_headers": {},
        "error": None,
    }
    try:
        request = Request(
            url,
            method="GET",
            headers={
                "User-Agent": "SentinelWpoCacheSocPurge/6.10",
                "Accept": "text/html,application/xhtml+xml",
                "Accept-Encoding": "identity",
            },
        )
        with urlopen(request, timeout=30) as response:  # noqa: S310 - own site healthcheck, GET only
            body = response.read(1_500_000).decode("utf-8", errors="replace")
            result["http_status"] = int(response.status)
            result["cache_headers"] = cache_headers(response.headers)
    except HTTPError as exc:
        body = exc.read(1_500_000).decode("utf-8", errors="replace")
        result["http_status"] = int(exc.code)
        result["cache_headers"] = cache_headers(exc.headers)
        result["error"] = redact_text(exc, max_len=300)
    except (OSError, URLError) as exc:
        body = ""
        result["error"] = redact_text(exc, max_len=300)
    result["jsonld_script_count"] = len(re.findall(r"<script\b[^>]*application/ld\+json", body, flags=re.I))
    result["soc_schema_graph_present"] = "soc-schema-graph" in body
    result["data_soc_schema_present"] = "data-soc-schema" in body
    result["RadioStation_raw_count"] = body.count("RadioStation")
    result["MusicGroup_raw_count"] = body.count("MusicGroup")
    result["Organization_raw_count"] = body.count("Organization")
    result["WebSite_raw_count"] = body.count("WebSite")
    return result


def safety_breaches(matches: List[Dict[str, Any]], *, backup_errors: Optional[List[str]] = None) -> List[str]:
    reasons: List[str] = []
    if len(matches) > MAX_DELETE_FILES:
        reasons.append("more than 100 cache files would be deleted")
    for match in matches:
        remote_path = str(match.get("remote_path", ""))
        valid, path_reasons = validate_remote_path(remote_path)
        reasons.extend(f"{remote_path}: {reason}" for reason in path_reasons if not valid)
    for error in backup_errors or []:
        if "backup" in error.lower():
            reasons.append(error)
    return sorted(set(reasons))


def determine_status(mode: str, matched_count: int, deleted_count: int, breach: bool, error: Optional[str]) -> str:
    if breach:
        return STATUS_BLOCKED_BY_SAFETY
    if error:
        return STATUS_FAILED
    if matched_count == 0:
        return STATUS_NO_MATCHES
    if mode == "dry-run":
        return STATUS_DRY_RUN_READY
    if deleted_count > 0:
        return STATUS_APPLIED
    return STATUS_FAILED


def build_report(
    *,
    mode: str,
    timestamp: str,
    matches: List[Dict[str, Any]],
    scan_stats: Dict[str, Any],
    deleted: List[Dict[str, Any]],
    backup_dir: Optional[Path],
    healthcheck: Optional[Dict[str, Any]],
    error: Optional[str],
    breach_reasons: List[str],
    sftp_status: str,
) -> Dict[str, Any]:
    breach = bool(breach_reasons)
    status = determine_status(mode, len(matches), len(deleted), breach, error)
    safe_matches: List[Dict[str, Any]] = []
    for match in matches:
        item = dict(match)
        if backup_dir:
            try:
                item["planned_backup_path"] = str(backup_path_for_remote(str(match["remote_path"]), backup_dir))
            except ValueError:
                item["planned_backup_path"] = ""
        safe_matches.append(item)
    return {
        "schema_version": SCHEMA_VERSION,
        "timestamp_utc": utc_now(),
        "timestamp": timestamp,
        "status": status,
        "mode": mode,
        "apply": mode == "apply",
        "allowed_remote_prefix": ALLOWED_REMOTE_PREFIX,
        "marker_terms": list(MARKERS),
        "sftp_env_present": sftp_env_presence(),
        "sftp_status": sftp_status,
        "matched_cache_files_count": len(matches),
        "matched_cache_files": safe_matches,
        "deleted_cache_files_count": len(deleted),
        "deleted_cache_files": deleted,
        "backup_dir": str(backup_dir) if backup_dir else "",
        "public_healthcheck": healthcheck or {},
        "breach": breach,
        "breach_reasons": breach_reasons,
        "error": redact_text(error, default=None, max_len=500) if error else None,
        "files_seen": scan_stats.get("files_seen", 0),
        "files_scanned": scan_stats.get("files_scanned", 0),
        "files_skipped": scan_stats.get("files_skipped", 0),
        "scan_errors": scan_stats.get("scan_errors", []),
        "safety": {
            "no_database_change": True,
            "no_theme_change": True,
            "no_plugin_change": True,
            "no_mu_plugin_change": True,
            "no_htaccess_change": True,
            "no_cloudflare_change": True,
            "no_nginx_change": True,
            "no_upload": True,
            "no_rename": True,
            "no_directory_delete": True,
            "only_html_cache_files": True,
            "max_delete_files": MAX_DELETE_FILES,
        },
        "outputs": {
            "report_json": str(REPORT_JSON),
            "report_md": str(REPORT_MD),
            "snapshot_json": str(SNAPSHOT_DIR / f"wpo-cache-soc-marker-purge-{timestamp}.json"),
            "audit_jsonl": str(AUDIT_JSONL),
        },
    }


def render_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# WPO Cache SOC Marker Purge",
        "",
        f"- Status: `{report.get('status')}`",
        f"- Mode: `{report.get('mode')}`",
        f"- Apply: `{report.get('apply')}`",
        f"- Matched cache files: `{report.get('matched_cache_files_count')}`",
        f"- Deleted cache files: `{report.get('deleted_cache_files_count')}`",
        f"- Backup dir: `{report.get('backup_dir')}`",
        f"- Breach: `{report.get('breach')}`",
        f"- Error: `{report.get('error')}`",
        "",
        "## Matched Files",
        "",
    ]
    matches = report.get("matched_cache_files") if isinstance(report.get("matched_cache_files"), list) else []
    if not matches:
        lines.append("- none")
    for item in matches:
        lines.append(
            "- `{}` size={} sha256={} markers={}".format(
                redact_text(item.get("remote_path"), max_len=500),
                item.get("size_bytes"),
                redact_text(item.get("sha256"), max_len=80),
                ", ".join(item.get("matched_markers", [])),
            )
        )
    lines.extend(["", "## Deleted Files", ""])
    deleted = report.get("deleted_cache_files") if isinstance(report.get("deleted_cache_files"), list) else []
    if not deleted:
        lines.append("- none")
    for item in deleted:
        lines.append(
            "- `{}` backup=`{}` deleted=`{}`".format(
                redact_text(item.get("remote_path"), max_len=500),
                redact_text(item.get("backup_path"), max_len=500),
                item.get("deleted"),
            )
        )
    health = report.get("public_healthcheck") if isinstance(report.get("public_healthcheck"), dict) else {}
    if health:
        lines.extend(
            [
                "",
                "## Public Healthcheck",
                "",
                f"- URL: `{redact_text(health.get('url'), max_len=500)}`",
                f"- HTTP status: `{health.get('http_status')}`",
                f"- JSON-LD script count: `{health.get('jsonld_script_count')}`",
                f"- soc_schema_graph_present: `{health.get('soc_schema_graph_present')}`",
                f"- data_soc_schema_present: `{health.get('data_soc_schema_present')}`",
                f"- RadioStation_raw_count: `{health.get('RadioStation_raw_count')}`",
                f"- MusicGroup_raw_count: `{health.get('MusicGroup_raw_count')}`",
                f"- Organization_raw_count: `{health.get('Organization_raw_count')}`",
                f"- WebSite_raw_count: `{health.get('WebSite_raw_count')}`",
                f"- Cache-Headers: `{json.dumps(health.get('cache_headers', {}), ensure_ascii=False, sort_keys=True)}`",
            ]
        )
    if report.get("breach_reasons"):
        lines.extend(["", "## Breach Reasons", ""])
        for reason in report.get("breach_reasons", []):
            lines.append(f"- {redact_text(reason, max_len=600)}")
    lines.extend(
        [
            "",
            "## Safety",
            "",
            "- No WordPress database change.",
            "- No theme/plugin/MU-plugin change.",
            "- No .htaccess, Cloudflare or Nginx change.",
            "- No upload, rename or directory delete.",
            "- Deletes are limited to matching `.html`/`.htm` files under the exact WPO cache prefix.",
            "",
        ]
    )
    return "\n".join(lines)


def write_outputs(report: Dict[str, Any]) -> None:
    snapshot_path = SNAPSHOT_DIR / f"wpo-cache-soc-marker-purge-{report['timestamp']}.json"
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, render_markdown(report))
    write_json_atomic(snapshot_path, report)
    append_jsonl(
        AUDIT_JSONL,
        [
            {
                "timestamp_utc": report.get("timestamp_utc"),
                "timestamp": report.get("timestamp"),
                "status": report.get("status"),
                "mode": report.get("mode"),
                "matched_cache_files_count": report.get("matched_cache_files_count"),
                "deleted_cache_files_count": report.get("deleted_cache_files_count"),
                "backup_dir": report.get("backup_dir"),
                "breach": report.get("breach"),
                "error": report.get("error"),
            }
        ],
    )


def run_purge(mode: str) -> Dict[str, Any]:
    timestamp = timestamp_tag()
    backup_dir = BACKUP_ROOT / timestamp if mode == "apply" else None
    healthcheck: Optional[Dict[str, Any]] = None
    matches: List[Dict[str, Any]] = []
    deleted: List[Dict[str, Any]] = []
    scan_stats: Dict[str, Any] = {"files_seen": 0, "files_scanned": 0, "files_skipped": 0, "scan_errors": []}
    error: Optional[str] = None
    breach_reasons: List[str] = []
    config, sftp_status = read_sftp_config()
    if config is None:
        error = sftp_status
        report = build_report(
            mode=mode,
            timestamp=timestamp,
            matches=matches,
            scan_stats=scan_stats,
            deleted=deleted,
            backup_dir=backup_dir,
            healthcheck=healthcheck,
            error=error,
            breach_reasons=breach_reasons,
            sftp_status=sftp_status,
        )
        write_outputs(report)
        return report
    client = None
    sftp = None
    try:
        client, sftp = open_sftp(config)
        matches, scan_stats = scan_remote_cache(sftp)
        breach_reasons = safety_breaches(matches)
        if breach_reasons:
            mode_for_status = mode
        elif mode == "apply" and matches:
            if backup_dir is None:
                breach_reasons.append("backup dir missing before apply")
            else:
                backup_dir.mkdir(parents=True, exist_ok=True)
                deleted, delete_errors = apply_deletes(sftp, matches, backup_dir)
                breach_reasons.extend(safety_breaches(matches, backup_errors=delete_errors))
                if delete_errors and not breach_reasons:
                    error = "; ".join(delete_errors)
                elif delete_errors:
                    error = "; ".join(delete_errors)
                healthcheck = public_healthcheck(timestamp)
        report = build_report(
            mode=mode,
            timestamp=timestamp,
            matches=matches,
            scan_stats=scan_stats,
            deleted=deleted,
            backup_dir=backup_dir,
            healthcheck=healthcheck,
            error=error,
            breach_reasons=breach_reasons,
            sftp_status=sftp_status,
        )
        write_outputs(report)
        return report
    except Exception as exc:  # noqa: BLE001 - report and stop without secrets
        error = redact_text(exc, max_len=500)
        report = build_report(
            mode=mode,
            timestamp=timestamp,
            matches=matches,
            scan_stats=scan_stats,
            deleted=deleted,
            backup_dir=backup_dir,
            healthcheck=healthcheck,
            error=error,
            breach_reasons=breach_reasons,
            sftp_status=sftp_status,
        )
        write_outputs(report)
        return report
    finally:
        try:
            if sftp is not None:
                sftp.close()
            if client is not None:
                client.close()
        except Exception:
            pass


def run_self_test() -> int:
    valid = "/wordpress/wp-content/cache/wpo-cache/electri-c-ity-studios-24-7.com/index.html"
    outside = "/wordpress/wp-content/cache/other.example/index.html"
    php_path = "/wordpress/wp-content/cache/wpo-cache/electri-c-ity-studios-24-7.com/index.php"
    if not validate_remote_path(valid)[0]:
        raise AssertionError("allowed path rejected")
    if validate_remote_path(outside)[0]:
        raise AssertionError("outside path accepted")
    if validate_remote_path(php_path)[0]:
        raise AssertionError(".php path accepted")
    if matched_markers_from_bytes(b'<script id="soc-schema-graph" data-soc-schema="1"></script>') != ["soc-schema-graph", "data-soc-schema"]:
        raise AssertionError("marker detection failed")
    test_backup_root = BACKUP_ROOT / "selftest"
    backup = backup_path_for_remote(valid, test_backup_root)
    if not is_within(backup, test_backup_root) or backup.suffix != ".html":
        raise AssertionError("safe local backup path failed")
    if backup_is_valid(PROJECT_DIR / "definitely-missing-backup.html", "0" * 64, 1):
        raise AssertionError("apply without backup was possible")
    sample = "password=abcd1234 token=abcd1234"
    redacted = redact_text(sample)
    if "abcd1234" in redacted:
        raise AssertionError("secret output pattern not redacted")
    source = Path(__file__).read_text(encoding="utf-8")
    forbidden_call_tokens = ("rm " + "-rf", "." + "put(", "." + "rename(", "." + "rmdir(", "rm" + "tree(")
    for token in forbidden_call_tokens:
        if token in source:
            raise AssertionError(f"forbidden call token found: {token}")
    if "sftp.remove(" not in source:
        raise AssertionError("expected file delete call missing")
    print("self-test ok")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Purge stale SOC schema WP Optimize HTML cache files safely.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--dry-run", action="store_true", help="Scan matching remote cache files and write report; delete nothing.")
    group.add_argument("--apply", action="store_true", help="Backup and delete matching remote cache HTML files, then healthcheck.")
    group.add_argument("--self-test", action="store_true", help="Run local safety self-tests.")
    args = parser.parse_args(argv)
    if args.self_test:
        return run_self_test()
    mode = "apply" if args.apply else "dry-run"
    report = run_purge(mode)
    print(f"status={report.get('status')}")
    print(f"matched_cache_files_count={report.get('matched_cache_files_count')}")
    print(f"deleted_cache_files_count={report.get('deleted_cache_files_count')}")
    print(f"backup_dir={report.get('backup_dir')}")
    print(f"breach={report.get('breach')}")
    if report.get("error"):
        print(f"error={report.get('error')}", file=sys.stderr)
    return 0 if not report.get("breach") else 2


if __name__ == "__main__":
    sys.exit(main())
