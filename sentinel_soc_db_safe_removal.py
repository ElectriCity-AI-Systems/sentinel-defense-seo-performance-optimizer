#!/usr/bin/env python3
"""SOC DB Safe Removal (Phase 6.16).

Deletes only the exact allowed SOC baseline option after a successful dry-run,
local backup, and token-gated temporary MU endpoint. No posts, revisions,
templates, files, Cloudflare, Nginx, or .htaccess entries are changed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import posixpath
import re
import secrets
import sys
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


PROJECT_DIR = Path("/srv/sentinel-defense")
REMOTE_PLUGIN = "/wordpress/wp-content/mu-plugins/sentinel-soc-db-safe-removal.php"
PUBLIC_BASE = "https://electri-c-ity-studios-24-7.com/"
ALLOWED_OPTION = "soc_baseline_metrics"
WPO_CACHE_PREFIX = "/wordpress/wp-content/cache/wpo-cache/electri-c-ity-studios-24-7.com/"

REPORT_JSON = PROJECT_DIR / "reports/latest/soc-db-safe-removal.json"
REPORT_MD = PROJECT_DIR / "reports/latest/soc-db-safe-removal.md"
FINAL_REPORT_MD = PROJECT_DIR / "reports/latest/soc-active-generator-final-report.md"
SNAPSHOT_DIR = PROJECT_DIR / "snapshots"
AUDIT_JSONL = PROJECT_DIR / "audit/soc-db-safe-removal.jsonl"
BACKUP_ROOT = PROJECT_DIR / "backups/soc-db-safe-removal"
RESOLVER_REPORT = PROJECT_DIR / "reports/latest/soc-db-source-resolver.json"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "snapshots",
    PROJECT_DIR / "audit",
    BACKUP_ROOT,
)

STATUS_DRY_RUN_READY = "SOC_DB_SAFE_REMOVAL_DRY_RUN_READY"
STATUS_APPLIED = "SOC_DB_SAFE_REMOVAL_APPLIED"
STATUS_NO_SAFE_CANDIDATE = "SOC_DB_SAFE_REMOVAL_NO_SAFE_CANDIDATE"
STATUS_BLOCKED = "SOC_DB_SAFE_REMOVAL_BLOCKED_BY_SAFETY"
STATUS_FAILED = "SOC_DB_SAFE_REMOVAL_FAILED"

MARKERS = (
    "soc-schema-graph",
    "data-soc-schema",
    "#soc-entity",
    "#soc-logo",
    "#soc-website",
    "soc-entity",
    "soc-website",
    "ecs-soc",
)

SECRET_NAME_RE = re.compile(r"(?i)(secret|key|token|password|passwd|api[_-]?key|credential|authorization|cookie|session|license)")
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|password|passwd|bearer|token|credential|session|"
    r"authorization|set-cookie|cookie|x-api-key|access[_-]?key|license)\b\s*[:=]\s*"
    r"[\"']?(?!false\b|true\b|null\b|none\b|not_applied\b|<redacted|-\b|0\b)"
    r"[A-Za-z0-9+/=_\-]{4,}"
)
LONG_HEX_RE = re.compile(r"\b[A-Fa-f0-9]{32,}\b")


class JsonLdCounter(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.jsonld_script_count = 0

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        if tag.lower() != "script":
            return
        attr_map = {name.lower(): (value or "") for name, value in attrs}
        if attr_map.get("type", "").lower() == "application/ld+json":
            self.jsonld_script_count += 1


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
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text or default


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError):
        return False


def assert_allowed_write(path: Path) -> None:
    if not any(is_within(path, root) for root in ALLOWED_WRITE_ROOTS):
        raise ValueError(f"Refusing write outside allowed roots: {path}")
    if path.suffix.lower() in {".sh", ".service", ".timer", ".php", ".py", ".env", ".bin", ".run"}:
        raise ValueError(f"Refusing executable/secret-like output: {path}")
    if SECRET_NAME_RE.search(path.name):
        raise ValueError(f"Refusing secret-like output path: {path}")


def write_text_atomic(path: Path, content: str) -> None:
    assert_allowed_write(path)
    if SECRET_ASSIGNMENT_RE.search(content):
        raise ValueError(f"Secret-like content refused for {path}")
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
                raise ValueError("Secret-like audit content refused")
            handle.write(text + "\n")


def load_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def sftp_presence() -> Dict[str, bool]:
    return {name: bool(os.environ.get(name)) for name in (
        "SENTINEL_SFTP_HOST",
        "SENTINEL_SFTP_PORT",
        "SENTINEL_SFTP_USER",
        "SENTINEL_SFTP_REMOTE_ROOT",
        "SENTINEL_SFTP_PASSWORD",
    )}


def read_sftp_config() -> Tuple[Optional[Dict[str, Any]], str]:
    presence = sftp_presence()
    if not all(presence.values()):
        return None, "missing_env:" + ",".join(k for k, v in presence.items() if not v)
    remote_root = os.environ["SENTINEL_SFTP_REMOTE_ROOT"].strip().rstrip("/")
    if remote_root != "/wordpress":
        return None, "remote_root_must_be_/wordpress"
    try:
        port = int(os.environ.get("SENTINEL_SFTP_PORT", "22"))
    except ValueError:
        port = 22
    return {
        "host": os.environ["SENTINEL_SFTP_HOST"].strip(),
        "port": port,
        "user": os.environ["SENTINEL_SFTP_USER"].strip(),
        "password": os.environ["SENTINEL_SFTP_PASSWORD"],
        "remote_root": remote_root,
    }, "ok"


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


def validate_remote_plugin_path(path: str) -> bool:
    return posixpath.normpath(path) == REMOTE_PLUGIN


def is_safe_candidate_from_resolver(report: Optional[Dict[str, Any]]) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    if not isinstance(report, dict):
        return False, "resolver_report_not_available", None
    if report.get("breach"):
        return False, "resolver_report_has_breach", None
    candidate = report.get("safe_option_candidate")
    if not isinstance(candidate, dict):
        return False, "no_safe_option_candidate", None
    if candidate.get("option_name") != ALLOWED_OPTION:
        return False, "target_option_not_exactly_allowed", candidate
    if SECRET_NAME_RE.search(str(candidate.get("option_name", ""))):
        return False, "target_option_secret_like", candidate
    if not candidate.get("safe_for_option_delete"):
        return False, "candidate_not_marked_safe_for_option_delete", candidate
    return True, "ok", candidate


def php_plugin(token: str) -> str:
    token_escaped = token.replace("\\", "\\\\").replace("'", "\\'")
    option_escaped = ALLOWED_OPTION.replace("\\", "\\\\").replace("'", "\\'")
    return f"""<?php
/*
Plugin Name: Sentinel SOC DB Safe Removal
Description: Temporary token-gated single-option removal endpoint. Remove immediately after use.
Version: 0.1.0
*/
if (!defined('ABSPATH')) {{ exit; }}
add_action('init', function () {{
    if (!isset($_GET['sentinel_soc_db_safe_removal'])) {{ return; }}
    $given = isset($_GET['token']) ? sanitize_text_field(wp_unslash($_GET['token'])) : '';
    $expected = '{token_escaped}';
    if (!hash_equals($expected, $given)) {{
        status_header(403);
        header('Content-Type: application/json; charset=utf-8');
        echo wp_json_encode(array('ok' => false, 'error' => 'forbidden'));
        exit;
    }}
    nocache_headers();
    header('Content-Type: application/json; charset=utf-8');
    $mode = isset($_GET['mode']) ? sanitize_key(wp_unslash($_GET['mode'])) : 'dry_run';
    $confirm = isset($_GET['confirm']) ? sanitize_key(wp_unslash($_GET['confirm'])) : '';
    $expected_sha = isset($_GET['expected_sha256']) ? sanitize_text_field(wp_unslash($_GET['expected_sha256'])) : '';
    $option_name = '{option_escaped}';
    $value = get_option($option_name, null);
    $exists = ($value !== null);
    $value_string = $exists ? maybe_serialize($value) : '';
    $payload = array(
        'ok' => true,
        'phase' => '6.16-soc-db-safe-removal',
        'timestamp_utc' => gmdate('c'),
        'target_option' => $option_name,
        'option_exists' => $exists,
        'value_size' => strlen($value_string),
        'value_sha256' => hash('sha256', $value_string),
        'value_raw' => $value_string,
        'db_write_performed' => false,
        'deleted' => false,
        'mode' => $mode
    );
    if ($mode === 'dry_run') {{
        echo wp_json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        exit;
    }}
    if ($mode !== 'apply') {{
        status_header(400);
        echo wp_json_encode(array('ok' => false, 'error' => 'invalid_mode'));
        exit;
    }}
    if ($confirm !== 'delete_option') {{
        status_header(400);
        echo wp_json_encode(array('ok' => false, 'error' => 'confirm_required'));
        exit;
    }}
    if (!$exists) {{
        echo wp_json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        exit;
    }}
    if (!preg_match('/^[a-f0-9]{{64}}$/', $expected_sha) || !hash_equals($payload['value_sha256'], $expected_sha)) {{
        status_header(409);
        echo wp_json_encode(array('ok' => false, 'error' => 'sha256_mismatch_or_missing'));
        exit;
    }}
    $deleted = delete_option($option_name);
    $payload['db_write_performed'] = true;
    $payload['deleted'] = (bool) $deleted;
    unset($payload['value_raw']);
    echo wp_json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}});
"""


def upload_temp_plugin(sftp: Any, content: str) -> None:
    if not validate_remote_plugin_path(REMOTE_PLUGIN):
        raise ValueError("temporary plugin path not allowed")
    with sftp.open(REMOTE_PLUGIN, "w") as handle:
        handle.write(content)


def remove_temp_plugin(sftp: Any) -> bool:
    try:
        sftp.remove(REMOTE_PLUGIN)
    except OSError:
        pass
    try:
        sftp.stat(REMOTE_PLUGIN)
        return False
    except OSError:
        return True


def fetch_endpoint(token: str, mode: str, expected_sha256: Optional[str] = None) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
    params = {"sentinel_soc_db_safe_removal": "1", "token": token, "mode": mode}
    if mode == "apply":
        params["confirm"] = "delete_option"
        if expected_sha256:
            params["expected_sha256"] = expected_sha256
    url = PUBLIC_BASE + "?" + urlencode(params)
    meta: Dict[str, Any] = {"http_status": None, "error": None}
    try:
        req = Request(url, method="GET", headers={"User-Agent": "SentinelSocDbSafeRemoval/6.16", "Accept": "application/json"})
        with urlopen(req, timeout=30) as response:  # noqa: S310 - own site token-gated endpoint
            body = response.read(1_800_000).decode("utf-8", errors="replace")
            meta["http_status"] = int(response.status)
    except HTTPError as exc:
        body = exc.read(1_800_000).decode("utf-8", errors="replace")
        meta["http_status"] = int(exc.code)
        meta["error"] = redact_text(exc, max_len=300)
    except (OSError, URLError) as exc:
        return None, {"http_status": None, "error": redact_text(exc, max_len=300)}
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return None, {**meta, "error": "invalid_json_response"}
    return data if isinstance(data, dict) else None, meta


def create_backup(timestamp: str, dry_run_data: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    if dry_run_data.get("target_option") != ALLOWED_OPTION:
        return None, "backup_target_not_allowed"
    value_raw = dry_run_data.get("value_raw")
    if not isinstance(value_raw, str):
        return None, "backup_value_missing"
    if SECRET_ASSIGNMENT_RE.search(value_raw):
        return None, "backup_value_secret_like"
    expected_sha = dry_run_data.get("value_sha256")
    if sha256_text(value_raw) != expected_sha:
        return None, "backup_sha_mismatch"
    backup_dir = BACKUP_ROOT / timestamp
    backup_file = backup_dir / f"option-{ALLOWED_OPTION}.json"
    backup = {
        "timestamp_utc": utc_now(),
        "option_name": ALLOWED_OPTION,
        "value_size": len(value_raw.encode("utf-8")),
        "value_sha256": expected_sha,
        "value_raw": value_raw,
        "restore_note": "Manual restore reference only. No restore script was generated.",
    }
    write_json_atomic(backup_file, backup)
    return {
        "backup_dir": str(backup_dir),
        "backup_path": str(backup_file),
        "option_name": ALLOWED_OPTION,
        "value_size": backup["value_size"],
        "value_sha256": expected_sha,
    }, None


def public_healthcheck(timestamp: str) -> Dict[str, Any]:
    url = PUBLIC_BASE + "?" + urlencode({"after_soc_db_safe_removal": timestamp})
    result: Dict[str, Any] = {
        "http_status": None,
        "jsonld_script_count": None,
        "soc_schema_graph_present": None,
        "data_soc_schema_present": None,
        "RadioStation_raw_count": None,
        "MusicGroup_raw_count": None,
        "Organization_raw_count": None,
        "WebSite_raw_count": None,
        "cache_headers": {},
        "error": None,
    }
    try:
        req = Request(url, method="GET", headers={"User-Agent": "SentinelSocDbSafeRemovalHealthcheck/6.16", "Accept": "text/html"})
        with urlopen(req, timeout=30) as response:  # noqa: S310 - own public homepage healthcheck
            body = response.read(2_000_000).decode("utf-8", errors="replace")
            result["http_status"] = int(response.status)
            result["cache_headers"] = {
                k: v for k, v in response.headers.items()
                if k.lower() in {"cache-control", "cf-cache-status", "x-cache", "x-wp-optimize-cache", "age", "expires", "server"}
            }
    except HTTPError as exc:
        body = exc.read(2_000_000).decode("utf-8", errors="replace")
        result["http_status"] = int(exc.code)
        result["error"] = redact_text(exc, max_len=300)
    except (OSError, URLError) as exc:
        result["error"] = redact_text(exc, max_len=300)
        return result
    parser = JsonLdCounter()
    parser.feed(body)
    result.update({
        "jsonld_script_count": parser.jsonld_script_count,
        "soc_schema_graph_present": "soc-schema-graph" in body,
        "data_soc_schema_present": "data-soc-schema" in body,
        "RadioStation_raw_count": body.count("RadioStation"),
        "MusicGroup_raw_count": body.count("MusicGroup"),
        "Organization_raw_count": body.count("Organization"),
        "WebSite_raw_count": body.count("WebSite"),
    })
    return result


def safe_cache_path(path: str) -> bool:
    normalized = posixpath.normpath(path)
    if not normalized.startswith(WPO_CACHE_PREFIX):
        return False
    return normalized.lower().endswith((".html", ".htm"))


def scan_wpo_cache_markers(sftp: Any, max_files: int = 7000) -> Dict[str, Any]:
    stack = [WPO_CACHE_PREFIX.rstrip("/")]
    files_seen = 0
    hits: List[Dict[str, Any]] = []
    errors: List[str] = []
    while stack and files_seen < max_files:
        current = stack.pop()
        try:
            entries = list(sftp.listdir_attr(current))
        except OSError as exc:
            errors.append(redact_text(f"{current}: {exc}", max_len=200))
            continue
        for entry in entries:
            path = current.rstrip("/") + "/" + entry.filename
            mode = getattr(entry, "st_mode", 0)
            if mode and (mode & 0o170000) == 0o040000:
                if path.startswith(WPO_CACHE_PREFIX):
                    stack.append(path)
                continue
            files_seen += 1
            if not safe_cache_path(path):
                continue
            try:
                with sftp.open(path, "rb") as handle:
                    data = handle.read(1_500_000)
            except OSError as exc:
                errors.append(redact_text(f"{path}: {exc}", max_len=200))
                continue
            text = data.decode("utf-8", errors="replace")
            matched = [marker for marker in MARKERS if marker in text]
            if matched:
                hits.append({
                    "path": path,
                    "size": len(data),
                    "sha256": sha256_bytes(data),
                    "matched_markers": matched,
                })
    return {
        "files_seen": files_seen,
        "hits_count": len(hits),
        "hits": hits[:50],
        "errors": errors[:20],
    }


def build_report(
    mode: str,
    timestamp: str,
    resolver_ok: bool,
    resolver_reason: str,
    candidate: Optional[Dict[str, Any]],
    endpoint_data: Optional[Dict[str, Any]],
    endpoint_meta: Dict[str, Any],
    cleanup_ok: bool,
    backup_info: Optional[Dict[str, Any]],
    apply_data: Optional[Dict[str, Any]],
    apply_meta: Optional[Dict[str, Any]],
    healthcheck: Optional[Dict[str, Any]],
    cache_scan: Optional[Dict[str, Any]],
    error: Optional[str],
) -> Dict[str, Any]:
    breach_reasons: List[str] = []
    if not cleanup_ok:
        breach_reasons.append("temporary MU plugin remained after cleanup")
    if not resolver_ok:
        breach_reasons.append(resolver_reason)
    if candidate and candidate.get("option_name") != ALLOWED_OPTION:
        breach_reasons.append("target option not exactly allowed")
    if mode == "apply" and not backup_info:
        breach_reasons.append("DB write blocked because backup missing")
    if apply_data and apply_data.get("target_option") != ALLOWED_OPTION:
        breach_reasons.append("apply target option not exactly allowed")
    if apply_data and apply_data.get("db_write_performed") and not backup_info:
        breach_reasons.append("DB write happened without backup")
    if apply_data and apply_data.get("db_write_performed") and not apply_data.get("deleted"):
        breach_reasons.append("DB write reported but option delete not confirmed")
    if mode == "apply" and (not healthcheck or healthcheck.get("http_status") is None):
        breach_reasons.append("healthcheck not executable after apply")
    if error:
        status = STATUS_FAILED
    elif breach_reasons:
        status = STATUS_BLOCKED
    elif not resolver_ok:
        status = STATUS_NO_SAFE_CANDIDATE
    elif mode == "apply" and apply_data and apply_data.get("deleted"):
        status = STATUS_APPLIED
    elif mode == "apply" and apply_data and not apply_data.get("option_exists"):
        status = STATUS_APPLIED
    else:
        status = STATUS_DRY_RUN_READY
    breach = bool(breach_reasons)
    if mode == "apply" and apply_data and apply_data.get("db_write_performed") and apply_data.get("deleted"):
        apply_status = "applied_controlled_option_delete"
    elif mode == "apply" and endpoint_data and not endpoint_data.get("option_exists"):
        apply_status = "not_applied_option_absent"
    else:
        apply_status = "not_applied"
    return {
        "schema_version": "soc-db-safe-removal-6.16",
        "timestamp_utc": utc_now(),
        "timestamp": timestamp,
        "mode": mode,
        "removal_status": status,
        "target_option": ALLOWED_OPTION,
        "resolver_candidate_ok": resolver_ok,
        "resolver_candidate_reason": resolver_reason,
        "candidate": candidate,
        "dry_run_http_status": endpoint_meta.get("http_status"),
        "dry_run_option_exists": endpoint_data.get("option_exists") if isinstance(endpoint_data, dict) else None,
        "dry_run_value_size": endpoint_data.get("value_size") if isinstance(endpoint_data, dict) else None,
        "dry_run_value_sha256": endpoint_data.get("value_sha256") if isinstance(endpoint_data, dict) else None,
        "backup_dir": (backup_info or {}).get("backup_dir"),
        "backup_path": (backup_info or {}).get("backup_path"),
        "apply_http_status": (apply_meta or {}).get("http_status"),
        "apply_deleted": apply_data.get("deleted") if isinstance(apply_data, dict) else False,
        "db_write_performed": bool(apply_data.get("db_write_performed")) if isinstance(apply_data, dict) else False,
        "plugin_removed": cleanup_ok,
        "remote_exists_after_cleanup": not cleanup_ok,
        "healthcheck": healthcheck,
        "wpo_cache_marker_scan": cache_scan,
        "apply_status": apply_status,
        "breach": breach,
        "breach_reasons": breach_reasons,
        "error": redact_text(error, default=None, max_len=500) if error else endpoint_meta.get("error") or ((apply_meta or {}).get("error")),
        "safety": {
            "only_allowed_option": True,
            "posts_modified": False,
            "revisions_modified": False,
            "themes_modified": False,
            "plugins_modified_except_temporary_mu_apply": False,
            "cloudflare_changed": False,
            "nginx_changed": False,
            "htaccess_changed": False,
            "sftp_rename_used": False,
            "directory_delete_used": False,
        },
    }


def render_report_md(report: Dict[str, Any]) -> str:
    hc = report.get("healthcheck") or {}
    scan = report.get("wpo_cache_marker_scan") or {}
    lines = [
        "# SOC DB Safe Removal",
        "",
        f"- Status: `{report.get('removal_status')}`",
        f"- Mode: `{report.get('mode')}`",
        f"- Target option: `{report.get('target_option')}`",
        f"- Dry-run option exists: `{report.get('dry_run_option_exists')}`",
        f"- Backup dir: `{report.get('backup_dir') or '-'}`",
        f"- Apply deleted: `{report.get('apply_deleted')}`",
        f"- DB write performed: `{report.get('db_write_performed')}`",
        f"- Temporary plugin removed: `{report.get('plugin_removed')}`",
        f"- Breach: `{report.get('breach')}`",
        "",
        "## Public Healthcheck",
        "",
        f"- HTTP status: `{hc.get('http_status')}`",
        f"- JSON-LD script count: `{hc.get('jsonld_script_count')}`",
        f"- soc_schema_graph_present: `{hc.get('soc_schema_graph_present')}`",
        f"- data_soc_schema_present: `{hc.get('data_soc_schema_present')}`",
        f"- RadioStation_raw_count: `{hc.get('RadioStation_raw_count')}`",
        f"- MusicGroup_raw_count: `{hc.get('MusicGroup_raw_count')}`",
        f"- Organization_raw_count: `{hc.get('Organization_raw_count')}`",
        f"- WebSite_raw_count: `{hc.get('WebSite_raw_count')}`",
        "",
        "## WPO Cache Marker Scan",
        "",
        f"- Files seen: `{scan.get('files_seen')}`",
        f"- Hits count: `{scan.get('hits_count')}`",
        "",
        "## Interpretation",
        "",
    ]
    if report.get("mode") == "apply" and (hc.get("soc_schema_graph_present") or hc.get("data_soc_schema_present")):
        lines.append("SOC markers remain visible after the safe option removal. Stop here; next step is manual WordPress editor/FSE template review.")
    elif report.get("mode") == "apply":
        lines.append("The exact allowed option was removed and public markers are not visible in the immediate healthcheck.")
    else:
        lines.append("Dry-run only. No DB write was performed.")
    return "\n".join(lines) + "\n"


def render_final_report(report: Dict[str, Any]) -> str:
    hc = report.get("healthcheck") or {}
    still_present = bool(hc.get("soc_schema_graph_present") or hc.get("data_soc_schema_present"))
    lines = [
        "# SOC Active Generator Final Report",
        "",
        f"- Latest safe-removal status: `{report.get('removal_status')}`",
        f"- Mode: `{report.get('mode')}`",
        f"- Breach: `{report.get('breach')}`",
        f"- Backup dir: `{report.get('backup_dir') or '-'}`",
        f"- soc_schema_graph_present: `{hc.get('soc_schema_graph_present')}`",
        f"- data_soc_schema_present: `{hc.get('data_soc_schema_present')}`",
        "",
        "## Bot Learning",
        "",
        "- The bot can automatically recognize duplicate/stale schema symptoms through public HTML checks and JSON-LD counting.",
        "- Regular SEO/Performance monitoring should include schema_duplicate_scan, jsonld_source_map, wpo_cache_marker_scan, public_healthcheck_after_apply, seo_score_delta_report, and performance_cache_status_report.",
        "- Autonomous actions remain forbidden for DB changes, FSE template edits, post content edits, plugin/theme changes, Cloudflare, Nginx, and .htaccess changes.",
        "- Cache purge with exact prefix and backup can be prepared for Owner-approved MEDIUM-risk execution.",
        "- DB option deletion remains HIGH risk and requires explicit Owner approval, backup, dry-run, apply confirmation, and post-apply healthcheck.",
        "",
        "## Next Recommendation",
        "",
    ]
    if report.get("mode") == "apply" and still_present:
        lines.append("Stop after this exact option action. Source is likely active FSE template/custom block or plugin runtime. Next step: manual WP-Editor review of Blog-Startseite, Blogpage-KOPIE, and FSE templates.")
    elif report.get("mode") == "apply" and not still_present:
        lines.append("Observe public HTML and SEO reports for regeneration. Do not perform further DB edits unless a new explicit source is confirmed.")
    else:
        lines.append("Dry-run completed. Apply only if the Owner explicitly approves the exact `soc_baseline_metrics` option delete.")
    return "\n".join(lines) + "\n"


def write_outputs(report: Dict[str, Any]) -> None:
    ts = str(report["timestamp"])
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, render_report_md(report))
    write_text_atomic(FINAL_REPORT_MD, render_final_report(report))
    write_json_atomic(SNAPSHOT_DIR / f"soc-db-safe-removal-{ts}.json", report)
    append_jsonl(
        AUDIT_JSONL,
        [{
            "timestamp_utc": report.get("timestamp_utc"),
            "timestamp": report.get("timestamp"),
            "mode": report.get("mode"),
            "removal_status": report.get("removal_status"),
            "target_option": report.get("target_option"),
            "apply_deleted": report.get("apply_deleted"),
            "backup_dir": report.get("backup_dir"),
            "healthcheck_soc_schema_graph_present": (report.get("healthcheck") or {}).get("soc_schema_graph_present"),
            "healthcheck_data_soc_schema_present": (report.get("healthcheck") or {}).get("data_soc_schema_present"),
            "breach": report.get("breach"),
        }],
    )


def previous_dry_run_ok() -> Tuple[bool, str]:
    previous = load_json(REPORT_JSON)
    if not previous:
        return False, "previous_dry_run_report_missing"
    if previous.get("mode") != "dry-run":
        return False, "previous_report_not_dry_run"
    if previous.get("breach"):
        return False, "previous_dry_run_has_breach"
    if previous.get("removal_status") != STATUS_DRY_RUN_READY:
        return False, "previous_dry_run_not_ready"
    if previous.get("target_option") != ALLOWED_OPTION:
        return False, "previous_dry_run_target_not_allowed"
    return True, "ok"


def execute(mode: str) -> Dict[str, Any]:
    timestamp = timestamp_tag()
    resolver_report = load_json(RESOLVER_REPORT)
    resolver_ok, resolver_reason, candidate = is_safe_candidate_from_resolver(resolver_report)
    if mode == "apply":
        dry_run_ok, dry_run_reason = previous_dry_run_ok()
        if not dry_run_ok:
            report = build_report(mode, timestamp, False, dry_run_reason, candidate, None, {"http_status": None, "error": dry_run_reason}, False, None, None, None, None, None, None)
            write_outputs(report)
            return report
    config, sftp_status = read_sftp_config()
    if config is None:
        report = build_report(mode, timestamp, resolver_ok, resolver_reason, candidate, None, {"http_status": None, "error": sftp_status}, False, None, None, None, None, None, sftp_status)
        write_outputs(report)
        return report
    token = secrets.token_urlsafe(32)
    endpoint_data: Optional[Dict[str, Any]] = None
    endpoint_meta: Dict[str, Any] = {"http_status": None, "error": None}
    apply_data: Optional[Dict[str, Any]] = None
    apply_meta: Optional[Dict[str, Any]] = None
    backup_info: Optional[Dict[str, Any]] = None
    healthcheck: Optional[Dict[str, Any]] = None
    cache_scan: Optional[Dict[str, Any]] = None
    cleanup_ok = False
    error: Optional[str] = None
    client = None
    sftp = None
    try:
        client, sftp = open_sftp(config)
        upload_temp_plugin(sftp, php_plugin(token))
        endpoint_data, endpoint_meta = fetch_endpoint(token, "dry_run")
        if mode == "apply":
            if not resolver_ok:
                raise RuntimeError(resolver_reason)
            if not isinstance(endpoint_data, dict) or endpoint_data.get("target_option") != ALLOWED_OPTION:
                raise RuntimeError("dry_run_target_not_allowed")
            backup_info, backup_error = create_backup(timestamp, endpoint_data)
            if backup_error:
                raise RuntimeError(backup_error)
            apply_data, apply_meta = fetch_endpoint(token, "apply", str(endpoint_data.get("value_sha256")))
            healthcheck = public_healthcheck(timestamp)
            cache_scan = scan_wpo_cache_markers(sftp)
    except Exception as exc:  # noqa: BLE001
        error = redact_text(exc, max_len=500)
    finally:
        try:
            if sftp is not None:
                cleanup_ok = remove_temp_plugin(sftp)
        finally:
            try:
                if sftp is not None:
                    sftp.close()
                if client is not None:
                    client.close()
            except Exception:
                pass
    report = build_report(mode, timestamp, resolver_ok, resolver_reason, candidate, endpoint_data, endpoint_meta, cleanup_ok, backup_info, apply_data, apply_meta, healthcheck, cache_scan, error)
    write_outputs(report)
    return report


def run_self_test() -> int:
    fake_resolver = {
        "breach": False,
        "safe_option_candidate": {
            "option_name": ALLOWED_OPTION,
            "safe_for_option_delete": True,
        },
    }
    ok, reason, _candidate = is_safe_candidate_from_resolver(fake_resolver)
    if not ok or reason != "ok":
        raise AssertionError("allowed option exact match failed")
    bad = {"breach": False, "safe_option_candidate": {"option_name": "soc_secret_token", "safe_for_option_delete": True}}
    ok, _reason, _candidate = is_safe_candidate_from_resolver(bad)
    if ok:
        raise AssertionError("unsafe option accepted")
    bad_secret = {"breach": False, "safe_option_candidate": {"option_name": "api_token", "safe_for_option_delete": True}}
    ok, _reason, _candidate = is_safe_candidate_from_resolver(bad_secret)
    if ok:
        raise AssertionError("secret-like option accepted")
    dry = {"target_option": ALLOWED_OPTION, "value_raw": "a soc-entity value", "value_sha256": sha256_text("a soc-entity value")}
    selftest_backup_path = BACKUP_ROOT / (timestamp_tag() + "-selftest") / f"option-{ALLOWED_OPTION}.json"
    assert_allowed_write(selftest_backup_path)
    if sha256_text(dry["value_raw"]) != dry["value_sha256"]:
        raise AssertionError("backup sha check failed")
    unsafe_dry = {"target_option": ALLOWED_OPTION, "value_raw": "token=abcdef12345", "value_sha256": sha256_text("token=abcdef12345")}
    backup, err = create_backup(timestamp_tag() + "-selftest-secret", unsafe_dry)
    if backup or err != "backup_value_secret_like":
        raise AssertionError("secret-like backup not blocked")
    fake_report = build_report("apply", timestamp_tag(), True, "ok", {"option_name": ALLOWED_OPTION}, dry, {"http_status": 200}, True, None, {"db_write_performed": True, "deleted": True, "target_option": ALLOWED_OPTION}, {"http_status": 200}, {"http_status": 200}, None, None)
    if not fake_report["breach"]:
        raise AssertionError("apply without backup did not breach")
    source = Path(__file__).read_text(encoding="utf-8")
    forbidden_tokens = ("rm " + "-rf", "." + "put(", "." + "rename(", "." + "rmdir(", "rm" + "tree(", "sub" + "process")
    for token in forbidden_tokens:
        if token in source:
            raise AssertionError(f"forbidden token found: {token}")
    if not validate_remote_plugin_path(REMOTE_PLUGIN):
        raise AssertionError("temporary plugin path rejected")
    if validate_remote_plugin_path("/wordpress/wp-content/mu-plugins/other.php"):
        raise AssertionError("unexpected temp plugin path accepted")
    print("self-test ok")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Safely remove the exact SOC baseline DB option after dry-run and backup.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--dry-run", action="store_true")
    group.add_argument("--apply", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return run_self_test()
    if not args.dry_run and not args.apply:
        parser.error("Use --dry-run, --apply, or --self-test")
    mode = "apply" if args.apply else "dry-run"
    report = execute(mode)
    print(f"removal_status={report.get('removal_status')}")
    print(f"mode={report.get('mode')}")
    print(f"target_option={report.get('target_option')}")
    print(f"backup_dir={report.get('backup_dir') or '-'}")
    print(f"apply_deleted={report.get('apply_deleted')}")
    print(f"breach={report.get('breach')}")
    healthcheck = report.get("healthcheck") or {}
    if healthcheck:
        print(f"soc_schema_graph_present={healthcheck.get('soc_schema_graph_present')}")
        print(f"data_soc_schema_present={healthcheck.get('data_soc_schema_present')}")
        print(f"jsonld_script_count={healthcheck.get('jsonld_script_count')}")
    if report.get("error"):
        print(f"error={report.get('error')}", file=sys.stderr)
    return 0 if not report.get("breach") else 2


if __name__ == "__main__":
    sys.exit(main())
