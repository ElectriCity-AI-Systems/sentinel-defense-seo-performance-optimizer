#!/usr/bin/env python3
"""SOC DB Source Resolver (Phase 6.14).

Uploads one temporary read-only MU diagnostic plugin, fetches a token-gated
diagnostic endpoint, removes the plugin, and writes sanitized reports. No DB
writes are performed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import posixpath
import re
import secrets
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


PROJECT_DIR = Path("/srv/sentinel-defense")
REMOTE_PLUGIN = "/wordpress/wp-content/mu-plugins/sentinel-soc-db-source-resolver.php"
PUBLIC_BASE = "https://electri-c-ity-studios-24-7.com/"

REPORT_JSON = PROJECT_DIR / "reports/latest/soc-db-source-resolver.json"
REPORT_MD = PROJECT_DIR / "reports/latest/soc-db-source-resolver.md"
DECISION_REPORT_MD = PROJECT_DIR / "reports/latest/soc-removal-owner-decision.md"
DECISION_DRAFT_MD = PROJECT_DIR / "drafts/owner/soc-removal-owner-decision.md"
BOT_LEARNING_JSON = PROJECT_DIR / "reports/latest/bot-learning-soc-schema-cleanup.json"
BOT_LEARNING_MD = PROJECT_DIR / "reports/latest/bot-learning-soc-schema-cleanup.md"
POLICY_UPDATE_MD = PROJECT_DIR / "reports/latest/sentinel-safe-autonomy-policy-update.md"
SNAPSHOT_DIR = PROJECT_DIR / "snapshots"
AUDIT_JSONL = PROJECT_DIR / "audit/soc-db-source-resolver.jsonl"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "drafts/owner",
    PROJECT_DIR / "snapshots",
    PROJECT_DIR / "audit",
)

STATUS_FOUND_PRIMARY = "SOC_DB_SOURCE_RESOLVER_FOUND_PRIMARY_SOURCE"
STATUS_FOUND_SECONDARY = "SOC_DB_SOURCE_RESOLVER_FOUND_ONLY_SECONDARY_CLUES"
STATUS_NO_SOURCE = "SOC_DB_SOURCE_RESOLVER_NO_SOURCE_FOUND"
STATUS_FAILED = "SOC_DB_SOURCE_RESOLVER_FAILED"
STATUS_BLOCKED = "SOC_DB_SOURCE_RESOLVER_BLOCKED_BY_SAFETY"

SCHEMA_VERSION = "soc-db-source-resolver-6.14"
ALLOWED_OPTION = "soc_baseline_metrics"

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
DIRECT_MARKERS = {"soc-schema-graph", "data-soc-schema", "#soc-entity", "#soc-logo", "#soc-website"}

SECRET_NAME_RE = re.compile(r"(?i)(secret|key|token|password|passwd|api[_-]?key|credential|authorization|cookie|session|license)")
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|password|passwd|bearer|token|credential|session|"
    r"authorization|set-cookie|cookie|x-api-key|access[_-]?key|license)\b\s*[:=]\s*"
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


def marker_sql_array() -> str:
    return ",\n        ".join(repr(marker) for marker in MARKERS)


def php_plugin(token: str) -> str:
    token_escaped = token.replace("\\", "\\\\").replace("'", "\\'")
    return f"""<?php
/*
Plugin Name: Sentinel SOC DB Source Resolver
Description: Temporary read-only SOC DB resolver. Remove immediately after use.
Version: 0.1.0
*/
if (!defined('ABSPATH')) {{ exit; }}
add_action('init', function () {{
    if (!isset($_GET['sentinel_soc_db_source_resolver'])) {{ return; }}
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
    global $wpdb;
    $markers = array({marker_sql_array()});
    $secret_terms = array('password','secret','token','key','credential','license','api','cookie','session');
    $secret_name = function ($name) use ($secret_terms) {{
        $lower = strtolower((string) $name);
        foreach ($secret_terms as $term) {{ if (strpos($lower, $term) !== false) {{ return true; }} }}
        return false;
    }};
    $hits_for_text = function ($text) use ($markers) {{
        $out = array();
        $lower = strtolower((string) $text);
        foreach ($markers as $marker) {{ if (strpos($lower, strtolower($marker)) !== false) {{ $out[] = $marker; }} }}
        return array_values(array_unique($out));
    }};
    $preview_for_marker = function ($text, $marker) {{
        $text = (string) $text;
        $lower = strtolower($text);
        $pos = strpos($lower, strtolower($marker));
        if ($pos === false) {{ return null; }}
        $start = max(0, $pos - 100);
        $piece = substr($text, $start, 320);
        $piece = wp_strip_all_tags($piece);
        $piece = preg_replace('/\\s+/', ' ', $piece);
        return substr(trim($piece), 0, 320);
    }};
    $value_shape = function ($value) {{
        $value = (string) $value;
        if (is_serialized($value)) {{ return 'serialized'; }}
        json_decode($value, true);
        if (json_last_error() === JSON_ERROR_NONE && strlen($value) > 0) {{ return 'json'; }}
        return 'plain';
    }};
    $make_where = function ($columns) use ($wpdb, $markers) {{
        $parts = array();
        $values = array();
        foreach ($columns as $column) {{
            foreach ($markers as $marker) {{
                $parts[] = "$column LIKE %s";
                $values[] = '%' . $wpdb->esc_like($marker) . '%';
            }}
        }}
        return array('sql' => implode(' OR ', $parts), 'values' => $values);
    }};
    $contexts = function ($text, $matched) use ($preview_for_marker) {{
        $out = array();
        foreach ($matched as $marker) {{ $out[$marker] = $preview_for_marker($text, $marker); }}
        return $out;
    }};
    $result = array(
        'ok' => true,
        'phase' => '6.14-soc-db-source-resolver',
        'timestamp_utc' => gmdate('c'),
        'read_only' => true,
        'db_write_performed' => false,
        'hits' => array(
            'options_exact' => array(),
            'options_name_like' => array(),
            'options_value_markers' => array(),
            'posts_active' => array(),
            'posts_revisions' => array(),
            'postmeta' => array(),
            'termmeta' => array(),
            'fse_templates' => array(),
            'widgets_theme_mods' => array()
        ),
        'hit_counts' => array()
    );
    $option_rows = $wpdb->get_results($wpdb->prepare(
        "SELECT option_id, option_name, option_value, autoload FROM {{$wpdb->options}} WHERE option_name = %s LIMIT 1",
        'soc_baseline_metrics'
    ), ARRAY_A);
    foreach ($option_rows as $row) {{
        $matched = $hits_for_text($row['option_name'] . ' ' . $row['option_value']);
        $result['hits']['options_exact'][] = array(
            'option_id' => (int) $row['option_id'],
            'option_name' => $row['option_name'],
            'autoload' => $row['autoload'],
            'value_size' => strlen((string) $row['option_value']),
            'value_shape' => $value_shape($row['option_value']),
            'secret_like_name' => $secret_name($row['option_name']),
            'matched_markers' => $matched,
            'safe_context_preview' => $contexts($row['option_value'], $matched)
        );
    }}
    $like_rows = $wpdb->get_results(
        "SELECT option_id, option_name, option_value, autoload FROM {{$wpdb->options}} WHERE option_name LIKE '%soc%' OR option_name LIKE '%ecs%' LIMIT 120",
        ARRAY_A
    );
    foreach ($like_rows as $row) {{
        $matched = $hits_for_text($row['option_name'] . ' ' . $row['option_value']);
        $result['hits']['options_name_like'][] = array(
            'option_id' => (int) $row['option_id'],
            'option_name' => $secret_name($row['option_name']) ? '[redacted-option-name]' : $row['option_name'],
            'autoload' => $row['autoload'],
            'value_size' => strlen((string) $row['option_value']),
            'value_shape' => $value_shape($row['option_value']),
            'secret_like_name' => $secret_name($row['option_name']),
            'matched_markers' => $matched,
            'safe_context_preview' => $secret_name($row['option_name']) ? array() : $contexts($row['option_value'], $matched)
        );
    }}
    $where = $make_where(array('option_value'));
    $rows = $wpdb->get_results($wpdb->prepare(
        "SELECT option_id, option_name, option_value, autoload FROM {{$wpdb->options}} WHERE " . $where['sql'] . " LIMIT 120",
        $where['values']
    ), ARRAY_A);
    foreach ($rows as $row) {{
        if ($secret_name($row['option_name'])) {{ continue; }}
        $matched = $hits_for_text($row['option_value']);
        $result['hits']['options_value_markers'][] = array(
            'option_id' => (int) $row['option_id'],
            'option_name' => $row['option_name'],
            'autoload' => $row['autoload'],
            'value_size' => strlen((string) $row['option_value']),
            'value_shape' => $value_shape($row['option_value']),
            'matched_markers' => $matched,
            'safe_context_preview' => $contexts($row['option_value'], $matched)
        );
    }}
    $where = $make_where(array('post_title', 'post_content', 'post_excerpt'));
    $rows = $wpdb->get_results($wpdb->prepare(
        "SELECT ID, post_type, post_status, post_title, post_content, post_excerpt FROM {{$wpdb->posts}} WHERE (" . $where['sql'] . ") LIMIT 200",
        $where['values']
    ), ARRAY_A);
    foreach ($rows as $row) {{
        $combined = $row['post_title'] . ' ' . $row['post_content'] . ' ' . $row['post_excerpt'];
        $matched = $hits_for_text($combined);
        $item = array(
            'ID' => (int) $row['ID'],
            'post_type' => $row['post_type'],
            'post_status' => $row['post_status'],
            'post_title' => wp_strip_all_tags($row['post_title']),
            'matched_markers' => $matched,
            'safe_context_preview' => $contexts($combined, $matched)
        );
        if ($row['post_type'] === 'revision') {{
            $result['hits']['posts_revisions'][] = $item;
        }} else {{
            $result['hits']['posts_active'][] = $item;
            if (in_array($row['post_type'], array('wp_template','wp_template_part','wp_global_styles','wp_block'), true)) {{
                $result['hits']['fse_templates'][] = $item;
            }}
        }}
    }}
    $where = $make_where(array('meta_key', 'meta_value'));
    $rows = $wpdb->get_results($wpdb->prepare(
        "SELECT meta_id, post_id, meta_key, meta_value FROM {{$wpdb->postmeta}} WHERE " . $where['sql'] . " LIMIT 120",
        $where['values']
    ), ARRAY_A);
    foreach ($rows as $row) {{
        if ($secret_name($row['meta_key'])) {{ continue; }}
        $matched = $hits_for_text($row['meta_key'] . ' ' . $row['meta_value']);
        $result['hits']['postmeta'][] = array(
            'meta_id' => (int) $row['meta_id'],
            'post_id' => (int) $row['post_id'],
            'meta_key' => $row['meta_key'],
            'value_size' => strlen((string) $row['meta_value']),
            'matched_markers' => $matched,
            'safe_context_preview' => $contexts($row['meta_value'], $matched)
        );
    }}
    $termmeta_table = $wpdb->prefix . 'termmeta';
    if ($wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $termmeta_table)) === $termmeta_table) {{
        $where = $make_where(array('meta_key', 'meta_value'));
        $rows = $wpdb->get_results($wpdb->prepare(
            "SELECT meta_id, term_id, meta_key, meta_value FROM {{$termmeta_table}} WHERE " . $where['sql'] . " LIMIT 120",
            $where['values']
        ), ARRAY_A);
        foreach ($rows as $row) {{
            if ($secret_name($row['meta_key'])) {{ continue; }}
            $matched = $hits_for_text($row['meta_key'] . ' ' . $row['meta_value']);
            $result['hits']['termmeta'][] = array(
                'meta_id' => (int) $row['meta_id'],
                'term_id' => (int) $row['term_id'],
                'meta_key' => $row['meta_key'],
                'value_size' => strlen((string) $row['meta_value']),
                'matched_markers' => $matched,
                'safe_context_preview' => $contexts($row['meta_value'], $matched)
            );
        }}
    }}
    $rows = $wpdb->get_results(
        "SELECT option_id, option_name, option_value, autoload FROM {{$wpdb->options}} WHERE option_name LIKE 'theme_mods_%' OR option_name LIKE 'widget_%' OR option_name = 'sidebars_widgets' LIMIT 160",
        ARRAY_A
    );
    foreach ($rows as $row) {{
        if ($secret_name($row['option_name'])) {{ continue; }}
        $matched = $hits_for_text($row['option_name'] . ' ' . $row['option_value']);
        if (!$matched) {{ continue; }}
        $result['hits']['widgets_theme_mods'][] = array(
            'option_id' => (int) $row['option_id'],
            'option_name' => $row['option_name'],
            'autoload' => $row['autoload'],
            'value_size' => strlen((string) $row['option_value']),
            'value_shape' => $value_shape($row['option_value']),
            'matched_markers' => $matched,
            'safe_context_preview' => $contexts($row['option_value'], $matched)
        );
    }}
    foreach ($result['hits'] as $bucket => $items) {{ $result['hit_counts'][$bucket] = count($items); }}
    echo wp_json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
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


def fetch_diagnostic(token: str) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
    url = PUBLIC_BASE + "?" + urlencode({"sentinel_soc_db_source_resolver": "1", "token": token})
    meta: Dict[str, Any] = {"http_status": None, "error": None}
    try:
        req = Request(url, method="GET", headers={"User-Agent": "SentinelSocDbSourceResolver/6.14", "Accept": "application/json"})
        with urlopen(req, timeout=30) as response:  # noqa: S310 - own site token-gated read-only diagnostic
            body = response.read(1_500_000).decode("utf-8", errors="replace")
            meta["http_status"] = int(response.status)
    except HTTPError as exc:
        body = exc.read(1_500_000).decode("utf-8", errors="replace")
        meta["http_status"] = int(exc.code)
        meta["error"] = redact_text(exc, max_len=300)
    except (OSError, URLError) as exc:
        return None, {"http_status": None, "error": redact_text(exc, max_len=300)}
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return None, {**meta, "error": "invalid_json_response"}
    return data if isinstance(data, dict) else None, meta


def secret_like_option_name(name: str) -> bool:
    return bool(SECRET_NAME_RE.search(name))


def classify_result(db_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    hits = db_result.get("hits", {}) if isinstance(db_result, dict) else {}
    exact_options = hits.get("options_exact", []) if isinstance(hits.get("options_exact"), list) else []
    active_posts = hits.get("posts_active", []) if isinstance(hits.get("posts_active"), list) else []
    revisions = hits.get("posts_revisions", []) if isinstance(hits.get("posts_revisions"), list) else []
    fse = hits.get("fse_templates", []) if isinstance(hits.get("fse_templates"), list) else []
    postmeta = hits.get("postmeta", []) if isinstance(hits.get("postmeta"), list) else []
    widgets = hits.get("widgets_theme_mods", []) if isinstance(hits.get("widgets_theme_mods"), list) else []

    safe_option_candidates = []
    for row in exact_options:
        option_name = str(row.get("option_name", ""))
        markers = set(row.get("matched_markers", []) or [])
        if (
            option_name == ALLOWED_OPTION
            and markers
            and not row.get("secret_like_name")
            and not secret_like_option_name(option_name)
        ):
            safe_option_candidates.append(
                {
                    "option_name": option_name,
                    "option_id": row.get("option_id"),
                    "matched_markers": sorted(markers),
                    "value_shape": row.get("value_shape"),
                    "value_size": row.get("value_size"),
                    "safe_for_option_delete": True,
                    "reason": "Exact allowed SOC baseline metrics option contains SOC markers and is not secret-like.",
                }
            )

    direct_active = []
    secondary_active = []
    for row in active_posts + fse + postmeta + widgets:
        markers = set(row.get("matched_markers", []) or [])
        if markers & DIRECT_MARKERS:
            direct_active.append(row)
        elif markers:
            secondary_active.append(row)

    if direct_active:
        status = STATUS_FOUND_PRIMARY
        primary_source_type = "active_db_content_direct_soc_schema_marker"
    elif safe_option_candidates:
        status = STATUS_FOUND_PRIMARY
        primary_source_type = "safe_exact_option_soc_baseline_metrics"
    elif secondary_active or revisions:
        status = STATUS_FOUND_SECONDARY
        primary_source_type = "secondary_clues_only"
    else:
        status = STATUS_NO_SOURCE
        primary_source_type = "none"

    return {
        "resolver_status": status,
        "primary_source_type": primary_source_type,
        "safe_option_candidates": safe_option_candidates,
        "manual_editor_review_candidates": [
            {
                "ID": row.get("ID"),
                "post_type": row.get("post_type"),
                "post_status": row.get("post_status"),
                "post_title": row.get("post_title"),
                "matched_markers": row.get("matched_markers", []),
                "reason": "Active post/template contains SOC clue; manual WordPress editor review required.",
            }
            for row in active_posts + fse
            if row.get("matched_markers")
        ],
        "revision_hits_count": len(revisions),
        "postmeta_hits_count": len(postmeta),
        "widgets_theme_mods_hits_count": len(widgets),
        "safe_removal_allowed": len(safe_option_candidates) == 1,
    }


def sanitize_db_result(db_result: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not isinstance(db_result, dict):
        return None
    return db_result


def build_report(timestamp: str, db_result: Optional[Dict[str, Any]], fetch_meta: Dict[str, Any], sftp_status: str, cleanup_ok: bool, error: Optional[str]) -> Dict[str, Any]:
    classification = classify_result(db_result)
    breach_reasons: List[str] = []
    if not cleanup_ok:
        breach_reasons.append("temporary MU plugin remained after cleanup")
    if error:
        status = STATUS_FAILED
    else:
        status = classification["resolver_status"]
    if breach_reasons:
        status = STATUS_BLOCKED
    return {
        "schema_version": SCHEMA_VERSION,
        "timestamp_utc": utc_now(),
        "timestamp": timestamp,
        "resolver_status": status,
        "connected": sftp_status == "ok",
        "plugin_uploaded": sftp_status == "ok",
        "diagnostic_fetch_ok": isinstance(db_result, dict) and bool(db_result.get("ok")),
        "plugin_removed": cleanup_ok,
        "remote_exists_after_cleanup": not cleanup_ok,
        "http_status": fetch_meta.get("http_status"),
        "db_result": sanitize_db_result(db_result),
        "classification": classification,
        "safe_option_candidate": classification["safe_option_candidates"][0] if classification["safe_option_candidates"] else None,
        "manual_editor_review_candidates": classification["manual_editor_review_candidates"],
        "breach": bool(breach_reasons),
        "breach_reasons": breach_reasons,
        "error": redact_text(error, default=None, max_len=500) if error else fetch_meta.get("error"),
        "safety": {
            "temporary_mu_plugin": True,
            "db_read_only": True,
            "db_write_performed": False,
            "sftp_upload_one_temp_file": True,
            "sftp_remove_same_file_after": True,
            "no_theme_change": True,
            "no_plugin_change_except_temporary_mu_diagnostic": True,
            "no_htaccess_change": True,
            "no_cloudflare_change": True,
            "no_nginx_change": True,
        },
    }


def render_report_md(report: Dict[str, Any]) -> str:
    c = report.get("classification", {})
    lines = [
        "# SOC DB Source Resolver",
        "",
        f"- Status: `{report.get('resolver_status')}`",
        f"- Connected: `{report.get('connected')}`",
        f"- Diagnostic fetch OK: `{report.get('diagnostic_fetch_ok')}`",
        f"- Temporary plugin removed: `{report.get('plugin_removed')}`",
        f"- Breach: `{report.get('breach')}`",
        f"- Primary source type: `{c.get('primary_source_type')}`",
        f"- Safe option candidates: `{len(c.get('safe_option_candidates', []))}`",
        f"- Manual editor review candidates: `{len(c.get('manual_editor_review_candidates', []))}`",
        f"- Revision hits count: `{c.get('revision_hits_count')}`",
        "",
        "## Safe Option Candidates",
        "",
    ]
    for item in c.get("safe_option_candidates", []):
        lines.append(f"- `{item.get('option_name')}` id=`{item.get('option_id')}` markers=`{', '.join(item.get('matched_markers', []))}`")
    if not c.get("safe_option_candidates"):
        lines.append("- none")
    lines.extend(["", "## Manual WP Editor Review Candidates", ""])
    for item in c.get("manual_editor_review_candidates", [])[:30]:
        lines.append(
            f"- ID `{item.get('ID')}` `{item.get('post_type')}` `{item.get('post_status')}` title=`{redact_text(item.get('post_title'), max_len=200)}` markers=`{', '.join(item.get('matched_markers', []))}`"
        )
    if not c.get("manual_editor_review_candidates"):
        lines.append("- none")
    return "\n".join(lines) + "\n"


def render_decision_plan(report: Dict[str, Any]) -> str:
    c = report.get("classification", {})
    safe = c.get("safe_option_candidates", [])
    manual = c.get("manual_editor_review_candidates", [])
    lines = [
        "# SOC Removal Owner Decision Plan",
        "",
        "## A) Sichere Kandidaten zum Entfernen",
        "",
    ]
    if safe:
        for item in safe:
            lines.append(f"- `{item.get('option_name')}`: exakt erlaubte Option, nicht secret-like, Backup vor Delete erforderlich.")
    else:
        lines.append("- Keine sichere automatische Option gefunden.")
    lines.extend(["", "## B) Manuelle WordPress-Editor-Prüfung", ""])
    if manual:
        for item in manual[:30]:
            lines.append(f"- ID `{item.get('ID')}` `{item.get('post_type')}` `{item.get('post_status')}` `{redact_text(item.get('post_title'), max_len=200)}` markers=`{', '.join(item.get('matched_markers', []))}`")
    else:
        lines.append("- Keine aktiven Editor-/Template-Kandidaten gemeldet.")
    lines.extend(
        [
            "",
            "## C) Nicht automatisch ändern",
            "",
            "- Revisions bleiben unverändert.",
            "- Unknown plugin settings bleiben unverändert.",
            "- Secret-like option names bleiben unverändert.",
            "- Serialisierte komplexe Daten werden nicht gepatcht; nur die exakt erlaubte Option darf nach Backup gelöscht werden.",
            "",
        ]
    )
    return "\n".join(lines)


def bot_learning_report() -> Dict[str, Any]:
    return {
        "problem_types": ["duplicate_schema", "stale_schema_generator", "cache_regeneration"],
        "symptoms": ["soc-schema-graph visible", "data-soc-schema visible", "Organization/WebSite duplicated"],
        "diagnostic_path": [
            "public HTML check",
            "cache locator",
            "cache purge",
            "post-purge public probe",
            "deep file scan",
            "temporary DB diagnostic",
        ],
        "safe_actions": [
            "read-only public probe",
            "read-only SFTP scan",
            "cache-file purge only under exact WPO cache prefix",
            "temporary read-only MU diagnostic plugin with token",
        ],
        "risky_actions": [
            "DB option delete",
            "FSE template edit",
            "post content edit",
            "plugin/theme modification",
        ],
        "autonomy_classification": {
            "read_only_checks": "LOW risk, future automatic allowed by policy",
            "cache_purge_with_backup": "MEDIUM risk, owner approval required",
            "db_option_delete": "HIGH risk, explicit owner approval required",
            "post_template_edits": "HIGH risk, never automatic without review",
        },
        "rollback": ["Cache backups", "DB value backups", "Audit JSONL", "Snapshot JSON"],
        "future_automatic_checks": [
            "schema_duplicate_scan",
            "jsonld_source_map",
            "wpo_cache_marker_scan",
            "public_healthcheck_after_apply",
            "seo_score_delta_report",
            "performance_cache_status_report",
        ],
    }


def render_bot_learning_md(data: Dict[str, Any]) -> str:
    lines = ["# Bot Learning: SOC Schema Cleanup", ""]
    for key, value in data.items():
        lines.append(f"## {key.replace('_', ' ').title()}")
        if isinstance(value, list):
            for item in value:
                lines.append(f"- {item}")
        elif isinstance(value, dict):
            for k, v in value.items():
                lines.append(f"- `{k}`: {v}")
        else:
            lines.append(str(value))
        lines.append("")
    return "\n".join(lines)


def policy_update_md() -> str:
    return """# Sentinel Safe Autonomy Policy Update

- Der Bot darf künftig automatisch read-only SEO/Performance-Prüfungen durchführen.
- Der Bot darf Vorschläge und Patches vorbereiten.
- Der Bot darf LOW-RISK Aufgaben nur nach vorher definierter Policy ausführen.
- MEDIUM-RISK Aufgaben wie Cache-Purge brauchen Owner-Freigabe.
- HIGH-RISK Aufgaben wie DB-Änderungen, Template-Änderungen, Plugin-/Theme-Änderungen brauchen immer explizite Review + Backup + Apply-Freigabe.
- Keine unkontrollierte Autonomie.
- Kein blindes Löschen.
- Keine Cloudflare/Nginx/.htaccess/DB-Änderung ohne Freigabe.
- Alles bleibt auditierbar, reversibel und reportpflichtig.
"""


def write_outputs(report: Dict[str, Any]) -> None:
    ts = str(report["timestamp"])
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, render_report_md(report))
    write_json_atomic(SNAPSHOT_DIR / f"soc-db-source-resolver-{ts}.json", report)
    decision = render_decision_plan(report)
    write_text_atomic(DECISION_REPORT_MD, decision)
    write_text_atomic(DECISION_DRAFT_MD, decision)
    learning = bot_learning_report()
    write_json_atomic(BOT_LEARNING_JSON, learning)
    write_text_atomic(BOT_LEARNING_MD, render_bot_learning_md(learning))
    write_text_atomic(POLICY_UPDATE_MD, policy_update_md())
    append_jsonl(
        AUDIT_JSONL,
        [{
            "timestamp_utc": report.get("timestamp_utc"),
            "timestamp": report.get("timestamp"),
            "resolver_status": report.get("resolver_status"),
            "diagnostic_fetch_ok": report.get("diagnostic_fetch_ok"),
            "plugin_removed": report.get("plugin_removed"),
            "safe_option_candidate": (report.get("safe_option_candidate") or {}).get("option_name"),
            "manual_editor_review_candidates_count": len(report.get("manual_editor_review_candidates", [])),
            "breach": report.get("breach"),
        }],
    )


def run_resolver() -> Dict[str, Any]:
    timestamp = timestamp_tag()
    token = secrets.token_urlsafe(32)
    config, sftp_status = read_sftp_config()
    db_result: Optional[Dict[str, Any]] = None
    fetch_meta: Dict[str, Any] = {"http_status": None, "error": None}
    cleanup_ok = False
    error: Optional[str] = None
    client = None
    sftp = None
    if config is None:
        report = build_report(timestamp, None, fetch_meta, sftp_status, False, sftp_status)
        write_outputs(report)
        return report
    try:
        client, sftp = open_sftp(config)
        upload_temp_plugin(sftp, php_plugin(token))
        db_result, fetch_meta = fetch_diagnostic(token)
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
    report = build_report(timestamp, db_result, fetch_meta, sftp_status, cleanup_ok, error)
    write_outputs(report)
    return report


def run_self_test() -> int:
    if ".sentinel-sftp.env" in json.dumps(bot_learning_report()):
        raise AssertionError("env file leaked into learning report")
    if not secret_like_option_name("api_token_setting"):
        raise AssertionError("secret-like option detection failed")
    if secret_like_option_name(ALLOWED_OPTION):
        raise AssertionError("allowed option marked secret-like")
    fake = {
        "ok": True,
        "hits": {
            "options_exact": [{"option_id": 1, "option_name": ALLOWED_OPTION, "matched_markers": ["#soc-entity"], "secret_like_name": False, "value_shape": "serialized", "value_size": 100}],
            "posts_active": [],
            "posts_revisions": [{"ID": 1, "matched_markers": ["ecs-soc"]}],
            "fse_templates": [],
            "postmeta": [],
            "widgets_theme_mods": [],
        },
    }
    c = classify_result(fake)
    if not c["safe_removal_allowed"]:
        raise AssertionError("safe option candidate not detected")
    source = Path(__file__).read_text(encoding="utf-8")
    for token in ("rm " + "-rf", "." + "rename(", "." + "rmdir(", "rm" + "tree("):
        if token in source:
            raise AssertionError(f"forbidden token found: {token}")
    print("self-test ok")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Resolve active SOC schema DB source with a temporary read-only MU plugin.")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return run_self_test()
    report = run_resolver()
    print(f"resolver_status={report.get('resolver_status')}")
    print(f"diagnostic_fetch_ok={report.get('diagnostic_fetch_ok')}")
    print(f"safe_option_candidate={(report.get('safe_option_candidate') or {}).get('option_name')}")
    print(f"manual_editor_review_candidates_count={len(report.get('manual_editor_review_candidates', []))}")
    print(f"breach={report.get('breach')}")
    if report.get("error"):
        print(f"error={report.get('error')}", file=sys.stderr)
    return 0 if not report.get("breach") else 2


if __name__ == "__main__":
    sys.exit(main())
