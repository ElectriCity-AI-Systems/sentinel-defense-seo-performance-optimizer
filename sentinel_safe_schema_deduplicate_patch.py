#!/usr/bin/env python3
"""Safe Schema De-Duplicate Patch for the JSON-LD MU-Plugin (Phase 6.2).

The live site already emits Organization and WebSite JSON-LD from other sources,
so the Sentinel MU-plugin must stop duplicating them. This module regenerates the
single allowed MU-plugin with a SLIM JSON-LD ``@graph`` that contains ONLY the
genuinely additive types:

- RadioStation
- MusicGroup

Organization, WebSite, BreadcrumbList, FAQPage and CreativeWork are removed from
the MU-plugin output. The same tightly-scoped SFTP apply lane as Phase 6.1 guards
the change: dry-run/prepare never upload; live apply needs an explicit owner
approval file and touches only the one allowed remote path, with backup + atomic
rename + HTTP healthcheck + SFTP rollback.

No upload without owner approval. Schema duplicate reduction prepared safely.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


PROJECT_DIR = Path("/srv/sentinel-defense")

JSONLD_PACK_MD = PROJECT_DIR / "drafts/owner/wordpress-jsonld-schema-pack.md"
APPLY_LANE_JSON = PROJECT_DIR / "reports/latest/safe-sftp-seo-apply-lane.json"
SAFE_END_SUMMARY_JSON = PROJECT_DIR / "reports/latest/safe-end-summary.json"
MASTER_JSON = PROJECT_DIR / "reports/latest/sentinel-master-report.json"

OWNER_APPROVAL_JSON = PROJECT_DIR / "state/owner-approved-schema-deduplicate-apply.json"
APPROVAL_SCOPE = "schema_deduplicate_mu_plugin_patch"

EXPORT_DIR = PROJECT_DIR / "exports/sftp-seo-apply"
PLUGIN_BASENAME = "sentinel-seo-jsonld-injector.php"
EXPORT_PLUGIN = EXPORT_DIR / PLUGIN_BASENAME
EXPORT_MANIFEST = EXPORT_DIR / "manifest.json"
EXPORT_CHECKSUMS = EXPORT_DIR / "checksums.sha256.txt"

REPORT_JSON = PROJECT_DIR / "reports/latest/schema-deduplicate-patch.json"
REPORT_MD = PROJECT_DIR / "reports/latest/schema-deduplicate-patch.md"
OWNER_SUMMARY_MD = PROJECT_DIR / "drafts/owner/schema-deduplicate-owner-summary.md"
SNAPSHOT_JSON = PROJECT_DIR / "snapshots/schema-deduplicate-patch.json"
SNAPSHOT_MD = PROJECT_DIR / "snapshots/schema-deduplicate-patch.md"
AUDIT_JSONL = PROJECT_DIR / "audit/schema-deduplicate-patch.jsonl"

ALLOWED_REMOTE_TARGET = "wp-content/mu-plugins/sentinel-seo-jsonld-injector.php"

WEBSITE_URL = "https://electri-c-ity-studios-24-7.com/"
HEALTHCHECK_MARKER_JSONLD = "application/ld+json"
HEALTHCHECK_MARKER_BRAND = "Electri_C_ity Studios"
HEALTHCHECK_MARKER_PLUGIN = "Sentinel SEO JSON-LD Injector"

# The slim plugin must emit ONLY these top-level @graph types.
SLIM_ALLOWED_TYPES = ("RadioStation", "MusicGroup")
# These must never appear anywhere in the slim plugin output.
REMOVED_SCHEMA_TYPES = ("Organization", "WebSite", "BreadcrumbList", "FAQPage", "CreativeWork")

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "drafts/owner",
    PROJECT_DIR / "snapshots",
    PROJECT_DIR / "audit",
    PROJECT_DIR / "state",
    PROJECT_DIR / "exports",
)
ALLOWED_OUTPUT_PATHS = (
    EXPORT_PLUGIN,
    EXPORT_MANIFEST,
    EXPORT_CHECKSUMS,
    REPORT_JSON,
    REPORT_MD,
    OWNER_SUMMARY_MD,
    SNAPSHOT_JSON,
    SNAPSHOT_MD,
    AUDIT_JSONL,
)
FORBIDDEN_OUTPUT_SUFFIXES = (".sh", ".bash", ".zsh", ".service", ".timer", ".run", ".bin", ".py", ".php")
FORBIDDEN_INSTALL_PATH_TOKENS = ("/etc/systemd", "systemd/system", "/lib/systemd", "/usr/lib/systemd", "/etc/cron", "cron.d", "crontab")

SCHEMA_VERSION = "schema-deduplicate-patch-6.2"
APPLY_NOT_APPLIED = "not_applied"
APPLY_APPLIED = "applied"

MODE_DRY_RUN = "dry-run"
MODE_PREPARE = "prepare-upload"
MODE_APPLY = "apply-with-owner-approval"
MODE_ROLLBACK = "rollback"

STATUS_DRY_RUN_READY = "SCHEMA_DEDUP_DRY_RUN_READY"
STATUS_PREPARED_FOR_UPLOAD = "SCHEMA_DEDUP_PREPARED_FOR_UPLOAD"
STATUS_BLOCKED_NEEDS_OWNER_APPROVAL = "SCHEMA_DEDUP_BLOCKED_NEEDS_OWNER_APPROVAL"
STATUS_BLOCKED_SFTP_CONFIG_MISSING = "SCHEMA_DEDUP_BLOCKED_SFTP_CONFIG_MISSING"
STATUS_UPLOADED_HEALTHCHECK_OK = "SCHEMA_DEDUP_UPLOADED_HEALTHCHECK_OK"
STATUS_ROLLED_BACK_HEALTHCHECK_FAILED = "SCHEMA_DEDUP_ROLLED_BACK_HEALTHCHECK_FAILED"
STATUS_ROLLBACK_OK = "SCHEMA_DEDUP_ROLLBACK_OK"
STATUS_BREACH = "SCHEMA_DEDUP_BREACH"

FORBIDDEN_PLUGIN_RE = re.compile(
    r"(?i)(\beval\s*\(|base64_|gzinflate|gzuncompress|str_rot13|\bassert\s*\(|"
    r"\bsystem\s*\(|\bexec\s*\(|passthru|shell_exec|popen|proc_open|"
    r"curl_|wp_remote_|file_get_contents\s*\(\s*['\"]?https?|file_put_contents|"
    r"\bfopen\b|\bfwrite\b|\bfputs\b|unlink\s*\(|"
    r"update_option|add_option|delete_option|\$wpdb|register_rest_route|"
    r"\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$_SERVER\[|"
    r"include\s*\(\s*['\"]https?|require\s*\(\s*['\"]https?)"
)
REQUIRED_PLUGIN_TOKENS = ("add_action('wp_head'", "application/ld+json")

SECRETISH_RE = re.compile(
    r"(?i)(api[_-]?key|token|secret|password|passwd|bearer|authorization|"
    r"cookie|set-cookie|credential|x-api-key|access[_-]?key|session|private[_-]?key)"
)
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|password|passwd|bearer|token|credential|session|"
    r"authorization|set-cookie|cookie|x-api-key|access[_-]?key|private[_-]?key)\b\s*[:=]\s*"
    r"[\"']?(?!false\b|true\b|null\b|none\b|not_applied\b|<redacted|-\b|0\b)"
    r"[A-Za-z0-9+/=_\-]{4,}"
)
LONG_HEX_RE = re.compile(r"\b[A-Fa-f0-9]{32,}\b")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def timestamp_tag() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def detect_secret_like(value: Any) -> bool:
    text = "" if value is None else str(value)
    return bool(SECRET_ASSIGNMENT_RE.search(text) or LONG_HEX_RE.search(text))


def redact_text(value: Any, default: str = "-", max_len: int = 800) -> str:
    if value is None:
        return default
    text = str(value).replace("\r", " ").strip()
    text = SECRET_ASSIGNMENT_RE.sub("<redacted>", text)
    text = LONG_HEX_RE.sub("<redacted-hex>", text)
    if SECRETISH_RE.search(text):
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
    if path in ALLOWED_OUTPUT_PATHS:
        if any(token in str(path) for token in FORBIDDEN_INSTALL_PATH_TOKENS):
            raise ValueError(f"Refusing to write systemd/crontab path: {path}")
        return
    if not any(is_within(path, root) for root in ALLOWED_WRITE_ROOTS):
        raise ValueError(f"Refusing to write outside allowed patch roots: {path}")
    if path.suffix.lower() in FORBIDDEN_OUTPUT_SUFFIXES:
        raise ValueError(f"Refusing to write executable/install artifact: {path}")
    if any(token in str(path) for token in FORBIDDEN_INSTALL_PATH_TOKENS):
        raise ValueError(f"Refusing to write systemd/crontab path: {path}")


def write_text_atomic(path: Path, content: str) -> None:
    assert_allowed_write(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)


def write_json_atomic(path: Path, data: Dict[str, Any]) -> None:
    write_text_atomic(path, json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def append_jsonl(path: Path, records: List[Dict[str, Any]]) -> None:
    assert_allowed_write(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def read_optional_json(path: Path) -> Tuple[Optional[Any], str]:
    if ".env" in str(path).lower() or SECRETISH_RE.search(path.name):
        return None, "refused_secret_like_path"
    try:
        if not path.exists():
            return None, "not_available"
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return None, "read_error"
    try:
        return json.loads(raw), "ok"
    except (ValueError, json.JSONDecodeError):
        return None, "invalid_json"


# ---------------------------------------------------------------------------
# Slim JSON-LD graph + plugin generation
# ---------------------------------------------------------------------------

DEFAULT_SLIM_GRAPH = [
    {
        "@type": "RadioStation",
        "name": "Electri_C_ity Studios 24/7 AI Electro Radio",
        "url": "https://ai-radio.electri-c-ity-studios-24-7.com/",
        "genre": ["Electro", "Techno", "Progressive House", "AI-assisted music"],
    },
    {
        "@type": "MusicGroup",
        "name": "Electri_C_ity Studios",
        "url": "https://electri-c-ity-studios-24-7.com/",
        "genre": ["Electro", "Techno", "Progressive House"],
    },
]


def _strip_removed_keys(node: Dict[str, Any]) -> Dict[str, Any]:
    """Drop nested references that would re-introduce removed types
    (e.g. RadioStation.parentOrganization -> Organization)."""
    cleaned = {k: v for k, v in node.items() if k not in ("parentOrganization", "publisher", "isPartOf")}
    return cleaned


def load_slim_graph() -> Tuple[List[Dict[str, Any]], str]:
    if not JSONLD_PACK_MD.exists():
        return [dict(n) for n in DEFAULT_SLIM_GRAPH], "default_fallback"
    try:
        text = JSONLD_PACK_MD.read_text(encoding="utf-8")
    except OSError:
        return [dict(n) for n in DEFAULT_SLIM_GRAPH], "read_error_fallback"
    slim: List[Dict[str, Any]] = []
    for block in re.findall(r"```json\s*(.*?)```", text, re.DOTALL):
        try:
            obj = json.loads(block)
        except (ValueError, json.JSONDecodeError):
            continue
        if isinstance(obj, dict) and str(obj.get("@type")) in SLIM_ALLOWED_TYPES:
            obj.pop("@context", None)
            slim.append(_strip_removed_keys(obj))
    if not slim:
        return [dict(n) for n in DEFAULT_SLIM_GRAPH], "default_fallback"
    # Deterministic order: RadioStation first, then MusicGroup.
    slim.sort(key=lambda n: SLIM_ALLOWED_TYPES.index(str(n.get("@type"))) if str(n.get("@type")) in SLIM_ALLOWED_TYPES else 99)
    return slim, "ok"


def build_jsonld_document(graph: List[Dict[str, Any]]) -> str:
    document = {"@context": "https://schema.org", "@graph": graph}
    return json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True)


def generate_plugin_php(jsonld_document: str) -> str:
    return (
        "<?php\n"
        "/**\n"
        " * Plugin Name: Sentinel SEO JSON-LD Injector\n"
        " * Description: Outputs slim static JSON-LD (RadioStation + MusicGroup only) in wp_head.\n"
        " *              De-duplicated: emits only the two additive types; duplicate global types removed.\n"
        " *              No DB writes, no admin, no REST, no network, no file writes, no eval/base64.\n"
        " * Version: 1.1.0\n"
        " * Author: Sentinel Defense\n"
        " * License: GPL-2.0-or-later\n"
        " *\n"
        " * SAFETY: This MU-plugin ONLY echoes a single static JSON-LD <script> block on wp_head\n"
        " * containing exclusively the additive RadioStation and MusicGroup types. It performs no\n"
        " * database writes, no option changes, no admin pages, no REST routes, no external requests,\n"
        " * and no file writes.\n"
        " */\n"
        "\n"
        "if (!defined('ABSPATH')) {\n"
        "    exit;\n"
        "}\n"
        "\n"
        "add_action('wp_head', 'sentinel_seo_jsonld_injector_output', 20);\n"
        "\n"
        "function sentinel_seo_jsonld_injector_output() {\n"
        "    $sentinel_jsonld = <<<'SENTINEL_JSONLD'\n"
        f"{jsonld_document}\n"
        "SENTINEL_JSONLD;\n"
        "    echo \"\\n<script type=\\\"application/ld+json\\\">\\n\" . $sentinel_jsonld . \"\\n</script>\\n\";\n"
        "}\n"
    )


def validate_plugin(php: str) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    forbidden = FORBIDDEN_PLUGIN_RE.search(php)
    if forbidden:
        reasons.append(f"forbidden plugin token: {redact_text(forbidden.group(0), max_len=40)}")
    for token in REQUIRED_PLUGIN_TOKENS:
        if token not in php:
            reasons.append(f"missing required plugin token: {token}")
    if php.count("add_action(") != 1:
        reasons.append("plugin must register exactly one add_action(wp_head) hook")
    for slim_type in SLIM_ALLOWED_TYPES:
        if f'"@type": "{slim_type}"' not in php:
            reasons.append(f"missing required slim type: {slim_type}")
    for removed in REMOVED_SCHEMA_TYPES:
        if f'"@type": "{removed}"' in php or f'"{removed}"' in php:
            reasons.append(f"removed schema type still present: {removed}")
    return (not reasons), reasons


def php_syntax_check(path: Path) -> str:
    php_bin = None
    for candidate in ("php", "/usr/bin/php", "/usr/local/bin/php"):
        try:
            probe = subprocess.run([candidate, "-v"], capture_output=True, timeout=10)
            if probe.returncode == 0:
                php_bin = candidate
                break
        except (OSError, subprocess.SubprocessError):
            continue
    if not php_bin:
        return "skipped_no_php"
    try:
        result = subprocess.run([php_bin, "-l", str(path)], capture_output=True, timeout=20)
        return "ok" if result.returncode == 0 else "failed"
    except (OSError, subprocess.SubprocessError):
        return "failed"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# SFTP config + owner approval (env / state only; never written to outputs)
# ---------------------------------------------------------------------------


def read_sftp_config() -> Tuple[Optional[Dict[str, Any]], str]:
    host = os.environ.get("SENTINEL_SFTP_HOST", "").strip()
    user = os.environ.get("SENTINEL_SFTP_USER", "").strip()
    remote_root = os.environ.get("SENTINEL_SFTP_REMOTE_ROOT", "").strip()
    password = os.environ.get("SENTINEL_SFTP_PASSWORD", "")
    key_path = os.environ.get("SENTINEL_SFTP_KEY_PATH", "").strip()
    port_raw = os.environ.get("SENTINEL_SFTP_PORT", "").strip()
    try:
        port = int(port_raw) if port_raw else 22
    except ValueError:
        port = 22
    if not host or not user or not remote_root or not (password or key_path):
        return None, "sftp_config_missing"
    return {"host": host, "port": port, "user": user, "password": password, "key_path": key_path, "remote_root": remote_root}, "ok"


def read_owner_approval() -> Tuple[bool, str]:
    data, status = read_optional_json(OWNER_APPROVAL_JSON)
    if status != "ok" or not isinstance(data, dict):
        return False, "approval_missing"
    if not bool(data.get("approved", False)):
        return False, "approval_not_true"
    if str(data.get("scope", "")) != APPROVAL_SCOPE:
        return False, "approval_scope_mismatch"
    if str(data.get("target", "")) != ALLOWED_REMOTE_TARGET:
        return False, "approval_target_mismatch"
    return True, "approved"


# ---------------------------------------------------------------------------
# Breach detection + report
# ---------------------------------------------------------------------------


def compute_breach(results: Dict[str, Any], *, forced_flags: Optional[Dict[str, Any]] = None) -> Tuple[bool, List[str]]:
    flags = forced_flags or {}
    reasons: List[str] = []

    changed_paths = list(results.get("changed_remote_paths", []) or [])
    if flags.get("extra_changed_path"):
        changed_paths = changed_paths + [str(flags["extra_changed_path"])]
    for path in changed_paths:
        if path != ALLOWED_REMOTE_TARGET:
            reasons.append(f"change outside allowed target: {redact_text(path, max_len=200)}")
        low = str(path).lower()
        if ".htaccess" in low:
            reasons.append(".htaccess changed")
        if "wp-config.php" in low:
            reasons.append("wp-config.php changed")
        if ("/themes/" in low or "/plugins/" in low) and not low.endswith(ALLOWED_REMOTE_TARGET.lower()):
            reasons.append("theme/plugin file outside MU target changed")

    live_changed = int(results.get("changed_file_count", 0) or 0)
    if flags.get("changed_file_count") is not None:
        live_changed = int(flags["changed_file_count"])
    if live_changed > 1:
        reasons.append("more than 1 live file changed")

    if flags.get("cloudflare_nginx_systemd_crontab_action") or results.get("infra_action"):
        reasons.append("Cloudflare/Nginx/systemd/crontab action")
    if flags.get("database_write") or results.get("database_write"):
        reasons.append("database write")
    if flags.get("secret_like_output") or detect_secret_like(json.dumps(results.get("safe_echo", {}), ensure_ascii=False)):
        reasons.append("secret-like output")
    if flags.get("plugin_forbidden_token") or results.get("plugin_forbidden_token"):
        reasons.append("eval/base64/remote include in plugin")
    if results.get("healthcheck_failed") and results.get("rollback_failed"):
        reasons.append("healthcheck failed and rollback failed")
    if results.get("uploaded") and not results.get("owner_approved"):
        reasons.append("owner approval missing and upload happened")
    if flags.get("output_path_breach"):
        reasons.append("writing outside allowed roots")
    return bool(reasons), sorted(set(reasons))


def build_report(
    mode: str,
    results: Dict[str, Any],
    input_statuses: Dict[str, str],
    *,
    generated_at: Optional[str] = None,
    forced_flags: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    generated = generated_at or utc_now()
    breach, breach_reasons = compute_breach(results, forced_flags=forced_flags)

    uploaded = bool(results.get("uploaded", False)) and not breach
    live_apply = bool(results.get("live_apply", False)) and not breach
    apply_status = APPLY_APPLIED if (uploaded and results.get("healthcheck_status") == "ok") else APPLY_NOT_APPLIED
    changed_file_count = int(results.get("changed_file_count", 0) or 0)
    allowed_target_only = all(p == ALLOWED_REMOTE_TARGET for p in (results.get("changed_remote_paths") or []))

    base_status = results.get("status", STATUS_DRY_RUN_READY)
    dedup_status = STATUS_BREACH if breach else base_status

    recommended = results.get("recommended_owner_action") or "Dry-run/prepare only. No upload without owner approval."
    if breach:
        recommended = "Do not proceed. A safety breach was detected; resolve it before any apply."

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": generated,
        "dedup_status": dedup_status,
        "mode": mode,
        "target_file": ALLOWED_REMOTE_TARGET,
        "local_plugin_created": bool(results.get("local_plugin_created", False)),
        "uploaded": uploaded,
        "changed_file_count": changed_file_count,
        "changed_remote_paths": [redact_text(p, max_len=200) for p in (results.get("changed_remote_paths") or [])],
        "allowed_target_only": allowed_target_only,
        "healthcheck_status": results.get("healthcheck_status", "not_run"),
        "jsonld_script_count": results.get("jsonld_script_count"),
        "radio_station_detected": bool(results.get("radio_station_detected", False)),
        "music_group_detected": bool(results.get("music_group_detected", False)),
        "organization_duplicate_reduced_candidate": bool(results.get("organization_duplicate_reduced_candidate", False)),
        "website_duplicate_reduced_candidate": bool(results.get("website_duplicate_reduced_candidate", False)),
        "backup_created": bool(results.get("backup_created", False)),
        "backup_status": results.get("backup_status", "not_attempted"),
        "rollback_performed": bool(results.get("rollback_performed", False)),
        "rollback_status": results.get("rollback_status", "not_run"),
        "website_status_code": results.get("website_status_code"),
        "apply_status": apply_status,
        "live_apply": live_apply,
        "sftp_used": bool(results.get("sftp_used", False)),
        "sftp_config_present": bool(results.get("sftp_config_present", False)),
        "owner_approved": bool(results.get("owner_approved", False)),
        "apply_breach": breach,
        "apply_breach_reasons": breach_reasons,
        "recommended_owner_action": recommended,
        "plugin_basename": PLUGIN_BASENAME,
        "plugin_sha256": results.get("plugin_sha256"),
        "plugin_valid": bool(results.get("plugin_valid", False)),
        "php_syntax_check": results.get("php_syntax_check", "not_run"),
        "slim_graph_types": results.get("slim_graph_types", []),
        "removed_schema_types": list(REMOVED_SCHEMA_TYPES),
        "jsonld_source": results.get("jsonld_source", "unknown"),
        "read_only": mode in (MODE_DRY_RUN, MODE_PREPARE),
        "network_access": bool(results.get("network_access", False)),
        "api_access": False,
        "wordpress_login": False,
        "cloudflare_mutations": False,
        "nginx_mutations": False,
        "htaccess_mutations": False,
        "systemd_file_written": False,
        "crontab_file_written": False,
        "database_write": bool(results.get("database_write", False)),
        "secrets_output": False,
        "input_statuses": input_statuses,
        "safe_owner_next_actions": [
            recommended,
            "Default modes (dry-run/prepare-upload) never upload.",
            "Live apply touches only the single allowed MU-plugin path and requires owner approval.",
        ],
        "do_not_apply_conditions": [
            f"Only {ALLOWED_REMOTE_TARGET} may ever be written on the remote.",
            "Never change .htaccess, wp-config.php, themes, other plugins, Cloudflare, Nginx, systemd or crontab.",
            "Never perform database writes or external requests from the plugin.",
        ],
        "outputs": {
            "report_json": str(REPORT_JSON),
            "report_md": str(REPORT_MD),
            "owner_summary_md": str(OWNER_SUMMARY_MD),
            "export_plugin": str(EXPORT_PLUGIN),
            "export_manifest": str(EXPORT_MANIFEST),
            "export_checksums": str(EXPORT_CHECKSUMS),
            "snapshot_json": str(SNAPSHOT_JSON),
            "snapshot_md": str(SNAPSHOT_MD),
            "audit_jsonl": str(AUDIT_JSONL),
        },
    }


def render_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# Safe Schema De-Duplicate Patch (JSON-LD MU-Plugin)",
        "",
        "> No upload without owner approval. Schema duplicate reduction prepared safely.",
        "",
        f"- Generated (UTC): `{report.get('generated_at_utc')}`",
        f"- Dedup status: `{report.get('dedup_status')}`",
        f"- Mode: `{report.get('mode')}`",
        f"- Target file: `{report.get('target_file')}`",
        f"- Local plugin created: `{report.get('local_plugin_created')}`",
        f"- Uploaded: `{report.get('uploaded')}`",
        f"- Changed file count: `{report.get('changed_file_count')}`",
        f"- Allowed target only: `{report.get('allowed_target_only')}`",
        f"- Healthcheck status: `{report.get('healthcheck_status')}`",
        f"- JSON-LD script count: `{report.get('jsonld_script_count')}`",
        f"- RadioStation detected: `{report.get('radio_station_detected')}`",
        f"- MusicGroup detected: `{report.get('music_group_detected')}`",
        f"- Organization duplicate reduced (candidate): `{report.get('organization_duplicate_reduced_candidate')}`",
        f"- WebSite duplicate reduced (candidate): `{report.get('website_duplicate_reduced_candidate')}`",
        f"- Backup created: `{report.get('backup_created')}` (`{report.get('backup_status')}`)",
        f"- Rollback performed: `{report.get('rollback_performed')}` (`{report.get('rollback_status')}`)",
        f"- Website status code: `{report.get('website_status_code')}`",
        f"- Apply status: `{report.get('apply_status')}`",
        f"- Live apply: `{report.get('live_apply')}`",
        f"- SFTP used: `{report.get('sftp_used')}`  |  SFTP config present: `{report.get('sftp_config_present')}`",
        f"- Owner approved: `{report.get('owner_approved')}`",
        f"- Plugin valid: `{report.get('plugin_valid')}`  |  PHP syntax: `{report.get('php_syntax_check')}`",
        f"- Plugin sha256: `{report.get('plugin_sha256')}`",
        f"- Slim graph types: `{', '.join(report.get('slim_graph_types', []))}`",
        f"- Removed schema types: `{', '.join(report.get('removed_schema_types', []))}`",
        f"- Apply breach: `{report.get('apply_breach')}`",
        f"- Recommended owner action: {redact_text(report.get('recommended_owner_action'), max_len=900)}",
        "",
    ]
    if report.get("apply_breach_reasons"):
        lines.extend(["## Breach Reasons", ""])
        for reason in report.get("apply_breach_reasons", []):
            lines.append(f"- {redact_text(reason, max_len=400)}")
        lines.append("")
    lines.extend(["## Safe Owner Next Actions", ""])
    for item in report.get("safe_owner_next_actions", []):
        lines.append(f"- {redact_text(item, max_len=700)}")
    lines.extend(["", "## Do Not Apply Conditions", ""])
    for item in report.get("do_not_apply_conditions", []):
        lines.append(f"- {redact_text(item, max_len=700)}")
    lines.extend(
        [
            "",
            "## Owner Approval (manual, required for live apply)",
            "",
            "```text",
            f"# {OWNER_APPROVAL_JSON}",
            "{",
            '  "approved": true,',
            f'  "scope": "{APPROVAL_SCOPE}",',
            f'  "target": "{ALLOWED_REMOTE_TARGET}",',
            '  "owner_note": "Owner approves schema de-duplicate patch only. Keep RadioStation and MusicGroup. Remove duplicate Organization/WebSite from MU-plugin.",',
            '  "timestamp_utc": "<UTC>"',
            "}",
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def audit_record(report: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "timestamp_utc": report.get("generated_at_utc"),
        "schema_version": SCHEMA_VERSION,
        "dedup_status": report.get("dedup_status"),
        "mode": report.get("mode"),
        "uploaded": report.get("uploaded"),
        "changed_file_count": report.get("changed_file_count"),
        "allowed_target_only": report.get("allowed_target_only"),
        "healthcheck_status": report.get("healthcheck_status"),
        "radio_station_detected": report.get("radio_station_detected"),
        "music_group_detected": report.get("music_group_detected"),
        "rollback_status": report.get("rollback_status"),
        "apply_status": report.get("apply_status"),
        "live_apply": report.get("live_apply"),
        "sftp_used": report.get("sftp_used"),
        "apply_breach": report.get("apply_breach"),
        "plugin_sha256": report.get("plugin_sha256"),
        "network_access": report.get("network_access"),
    }


def write_outputs(report: Dict[str, Any]) -> None:
    markdown = render_markdown(report)
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, markdown)
    write_text_atomic(OWNER_SUMMARY_MD, markdown)
    write_json_atomic(SNAPSHOT_JSON, report)
    write_text_atomic(SNAPSHOT_MD, markdown)
    append_jsonl(AUDIT_JSONL, [audit_record(report)])


def gather_input_statuses() -> Dict[str, str]:
    statuses: Dict[str, str] = {}
    statuses["jsonld_schema_pack"] = "ok" if JSONLD_PACK_MD.exists() else "not_available"
    for label, path in (
        ("safe_sftp_seo_apply_lane", APPLY_LANE_JSON),
        ("safe_end_summary", SAFE_END_SUMMARY_JSON),
        ("sentinel_master_json", MASTER_JSON),
    ):
        _, status = read_optional_json(path)
        statuses[label] = status
    return statuses


def generate_export() -> Dict[str, Any]:
    graph, source = load_slim_graph()
    jsonld_document = build_jsonld_document(graph)
    php = generate_plugin_php(jsonld_document)
    plugin_valid, plugin_reasons = validate_plugin(php)
    EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    write_text_atomic(EXPORT_PLUGIN, php)
    sha = sha256_file(EXPORT_PLUGIN)
    syntax = php_syntax_check(EXPORT_PLUGIN)
    graph_types = [str(item.get("@type")) for item in graph if isinstance(item, dict)]
    organization_reduced = "Organization" not in php
    website_reduced = "WebSite" not in php
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "patch": "schema_deduplicate",
        "plugin_basename": PLUGIN_BASENAME,
        "plugin_sha256": sha,
        "plugin_bytes": EXPORT_PLUGIN.stat().st_size,
        "allowed_remote_target": ALLOWED_REMOTE_TARGET,
        "jsonld_source": source,
        "slim_graph_types": graph_types,
        "removed_schema_types": list(REMOVED_SCHEMA_TYPES),
        "organization_duplicate_reduced_candidate": organization_reduced,
        "website_duplicate_reduced_candidate": website_reduced,
        "plugin_valid": plugin_valid,
        "plugin_validation_reasons": plugin_reasons,
        "php_syntax_check": syntax,
        "upload_strategy": {
            "upload_as": ALLOWED_REMOTE_TARGET + ".tmp-<timestamp>",
            "atomic_rename_to": ALLOWED_REMOTE_TARGET,
            "never_touch_other_files": True,
        },
        "backup_plan": {
            "if_exists_backup_to": ALLOWED_REMOTE_TARGET + ".bak-<timestamp>",
            "if_absent_status": "no_existing_file",
        },
        "rollback_plan": {"restore_backup_or_remove_new_file": True, "scope": ALLOWED_REMOTE_TARGET},
        "healthcheck": {
            "url": WEBSITE_URL,
            "method": "GET",
            "expect_status": "200_or_3xx",
            "expect_markers": [HEALTHCHECK_MARKER_JSONLD, "RadioStation", "MusicGroup", HEALTHCHECK_MARKER_BRAND],
        },
    }
    write_json_atomic(EXPORT_MANIFEST, manifest)
    write_text_atomic(EXPORT_CHECKSUMS, f"{sha}  {PLUGIN_BASENAME}\n")
    return {
        "local_plugin_created": True,
        "plugin_sha256": sha,
        "plugin_valid": plugin_valid,
        "plugin_forbidden_token": not plugin_valid and any("forbidden" in r for r in plugin_reasons),
        "php_syntax_check": syntax,
        "slim_graph_types": graph_types,
        "jsonld_source": source,
        "organization_duplicate_reduced_candidate": organization_reduced,
        "website_duplicate_reduced_candidate": website_reduced,
        # Local plugin content (live values are re-confirmed by the apply healthcheck).
        "radio_station_detected": "RadioStation" in graph_types,
        "music_group_detected": "MusicGroup" in graph_types,
    }


# ---------------------------------------------------------------------------
# SFTP + healthcheck (real apply path; guarded, never run in dry-run/prepare/self-test)
# ---------------------------------------------------------------------------


def _open_sftp(config: Dict[str, Any]):
    import paramiko

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.load_system_host_keys()
    except Exception:
        pass
    connect_kwargs: Dict[str, Any] = {
        "hostname": config["host"],
        "port": int(config["port"]),
        "username": config["user"],
        "timeout": 30,
        "allow_agent": False,
        "look_for_keys": False,
    }
    if config.get("key_path"):
        connect_kwargs["key_filename"] = config["key_path"]
    else:
        connect_kwargs["password"] = config["password"]
    client.connect(**connect_kwargs)
    return client, client.open_sftp()


def http_healthcheck() -> Dict[str, Any]:
    import urllib.request

    result = {
        "status_code": None,
        "jsonld_script_count": 0,
        "jsonld_detected": False,
        "radio_station_detected": False,
        "music_group_detected": False,
        "brand_or_plugin_detected": False,
        "ok": False,
        "error": None,
    }
    try:
        req = urllib.request.Request(WEBSITE_URL, method="GET", headers={"User-Agent": "SentinelSchemaDedupHealthcheck/1.0"})
        with urllib.request.urlopen(req, timeout=30) as response:  # noqa: S310 (own site, GET only)
            result["status_code"] = response.status
            body = response.read(600000).decode("utf-8", errors="replace")
            result["jsonld_script_count"] = body.count(HEALTHCHECK_MARKER_JSONLD)
            result["jsonld_detected"] = HEALTHCHECK_MARKER_JSONLD in body
            result["radio_station_detected"] = "RadioStation" in body
            result["music_group_detected"] = "MusicGroup" in body
            result["brand_or_plugin_detected"] = (HEALTHCHECK_MARKER_PLUGIN in body) or (HEALTHCHECK_MARKER_BRAND in body)
            status_ok = response.status == 200 or 300 <= response.status < 400
            result["ok"] = (
                status_ok
                and result["jsonld_detected"]
                and result["radio_station_detected"]
                and result["music_group_detected"]
                and result["brand_or_plugin_detected"]
            )
    except Exception as exc:  # noqa: BLE001
        result["error"] = redact_text(str(exc), max_len=200)
    return result


# ---------------------------------------------------------------------------
# Mode runners
# ---------------------------------------------------------------------------


def run_dry_run() -> Dict[str, Any]:
    export = generate_export()
    results = {
        "status": STATUS_DRY_RUN_READY,
        "uploaded": False,
        "live_apply": False,
        "sftp_used": False,
        "sftp_config_present": read_sftp_config()[1] == "ok",
        "owner_approved": False,
        "changed_file_count": 0,
        "changed_remote_paths": [],
        "healthcheck_status": "not_run",
        "rollback_status": "not_run",
        "network_access": False,
        "recommended_owner_action": "Dry-run ready. Slim RadioStation+MusicGroup plugin generated. No upload performed.",
        **export,
    }
    return build_report(MODE_DRY_RUN, results, gather_input_statuses())


def run_prepare_upload() -> Dict[str, Any]:
    export = generate_export()
    sftp_config, sftp_status = read_sftp_config()
    results = {
        "status": STATUS_PREPARED_FOR_UPLOAD,
        "uploaded": False,
        "live_apply": False,
        "sftp_used": False,
        "sftp_config_present": sftp_status == "ok",
        "owner_approved": read_owner_approval()[0],
        "changed_file_count": 0,
        "changed_remote_paths": [],
        "backup_status": "planned_only",
        "healthcheck_status": "not_run",
        "rollback_status": "not_run",
        "network_access": False,
        "recommended_owner_action": "Upload package prepared with backup/rollback plan. Provide owner approval file and SFTP env to apply.",
        **export,
    }
    return build_report(MODE_PREPARE, results, gather_input_statuses())


def run_apply_with_owner_approval() -> Dict[str, Any]:
    export = generate_export()
    base = {
        "uploaded": False,
        "live_apply": False,
        "sftp_used": False,
        "changed_file_count": 0,
        "changed_remote_paths": [],
        "backup_status": "not_attempted",
        "healthcheck_status": "not_run",
        "rollback_status": "not_run",
        "network_access": False,
        **export,
    }
    approved, approval_status = read_owner_approval()
    base["owner_approved"] = approved
    if not approved:
        base["status"] = STATUS_BLOCKED_NEEDS_OWNER_APPROVAL
        base["sftp_config_present"] = read_sftp_config()[1] == "ok"
        base["recommended_owner_action"] = (
            f"Live apply blocked: owner approval file missing/invalid ({approval_status}). No upload performed."
        )
        return build_report(MODE_APPLY, base, gather_input_statuses())

    sftp_config, sftp_status = read_sftp_config()
    base["sftp_config_present"] = sftp_status == "ok"
    if sftp_status != "ok":
        base["status"] = STATUS_BLOCKED_SFTP_CONFIG_MISSING
        base["recommended_owner_action"] = "Live apply blocked: SFTP configuration missing in environment. No upload performed."
        return build_report(MODE_APPLY, base, gather_input_statuses())

    if not base.get("plugin_valid", False):
        base["plugin_forbidden_token"] = True
        base["status"] = STATUS_BREACH
        base["recommended_owner_action"] = "Live apply blocked: generated plugin failed validation. No upload performed."
        return build_report(MODE_APPLY, base, gather_input_statuses())

    try:
        import paramiko  # noqa: F401
    except Exception:
        base["status"] = STATUS_BLOCKED_SFTP_CONFIG_MISSING
        base["recommended_owner_action"] = "Live apply blocked: SFTP library (paramiko) unavailable. No upload performed."
        return build_report(MODE_APPLY, base, gather_input_statuses())

    base.update(_perform_upload(sftp_config))
    return build_report(MODE_APPLY, base, gather_input_statuses())


def _perform_upload(config: Dict[str, Any]) -> Dict[str, Any]:
    import posixpath

    out: Dict[str, Any] = {
        "uploaded": False,
        "live_apply": True,
        "sftp_used": True,
        "network_access": True,
        "changed_file_count": 0,
        "changed_remote_paths": [],
        "backup_created": False,
        "backup_status": "not_attempted",
        "healthcheck_status": "not_run",
        "rollback_status": "not_run",
        "rollback_performed": False,
    }
    tag = timestamp_tag()
    remote_root = str(config["remote_root"]).rstrip("/")
    remote_target = posixpath.join(remote_root, ALLOWED_REMOTE_TARGET)
    remote_tmp = f"{remote_target}.tmp-{tag}"
    remote_bak = f"{remote_target}.bak-{tag}"
    client = None
    try:
        client, sftp = _open_sftp(config)
        existed = True
        try:
            sftp.stat(remote_target)
        except IOError:
            existed = False
        if existed:
            sftp.rename(remote_target, remote_bak)
            out["backup_created"] = True
            out["backup_status"] = f"backup_created:{ALLOWED_REMOTE_TARGET}.bak-{tag}"
        else:
            out["backup_status"] = "no_existing_file"
        sftp.put(str(EXPORT_PLUGIN), remote_tmp)
        sftp.rename(remote_tmp, remote_target)
        out["uploaded"] = True
        out["changed_file_count"] = 1
        out["changed_remote_paths"] = [ALLOWED_REMOTE_TARGET]

        health = http_healthcheck()
        out["website_status_code"] = health.get("status_code")
        out["jsonld_script_count"] = health.get("jsonld_script_count")
        out["radio_station_detected"] = bool(health.get("radio_station_detected"))
        out["music_group_detected"] = bool(health.get("music_group_detected"))
        if health.get("ok"):
            out["healthcheck_status"] = "ok"
            out["status"] = STATUS_UPLOADED_HEALTHCHECK_OK
            out["recommended_owner_action"] = "Upload + healthcheck OK. Slim RadioStation+MusicGroup plugin live; duplicates reduced."
        else:
            out["healthcheck_status"] = "failed"
            out["healthcheck_failed"] = True
            try:
                if out["backup_created"]:
                    try:
                        sftp.remove(remote_target)
                    except IOError:
                        pass
                    sftp.rename(remote_bak, remote_target)
                else:
                    sftp.remove(remote_target)
                out["rollback_performed"] = True
                out["rollback_status"] = "rollback_ok"
                out["status"] = STATUS_ROLLED_BACK_HEALTHCHECK_FAILED
                out["uploaded"] = False
                out["live_apply"] = False
                out["changed_file_count"] = 0
                out["changed_remote_paths"] = []
                out["recommended_owner_action"] = "Healthcheck failed; rolled back to prior state. Review before retrying."
            except Exception as exc:  # noqa: BLE001
                out["rollback_failed"] = True
                out["rollback_status"] = f"rollback_failed:{redact_text(str(exc), max_len=120)}"
                out["status"] = STATUS_ROLLED_BACK_HEALTHCHECK_FAILED
                out["recommended_owner_action"] = "Healthcheck AND rollback failed. Manual SFTP intervention required."
    except Exception as exc:  # noqa: BLE001
        out.setdefault("status", STATUS_BLOCKED_SFTP_CONFIG_MISSING)
        out["sftp_error"] = redact_text(str(exc), max_len=200)
        out["recommended_owner_action"] = "SFTP upload could not complete. No confirmed change. Review SFTP access."
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
    return out


def run_rollback() -> Dict[str, Any]:
    export = generate_export()
    base = {
        "uploaded": False,
        "live_apply": False,
        "sftp_used": False,
        "changed_file_count": 0,
        "changed_remote_paths": [],
        "backup_status": "not_attempted",
        "healthcheck_status": "not_run",
        "rollback_status": "not_run",
        "owner_approved": read_owner_approval()[0],
        **export,
    }
    sftp_config, sftp_status = read_sftp_config()
    base["sftp_config_present"] = sftp_status == "ok"
    if sftp_status != "ok":
        base["status"] = STATUS_BLOCKED_SFTP_CONFIG_MISSING
        base["recommended_owner_action"] = "Rollback blocked: SFTP configuration missing in environment."
        return build_report(MODE_ROLLBACK, base, gather_input_statuses())
    try:
        import paramiko  # noqa: F401
    except Exception:
        base["status"] = STATUS_BLOCKED_SFTP_CONFIG_MISSING
        base["recommended_owner_action"] = "Rollback blocked: SFTP library (paramiko) unavailable."
        return build_report(MODE_ROLLBACK, base, gather_input_statuses())
    base.update(_perform_rollback(sftp_config))
    return build_report(MODE_ROLLBACK, base, gather_input_statuses())


def _perform_rollback(config: Dict[str, Any]) -> Dict[str, Any]:
    import posixpath

    out: Dict[str, Any] = {
        "sftp_used": True,
        "network_access": True,
        "changed_file_count": 0,
        "changed_remote_paths": [],
        "rollback_performed": False,
        "rollback_status": "not_run",
    }
    remote_root = str(config["remote_root"]).rstrip("/")
    remote_target = posixpath.join(remote_root, ALLOWED_REMOTE_TARGET)
    remote_dir = posixpath.dirname(remote_target)
    base_name = posixpath.basename(remote_target)
    client = None
    try:
        client, sftp = _open_sftp(config)
        backups = sorted(name for name in sftp.listdir(remote_dir) if name.startswith(base_name + ".bak-"))
        if backups:
            latest = posixpath.join(remote_dir, backups[-1])
            try:
                sftp.remove(remote_target)
            except IOError:
                pass
            sftp.rename(latest, remote_target)
            out["rollback_status"] = "restored_from_backup"
        else:
            try:
                sftp.remove(remote_target)
                out["rollback_status"] = "removed_injected_file"
            except IOError:
                out["rollback_status"] = "nothing_to_rollback"
        out["rollback_performed"] = True
        out["changed_file_count"] = 1
        out["changed_remote_paths"] = [ALLOWED_REMOTE_TARGET]
        out["status"] = STATUS_ROLLBACK_OK
        out["recommended_owner_action"] = "Rollback completed for the single allowed MU-plugin file only."
    except Exception as exc:  # noqa: BLE001
        out["status"] = STATUS_BLOCKED_SFTP_CONFIG_MISSING
        out["rollback_status"] = f"rollback_error:{redact_text(str(exc), max_len=120)}"
        out["recommended_owner_action"] = "Rollback could not complete. Review SFTP access; no other file touched."
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
    return out


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------


def run_self_test() -> int:
    graph, source = load_slim_graph()
    types = sorted(str(n.get("@type")) for n in graph)
    if types != sorted(SLIM_ALLOWED_TYPES):
        raise AssertionError(f"slim graph must be exactly RadioStation+MusicGroup, got {types}")

    document = build_jsonld_document(graph)
    php = generate_plugin_php(document)

    ok, reasons = validate_plugin(php)
    if not ok:
        raise AssertionError(f"slim plugin failed validation: {reasons}")
    if f'"@type": "RadioStation"' not in php or f'"@type": "MusicGroup"' not in php:
        raise AssertionError("plugin missing required slim types")
    for removed in REMOVED_SCHEMA_TYPES:
        if removed in php:
            raise AssertionError(f"removed schema type still present in plugin: {removed}")
    if "Organization" in php or "WebSite" in php or "BreadcrumbList" in php or "FAQPage" in php or "CreativeWork" in php:
        raise AssertionError("plugin must not contain any removed schema type")
    if FORBIDDEN_PLUGIN_RE.search(php):
        raise AssertionError("plugin contains forbidden token")

    # Malicious plugins must fail validation.
    for bad in ("<?php eval($x); add_action('wp_head','f');", "<?php $y=base64_decode('aa'); add_action('wp_head','f');"):
        if validate_plugin(bad)[0]:
            raise AssertionError("malicious plugin passed validation")

    base_results = {
        "status": STATUS_DRY_RUN_READY,
        "uploaded": False,
        "live_apply": False,
        "changed_file_count": 0,
        "changed_remote_paths": [],
        "plugin_valid": True,
        "plugin_sha256": "deadbeef",
        "radio_station_detected": True,
        "music_group_detected": True,
    }

    dry = build_report(MODE_DRY_RUN, dict(base_results), {})
    if dry["uploaded"] or dry["live_apply"] or dry["apply_status"] != APPLY_NOT_APPLIED or dry["apply_breach"]:
        raise AssertionError("dry-run invariants failed")

    # Wrong target path -> breach.
    if not build_report(MODE_APPLY, dict(base_results, uploaded=True, owner_approved=True, changed_file_count=1, changed_remote_paths=["wp-content/themes/x/functions.php"]), {})["apply_breach"]:
        raise AssertionError("wrong target path did not breach")
    # More than one file -> breach.
    if not build_report(MODE_APPLY, dict(base_results, uploaded=True, owner_approved=True, changed_file_count=2, changed_remote_paths=[ALLOWED_REMOTE_TARGET]), {})["apply_breach"]:
        raise AssertionError("multi-file did not breach")
    # .htaccess -> breach.
    if not build_report(MODE_APPLY, dict(base_results, uploaded=True, owner_approved=True, changed_file_count=1, changed_remote_paths=[".htaccess"]), {})["apply_breach"]:
        raise AssertionError(".htaccess did not breach")
    # Upload without approval -> breach.
    if not build_report(MODE_APPLY, dict(base_results, uploaded=True, owner_approved=False, changed_file_count=1, changed_remote_paths=[ALLOWED_REMOTE_TARGET]), {})["apply_breach"]:
        raise AssertionError("upload without approval did not breach")
    # Healthcheck+rollback failure -> breach.
    if not build_report(MODE_APPLY, dict(base_results, owner_approved=True, healthcheck_failed=True, rollback_failed=True), {})["apply_breach"]:
        raise AssertionError("healthcheck+rollback failure did not breach")
    # Secret-like / infra / db write -> breach.
    if not build_report(MODE_APPLY, dict(base_results, owner_approved=True), {}, forced_flags={"secret_like_output": True})["apply_breach"]:
        raise AssertionError("secret-like did not breach")
    if not build_report(MODE_APPLY, dict(base_results, owner_approved=True, infra_action=True), {})["apply_breach"]:
        raise AssertionError("infra action did not breach")
    if not build_report(MODE_APPLY, dict(base_results, owner_approved=True, database_write=True), {})["apply_breach"]:
        raise AssertionError("database write did not breach")

    # Healthy single-file apply -> no breach, applied.
    good = build_report(MODE_APPLY, dict(base_results, uploaded=True, live_apply=True, owner_approved=True, changed_file_count=1, changed_remote_paths=[ALLOWED_REMOTE_TARGET], healthcheck_status="ok"), {})
    if good["apply_breach"] or not good["uploaded"] or good["apply_status"] != APPLY_APPLIED or not good["allowed_target_only"]:
        raise AssertionError("healthy apply invariants failed")

    # Missing approval/SFTP must not crash and must not upload.
    approved, _ = read_owner_approval()
    if approved:
        raise AssertionError("self-test environment unexpectedly has owner approval")
    _, sftp_status = read_sftp_config()
    if sftp_status not in ("ok", "sftp_config_missing"):
        raise AssertionError("unexpected sftp status")

    # Write-path guards.
    for forbidden in (
        PROJECT_DIR / "exports/sftp-seo-apply/evil.php",
        PROJECT_DIR / "reports/latest/x.sh",
        PROJECT_DIR / "drafts/owner/x.service",
        PROJECT_DIR / "config/x.json",
    ):
        try:
            assert_allowed_write(forbidden)
        except ValueError:
            pass
        else:
            raise AssertionError(f"forbidden path not rejected: {forbidden}")
    assert_allowed_write(EXPORT_PLUGIN)
    if not detect_secret_like("password=supersecretvalue"):
        raise AssertionError("secret detector failed")
    print("schema-deduplicate-patch self-tests: OK")
    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Safe Schema De-Duplicate Patch for the JSON-LD MU-plugin; dry-run/prepare default, gated live apply.")
    parser.add_argument("--self-test", action="store_true", help="Run in-memory safety tests and exit.")
    parser.add_argument("mode", nargs="?", default=MODE_DRY_RUN, choices=[MODE_DRY_RUN, MODE_PREPARE, MODE_APPLY, MODE_ROLLBACK], help="Patch mode (default: dry-run).")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()
    runners = {
        MODE_DRY_RUN: run_dry_run,
        MODE_PREPARE: run_prepare_upload,
        MODE_APPLY: run_apply_with_owner_approval,
        MODE_ROLLBACK: run_rollback,
    }
    report = runners[args.mode]()
    write_outputs(report)
    print(
        "Safe Schema De-Duplicate Patch: "
        f"status={report.get('dedup_status')}, "
        f"mode={report.get('mode')}, "
        f"uploaded={report.get('uploaded')}, "
        f"radio={report.get('radio_station_detected')}, "
        f"music={report.get('music_group_detected')}, "
        f"changed_files={report.get('changed_file_count')}, "
        f"breach={report.get('apply_breach')}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
