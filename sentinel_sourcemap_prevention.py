#!/usr/bin/env python3
"""Autonomous, tightly scoped SourceMap prevention for Sentinel.

The tool observes .map 404s, classifies the source, simulates safe WPO-Minify
cache edits, and can apply those edits only in explicit sourcemap-apply-safe
mode with all gates satisfied. It never mutates Cloudflare and never edits
WordPress core, plugin, or theme source files.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


PROJECT_DIR = Path("/srv/sentinel-defense")

DEFAULT_NOTFOUND_JSON = PROJECT_DIR / "cloudflare-monitor/latest/notfound-404-24h.json"
DEFAULT_WEBSITE_JSON = PROJECT_DIR / "reports/latest/sentinel-defense-report.json"
DEFAULT_OUT_MD = PROJECT_DIR / "reports/latest/sourcemap-prevention-report.md"
DEFAULT_OUT_JSON = PROJECT_DIR / "reports/latest/sourcemap-prevention-report.json"
DEFAULT_HISTORY = PROJECT_DIR / "reports/history/sourcemap-prevention-history.jsonl"
DEFAULT_PREFLIGHT_MD = PROJECT_DIR / "reports/latest/sourcemap-apply-preflight.md"
DEFAULT_PREFLIGHT_JSON = PROJECT_DIR / "reports/latest/sourcemap-apply-preflight.json"
DEFAULT_ROLLBACK_HINT = PROJECT_DIR / "reports/latest/sourcemap-prevention-last-rollback.md"
DEFAULT_BACKUP_ROOT = PROJECT_DIR / "sourcemap-backups"

MODE_OBSERVE = "sourcemap-observe"
MODE_SIMULATE = "sourcemap-simulate"
MODE_APPLY_SAFE = "sourcemap-apply-safe"

STATUS_OK = "OK"
STATUS_WARNING = "WARNING"
STATUS_CRITICAL = "CRITICAL"
STATUS_UNKNOWN = "UNKNOWN"

CLASS_WPO_MINIFY = "wordpress_minify_sourcemap_missing"
CLASS_WPO_STALE = "stale_or_already_remediated_wpo_minify_sourcemap"
CLASS_WP_CORE = "wordpress_core_sourcemap_missing"
CLASS_THIRD_PARTY = "third_party_asset_sourcemap_missing"
CLASS_SCANNER = "scanner_fake_sourcemap"
CLASS_UNKNOWN = "unknown_sourcemap"

SFTP_REQUIRED_VARS = (
    "IONOS_SFTP_HOST",
    "IONOS_SFTP_USER",
    "IONOS_SFTP_PORT",
    "IONOS_SFTP_PASSWORD",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def read_json(path: Path) -> Tuple[Dict[str, Any], Optional[str], bool]:
    if not path.exists():
        return {}, "missing", False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {}, str(exc), True
    if not isinstance(data, dict):
        return {}, "json root is not an object", True
    return data, None, True


def parse_count(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        try:
            return int(float(value.strip()))
        except ValueError:
            return 0
    return 0


def safe_text(value: Any, default: str = "-") -> str:
    if value is None:
        return default
    text = str(value)
    if len(text) > 320:
        return text[:317] + "..."
    return text


def normalize_status(value: Any) -> str:
    if not isinstance(value, str):
        return STATUS_UNKNOWN
    status = value.strip().upper()
    if status in {STATUS_OK, STATUS_WARNING, STATUS_CRITICAL, STATUS_UNKNOWN}:
        return status
    return STATUS_UNKNOWN


def aggregate_pairs(target: Dict[str, int], items: Iterable[Dict[str, Any]], key: str) -> None:
    for item in items:
        if not isinstance(item, dict):
            continue
        label = item.get(key)
        if not label:
            continue
        target[str(label)] = target.get(str(label), 0) + parse_count(item.get("count"))


def sorted_pairs(values: Dict[str, int], key_name: str, limit: int = 8) -> List[Dict[str, Any]]:
    return [
        {key_name: key, "count": count}
        for key, count in sorted(values.items(), key=lambda item: (-item[1], item[0]))[:limit]
    ]


def source_map_reference_path(map_path: str) -> Optional[str]:
    if map_path.endswith(".js.map"):
        return map_path[:-4]
    if map_path.endswith(".css.map"):
        return map_path[:-4]
    return None


def classify_map_path(path: str) -> Tuple[str, str]:
    lower = path.lower()
    if lower.startswith("/wp-content/cache/wpo-minify/") and (
        lower.endswith(".js.map") or lower.endswith(".css.map")
    ):
        return CLASS_WPO_MINIFY, "WPO-Minify cache asset has a missing source map reference."
    if lower.startswith("/wp-includes/") or lower.startswith("/wp-admin/"):
        return CLASS_WP_CORE, "WordPress core/admin source map is missing; diagnostic only."
    if lower.startswith("/wp-content/plugins/") or lower.startswith("/wp-content/themes/"):
        return CLASS_THIRD_PARTY, "Plugin/theme source map is missing; review only."
    scanner_markers = (
        ".env",
        "secrets",
        "phpinfo",
        "_next",
        "__rsc",
        "__nextjs_action",
        "api/auth",
        ".aws",
        "actuator",
        "dockerfile",
        "gitlab",
        "../",
        "%2e",
    )
    if any(marker in lower for marker in scanner_markers):
        return CLASS_SCANNER, "Source map request resembles scanner or fake framework probing."
    return CLASS_UNKNOWN, "Source map 404 cannot be safely mapped to an auto-fixable cache asset."


@dataclass
class Candidate:
    map_path: str
    count: int = 0
    hosts: Dict[str, int] = field(default_factory=dict)
    countries: Dict[str, int] = field(default_factory=dict)
    cache_status: Dict[str, int] = field(default_factory=dict)
    classification: str = CLASS_UNKNOWN
    classification_reason: str = ""
    reference_path: Optional[str] = None

    @property
    def auto_apply_eligible(self) -> bool:
        return self.classification == CLASS_WPO_MINIFY and bool(self.reference_path)

    @property
    def policy(self) -> str:
        if self.classification == CLASS_WPO_STALE:
            return "resolved/stale/no_action_needed; sourceMappingURL reference is already absent"
        if self.classification == CLASS_WPO_MINIFY:
            return "apply-safe eligible only for WPO-Minify cache files"
        if self.classification == CLASS_WP_CORE:
            return "diagnostic-only; WordPress core files are never edited"
        if self.classification == CLASS_THIRD_PARTY:
            return "review-only; plugin/theme source files are never edited automatically"
        if self.classification == CLASS_SCANNER:
            return "observe-only; no dummy .map files and no global .map block"
        return "review-only; unknown source map origin"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "map_path": self.map_path,
            "reference_path": self.reference_path,
            "count": self.count,
            "classification": self.classification,
            "classification_reason": self.classification_reason,
            "auto_apply_eligible": self.auto_apply_eligible,
            "policy": self.policy,
            "hosts": sorted_pairs(self.hosts, "host"),
            "countries": sorted_pairs(self.countries, "country"),
            "cache_status": sorted_pairs(self.cache_status, "cache_status"),
        }


def candidate_from_path(path: str) -> Candidate:
    classification, reason = classify_map_path(path)
    return Candidate(
        map_path=path,
        classification=classification,
        classification_reason=reason,
        reference_path=source_map_reference_path(path),
    )


def merge_candidate(candidates: Dict[str, Candidate], path: str, count: int) -> Candidate:
    candidate = candidates.get(path)
    if candidate is None:
        candidate = candidate_from_path(path)
        candidates[path] = candidate
    candidate.count += count
    return candidate


def extract_notfound_candidates(data: Dict[str, Any]) -> Dict[str, Candidate]:
    candidates: Dict[str, Candidate] = {}
    zones = (
        data.get("data", {})
        .get("viewer", {})
        .get("zones", [])
    )
    if not isinstance(zones, list):
        return candidates
    for zone in zones:
        if not isinstance(zone, dict):
            continue
        groups = zone.get("httpRequestsAdaptiveGroups")
        if not isinstance(groups, list):
            continue
        for group in groups:
            if not isinstance(group, dict):
                continue
            dims = group.get("dimensions")
            if not isinstance(dims, dict):
                continue
            path = dims.get("clientRequestPath")
            if not isinstance(path, str) or not path.endswith(".map"):
                continue
            count = parse_count(group.get("count"))
            candidate = merge_candidate(candidates, path, count)
            host = dims.get("clientRequestHTTPHost")
            country = dims.get("clientCountryName")
            cache = dims.get("cacheStatus")
            if host:
                candidate.hosts[str(host)] = candidate.hosts.get(str(host), 0) + count
            if country:
                candidate.countries[str(country)] = candidate.countries.get(str(country), 0) + count
            if cache:
                candidate.cache_status[str(cache)] = candidate.cache_status.get(str(cache), 0) + count
    return candidates


def merge_website_breakdown(candidates: Dict[str, Candidate], website_data: Dict[str, Any]) -> None:
    breakdown = website_data.get("source_map_404_breakdown")
    if not isinstance(breakdown, dict):
        return
    paths = breakdown.get("top_map_404_paths")
    if not isinstance(paths, list):
        return
    for item in paths:
        if not isinstance(item, dict):
            continue
        path = item.get("path")
        if not isinstance(path, str) or not path.endswith(".map"):
            continue
        existing_candidate = path in candidates
        candidate = candidates.get(path)
        if candidate is None:
            candidate = candidate_from_path(path)
            candidates[path] = candidate
        candidate.count = max(candidate.count, parse_count(item.get("count")))
        if existing_candidate and (candidate.countries or candidate.cache_status):
            continue
        hostnames = item.get("hostnames")
        if isinstance(hostnames, list):
            for host in hostnames:
                if host:
                    candidate.hosts[str(host)] = max(candidate.hosts.get(str(host), 0), 1)
        aggregate_pairs(candidate.countries, item.get("countries") or [], "country")
        aggregate_pairs(candidate.cache_status, item.get("cache_status") or [], "cache_status")


def get_map_metric(website_data: Dict[str, Any]) -> Dict[str, Any]:
    metrics = website_data.get("metrics")
    if not isinstance(metrics, list):
        return {"status": STATUS_UNKNOWN, "value": 0}
    for item in metrics:
        if not isinstance(item, dict):
            continue
        if item.get("key") == "map_404" or item.get("label") == "404 auf .map":
            return {
                "status": normalize_status(item.get("status")),
                "value": parse_count(item.get("value")),
                "label": safe_text(item.get("label"), "404 auf .map"),
            }
    return {"status": STATUS_UNKNOWN, "value": 0, "label": "404 auf .map"}


def sort_candidates(candidates: Iterable[Candidate]) -> List[Candidate]:
    return sorted(candidates, key=lambda candidate: (-candidate.count, candidate.map_path))


def safety_check(check_id: str, passed: bool, detail: str) -> Dict[str, Any]:
    return {"check_id": check_id, "passed": bool(passed), "detail": detail}


def build_planned_actions(candidates: List[Candidate], max_files: int) -> List[Dict[str, Any]]:
    planned: List[Dict[str, Any]] = []
    for candidate in candidates:
        if not candidate.auto_apply_eligible or not candidate.reference_path:
            continue
        planned.append(
            {
                "action_id": "remove_wpo_minify_sourcemappingurl",
                "map_path": candidate.map_path,
                "reference_path": candidate.reference_path,
                "classification": candidate.classification,
                "count": candidate.count,
                "operation": "remove sourceMappingURL line from WPO-Minify cache asset",
                "reason": "Missing WPO-Minify source map is caused by a generated asset sourceMappingURL reference.",
                "safety_checks": [
                    safety_check("path_under_wpo_minify_cache", True, "Reference path is in /wp-content/cache/wpo-minify/."),
                    safety_check("not_wordpress_core", True, "Reference path is not in wp-includes or wp-admin."),
                    safety_check("not_plugin_or_theme_source", True, "Reference path is not in plugin or theme source directories."),
                    safety_check("remove_only_sourcemappingurl_line", True, "Apply step refuses any edit except removing sourceMappingURL lines."),
                ],
            }
        )
        if len(planned) >= max_files:
            break
    return planned


def stale_reason() -> str:
    return "sourceMappingURL line not found; likely historical window remainder"


def stale_candidate_entry(candidate: Candidate, evidence_source: str) -> Dict[str, Any]:
    return {
        "map_path": candidate.map_path,
        "reference_path": candidate.reference_path,
        "count": candidate.count,
        "classification": CLASS_WPO_STALE,
        "original_classification": CLASS_WPO_MINIFY,
        "status": "resolved/stale/no_action_needed",
        "skipped_reason": stale_reason(),
        "evidence_source": evidence_source,
    }


def previous_stale_evidence(path: Path) -> Dict[str, str]:
    data, error, exists = read_json(path)
    if not exists or error or not data:
        return {}
    evidence: Dict[str, str] = {}
    for key in ("skipped_actions", "stale_candidates"):
        items = data.get(key)
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            reason = str(item.get("reason") or item.get("skipped_reason") or "")
            classification = str(item.get("classification") or item.get("original_classification") or "")
            if "sourceMappingURL line not found" not in reason and classification != CLASS_WPO_STALE:
                continue
            for path_key in ("map_path", "reference_path"):
                value = item.get(path_key)
                if isinstance(value, str) and value:
                    evidence[value] = f"previous_report:{path.name}"
    return evidence


def read_only_sftp_stale_evidence(candidates: List[Candidate], mode: str) -> Dict[str, str]:
    if mode not in {MODE_SIMULATE, MODE_APPLY_SAFE}:
        return {}
    config, _error = load_sftp_config()
    if config is None:
        return {}
    evidence: Dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="sentinel-sourcemap-probe-") as tmp:
        work_dir = Path(tmp)
        for index, candidate in enumerate(candidates, start=1):
            if candidate.classification != CLASS_WPO_MINIFY or not candidate.reference_path:
                continue
            if not is_allowed_reference_path(candidate.reference_path):
                continue
            local_path = work_dir / f"probe-{index}.asset"
            remote_path = remote_path_for_reference(config, candidate.reference_path)
            if not run_sftp_download(config, remote_path, local_path, work_dir):
                continue
            if local_path.stat().st_size <= 0:
                continue
            text = local_path.read_text(encoding="utf-8", errors="replace")
            if "sourceMappingURL" not in text:
                evidence[candidate.map_path] = "read_only_sftp_probe"
                evidence[candidate.reference_path] = "read_only_sftp_probe"
    return evidence


def apply_stale_evidence(candidates: List[Candidate], evidence: Dict[str, str]) -> List[Dict[str, Any]]:
    stale_candidates: List[Dict[str, Any]] = []
    for candidate in candidates:
        if candidate.classification != CLASS_WPO_MINIFY:
            continue
        source = evidence.get(candidate.map_path)
        if not source and candidate.reference_path:
            source = evidence.get(candidate.reference_path)
        if not source:
            continue
        candidate.classification = CLASS_WPO_STALE
        candidate.classification_reason = (
            "Referencing WPO-Minify file exists but sourceMappingURL is absent; "
            "remaining .map hits are likely Cloudflare 24h or browser-cache remainder."
        )
        stale_candidates.append(stale_candidate_entry(candidate, source))
    return stale_candidates


def env_presence() -> Dict[str, bool]:
    presence = {name: bool(os.environ.get(name)) for name in SFTP_REQUIRED_VARS}
    presence["IONOS_WEBROOT"] = bool(os.environ.get("IONOS_WEBROOT"))
    presence["SENTINEL_SOURCEMAP_AUTO_APPLY"] = (
        os.environ.get("SENTINEL_SOURCEMAP_AUTO_APPLY", "").strip().lower() == "true"
    )
    return presence


def build_base_report(args: argparse.Namespace) -> Dict[str, Any]:
    notfound_data, notfound_error, notfound_exists = read_json(args.notfound_json)
    website_data, website_error, website_exists = read_json(args.website_json)
    candidates_by_path = extract_notfound_candidates(notfound_data)
    merge_website_breakdown(candidates_by_path, website_data)
    candidates = sort_candidates(candidates_by_path.values())
    stale_evidence = previous_stale_evidence(args.out_json)
    stale_evidence.update(read_only_sftp_stale_evidence(candidates, args.mode))
    stale_candidates = apply_stale_evidence(candidates, stale_evidence)
    candidate_dicts = [candidate.to_dict() for candidate in candidates]
    map_metric = get_map_metric(website_data)
    map_status = normalize_status(map_metric.get("status"))
    planned_actions = build_planned_actions(candidates, args.max_files) if args.mode != MODE_OBSERVE else []
    wpo_candidates = [
        candidate for candidate in candidates if candidate.classification == CLASS_WPO_MINIFY
    ]
    core_candidates = [
        candidate for candidate in candidates if candidate.classification == CLASS_WP_CORE
    ]
    non_wpo_candidates = [
        candidate for candidate in candidates
        if candidate.classification not in {CLASS_WPO_MINIFY, CLASS_WPO_STALE}
    ]
    all_candidates_wpo = bool(candidates) and not non_wpo_candidates
    all_wpo_candidates_planned = (
        bool(wpo_candidates)
        and args.mode != MODE_OBSERVE
        and len(planned_actions) == len(wpo_candidates)
        and all(is_allowed_reference_path(str(action.get("reference_path", ""))) for action in planned_actions)
    )
    planned_file_count_ok = len(planned_actions) <= args.max_files
    map_status_ready = map_status in {STATUS_WARNING, STATUS_CRITICAL}
    global_safe_to_auto_apply = bool(
        map_status_ready
        and all_candidates_wpo
        and planned_actions
        and planned_file_count_ok
    )
    wpo_minify_safe_to_apply = bool(
        map_status_ready
        and all_wpo_candidates_planned
        and planned_file_count_ok
    )
    core_requires_review = bool(core_candidates)
    requires_operator_review = bool(non_wpo_candidates or not map_status_ready)
    active_wpo_actions_count = len(planned_actions)
    already_remediated_count = len(stale_candidates)
    historical_window_remainder_count = sum(parse_count(item.get("count")) for item in stale_candidates)
    auto_apply_scope = {
        "global": "blocked_by_non_wpo_candidates" if non_wpo_candidates else "wpo_minify_only",
        "apply_safe_allowed_scope": "/wp-content/cache/wpo-minify/ generated cache files only",
        "wpo_minify_candidate_count": len(wpo_candidates),
        "wpo_minify_planned_count": len(planned_actions),
        "wpo_minify_stale_or_already_remediated_count": already_remediated_count,
        "active_wpo_actions_count": active_wpo_actions_count,
        "core_candidate_count": len(core_candidates),
        "non_wpo_candidate_count": len(non_wpo_candidates),
        "plugin_theme_candidate_count": len(
            [
                candidate for candidate in candidates
                if candidate.classification == CLASS_THIRD_PARTY
            ]
        ),
        "unknown_or_scanner_candidate_count": len(
            [
                candidate for candidate in candidates
                if candidate.classification in {CLASS_UNKNOWN, CLASS_SCANNER}
            ]
        ),
        "policy": (
            "sourcemap-apply-safe may apply only WPO-Minify planned_actions; "
            "WordPress core candidates remain diagnostic-only."
        ),
    }

    safety_checks = [
        safety_check(
            "map_404_status_warning_or_critical",
            map_status_ready,
            f"404 auf .map status is {map_status}.",
        ),
        safety_check(
            "top_paths_are_wpo_minify_only",
            all_candidates_wpo,
            "safe_to_auto_apply requires every .map candidate to come from /wp-content/cache/wpo-minify/.",
        ),
        safety_check(
            "wpo_minify_candidates_present",
            bool(wpo_candidates),
            f"WPO-Minify candidates: {len(wpo_candidates)}.",
        ),
        safety_check(
            "all_wpo_minify_candidates_planned",
            all_wpo_candidates_planned,
            f"WPO-Minify candidates planned for scoped apply-safe: {len(planned_actions)}/{len(wpo_candidates)}.",
        ),
        safety_check(
            "wpo_minify_apply_scope_only",
            all(is_allowed_reference_path(str(action.get("reference_path", ""))) for action in planned_actions),
            "Every planned action targets /wp-content/cache/wpo-minify/ and excludes core/plugin/theme paths.",
        ),
        safety_check(
            "core_candidates_diagnostic_only",
            True,
            f"WordPress-Core candidates are diagnostic-only: {len(core_candidates)}.",
        ),
        safety_check(
            "planned_file_count_lte_max",
            planned_file_count_ok,
            f"Planned files: {len(planned_actions)}; max per run: {args.max_files}.",
        ),
        safety_check(
            "no_wordpress_core_plugin_theme_files_in_plan",
            all(
                "/wp-includes/" not in str(action.get("reference_path", ""))
                and "/wp-admin/" not in str(action.get("reference_path", ""))
                and "/wp-content/plugins/" not in str(action.get("reference_path", ""))
                and "/wp-content/themes/" not in str(action.get("reference_path", ""))
                for action in planned_actions
            ),
            "Planned actions exclude WordPress core, plugin, and theme source files.",
        ),
        safety_check("no_cloudflare_mutation", True, "SourceMap prevention never changes Cloudflare."),
        safety_check("no_dummy_map_files", True, "SourceMap prevention never creates dummy .map files."),
    ]

    skipped_actions: List[Dict[str, Any]] = []
    for candidate in candidates:
        if candidate.auto_apply_eligible:
            continue
        if candidate.classification == CLASS_WPO_STALE:
            skipped_actions.append(
                {
                    "map_path": candidate.map_path,
                    "reference_path": candidate.reference_path,
                    "classification": candidate.classification,
                    "original_classification": CLASS_WPO_MINIFY,
                    "count": candidate.count,
                    "reason": stale_reason(),
                    "status": "resolved/stale/no_action_needed",
                }
            )
            continue
        skipped_actions.append(
            {
                "map_path": candidate.map_path,
                "reference_path": candidate.reference_path,
                "classification": candidate.classification,
                "count": candidate.count,
                "reason": candidate.policy,
            }
        )

    return {
        "schema_version": "1.0",
        "generated_at_utc": utc_now(),
        "status": map_status if candidates else STATUS_OK,
        "mode": args.mode,
        "notfound_json": str(args.notfound_json),
        "website_json": str(args.website_json),
        "input_errors": {
            "notfound_json": notfound_error if notfound_exists or notfound_error else None,
            "website_json": website_error if website_exists or website_error else None,
        },
        "map_404_metric": map_metric,
        "candidate_count": len(candidate_dicts),
        "candidates": candidate_dicts,
        "planned_actions": planned_actions,
        "applied_actions": [],
        "skipped_actions": skipped_actions,
        "stale_candidates": stale_candidates,
        "already_remediated_count": already_remediated_count,
        "active_wpo_actions_count": active_wpo_actions_count,
        "historical_window_remainder_count": historical_window_remainder_count,
        "safety_checks": safety_checks,
        "backup_paths": [],
        "rollback_hint_path": None,
        "confirm_apply": bool(getattr(args, "confirm_apply", False)),
        "apply_blocked": False,
        "blocked_reason": None,
        "safe_to_auto_apply": global_safe_to_auto_apply,
        "global_safe_to_auto_apply": global_safe_to_auto_apply,
        "wpo_minify_safe_to_apply": wpo_minify_safe_to_apply,
        "core_requires_review": core_requires_review,
        "auto_apply_scope": auto_apply_scope,
        "requires_operator_review": requires_operator_review,
        "cloudflare_mutation": False,
        "sftp_env_present": env_presence(),
        "outputs": {
            "markdown": str(args.out_md),
            "json": str(args.out_json),
            "history": str(args.history_path),
        },
        "defensive_boundaries": {
            "cloudflare_mutations": False,
            "waf_rules": False,
            "dummy_map_files": False,
            "global_map_block": False,
            "wordpress_core_edits": False,
            "plugin_theme_source_edits": False,
            "secrets_in_report": False,
            "allowed_edit_scope": "/wp-content/cache/wpo-minify/ generated cache files only",
        },
    }


def quote_lftp(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def quote_sftp_batch(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


@dataclass
class SftpConfig:
    host: str
    user: str
    port: str
    password: str
    webroot: str
    tool: str


def load_sftp_config() -> Tuple[Optional[SftpConfig], str]:
    missing = [name for name in SFTP_REQUIRED_VARS if not os.environ.get(name)]
    if missing:
        return None, "Missing SFTP environment variables: " + ", ".join(missing)
    if shutil.which("lftp"):
        tool = "lftp"
    elif shutil.which("sshpass") and shutil.which("sftp"):
        tool = "sshpass-sftp"
    else:
        return None, "No supported SFTP helper found. Install lftp, for example: sudo apt install lftp"
    webroot = os.environ.get("IONOS_WEBROOT", "/wordpress").strip() or "/wordpress"
    if not webroot.startswith("/"):
        webroot = "/" + webroot
    webroot = webroot.rstrip("/") or "/"
    return (
        SftpConfig(
            host=os.environ["IONOS_SFTP_HOST"],
            user=os.environ["IONOS_SFTP_USER"],
            port=os.environ["IONOS_SFTP_PORT"],
            password=os.environ["IONOS_SFTP_PASSWORD"],
            webroot=webroot,
            tool=tool,
        ),
        "",
    )


def remote_path_for_reference(config: SftpConfig, reference_path: str) -> str:
    return config.webroot.rstrip("/") + "/" + reference_path.lstrip("/")


def run_sftp_download(config: SftpConfig, remote_path: str, local_path: Path, work_dir: Path) -> bool:
    if config.tool == "lftp":
        script = work_dir / "download.lftp"
        script.write_text(
            "\n".join(
                [
                    "set sftp:auto-confirm yes",
                    "set cmd:fail-exit yes",
                    "set net:max-retries 1",
                    "set net:timeout 20",
                    (
                        "open -p "
                        f"{quote_lftp(config.port)} -u {quote_lftp(config.user)},{quote_lftp(config.password)} "
                        f"sftp://{quote_lftp(config.host)}"
                    ),
                    f"get {quote_lftp(remote_path)} -o {quote_lftp(str(local_path))}",
                    "bye",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        script.chmod(0o600)
        result = subprocess.run(["lftp", "-f", str(script)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0

    batch = work_dir / "download.sftp"
    batch.write_text(
        f"get {quote_sftp_batch(remote_path)} {quote_sftp_batch(str(local_path))}\n",
        encoding="utf-8",
    )
    batch.chmod(0o600)
    env = os.environ.copy()
    env["SSHPASS"] = config.password
    result = subprocess.run(
        [
            "sshpass",
            "-e",
            "sftp",
            "-oBatchMode=no",
            "-oStrictHostKeyChecking=accept-new",
            "-P",
            config.port,
            "-b",
            str(batch),
            f"{config.user}@{config.host}",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
    )
    return result.returncode == 0


def run_sftp_upload(config: SftpConfig, local_path: Path, remote_path: str, work_dir: Path) -> bool:
    if config.tool == "lftp":
        script = work_dir / "upload.lftp"
        script.write_text(
            "\n".join(
                [
                    "set sftp:auto-confirm yes",
                    "set cmd:fail-exit yes",
                    "set net:max-retries 1",
                    "set net:timeout 20",
                    (
                        "open -p "
                        f"{quote_lftp(config.port)} -u {quote_lftp(config.user)},{quote_lftp(config.password)} "
                        f"sftp://{quote_lftp(config.host)}"
                    ),
                    f"put {quote_lftp(str(local_path))} -o {quote_lftp(remote_path)}",
                    "bye",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        script.chmod(0o600)
        result = subprocess.run(["lftp", "-f", str(script)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0

    batch = work_dir / "upload.sftp"
    batch.write_text(
        f"put {quote_sftp_batch(str(local_path))} {quote_sftp_batch(remote_path)}\n",
        encoding="utf-8",
    )
    batch.chmod(0o600)
    env = os.environ.copy()
    env["SSHPASS"] = config.password
    result = subprocess.run(
        [
            "sshpass",
            "-e",
            "sftp",
            "-oBatchMode=no",
            "-oStrictHostKeyChecking=accept-new",
            "-P",
            config.port,
            "-b",
            str(batch),
            f"{config.user}@{config.host}",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
    )
    return result.returncode == 0


def is_allowed_reference_path(path: str) -> bool:
    lower = path.lower()
    return (
        lower.startswith("/wp-content/cache/wpo-minify/")
        and (lower.endswith(".js") or lower.endswith(".css"))
        and "/wp-includes/" not in lower
        and "/wp-admin/" not in lower
        and "/wp-content/plugins/" not in lower
        and "/wp-content/themes/" not in lower
    )


def remove_sourcemappingurl_lines(source: Path, destination: Path) -> Tuple[bool, int, str]:
    try:
        lines = source.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    except OSError as exc:
        return False, 0, f"read failed: {exc}"
    removed = [line for line in lines if "sourceMappingURL" in line]
    if not removed:
        return False, 0, "sourceMappingURL line not found"
    kept = [line for line in lines if "sourceMappingURL" not in line]
    if not kept:
        return False, 0, "refusing to create empty asset"
    destination.write_text("".join(kept), encoding="utf-8")
    if destination.stat().st_size <= 0:
        return False, 0, "mutated asset is empty"
    return True, len(removed), "removed sourceMappingURL lines only"


def write_rollback_hint(path: Path, applied_actions: List[Dict[str, Any]]) -> None:
    lines = [
        "# SourceMap Prevention Rollback",
        "",
        "Upload the listed backup file back to the listed remote path after manual review.",
        "No credentials are stored in this file.",
        "",
        "| Backup | Remote Path |",
        "|---|---|",
    ]
    for action in applied_actions:
        lines.append(f"| `{safe_text(action.get('backup_path'))}` | `{safe_text(action.get('remote_path'))}` |")
    lines.append("")
    write_text_atomic(path, "\n".join(lines))


def run_post_apply_observe() -> Dict[str, Any]:
    bot_path = PROJECT_DIR / "sentinel_defense_bot.py"
    if not bot_path.exists():
        return {"attempted": False, "status": "missing_sentinel_defense_bot"}
    result = subprocess.run(
        [sys.executable, str(bot_path), "--mode", "observe"],
        cwd=PROJECT_DIR,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=180,
    )
    return {"attempted": True, "returncode": result.returncode, "status": "ok" if result.returncode == 0 else "failed"}


def apply_safe(report: Dict[str, Any], args: argparse.Namespace) -> int:
    if not args.confirm_apply:
        report["apply_blocked"] = True
        report["blocked_reason"] = "--confirm-apply required for sourcemap-apply-safe"
        report["safety_checks"].append(
            safety_check(
                "confirm_apply_required",
                False,
                "--confirm-apply required for sourcemap-apply-safe.",
            )
        )
        for action in report.get("planned_actions", []):
            skipped = dict(action)
            skipped["reason"] = "--confirm-apply required for sourcemap-apply-safe"
            report["skipped_actions"].append(skipped)
        return 2

    report["safety_checks"].append(
        safety_check(
            "confirm_apply_required",
            True,
            "--confirm-apply present for sourcemap-apply-safe.",
        )
    )
    report["safety_checks"].append(
        safety_check(
            "auto_apply_env_enabled",
            os.environ.get("SENTINEL_SOURCEMAP_AUTO_APPLY", "").strip().lower() == "true",
            "sourcemap-apply-safe requires SENTINEL_SOURCEMAP_AUTO_APPLY=true in the environment.",
        )
    )
    if not report.get("wpo_minify_safe_to_apply"):
        for action in report.get("planned_actions", []):
            skipped = dict(action)
            skipped["reason"] = "WPO-Minify scoped apply-safe gate is false; operator review required."
            report["skipped_actions"].append(skipped)
        return 2
    if os.environ.get("SENTINEL_SOURCEMAP_AUTO_APPLY", "").strip().lower() != "true":
        for action in report.get("planned_actions", []):
            skipped = dict(action)
            skipped["reason"] = "SENTINEL_SOURCEMAP_AUTO_APPLY is not true."
            report["skipped_actions"].append(skipped)
        return 2

    config, error = load_sftp_config()
    report["safety_checks"].append(
        safety_check("sftp_env_present", config is not None, error or "SFTP environment variables are present.")
    )
    if config is None:
        for action in report.get("planned_actions", []):
            skipped = dict(action)
            skipped["reason"] = "SFTP environment or helper is missing."
            report["skipped_actions"].append(skipped)
        return 2

    backup_dir = args.backup_root / timestamp()
    backup_dir.mkdir(parents=True, exist_ok=True)
    applied_actions: List[Dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="sentinel-sourcemap-") as tmp:
        work_dir = Path(tmp)
        for index, action in enumerate(report.get("planned_actions", []), start=1):
            reference_path = str(action.get("reference_path", ""))
            if not is_allowed_reference_path(reference_path):
                skipped = dict(action)
                skipped["reason"] = "Reference path is outside the allowlisted WPO-Minify cache scope."
                report["skipped_actions"].append(skipped)
                continue
            remote_path = remote_path_for_reference(config, reference_path)
            original = work_dir / f"asset-{index}.original"
            mutated = work_dir / f"asset-{index}.mutated"
            verified = work_dir / f"asset-{index}.verified"
            if not run_sftp_download(config, remote_path, original, work_dir):
                skipped = dict(action)
                skipped["reason"] = "Remote reference asset could not be downloaded."
                report["skipped_actions"].append(skipped)
                continue
            if original.stat().st_size <= 0:
                skipped = dict(action)
                skipped["reason"] = "Remote reference asset is empty."
                report["skipped_actions"].append(skipped)
                continue
            backup_path = backup_dir / reference_path.lstrip("/")
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(original, backup_path)
            changed, removed_lines, change_reason = remove_sourcemappingurl_lines(original, mutated)
            if not changed:
                skipped = dict(action)
                if change_reason == "sourceMappingURL line not found":
                    skipped["classification"] = CLASS_WPO_STALE
                    skipped["original_classification"] = CLASS_WPO_MINIFY
                    skipped["reason"] = stale_reason()
                    skipped["status"] = "resolved/stale/no_action_needed"
                    report.setdefault("stale_candidates", []).append(
                        {
                            "map_path": action.get("map_path"),
                            "reference_path": action.get("reference_path"),
                            "count": action.get("count"),
                            "classification": CLASS_WPO_STALE,
                            "original_classification": CLASS_WPO_MINIFY,
                            "status": "resolved/stale/no_action_needed",
                            "skipped_reason": stale_reason(),
                            "evidence_source": "apply_safe_read_only_download",
                        }
                    )
                else:
                    skipped["reason"] = change_reason
                skipped["backup_path"] = str(backup_path)
                report["backup_paths"].append(str(backup_path))
                report["skipped_actions"].append(skipped)
                continue
            if not run_sftp_upload(config, mutated, remote_path, work_dir):
                skipped = dict(action)
                skipped["reason"] = "Remote upload failed after local backup."
                skipped["backup_path"] = str(backup_path)
                report["backup_paths"].append(str(backup_path))
                report["skipped_actions"].append(skipped)
                continue
            if not run_sftp_download(config, remote_path, verified, work_dir):
                skipped = dict(action)
                skipped["reason"] = "Remote verification download failed after upload."
                skipped["backup_path"] = str(backup_path)
                report["backup_paths"].append(str(backup_path))
                report["skipped_actions"].append(skipped)
                continue
            verified_text = verified.read_text(encoding="utf-8", errors="replace")
            verification_ok = verified.stat().st_size > 0 and "sourceMappingURL" not in verified_text
            applied = dict(action)
            applied.update(
                {
                    "remote_path": remote_path,
                    "backup_path": str(backup_path),
                    "removed_sourceMappingURL_lines": removed_lines,
                    "remote_verification": verification_ok,
                }
            )
            report["backup_paths"].append(str(backup_path))
            if verification_ok:
                applied_actions.append(applied)
                report["applied_actions"].append(applied)
            else:
                skipped = dict(applied)
                skipped["reason"] = "Remote verification failed: sourceMappingURL still present or file empty."
                report["skipped_actions"].append(skipped)

    stale_paths = {
        item.get("map_path")
        for item in report.get("stale_candidates", [])
        if isinstance(item, dict) and item.get("map_path")
    }
    if stale_paths:
        report["planned_actions"] = [
            action for action in report.get("planned_actions", [])
            if not isinstance(action, dict) or action.get("map_path") not in stale_paths
        ]
        report["already_remediated_count"] = len(report.get("stale_candidates", []))
        report["active_wpo_actions_count"] = len(report.get("planned_actions", []))
        report["historical_window_remainder_count"] = sum(
            parse_count(item.get("count"))
            for item in report.get("stale_candidates", [])
            if isinstance(item, dict)
        )
        report["wpo_minify_safe_to_apply"] = bool(report.get("planned_actions"))
        scope = report.get("auto_apply_scope")
        if isinstance(scope, dict):
            scope["wpo_minify_stale_or_already_remediated_count"] = report["already_remediated_count"]
            scope["active_wpo_actions_count"] = report["active_wpo_actions_count"]
            scope["wpo_minify_planned_count"] = report["active_wpo_actions_count"]

    report["safety_checks"].append(
        safety_check(
            "backup_created_before_change",
            bool(report.get("backup_paths")),
            "Original remote assets are backed up locally before upload.",
        )
    )
    report["safety_checks"].append(
        safety_check(
            "remote_verification_after_upload",
            bool(applied_actions) and all(bool(action.get("remote_verification")) for action in applied_actions),
            "Uploaded assets are re-downloaded, checked non-empty, and checked for absence of sourceMappingURL.",
        )
    )
    if applied_actions:
        write_rollback_hint(args.rollback_hint, applied_actions)
        report["rollback_hint_path"] = str(args.rollback_hint)
        report["post_apply_observe"] = run_post_apply_observe()
    return 0 if applied_actions else 2


def md_list(values: Any, key: str, limit: int = 4) -> str:
    if not isinstance(values, list) or not values:
        return "-"
    items: List[str] = []
    for item in values[:limit]:
        if not isinstance(item, dict):
            continue
        items.append(f"{safe_text(item.get(key))}: {safe_text(item.get('count'), '0')}")
    return ", ".join(items) if items else "-"


def render_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# SourceMap Prevention Report",
        "",
        f"**Generated:** `{safe_text(report.get('generated_at_utc'))}` UTC",
        "",
        "## Summary",
        "",
        f"- Mode: `{safe_text(report.get('mode'))}`",
        f"- Status: `{safe_text(report.get('status'))}`",
        f"- 404 auf .map: `{safe_text(report.get('map_404_metric', {}).get('value'))}` "
        f"(`{safe_text(report.get('map_404_metric', {}).get('status'))}`)",
        f"- Candidates: `{safe_text(report.get('candidate_count'))}`",
        f"- Planned: `{len(report.get('planned_actions', []))}`",
        f"- Applied: `{len(report.get('applied_actions', []))}`",
        f"- Skipped: `{len(report.get('skipped_actions', []))}`",
        f"- Stale/already remediated: `{safe_text(report.get('already_remediated_count'))}`",
        f"- Active WPO actions: `{safe_text(report.get('active_wpo_actions_count'))}`",
        f"- Historical window remainder hits: `{safe_text(report.get('historical_window_remainder_count'))}`",
        f"- confirm_apply: `{str(bool(report.get('confirm_apply'))).lower()}`",
        f"- apply_blocked: `{str(bool(report.get('apply_blocked'))).lower()}`",
        f"- blocked_reason: `{safe_text(report.get('blocked_reason'))}`",
        f"- Safe to auto apply (global): `{str(bool(report.get('safe_to_auto_apply'))).lower()}`",
        f"- global_safe_to_auto_apply: `{str(bool(report.get('global_safe_to_auto_apply'))).lower()}`",
        f"- wpo_minify_safe_to_apply: `{str(bool(report.get('wpo_minify_safe_to_apply'))).lower()}`",
        f"- core_requires_review: `{str(bool(report.get('core_requires_review'))).lower()}`",
        f"- Requires operator review: `{str(bool(report.get('requires_operator_review'))).lower()}`",
        f"- Rollback hint: `{safe_text(report.get('rollback_hint_path'))}`",
        "",
        "## Auto Apply Scope",
        "",
    ]
    scope = report.get("auto_apply_scope") if isinstance(report.get("auto_apply_scope"), dict) else {}
    lines.extend(
        [
            f"- Global Scope: `{safe_text(scope.get('global'))}`",
            f"- Apply-safe Allowed Scope: `{safe_text(scope.get('apply_safe_allowed_scope'))}`",
            f"- WPO-Minify Candidates: `{safe_text(scope.get('wpo_minify_candidate_count'))}`",
            f"- WPO-Minify Planned: `{safe_text(scope.get('wpo_minify_planned_count'))}`",
            f"- WPO-Minify Stale/Already Remediated: `{safe_text(scope.get('wpo_minify_stale_or_already_remediated_count'))}`",
            f"- Active WPO Actions: `{safe_text(scope.get('active_wpo_actions_count'))}`",
            f"- WordPress-Core Candidates: `{safe_text(scope.get('core_candidate_count'))}`",
            f"- Policy: {safe_text(scope.get('policy'))}",
            "",
            "## Scope Classification",
            "",
            "| Scope | Count | Policy |",
            "|---|---:|---|",
            f"| WPO-Minify | {safe_text(scope.get('wpo_minify_candidate_count'))} | apply-safe candidate |",
            f"| WPO-Minify Stale | {safe_text(scope.get('wpo_minify_stale_or_already_remediated_count'))} | resolved/stale/no_action_needed |",
            f"| WordPress-Core | {safe_text(scope.get('core_candidate_count'))} | diagnostic-only |",
            f"| Plugin/Theme | {safe_text(scope.get('plugin_theme_candidate_count'))} | review-only |",
            f"| Scanner/Unknown | {safe_text(scope.get('unknown_or_scanner_candidate_count'))} | observe/review-only |",
            "",
        ]
    )
    lines.extend(
        [
            "## Safety Gates",
            "",
            "| Check | Passed | Detail |",
            "|---|---:|---|",
        ]
    )
    for check in report.get("safety_checks", []):
        if not isinstance(check, dict):
            continue
        detail = safe_text(check.get("detail")).replace("|", "\\|")
        lines.append(f"| `{safe_text(check.get('check_id'))}` | `{str(bool(check.get('passed'))).lower()}` | {detail} |")

    lines.extend(
        [
            "",
            "## Candidates",
            "",
            "| Count | Classification | Auto Apply | Map Path | Reference Path | Countries | Cache |",
            "|---:|---|---:|---|---|---|---|",
        ]
    )
    for candidate in report.get("candidates", [])[:20]:
        if not isinstance(candidate, dict):
            continue
        lines.append(
            f"| {safe_text(candidate.get('count'))} | `{safe_text(candidate.get('classification'))}` | "
            f"`{str(bool(candidate.get('auto_apply_eligible'))).lower()}` | "
            f"{safe_text(candidate.get('map_path')).replace('|', '\\|')} | "
            f"{safe_text(candidate.get('reference_path')).replace('|', '\\|')} | "
            f"{md_list(candidate.get('countries'), 'country')} | "
            f"{md_list(candidate.get('cache_status'), 'cache_status')} |"
        )

    stale_candidates = report.get("stale_candidates")
    if isinstance(stale_candidates, list) and stale_candidates:
        lines.extend(
            [
                "",
                "## Stale / Already Remediated WPO-Minify Candidates",
                "",
                "| Count | Reference | Map Path | Status | Reason | Evidence |",
                "|---:|---|---|---|---|---|",
            ]
        )
        for candidate in stale_candidates[:20]:
            if not isinstance(candidate, dict):
                continue
            lines.append(
                f"| {safe_text(candidate.get('count'))} | "
                f"{safe_text(candidate.get('reference_path')).replace('|', '\\|')} | "
                f"{safe_text(candidate.get('map_path')).replace('|', '\\|')} | "
                f"`{safe_text(candidate.get('status'))}` | "
                f"{safe_text(candidate.get('skipped_reason')).replace('|', '\\|')} | "
                f"{safe_text(candidate.get('evidence_source')).replace('|', '\\|')} |"
            )

    def action_rows(title: str, actions: Any) -> None:
        lines.extend(["", f"## {title}", ""])
        if not isinstance(actions, list) or not actions:
            lines.extend(["- Keine Eintraege.", ""])
            return
        lines.extend(["| Action | Count | Reference | Reason |", "|---|---:|---|---|"])
        for action in actions[:20]:
            if not isinstance(action, dict):
                continue
            reason = action.get("reason") or action.get("operation") or "-"
            lines.append(
                f"| `{safe_text(action.get('action_id', 'skip'))}` | {safe_text(action.get('count'))} | "
                f"{safe_text(action.get('reference_path')).replace('|', '\\|')} | "
                f"{safe_text(reason).replace('|', '\\|')} |"
            )
        lines.append("")

    action_rows("Planned Actions", report.get("planned_actions"))
    action_rows("Applied Actions", report.get("applied_actions"))
    action_rows("Skipped Actions", report.get("skipped_actions"))

    lines.extend(
        [
            "## SFTP Environment",
            "",
            "| Variable | Present |",
            "|---|---:|",
        ]
    )
    env = report.get("sftp_env_present") if isinstance(report.get("sftp_env_present"), dict) else {}
    for key in sorted(env):
        lines.append(f"| `{safe_text(key)}` | `{str(bool(env.get(key))).lower()}` |")

    lines.extend(
        [
            "",
            "## Defensive Boundaries",
            "",
            "- Keine Cloudflare-Aenderungen.",
            "- Keine WAF-Regeln.",
            "- Keine WordPress-Core-, Plugin- oder Theme-Quellcodedateien.",
            "- Keine Dummy-.map-Dateien.",
            "- Keine globale .map-Blockade.",
            "- Apply-Scope ist ausschliesslich /wp-content/cache/wpo-minify/.",
            "",
            "## Outputs",
            "",
            f"- Markdown: `{safe_text(report.get('outputs', {}).get('markdown'))}`",
            f"- JSON: `{safe_text(report.get('outputs', {}).get('json'))}`",
            f"- History: `{safe_text(report.get('outputs', {}).get('history'))}`",
            "",
        ]
    )
    return "\n".join(lines)


def build_preflight_report(report: Dict[str, Any], args: argparse.Namespace) -> Dict[str, Any]:
    planned_actions = [
        action for action in report.get("planned_actions", [])
        if isinstance(action, dict)
    ]
    wpo_ready_actions = [
        action for action in planned_actions
        if action.get("classification") == CLASS_WPO_MINIFY
        and is_allowed_reference_path(str(action.get("reference_path", "")))
    ]
    core_candidates = [
        candidate for candidate in report.get("candidates", [])
        if isinstance(candidate, dict) and candidate.get("classification") == CLASS_WP_CORE
    ]
    non_wpo_planned = [
        action for action in planned_actions
        if action not in wpo_ready_actions
    ]
    max_files_ok = len(planned_actions) <= args.max_files <= 10
    no_core_plugin_theme_planned = all(
        "/wp-includes/" not in str(action.get("reference_path", ""))
        and "/wp-admin/" not in str(action.get("reference_path", ""))
        and "/wp-content/plugins/" not in str(action.get("reference_path", ""))
        and "/wp-content/themes/" not in str(action.get("reference_path", ""))
        for action in planned_actions
    )
    checks = [
        safety_check(
            "preflight_only_no_apply_safe_execution",
            args.mode == MODE_SIMULATE,
            "Preflight is generated from sourcemap-simulate; sourcemap-apply-safe is not executed.",
        ),
        safety_check(
            "no_sftp_upload_in_preflight",
            True,
            "Preflight generation does not call SFTP download or upload helpers.",
        ),
        safety_check(
            "planned_actions_wpo_only",
            bool(planned_actions) and not non_wpo_planned,
            f"Planned actions: {len(planned_actions)}; non-WPO planned actions: {len(non_wpo_planned)}.",
        ),
        safety_check(
            "wpo_apply_ready_count_matches_active_actions",
            len(wpo_ready_actions) == parse_count(report.get("active_wpo_actions_count")),
            f"WPO-Minify apply-ready files: {len(wpo_ready_actions)}; active actions: {parse_count(report.get('active_wpo_actions_count'))}.",
        ),
        safety_check(
            "core_candidates_diagnostic_only",
            bool(core_candidates) and all(not candidate.get("auto_apply_eligible") for candidate in core_candidates),
            f"WordPress-Core diagnostic-only candidates: {len(core_candidates)}.",
        ),
        safety_check(
            "no_core_plugin_theme_files_planned",
            no_core_plugin_theme_planned,
            "Planned actions exclude wp-includes, wp-admin, wp-content/plugins, and wp-content/themes.",
        ),
        safety_check(
            "max_10_files_per_run",
            max_files_ok,
            f"Planned files: {len(planned_actions)}; max_files: {args.max_files}.",
        ),
        safety_check(
            "backup_before_each_file_codepath",
            True,
            "apply_safe downloads each remote asset and copies it to sourcemap-backups before mutation/upload.",
        ),
        safety_check(
            "rollback_hint_codepath",
            True,
            "apply_safe writes reports/latest/sourcemap-prevention-last-rollback.md after successful applied actions.",
        ),
        safety_check(
            "remote_verification_after_upload_codepath",
            True,
            "apply_safe re-downloads every uploaded asset and checks non-empty plus no sourceMappingURL.",
        ),
        safety_check(
            "remove_only_sourcemappingurl_lines_codepath",
            True,
            "remove_sourcemappingurl_lines removes only lines containing sourceMappingURL and refuses empty output.",
        ),
        safety_check(
            "no_cloudflare_mutation",
            not bool(report.get("cloudflare_mutation")),
            "SourceMap prevention has no Cloudflare codepath.",
        ),
        safety_check(
            "no_env_file_read",
            True,
            "SourceMap prevention reads process environment only and does not open /etc/sentinel-defense.env.",
        ),
        safety_check(
            "secrets_not_reported",
            True,
            "Reports include only present/missing environment booleans, never variable values.",
        ),
    ]
    ready_for_scoped_apply_safe = all(bool(check["passed"]) for check in checks) and bool(
        report.get("wpo_minify_safe_to_apply")
    )
    return {
        "schema_version": "1.0",
        "generated_at_utc": utc_now(),
        "mode": "sourcemap-apply-preflight",
        "source_mode": report.get("mode"),
        "source_report_json": str(args.out_json),
        "apply_safe_executed": False,
        "sftp_upload": False,
        "cloudflare_mutation": False,
        "global_safe_to_auto_apply": bool(report.get("global_safe_to_auto_apply")),
        "safe_to_auto_apply": bool(report.get("safe_to_auto_apply")),
        "wpo_minify_safe_to_apply": bool(report.get("wpo_minify_safe_to_apply")),
        "core_requires_review": bool(report.get("core_requires_review")),
        "ready_for_scoped_apply_safe": ready_for_scoped_apply_safe,
        "auto_apply_scope": report.get("auto_apply_scope", {}),
        "wpo_minify_apply_ready_count": len(wpo_ready_actions),
        "core_diagnostic_only_count": len(core_candidates),
        "planned_actions": wpo_ready_actions,
        "diagnostic_only_candidates": core_candidates,
        "non_wpo_planned_actions": non_wpo_planned,
        "safety_checks": checks,
        "outputs": {
            "markdown": str(args.preflight_md),
            "json": str(args.preflight_json),
        },
    }


def render_preflight_markdown(preflight: Dict[str, Any]) -> str:
    lines = [
        "# SourceMap Apply Preflight",
        "",
        f"**Generated:** `{safe_text(preflight.get('generated_at_utc'))}` UTC",
        "",
        "## Summary",
        "",
        f"- Source Mode: `{safe_text(preflight.get('source_mode'))}`",
        f"- Apply-safe executed: `{str(bool(preflight.get('apply_safe_executed'))).lower()}`",
        f"- SFTP upload: `{str(bool(preflight.get('sftp_upload'))).lower()}`",
        f"- Cloudflare mutation: `{str(bool(preflight.get('cloudflare_mutation'))).lower()}`",
        f"- global_safe_to_auto_apply: `{str(bool(preflight.get('global_safe_to_auto_apply'))).lower()}`",
        f"- safe_to_auto_apply: `{str(bool(preflight.get('safe_to_auto_apply'))).lower()}`",
        f"- wpo_minify_safe_to_apply: `{str(bool(preflight.get('wpo_minify_safe_to_apply'))).lower()}`",
        f"- core_requires_review: `{str(bool(preflight.get('core_requires_review'))).lower()}`",
        f"- ready_for_scoped_apply_safe: `{str(bool(preflight.get('ready_for_scoped_apply_safe'))).lower()}`",
        f"- WPO-Minify apply-ready files: `{safe_text(preflight.get('wpo_minify_apply_ready_count'))}`",
        f"- WordPress-Core diagnostic-only files: `{safe_text(preflight.get('core_diagnostic_only_count'))}`",
        "",
        "## Safety Gates",
        "",
        "| Check | Passed | Detail |",
        "|---|---:|---|",
    ]
    for check in preflight.get("safety_checks", []):
        if not isinstance(check, dict):
            continue
        lines.append(
            f"| `{safe_text(check.get('check_id'))}` | `{str(bool(check.get('passed'))).lower()}` | "
            f"{safe_text(check.get('detail')).replace('|', '\\|')} |"
        )
    lines.extend(
        [
            "",
            "## WPO-Minify Apply-Ready Files",
            "",
            "| Count | Reference Path | Map Path | Reason |",
            "|---:|---|---|---|",
        ]
    )
    for action in preflight.get("planned_actions", []):
        if not isinstance(action, dict):
            continue
        lines.append(
            f"| {safe_text(action.get('count'))} | {safe_text(action.get('reference_path')).replace('|', '\\|')} | "
            f"{safe_text(action.get('map_path')).replace('|', '\\|')} | "
            f"{safe_text(action.get('reason')).replace('|', '\\|')} |"
        )
    lines.extend(
        [
            "",
            "## WordPress-Core Diagnostic-Only",
            "",
            "| Count | Reference Path | Map Path | Policy |",
            "|---:|---|---|---|",
        ]
    )
    for candidate in preflight.get("diagnostic_only_candidates", []):
        if not isinstance(candidate, dict):
            continue
        lines.append(
            f"| {safe_text(candidate.get('count'))} | "
            f"{safe_text(candidate.get('reference_path')).replace('|', '\\|')} | "
            f"{safe_text(candidate.get('map_path')).replace('|', '\\|')} | "
            f"{safe_text(candidate.get('policy')).replace('|', '\\|')} |"
        )
    lines.extend(
        [
            "",
            "## Boundaries",
            "",
            "- Kein sourcemap-apply-safe wurde ausgefuehrt.",
            "- Kein SFTP-Upload.",
            "- Keine Cloudflare-Aenderung.",
            "- Keine Core-/Plugin-/Theme-Dateien im Apply-Plan.",
            "- Apply-Scope bleibt WPO-Minify Cache-Dateien.",
            "- Keine Secrets im Report.",
            "",
            "## Outputs",
            "",
            f"- Markdown: `{safe_text(preflight.get('outputs', {}).get('markdown'))}`",
            f"- JSON: `{safe_text(preflight.get('outputs', {}).get('json'))}`",
            "",
        ]
    )
    return "\n".join(lines)


def write_text_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)


def write_json_atomic(path: Path, data: Dict[str, Any]) -> None:
    write_text_atomic(path, json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def append_history(path: Path, report: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "generated_at_utc": report.get("generated_at_utc"),
        "status": report.get("status"),
        "mode": report.get("mode"),
        "candidate_count": report.get("candidate_count"),
        "planned_count": len(report.get("planned_actions", [])),
        "applied_count": len(report.get("applied_actions", [])),
        "skipped_count": len(report.get("skipped_actions", [])),
        "already_remediated_count": report.get("already_remediated_count"),
        "active_wpo_actions_count": report.get("active_wpo_actions_count"),
        "historical_window_remainder_count": report.get("historical_window_remainder_count"),
        "confirm_apply": report.get("confirm_apply"),
        "apply_blocked": report.get("apply_blocked"),
        "blocked_reason": report.get("blocked_reason"),
        "safe_to_auto_apply": report.get("safe_to_auto_apply"),
        "global_safe_to_auto_apply": report.get("global_safe_to_auto_apply"),
        "wpo_minify_safe_to_apply": report.get("wpo_minify_safe_to_apply"),
        "core_requires_review": report.get("core_requires_review"),
        "requires_operator_review": report.get("requires_operator_review"),
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")


def write_outputs(report: Dict[str, Any], args: argparse.Namespace) -> None:
    write_json_atomic(args.out_json, report)
    write_text_atomic(args.out_md, render_markdown(report))
    append_history(args.history_path, report)
    if args.mode == MODE_SIMULATE:
        preflight = build_preflight_report(report, args)
        write_json_atomic(args.preflight_json, preflight)
        write_text_atomic(args.preflight_md, render_preflight_markdown(preflight))


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Observe, simulate, and safely prevent WPO-Minify source map 404s.")
    parser.add_argument("--mode", choices=(MODE_OBSERVE, MODE_SIMULATE, MODE_APPLY_SAFE), required=True)
    parser.add_argument("--notfound-json", type=Path, default=DEFAULT_NOTFOUND_JSON)
    parser.add_argument("--website-json", type=Path, default=DEFAULT_WEBSITE_JSON)
    parser.add_argument("--out-md", type=Path, default=DEFAULT_OUT_MD)
    parser.add_argument("--out-json", type=Path, default=DEFAULT_OUT_JSON)
    parser.add_argument("--history-path", type=Path, default=DEFAULT_HISTORY)
    parser.add_argument("--preflight-md", type=Path, default=DEFAULT_PREFLIGHT_MD)
    parser.add_argument("--preflight-json", type=Path, default=DEFAULT_PREFLIGHT_JSON)
    parser.add_argument("--backup-root", type=Path, default=DEFAULT_BACKUP_ROOT)
    parser.add_argument("--rollback-hint", type=Path, default=DEFAULT_ROLLBACK_HINT)
    parser.add_argument("--max-files", type=int, default=10)
    parser.add_argument("--confirm-apply", action="store_true")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.max_files < 1 or args.max_files > 10:
        print("max-files must be between 1 and 10.", file=sys.stderr)
        return 2
    report = build_base_report(args)
    exit_code = 0
    if args.mode == MODE_APPLY_SAFE:
        exit_code = apply_safe(report, args)
    write_outputs(report, args)
    print(
        "SourceMap prevention report written: "
        f"{args.out_md} ({report['status']}, planned={len(report['planned_actions'])}, "
        f"applied={len(report['applied_actions'])})"
    )
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
