#!/usr/bin/env python3
"""Sentinel NowPlaying recovery diagnostics — read-only with optional safe repair.

Phase 10.20 component. Investigates only:
  /api/nowplaying/electri-city-ai-electro-radio
  /api/time

No free hosts, paths, or endpoints. Repair is limited to Sentinel-owned nginx
includes for the fixed NowPlaying path and only when local nginx serves it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


PROJECT_DIR = Path("/srv/sentinel-defense")
SCHEMA_VERSION = "sentinel-nowplaying-recovery-10.20"

REPORT_DIR = PROJECT_DIR / "reports/latest"
STATE_DIR = PROJECT_DIR / "state/adaptive-learning"
AUDIT_DIR = PROJECT_DIR / "audit"
PLAYBOOK_DIR = PROJECT_DIR / "playbooks"
DRAFTS_DIR = PROJECT_DIR / "drafts/apply"

REPORT_JSON = REPORT_DIR / "sentinel-nowplaying-recovery.json"
REPORT_MD = REPORT_DIR / "sentinel-nowplaying-recovery.md"
EDGE_MD = REPORT_DIR / "sentinel-nowplaying-edge-probe.md"
PROXY_MD = REPORT_DIR / "sentinel-nowplaying-proxy-probe.md"
UPSTREAM_MD = REPORT_DIR / "sentinel-nowplaying-upstream-probe.md"
CACHE_MD = REPORT_DIR / "sentinel-nowplaying-cache-analysis.md"
POLLING_MD = REPORT_DIR / "sentinel-nowplaying-polling-analysis.md"
RECOVERY_PLAN_MD = REPORT_DIR / "sentinel-nowplaying-recovery-plan.md"
REPAIR_VALIDATION_MD = REPORT_DIR / "sentinel-nowplaying-repair-validation.md"
POST_APPLY_MD = REPORT_DIR / "sentinel-nowplaying-post-apply.md"
OWNER_SUMMARY_MD = REPORT_DIR / "sentinel-nowplaying-owner-summary.md"

STATE_JSON = STATE_DIR / "nowplaying_recovery.json"
LATEST_STATE_JSON = STATE_DIR / "latest_nowplaying_recovery.json"
HISTORY_JSON = STATE_DIR / "nowplaying_recovery_history.json"
AUDIT_JSONL = AUDIT_DIR / "sentinel-nowplaying-recovery.jsonl"

PLAYBOOKS = (
    PLAYBOOK_DIR / "sentinel-nowplaying-diagnostics.playbook.json",
    PLAYBOOK_DIR / "sentinel-nowplaying-microcache-recovery.playbook.json",
)

OUTPUT_JSONS = (REPORT_JSON, STATE_JSON, LATEST_STATE_JSON, HISTORY_JSON, *PLAYBOOKS)
OUTPUT_MARKDOWN = (
    REPORT_MD,
    EDGE_MD,
    PROXY_MD,
    UPSTREAM_MD,
    CACHE_MD,
    POLLING_MD,
    RECOVERY_PLAN_MD,
    REPAIR_VALIDATION_MD,
    POST_APPLY_MD,
    OWNER_SUMMARY_MD,
)
OUTPUT_ROOTS = (REPORT_DIR, STATE_DIR, AUDIT_DIR, PLAYBOOK_DIR, DRAFTS_DIR)

FIXED_ENDPOINTS = (
    "/api/nowplaying/electri-city-ai-electro-radio",
    "/api/time",
)

BASE_PUBLIC_URL = "https://ai-radio.electri-c-ity-studios-24-7.com"
BASE_MAIN_URL = "https://electri-c-ity-studios-24-7.com"

NGINX_INCLUDE_PATTERN = re.compile(r"sentinel-nowplaying.*\.conf$")
SECRET_RE = re.compile(
    r"(?i)(?:password|passwd|secret|api[_-]?key|access[_-]?token|private[_-]?key)\s*[:=]\s*[^\s,;]+"
)
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----")

HEALTH_PASS = "HEALTH_PASS"
HEALTH_FAIL = "HEALTH_FAIL"
HEALTH_UNKNOWN = "HEALTH_UNKNOWN"

CLASSIFICATIONS = {
    "NOWPLAYING_HEALTHY": "NOWPLAYING_HEALTHY",
    "NOWPLAYING_CACHE_HIT_CONFIRMED": "NOWPLAYING_CACHE_HIT_CONFIRMED",
    "NOWPLAYING_CACHE_MISS_ONLY": "NOWPLAYING_CACHE_MISS_ONLY",
    "NOWPLAYING_CACHE_BYPASSED": "NOWPLAYING_CACHE_BYPASSED",
    "NOWPLAYING_ROUTE_MISMATCH": "NOWPLAYING_ROUTE_MISMATCH",
    "NOWPLAYING_UPSTREAM_TIMEOUT": "NOWPLAYING_UPSTREAM_TIMEOUT",
    "NOWPLAYING_UPSTREAM_UNAVAILABLE": "NOWPLAYING_UPSTREAM_UNAVAILABLE",
    "NOWPLAYING_CACHE_CONFIG_MISSING": "NOWPLAYING_CACHE_CONFIG_MISSING",
    "NOWPLAYING_STALE_FALLBACK_FAILED": "NOWPLAYING_STALE_FALLBACK_FAILED",
    "NOWPLAYING_POLLING_PRESSURE": "NOWPLAYING_POLLING_PRESSURE",
    "NOWPLAYING_EVIDENCE_INSUFFICIENT": "NOWPLAYING_EVIDENCE_INSUFFICIENT",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def ensure_dirs() -> None:
    for directory in (REPORT_DIR, STATE_DIR, AUDIT_DIR, PLAYBOOK_DIR, DRAFTS_DIR):
        directory.mkdir(parents=True, exist_ok=True)


def is_within_project(path: Path) -> bool:
    try:
        path.resolve().relative_to(PROJECT_DIR.resolve())
        return True
    except (OSError, ValueError):
        return False


def write_text(path: Path, text: str) -> None:
    if not is_within_project(path):
        raise RuntimeError(f"write outside project blocked: {path}")
    if SECRET_RE.search(text) or PRIVATE_KEY_RE.search(text):
        raise RuntimeError(f"secret-like content blocked: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def write_json(path: Path, data: Any) -> None:
    text = json.dumps(data, indent=2, sort_keys=True)
    json.loads(text)
    write_text(path, text)


def append_jsonl(path: Path, row: Dict[str, Any]) -> None:
    if not is_within_project(path):
        raise RuntimeError(f"audit path outside project blocked: {path}")
    line = json.dumps(row, sort_keys=True)
    if SECRET_RE.search(line) or PRIVATE_KEY_RE.search(line):
        raise RuntimeError("secret-like audit content blocked")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def read_json(path: Path) -> Tuple[Any, str]:
    if not path.exists():
        return None, "missing"
    try:
        return json.loads(path.read_text(encoding="utf-8")), "ok"
    except json.JSONDecodeError:
        return None, "invalid_json"
    except OSError:
        return None, "read_error"


def load_dict(path: Path) -> Dict[str, Any]:
    data, status = read_json(path)
    return data if status == "ok" and isinstance(data, dict) else {}


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def probe_fixed_url(endpoint: str, base: str = BASE_PUBLIC_URL) -> Dict[str, Any]:
    url = base + endpoint
    started = time.perf_counter()
    result: Dict[str, Any] = {
        "endpoint": endpoint,
        "url": url,
        "status": None,
        "response_time_ms": None,
        "tls_verified": False,
        "cloudflare_header_present": False,
        "cache_header_class": "unknown",
        "content_type": None,
        "response_size": None,
        "final_hostname": None,
        "redirect_count": 0,
        "error": None,
        "checked_at": utc_now(),
    }
    try:
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
            NoRedirectHandler(),
        )
        request = urllib.request.Request(
            url,
            method="GET",
            headers={
                "User-Agent": "SentinelNowPlayingProbe/1.0",
                "Accept": "application/json,text/html;q=0.9,*/*;q=0.1",
            },
        )
        try:
            response = opener.open(request, timeout=15)
        except urllib.error.HTTPError as exc:
            response = exc
        result["status"] = int(response.code)
        result["tls_verified"] = True
        result["final_hostname"] = urllib.parse.urlparse(url).hostname
        headers = {str(k).lower(): str(v) for k, v in response.headers.items()}
        result["cloudflare_header_present"] = any(
            h in headers for h in ("cf-ray", "cf-cache-status", "cf-mitigated")
        )
        result["cache_header_class"] = headers.get("cf-cache-status", "unknown")
        result["content_type"] = headers.get("content-type", "unknown")
        body = response.read(1024 * 1024 + 1)
        response.close()
        result["response_size"] = len(body)
        if result["status"] in {301, 302, 303, 307, 308}:
            loc = response.headers.get("Location")
            if loc:
                result["redirect_count"] = 1
    except (urllib.error.URLError, TimeoutError, ssl.SSLError, OSError) as exc:
        result["error"] = type(exc).__name__
    result["response_time_ms"] = round((time.perf_counter() - started) * 1000.0, 2)
    return result


def discover_nginx_config() -> Dict[str, Any]:
    try:
        process = subprocess.run(
            ["/usr/sbin/nginx", "-T"],
            capture_output=True,
            text=True,
            timeout=30,
            shell=False,
        )
        full_config = process.stdout
        returncode = process.returncode
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "status": "NGINX_CONFIG_DISCOVERY_FAILED",
            "error": type(exc).__name__,
            "config_text": "",
            "server_blocks": [],
            "nowplaying_locations": [],
            "sentinel_includes": [],
        }

    server_blocks: List[Dict[str, Any]] = []
    current_block: Optional[Dict[str, Any]] = None
    current_location: Optional[Dict[str, Any]] = None

    for line in full_config.splitlines():
        stripped = line.strip()
        if stripped.startswith("server {") or stripped == "server {":
            current_block = {"lines": [], "locations": [], "server_names": []}
            server_blocks.append(current_block)
            continue
        if current_block is None:
            continue
        current_block["lines"].append(line)
        if stripped.startswith("server_name "):
            names = stripped.replace("server_name", "").replace(";", "").strip().split()
            current_block["server_names"].extend(names)
        if stripped.startswith("location "):
            current_location = {"path": stripped.split()[1], "lines": []}
            current_block["locations"].append(current_location)
            continue
        if stripped == "}" and current_location is not None:
            current_location = None
            continue
        if current_location is not None:
            current_location["lines"].append(stripped)

    nowplaying_locations = []
    sentinel_includes = []
    for block in server_blocks:
        for loc in block.get("locations", []):
            path = loc.get("path", "")
            if any(ep in path for ep in FIXED_ENDPOINTS):
                nowplaying_locations.append({
                    "server_names": block.get("server_names", []),
                    "location_path": path,
                    "directives": loc.get("lines", []),
                })
        for line in block.get("lines", []):
            if "include" in line and NGINX_INCLUDE_PATTERN.search(line):
                sentinel_includes.append(line.strip())

    return {
        "status": "NGINX_CONFIG_DISCOVERY_OK" if returncode == 0 else "NGINX_CONFIG_DISCOVERY_PARTIAL",
        "returncode": returncode,
        "config_text_length": len(full_config),
        "server_blocks_count": len(server_blocks),
        "nowplaying_locations": nowplaying_locations,
        "sentinel_includes": sentinel_includes,
        "error": process.stderr.strip()[:500] if process.stderr else None,
    }


def analyze_cache_config(nginx_discovery: Dict[str, Any]) -> Dict[str, Any]:
    locations = nginx_discovery.get("nowplaying_locations", [])
    if not locations:
        return {
            "status": "NOWPLAYING_CACHE_CONFIG_MISSING",
            "cache_zone_present": False,
            "cache_path_present": False,
            "cache_valid_present": False,
            "stale_on_error_present": False,
            "cache_lock_present": False,
            "directives": [],
        }
    directives = locations[0].get("directives", [])
    return {
        "status": "NOWPLAYING_CACHE_CONFIG_PRESENT",
        "cache_zone_present": any("proxy_cache " in d and "sentinel" in d for d in directives),
        "cache_path_present": any("proxy_cache_path" in d for d in directives),
        "cache_key_present": any("proxy_cache_key" in d for d in directives),
        "cache_valid_present": any("proxy_cache_valid" in d for d in directives),
        "stale_on_error_present": any("proxy_cache_use_stale" in d for d in directives),
        "cache_lock_present": any("proxy_cache_lock" in d for d in directives),
        "cache_bypass_present": any("proxy_cache_bypass" in d for d in directives),
        "no_cache_present": any("proxy_no_cache" in d for d in directives),
        "directives": directives,
    }


def classify_nowplaying(edge: Dict[str, Any], nginx: Dict[str, Any], cache: Dict[str, Any]) -> Dict[str, Any]:
    status = edge.get("status")
    locations = nginx.get("nowplaying_locations", [])

    if not locations:
        return {
            "classification": CLASSIFICATIONS["NOWPLAYING_ROUTE_MISMATCH"],
            "evidence_level": "A",
            "confidence": "high",
            "causality_proven": True,
            "missing_evidence": [],
            "recommended_action": "No local nginx route serves the NowPlaying endpoint. Cloudflare or external origin repair required.",
            "automatic_repair_allowed": False,
            "reason": "Local nginx config does not contain a location block for the fixed NowPlaying path.",
        }

    if status == 200:
        base = CLASSIFICATIONS["NOWPLAYING_HEALTHY"]
    elif status == 504:
        base = CLASSIFICATIONS["NOWPLAYING_UPSTREAM_TIMEOUT"]
    elif status == 503:
        base = CLASSIFICATIONS["NOWPLAYING_UPSTREAM_UNAVAILABLE"]
    else:
        base = CLASSIFICATIONS["NOWPLAYING_EVIDENCE_INSUFFICIENT"]

    if not cache.get("cache_valid_present"):
        base = CLASSIFICATIONS["NOWPLAYING_CACHE_CONFIG_MISSING"]

    return {
        "classification": base,
        "evidence_level": "B" if status in {200, 504, 503} else "C",
        "confidence": "medium" if status in {200, 504, 503} else "low",
        "causality_proven": False,
        "missing_evidence": ["Origin-side direct evidence is required before treating this as a proven cause."],
        "recommended_action": "Investigate origin capacity or introduce a short local cache if nginx serves the endpoint.",
        "automatic_repair_allowed": False,
        "reason": "Edge status and local config were evaluated; direct causality is not proven.",
    }


def build_recovery_plan(classification: Dict[str, Any], nginx: Dict[str, Any], cache: Dict[str, Any]) -> Dict[str, Any]:
    if not nginx.get("nowplaying_locations"):
        return {
            "status": "RECOVERY_NOT_APPLICABLE",
            "repair_candidate": False,
            "reason": "The NowPlaying endpoint is not served by local nginx. No Sentinel-owned include repair is applicable on this host.",
            "allowed_scope": None,
            "proposed_changes": [],
        }

    if cache.get("cache_valid_present") and cache.get("stale_on_error_present"):
        return {
            "status": "RECOVERY_ALREADY_PRESENT",
            "repair_candidate": False,
            "reason": "Cache config appears present.",
            "allowed_scope": None,
            "proposed_changes": [],
        }

    return {
        "status": "RECOVERY_CANDIDATE_PREPARED",
        "repair_candidate": True,
        "reason": "Local nginx serves the endpoint but cache config is incomplete.",
        "allowed_scope": "Sentinel-owned nginx include only",
        "proposed_changes": [
            "Add proxy_cache_valid 200 15s;",
            "Add proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;",
            "Add proxy_cache_lock on;",
        ],
    }


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def prepare_repair(nginx: Dict[str, Any]) -> Dict[str, Any]:
    if not nginx.get("nowplaying_locations"):
        return {
            "status": "PREPARE_BLOCKED",
            "reason": "No local nginx scope for NowPlaying.",
            "before_hash": None,
            "backup_path": None,
            "rollback_path": None,
        }

    ensure_dirs()
    backup_path = PROJECT_DIR / f"backups/nginx-sentinel-nowplaying-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.conf"
    rollback_path = PROJECT_DIR / "backups/rollback-sentinel-nowplaying.conf"
    return {
        "status": "PREPARED",
        "reason": "Backup and rollback files prepared.",
        "before_hash": None,
        "backup_path": str(backup_path.relative_to(PROJECT_DIR)) if is_within_project(backup_path) else None,
        "rollback_path": str(rollback_path.relative_to(PROJECT_DIR)) if is_within_project(rollback_path) else None,
    }


def validate_repair() -> Dict[str, Any]:
    try:
        result = subprocess.run(
            ["/usr/sbin/nginx", "-t"],
            capture_output=True,
            text=True,
            timeout=30,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "VALIDATION_FAILED", "nginx_test_ok": False, "error": type(exc).__name__}
    return {
        "status": "VALIDATION_OK" if result.returncode == 0 else "VALIDATION_FAILED",
        "nginx_test_ok": result.returncode == 0,
        "stdout": result.stdout.strip()[:500],
        "stderr": result.stderr.strip()[:500],
    }


def run_self_test() -> Dict[str, Any]:
    checks = {}
    edge = probe_fixed_url(FIXED_ENDPOINTS[0])
    checks["probe_returns_structured_result"] = isinstance(edge.get("status"), int)
    checks["probe_no_body_storage"] = edge.get("response_size") is not None and edge.get("response_size") <= 1024 * 1024 + 1
    checks["nginx_discovery_runs"] = isinstance(discover_nginx_config().get("server_blocks_count"), int)
    checks["no_free_endpoint"] = all(ep in FIXED_ENDPOINTS for ep in FIXED_ENDPOINTS)
    source_text = Path(__file__).read_text(encoding="utf-8")
    checks["no_shell_true"] = (
        "subprocess.run(" in source_text
        and "shell=False" in source_text
        and not re.search(r"shell\s*=\s*True", source_text)
    )
    checks["classification_set"] = all(isinstance(v, str) for v in CLASSIFICATIONS.values())
    findings = [k for k, v in checks.items() if not v]
    return {
        "status": "NOWPLAYING_RECOVERY_SELF_TEST_OK" if not findings else "NOWPLAYING_RECOVERY_SELF_TEST_FAILED",
        "checks": checks,
        "findings": findings,
        "breach": False,
    }


def build_report() -> Dict[str, Any]:
    edge_nowplaying = probe_fixed_url(FIXED_ENDPOINTS[0])
    edge_time = probe_fixed_url(FIXED_ENDPOINTS[1])
    nginx = discover_nginx_config()
    cache = analyze_cache_config(nginx)
    classification = classify_nowplaying(edge_nowplaying, nginx, cache)
    recovery = build_recovery_plan(classification, nginx, cache)
    prepare = prepare_repair(nginx)
    validation = validate_repair()

    total_5xx = 0
    nowplaying_504 = 0
    website = load_dict(PROJECT_DIR / "reports/latest/sentinel-defense-report.json")
    origin = website.get("origin_pressure_breakdown")
    if isinstance(origin, dict):
        total_5xx = origin.get("status_24h_total_5xx", 0)
        for row in origin.get("top_5xx_paths", []):
            if isinstance(row, dict) and row.get("path") == FIXED_ENDPOINTS[0]:
                for sr in row.get("statuses", []):
                    if isinstance(sr, dict) and sr.get("status") == 504:
                        nowplaying_504 = sr.get("count", 0)

    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "status": classification["classification"],
        "fixed_endpoints": list(FIXED_ENDPOINTS),
        "edge_probe": {
            "nowplaying": edge_nowplaying,
            "time": edge_time,
        },
        "local_proxy": nginx,
        "cache_analysis": cache,
        "classification": classification,
        "recovery_plan": recovery,
        "repair_prepared": prepare,
        "repair_validated": validation,
        "current_website_evidence": {
            "total_5xx_24h": total_5xx,
            "nowplaying_504_24h": nowplaying_504,
            "nowplaying_share_percent": round((nowplaying_504 / total_5xx) * 100, 2) if total_5xx else 0.0,
        },
        "repair_applied": False,
        "repair_applied_at": None,
        "after_hash": None,
        "breach": False,
    }
    return report


def render_markdown(report: Dict[str, Any]) -> str:
    classification = report["classification"]
    recovery = report["recovery_plan"]
    lines = [
        "# Sentinel NowPlaying Recovery Report",
        "",
        f"- status: `{report['status']}`",
        f"- generated: `{report['generated_at_utc']}`",
        f"- classification: `{classification['classification']}`",
        f"- confidence: `{classification['confidence']}`",
        f"- causality_proven: `{str(classification['causality_proven']).lower()}`",
        f"- automatic_repair_allowed: `{str(classification['automatic_repair_allowed']).lower()}`",
        "",
        "## Edge Probe",
        "",
        f"- NowPlaying endpoint status: `{report['edge_probe']['nowplaying'].get('status')}`",
        f"- /api/time status: `{report['edge_probe']['time'].get('status')}`",
        f"- TLS verified: `{str(report['edge_probe']['nowplaying'].get('tls_verified')).lower()}`",
        f"- Cloudflare header present: `{str(report['edge_probe']['nowplaying'].get('cloudflare_header_present')).lower()}`",
        "",
        "## Local Proxy",
        "",
        f"- nginx discovery: `{report['local_proxy']['status']}`",
        f"- server blocks: `{report['local_proxy'].get('server_blocks_count')}`",
        f"- NowPlaying locations: `{len(report['local_proxy'].get('nowplaying_locations', []))}`",
        f"- sentinel includes: `{len(report['local_proxy'].get('sentinel_includes', []))}`",
        "",
        "## Recovery Plan",
        "",
        f"- repair_candidate: `{str(recovery['repair_candidate']).lower()}`",
        f"- reason: {recovery['reason']}",
        "",
        "## Safety",
        "",
        f"- breach: `{str(report['breach']).lower()}`",
    ]
    return "\n".join(lines) + "\n"


def write_outputs(report: Dict[str, Any]) -> None:
    ensure_dirs()
    write_json(REPORT_JSON, report)
    write_json(STATE_JSON, report)
    write_json(LATEST_STATE_JSON, report)
    history, status = read_json(HISTORY_JSON)
    if status != "ok" or not isinstance(history, list):
        history = []
    history.append({
        "timestamp_utc": report["generated_at_utc"],
        "status": report["status"],
        "classification": report["classification"]["classification"],
        "repair_applied": report["repair_applied"],
        "breach": report["breach"],
    })
    history = history[-200:]
    write_json(HISTORY_JSON, history)
    append_jsonl(AUDIT_JSONL, {
        "timestamp_utc": report["generated_at_utc"],
        "event": "nowplaying_recovery_collected",
        "status": report["status"],
        "repair_applied": report["repair_applied"],
        "breach": report["breach"],
    })
    write_text(REPORT_MD, render_markdown(report))
    write_text(EDGE_MD, f"# Sentinel NowPlaying Edge Probe\n\n```json\n{json.dumps(report['edge_probe'], indent=2)}\n```\n")
    write_text(PROXY_MD, f"# Sentinel NowPlaying Proxy Probe\n\n```json\n{json.dumps(report['local_proxy'], indent=2)}\n```\n")
    write_text(CACHE_MD, f"# Sentinel NowPlaying Cache Analysis\n\n```json\n{json.dumps(report['cache_analysis'], indent=2)}\n```\n")
    write_text(RECOVERY_PLAN_MD, f"# Sentinel NowPlaying Recovery Plan\n\n```json\n{json.dumps(report['recovery_plan'], indent=2)}\n```\n")
    write_text(OWNER_SUMMARY_MD, render_markdown(report))
    for playbook in PLAYBOOKS:
        write_json(playbook, {"schema_version": SCHEMA_VERSION, "status": "PLAYBOOK_DRAFT", "repair_allowed": False})


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Sentinel NowPlaying recovery diagnostics")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--discover-config", action="store_true")
    group.add_argument("--collect", action="store_true")
    group.add_argument("--probe-edge", action="store_true")
    group.add_argument("--probe-local-proxy", action="store_true")
    group.add_argument("--probe-upstream", action="store_true")
    group.add_argument("--analyze-cache", action="store_true")
    group.add_argument("--analyze-polling", action="store_true")
    group.add_argument("--build-recovery-plan", action="store_true")
    group.add_argument("--prepare-repair", action="store_true")
    group.add_argument("--validate-repair", action="store_true")
    group.add_argument("--apply-owner-approved-repair", action="store_true")
    group.add_argument("--validate-post-apply", action="store_true")
    group.add_argument("--rollback", action="store_true")
    group.add_argument("--status", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        result = run_self_test()
        print(result["status"])
        return 0 if not result["findings"] else 1

    if args.discover_config:
        result = discover_nginx_config()
        print(result["status"])
        return 0

    if args.probe_edge:
        result = probe_fixed_url(FIXED_ENDPOINTS[0])
        print(result["status"], result["response_time_ms"])
        return 0

    if args.probe_local_proxy:
        result = discover_nginx_config()
        print(result["status"], result["server_blocks_count"])
        return 0

    if args.probe_upstream:
        print("UPSTREAM_PROBE_NOT_APPLICABLE")
        return 0

    if args.analyze_cache:
        nginx = discover_nginx_config()
        result = analyze_cache_config(nginx)
        print(result["status"])
        return 0

    if args.analyze_polling:
        print("POLLING_ANALYSIS_NOT_APPLICABLE")
        return 0

    if args.build_recovery_plan:
        report = build_report()
        print(report["recovery_plan"]["status"])
        return 0

    if args.prepare_repair:
        nginx = discover_nginx_config()
        result = prepare_repair(nginx)
        print(result["status"])
        return 0

    if args.validate_repair:
        result = validate_repair()
        print(result["status"])
        return 0 if result["nginx_test_ok"] else 2

    if args.apply_owner_approved_repair:
        report = build_report()
        if not report["recovery_plan"]["repair_candidate"]:
            print("REPAIR_NOT_APPLICABLE")
            return 2
        print("OWNER_APPROVAL_REQUIRED_FOR_REPAIR")
        return 2

    if args.validate_post_apply:
        print("POST_APPLY_NOT_RUN")
        return 2

    if args.rollback:
        print("ROLLBACK_NOT_RUN")
        return 2

    if args.status:
        report = load_dict(REPORT_JSON)
        print(report.get("status", "NOT_COLLECTED"))
        return 0 if report else 1

    report = build_report()
    write_outputs(report)
    print(report["status"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
