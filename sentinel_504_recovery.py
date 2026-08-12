#!/usr/bin/env python3
"""Sentinel evidence-guided 504 recovery — Phase 10.22.

Evidence first. Repair second. Measurement third. Rollback always.

The module separates the 24h rolling counter from actual current error
production. A rolling window that is still full of old errors is not proof that a
repair failed, and a shrinking rolling window alone is not proof that it worked.
Only the change of the rolling counter between consecutive monitor snapshots is
directly observed, so `new_errors_lower_bound = max(0, net_delta)` is the
strongest honest statement about newly produced errors.

A repair may only be prepared when the cause is PROVEN, the origin is this host,
the target file is on a fixed Sentinel-owned allowlist and a rollback exists.
Otherwise the result is NO_SAFE_AUTOMATIC_REPAIR, which is a valid outcome.

Read-only unless an approved, proven, scoped repair passes every gate. No
Cloudflare, DNS, TLS, WAF, WordPress, database or global nginx change; no blind
timeout increase; no caching of an authenticated REST endpoint; no free shell and
no free host, URL or path arguments.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import sentinel_origin_route_mapper as route_mapper


PROJECT_DIR = Path(__file__).resolve().parent
SCHEMA_VERSION = "sentinel-504-recovery-10.22"

REPORT_DIR = PROJECT_DIR / "reports/latest"
STATE_DIR = PROJECT_DIR / "state/adaptive-learning"
AUDIT_DIR = PROJECT_DIR / "audit"
PLAYBOOK_DIR = PROJECT_DIR / "playbooks"
BACKUP_DIR = PROJECT_DIR / "backups/origin-repair"
MONITOR_DIR = PROJECT_DIR / "cloudflare-monitor"

BASELINE_JSON = REPORT_DIR / "sentinel-504-baseline.json"
BASELINE_MD = REPORT_DIR / "sentinel-504-baseline.md"
RECOVERY_JSON = REPORT_DIR / "sentinel-504-recovery.json"
RECOVERY_MD = REPORT_DIR / "sentinel-504-recovery.md"
FAILURE_GRAPH_JSON = REPORT_DIR / "sentinel-origin-failure-graph.json"
FAILURE_GRAPH_MD = REPORT_DIR / "sentinel-origin-failure-graph.md"
REPAIRABILITY_JSON = REPORT_DIR / "sentinel-repairability-matrix.json"
REPAIRABILITY_MD = REPORT_DIR / "sentinel-repairability-matrix.md"
USERS_ME_JSON = REPORT_DIR / "sentinel-wp-users-me-analysis.json"
USERS_ME_MD = REPORT_DIR / "sentinel-wp-users-me-analysis.md"
EFFECT_JSON = REPORT_DIR / "sentinel-origin-recovery-effect.json"
EFFECT_MD = REPORT_DIR / "sentinel-origin-recovery-effect.md"
OWNER_SUMMARY_MD = REPORT_DIR / "sentinel-phase-10-22-owner-summary.md"

STATE_JSON = STATE_DIR / "origin_504_recovery.json"
HISTORY_JSON = STATE_DIR / "origin_504_recovery_history.json"
AUDIT_JSONL = AUDIT_DIR / "sentinel-504-recovery.jsonl"

PLAYBOOKS = {
    "sentinel-504-evidence-guided-recovery.playbook.json": "recovery",
    "sentinel-nowplaying-origin-recovery.playbook.json": "nowplaying",
    "sentinel-wordpress-users-me-diagnostics.playbook.json": "users_me",
    "sentinel-origin-repair-transaction.playbook.json": "transaction",
    "sentinel-504-effect-validation.playbook.json": "effect",
}

NOWPLAYING_PATH = route_mapper.NOWPLAYING_PATH
NOWPLAYING_HOST = route_mapper.NOWPLAYING_HOST
WP_USERS_ME_PATH = route_mapper.WP_USERS_ME_PATH
ZONE_APEX = route_mapper.ZONE_APEX

EVIDENCE_PROVEN = route_mapper.EVIDENCE_PROVEN
EVIDENCE_STRONG = route_mapper.EVIDENCE_STRONG
EVIDENCE_SUGGESTIVE = route_mapper.EVIDENCE_SUGGESTIVE
EVIDENCE_INSUFFICIENT = route_mapper.EVIDENCE_INSUFFICIENT
EVIDENCE_CONTRADICTED = route_mapper.EVIDENCE_CONTRADICTED
EVIDENCE_NOT_COLLECTED = "EVIDENCE_NOT_COLLECTED"

# The monitor writes a snapshot roughly every 15 minutes, so a 5-minute window
# has no evidence and is never interpolated.
SNAPSHOT_NOMINAL_MINUTES = 15
WINDOW_STEPS = {"15m": 1, "60m": 4}
SERIES_DEPTH = 10

TRACKED_ENDPOINTS: Tuple[Dict[str, str], ...] = route_mapper.FIXED_ENDPOINTS

# Repair classes that may ever be executed automatically.
REPAIR_CLASSES = {
    "R1": "sentinel_owned_cache_restoration",
    "R2": "sentinel_owned_stale_fallback_restoration",
    "R3": "exact_proxy_route_repair",
    "R4": "cache_stampede_protection",
}

# Fixed repair targets. A repair can only ever touch one of these paths, only on
# a host that authoritative DNS proves to be the origin for that endpoint.
SENTINEL_OWNED_REPAIR_TARGETS: Tuple[Dict[str, Any], ...] = (
    {
        "target_id": "nowplaying_microcache_include",
        "path": "/etc/nginx/conf.d/sentinel-nowplaying-microcache.conf",
        "endpoint": NOWPLAYING_PATH,
        "hostname": NOWPLAYING_HOST,
        "repair_classes": ("R1", "R2", "R4"),
        "sentinel_owned": True,
    },
)

FORBIDDEN_REPAIR_SUBJECTS = (
    "wordpress_code", "plugin_code", "theme_code", "database", "php_fpm_tuning",
    "global_nginx_tuning", "apache_tuning", "global_timeout_increase",
    "cloudflare_rules", "dns", "tls", "origin_migration", "load_balancer",
    "api_semantics", "frontend_polling_code", "users_me_behavior",
)

FIXED_COMMANDS = {
    "nginx_test": ("/usr/sbin/nginx", "-t"),
    "nginx_test_sudo": ("/usr/bin/sudo", "-n", "/usr/sbin/nginx", "-t"),
    "nginx_reload_sudo": ("/usr/bin/sudo", "-n", "/usr/bin/systemctl", "reload", "nginx"),
}

EXECUTION_BOUNDARIES = {
    **route_mapper.EXECUTION_BOUNDARIES,
    "blind_timeout_increase": False,
    "authenticated_endpoint_caching": False,
    "global_nginx_change": False,
    "php_fpm_change": False,
    "plugin_or_theme_change": False,
    "phase_type": "evidence_guided_recovery",
}

REPORT_CLASSIFICATION = list(route_mapper.REPORT_CLASSIFICATION)

SECRET_RE = route_mapper.SECRET_RE
PRIVATE_KEY_RE = route_mapper.PRIVATE_KEY_RE

# Identity material that must never enter an output.
FORBIDDEN_EVIDENCE_KEYS = (
    "cookie", "authorization", "token", "bearer", "session", "user_id", "userid",
    "user_login", "username", "email", "nonce", "password",
)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def rel(path: Path) -> str:
    return route_mapper.rel(path)


def is_within_project(path: Path) -> bool:
    return route_mapper.is_within_project(path)


def ensure_dirs() -> None:
    for directory in (REPORT_DIR, STATE_DIR, AUDIT_DIR, PLAYBOOK_DIR, BACKUP_DIR):
        directory.mkdir(parents=True, exist_ok=True)


def write_text(path: Path, text: str) -> None:
    route_mapper.write_text(path, text)


def write_json(path: Path, data: Any) -> None:
    route_mapper.write_json(path, data)


def append_jsonl(path: Path, row: Dict[str, Any]) -> None:
    route_mapper.append_jsonl(path, row)


def read_json(path: Path) -> Tuple[Any, str]:
    return route_mapper.read_json(path)


def load_dict(path: Path) -> Dict[str, Any]:
    return route_mapper.load_dict(path)


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
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def sha256_file(path: Path) -> Optional[str]:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def privacy_scan(payload: Any) -> List[str]:
    findings: List[str] = []

    def walk(node: Any, trail: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if any(marker in str(key).lower() for marker in FORBIDDEN_EVIDENCE_KEYS):
                    if not str(key).lower().endswith(("_present", "_evidence", "_stored", "_collected")):
                        findings.append(f"{trail}.{key}")
                walk(value, f"{trail}.{key}")
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, f"{trail}[{index}]")

    walk(payload, "evidence")
    return findings


# --------------------------------------------------------------------------- #
# Monitor snapshot series
# --------------------------------------------------------------------------- #

SNAPSHOT_DIR_RE = re.compile(r"^\d{8}-\d{6}$")


def snapshot_dirs(limit: int = SERIES_DEPTH) -> List[Path]:
    if not MONITOR_DIR.is_dir():
        return []
    candidates = [
        path for path in MONITOR_DIR.iterdir()
        if path.is_dir() and not path.is_symlink() and SNAPSHOT_DIR_RE.match(path.name)
    ]
    return sorted(candidates, key=lambda path: path.name)[-limit:]


def snapshot_timestamp(name: str) -> Optional[datetime]:
    try:
        return datetime.strptime(name, "%Y%m%d-%H%M%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def endpoint_key(host: Any, path: Any) -> str:
    return f"{host}{path}"


def read_snapshot(directory: Path) -> Dict[str, Any]:
    """Per-endpoint 5xx and request counts for one monitor snapshot."""
    result: Dict[str, Any] = {
        "snapshot_id": directory.name,
        "snapshot_at": None,
        "endpoints": {},
        "totals": {"total_5xx": 0, "504": 0, "503": 0, "522": 0, "526": 0},
        "read_status": "ok",
    }
    timestamp = snapshot_timestamp(directory.name)
    result["snapshot_at"] = timestamp.isoformat().replace("+00:00", "Z") if timestamp else None

    errors, errors_status = read_json(directory / "errors-5xx-24h.json")
    traffic, traffic_status = read_json(directory / "top-paths-24h.json")
    if errors_status != "ok":
        result["read_status"] = f"errors_{errors_status}"
        return result

    def rows_of(payload: Any) -> List[Dict[str, Any]]:
        try:
            rows = payload["data"]["viewer"]["zones"][0]["httpRequestsAdaptiveGroups"]
        except (KeyError, IndexError, TypeError):
            return []
        return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []

    for row in rows_of(errors):
        dimensions = row.get("dimensions", {})
        host = dimensions.get("clientRequestHTTPHost")
        path = dimensions.get("clientRequestPath")
        if not route_mapper.is_first_party_host(host) or not isinstance(path, str):
            continue
        count = int(row.get("count", 0) or 0)
        status_code = str(dimensions.get("edgeResponseStatus"))
        result["totals"]["total_5xx"] += count
        if status_code in result["totals"]:
            result["totals"][status_code] += count
        entry = result["endpoints"].setdefault(
            endpoint_key(host, path),
            {"hostname": host, "path": path, "total_5xx": 0, "status_counts": {}, "requests_24h": 0},
        )
        entry["total_5xx"] += count
        entry["status_counts"][status_code] = entry["status_counts"].get(status_code, 0) + count

    if traffic_status == "ok":
        for row in rows_of(traffic):
            dimensions = row.get("dimensions", {})
            host = dimensions.get("clientRequestHTTPHost")
            path = dimensions.get("clientRequestPath")
            if not route_mapper.is_first_party_host(host) or not isinstance(path, str):
                continue
            entry = result["endpoints"].setdefault(
                endpoint_key(host, path),
                {"hostname": host, "path": path, "total_5xx": 0, "status_counts": {}, "requests_24h": 0},
            )
            entry["requests_24h"] += int(row.get("count", 0) or 0)
            entry.setdefault("all_status_counts", {})
            status_code = str(dimensions.get("edgeResponseStatus"))
            entry["all_status_counts"][status_code] = (
                entry["all_status_counts"].get(status_code, 0) + int(row.get("count", 0) or 0)
            )
    else:
        result["read_status"] = f"traffic_{traffic_status}"
    return result


def load_series(depth: int = SERIES_DEPTH) -> List[Dict[str, Any]]:
    return [read_snapshot(directory) for directory in snapshot_dirs(depth)]


# --------------------------------------------------------------------------- #
# Rate engine — rolling counter versus current error production
# --------------------------------------------------------------------------- #

def endpoint_count(snapshot: Dict[str, Any], key: str, status: Optional[str] = None) -> int:
    entry = snapshot.get("endpoints", {}).get(key)
    if not entry:
        return 0
    if status is None:
        return int(entry.get("total_5xx", 0))
    return int(entry.get("status_counts", {}).get(status, 0))


def endpoint_requests(snapshot: Dict[str, Any], key: str) -> int:
    entry = snapshot.get("endpoints", {}).get(key)
    return int(entry.get("requests_24h", 0)) if entry else 0


def window_rate(
    series: List[Dict[str, Any]], key: str, steps: int, status: Optional[str] = "504"
) -> Dict[str, Any]:
    """Observed change of the 24h rolling counter over `steps` snapshots.

    The delta is directly observed. Because the window also drops errors that are
    24h old, only `max(0, delta)` is a proven lower bound for newly produced
    errors, and a delta of zero or less is consistent with no new errors at all.
    """
    if len(series) < steps + 1:
        return {
            "window_steps": steps,
            "evidence": EVIDENCE_NOT_COLLECTED,
            "reason": f"Fewer than {steps + 1} monitor snapshots are available.",
        }
    current = series[-1]
    previous = series[-1 - steps]
    current_at = parse_timestamp(current.get("snapshot_at"))
    previous_at = parse_timestamp(previous.get("snapshot_at"))
    if current_at is None or previous_at is None:
        return {"window_steps": steps, "evidence": EVIDENCE_NOT_COLLECTED, "reason": "Snapshot timestamps unusable."}
    minutes = round((current_at - previous_at).total_seconds() / 60.0, 2)
    current_count = endpoint_count(current, key, status)
    previous_count = endpoint_count(previous, key, status)
    delta = current_count - previous_count
    request_delta = endpoint_requests(current, key) - endpoint_requests(previous, key)
    return {
        "window_steps": steps,
        "window_minutes": minutes,
        "from_snapshot": previous.get("snapshot_id"),
        "to_snapshot": current.get("snapshot_id"),
        "rolling_count_before": previous_count,
        "rolling_count_now": current_count,
        "net_delta": delta,
        "new_errors_lower_bound": max(0, delta),
        "request_net_delta": request_delta,
        "decay_consistent_with_zero_new_errors": delta <= 0,
        "evidence": EVIDENCE_PROVEN,
        "interpretation": (
            "The rolling counter grew, so new errors were produced in this window."
            if delta > 0
            else "The rolling counter did not grow, which is consistent with no new errors."
        ),
    }


def endpoint_rates(series: List[Dict[str, Any]], key: str) -> Dict[str, Any]:
    rates: Dict[str, Any] = {
        "5m": {
            "evidence": EVIDENCE_NOT_COLLECTED,
            "reason": (
                f"Monitor snapshots are written about every {SNAPSHOT_NOMINAL_MINUTES} minutes; "
                "a 5-minute window is never interpolated."
            ),
        }
    }
    for label, steps in WINDOW_STEPS.items():
        rates[label] = window_rate(series, key, steps)
    return rates


# --------------------------------------------------------------------------- #
# Baseline
# --------------------------------------------------------------------------- #

def build_baseline() -> Dict[str, Any]:
    series = load_series()
    if not series:
        return {
            "schema_version": SCHEMA_VERSION,
            "generated_at_utc": utc_now(),
            "status": "BASELINE_EVIDENCE_MISSING",
            "reason": "No monitor snapshots are available.",
            "endpoints": {},
        }
    current = series[-1]
    totals = current["totals"]
    endpoints: Dict[str, Any] = {}
    for item in TRACKED_ENDPOINTS:
        key = endpoint_key(item["host"], item["path"])
        entry = current["endpoints"].get(key, {})
        endpoints[item["path"]] = {
            "hostname": item["host"],
            "path": item["path"],
            "total_5xx": int(entry.get("total_5xx", 0)),
            "count_504": int(entry.get("status_counts", {}).get("504", 0)),
            "count_503": int(entry.get("status_counts", {}).get("503", 0)),
            "requests_24h": int(entry.get("requests_24h", 0)),
            "status_mix": entry.get("all_status_counts", {}),
            "failure_ratio_percent": (
                round(int(entry.get("total_5xx", 0)) / int(entry.get("requests_24h", 0)) * 100, 2)
                if entry.get("requests_24h") else None
            ),
            "rates": endpoint_rates(series, key),
        }
    zone_key_totals = {
        "504": sum(
            endpoint_count(current, key, "504") for key in current["endpoints"]
        ),
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "status": "BASELINE_VALID",
        "report_classification": REPORT_CLASSIFICATION,
        "execution_boundaries": EXECUTION_BOUNDARIES,
        "snapshot_id": current["snapshot_id"],
        "baseline_at": current["snapshot_at"],
        "series_snapshots": [row["snapshot_id"] for row in series],
        "series_depth": len(series),
        "total_5xx": totals["total_5xx"],
        "total_504": totals["504"],
        "total_503": totals["503"],
        "total_522": totals["522"],
        "total_526": totals["526"],
        "first_party_504_total": zone_key_totals["504"],
        "nowplaying_504": endpoints.get(NOWPLAYING_PATH, {}).get("count_504", 0),
        "users_me_504": endpoints.get(WP_USERS_ME_PATH, {}).get("count_504", 0),
        "new_504_last_5m": EVIDENCE_NOT_COLLECTED,
        "new_504_last_15m": endpoints.get(NOWPLAYING_PATH, {}).get("rates", {}).get("15m", {}).get("new_errors_lower_bound"),
        "new_504_last_60m": endpoints.get(NOWPLAYING_PATH, {}).get("rates", {}).get("60m", {}).get("new_errors_lower_bound"),
        "endpoints": endpoints,
        "measurement_policy": {
            "rolling_window_is_not_current_production": True,
            "directly_observed": "net change of the 24h rolling counter between snapshots",
            "proven_lower_bound": "max(0, net_delta)",
            "never_interpolated": ["5m windows", "per-request timestamps"],
        },
    }


# --------------------------------------------------------------------------- #
# Classification
# --------------------------------------------------------------------------- #

USERS_ME_CLASSES = (
    "WP_USERS_ME_EXPECTED_ADMIN_TRAFFIC",
    "WP_USERS_ME_FRONTEND_DEPENDENCY",
    "WP_USERS_ME_PLUGIN_POLLING",
    "WP_USERS_ME_BOT_OR_SCANNER",
    "WP_USERS_ME_AUTHENTICATED_TIMEOUT",
    "WP_USERS_ME_ANONYMOUS_TIMEOUT",
    "WP_USERS_ME_ORIGIN_TIMEOUT",
    "WP_USERS_ME_REQUEST_STORM",
    "WP_USERS_ME_EVIDENCE_INSUFFICIENT",
)

# Which matched class becomes the primary one. Failure-mode classes rank above
# actor classes: an actor observation is context, never a proven cause, so a
# bot-like signal can only ever be a secondary signal.
USERS_ME_PRIMARY_PRIORITY = (
    "WP_USERS_ME_ORIGIN_TIMEOUT",
    "WP_USERS_ME_AUTHENTICATED_TIMEOUT",
    "WP_USERS_ME_ANONYMOUS_TIMEOUT",
    "WP_USERS_ME_REQUEST_STORM",
    "WP_USERS_ME_PLUGIN_POLLING",
    "WP_USERS_ME_FRONTEND_DEPENDENCY",
    "WP_USERS_ME_EXPECTED_ADMIN_TRAFFIC",
    "WP_USERS_ME_BOT_OR_SCANNER",
    "WP_USERS_ME_EVIDENCE_INSUFFICIENT",
)


def analyze_users_me(baseline: Dict[str, Any], matrix: Dict[str, Any]) -> Dict[str, Any]:
    """Read-only classification. No cookies, headers, tokens or identities."""
    endpoint = baseline.get("endpoints", {}).get(WP_USERS_ME_PATH, {})
    matrix_row = next(
        (row for row in matrix.get("endpoints", []) if row.get("endpoint") == WP_USERS_ME_PATH), {}
    )
    status_mix = endpoint.get("status_mix", {}) or {}
    count_504 = int(endpoint.get("count_504", 0))
    count_401 = int(status_mix.get("401", 0))
    count_200 = int(status_mix.get("200", 0))
    requests = int(endpoint.get("requests_24h", 0))
    rates = endpoint.get("rates", {})
    countries = matrix_row.get("country_mix", {}) or {}

    # A 401 response proves the request carried no valid authentication. A 200
    # would prove an authenticated context. Cookies and headers are never read.
    if count_401 > 0 and count_200 == 0:
        auth_evidence = "ANONYMOUS_REQUESTS_PROVEN_BY_401_RESPONSES"
        auth_level = EVIDENCE_PROVEN
    elif count_200 > 0:
        auth_evidence = "AUTHENTICATED_CONTEXT_POSSIBLE_200_RESPONSES_PRESENT"
        auth_level = EVIDENCE_STRONG
    else:
        auth_evidence = EVIDENCE_NOT_COLLECTED
        auth_level = EVIDENCE_INSUFFICIENT

    signals: List[Dict[str, Any]] = []

    def add(name: str, matched: bool, reason: str, level: str) -> None:
        signals.append({
            "classification": name,
            "matched": bool(matched),
            "reason": reason,
            "evidence_level": level if matched else EVIDENCE_INSUFFICIENT,
        })

    origin_timeout = count_504 > 0 and matrix_row.get("origin_evidence_level") in {
        EVIDENCE_PROVEN, EVIDENCE_STRONG
    }
    add(
        "WP_USERS_ME_ORIGIN_TIMEOUT",
        origin_timeout,
        f"{count_504} of {endpoint.get('total_5xx', 0)} current 5xx are gateway timeouts toward "
        f"the authoritative origin {matrix_row.get('origin')}.",
        EVIDENCE_STRONG,
    )
    anonymous_timeout = count_504 > 0 and count_401 > 0 and count_200 == 0
    add(
        "WP_USERS_ME_ANONYMOUS_TIMEOUT",
        anonymous_timeout,
        f"Every completed request answered {count_401}x 401, so the traffic reaching a response "
        "is unauthenticated; the timeouts share that population.",
        EVIDENCE_STRONG,
    )
    add(
        "WP_USERS_ME_AUTHENTICATED_TIMEOUT",
        count_200 > 0 and count_504 > 0,
        "Authenticated responses would be required to attribute timeouts to logged-in sessions."
        if count_200 == 0 else "Successful authenticated responses are present alongside timeouts.",
        EVIDENCE_SUGGESTIVE,
    )
    bot_like = len(countries) >= 3 and count_401 > 0
    add(
        "WP_USERS_ME_BOT_OR_SCANNER",
        bot_like,
        f"Unauthenticated probing of an identity endpoint from {len(countries)} countries "
        f"({', '.join(sorted(countries)[:6])}).",
        EVIDENCE_STRONG,
    )
    add(
        "WP_USERS_ME_EXPECTED_ADMIN_TRAFFIC",
        False,
        "Admin traffic would require authenticated 200 responses concentrated in one actor class.",
        EVIDENCE_INSUFFICIENT,
    )
    add(
        "WP_USERS_ME_FRONTEND_DEPENDENCY",
        False,
        "A frontend dependency would require browser referer evidence, which is not collected.",
        EVIDENCE_INSUFFICIENT,
    )
    add(
        "WP_USERS_ME_PLUGIN_POLLING",
        False,
        "Polling requires a per-path temporal distribution, which the snapshot does not contain.",
        EVIDENCE_NOT_COLLECTED,
    )
    request_rate_15m = rates.get("15m", {}).get("request_net_delta")
    storm = isinstance(request_rate_15m, int) and request_rate_15m > 200
    add(
        "WP_USERS_ME_REQUEST_STORM",
        storm,
        f"Observed request growth of {request_rate_15m} in the last window."
        if isinstance(request_rate_15m, int) else "No request-rate evidence.",
        EVIDENCE_STRONG,
    )

    matched = [row for row in signals if row["matched"]]
    order = {name: index for index, name in enumerate(USERS_ME_PRIMARY_PRIORITY)}
    if matched:
        primary = sorted(matched, key=lambda row: order.get(row["classification"], 99))[0]
    else:
        primary = {"classification": "WP_USERS_ME_EVIDENCE_INSUFFICIENT", "reason": "No signal matched."}

    analysis = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "status": primary["classification"],
        "report_classification": REPORT_CLASSIFICATION,
        "execution_boundaries": EXECUTION_BOUNDARIES,
        "endpoint": WP_USERS_ME_PATH,
        "hostname": ZONE_APEX,
        "primary_classification": primary["classification"],
        "primary_reason": primary.get("reason"),
        "secondary_signals": [
            row["classification"] for row in matched if row["classification"] != primary["classification"]
        ],
        "candidate_signals": signals,
        "allowed_classifications": list(USERS_ME_CLASSES),
        "evidence": {
            "current_504": count_504,
            "current_401": count_401,
            "current_200": count_200,
            "requests_24h": requests or None,
            "failure_ratio_percent": endpoint.get("failure_ratio_percent"),
            "country_classes": sorted(countries),
            "country_count": len(countries),
            "authenticated_request_evidence": auth_evidence,
            "authenticated_request_evidence_level": auth_level,
            "cookie_present_evidence": EVIDENCE_NOT_COLLECTED,
            "authorization_header_present_evidence": EVIDENCE_NOT_COLLECTED,
            "temporal_clustering": EVIDENCE_NOT_COLLECTED,
            "request_rate_windows": rates,
            "origin": matrix_row.get("origin"),
            "origin_class": matrix_row.get("origin_class"),
            "origin_evidence_level": matrix_row.get("origin_evidence_level"),
        },
        "privacy": {
            "cookies_stored": False,
            "authorization_headers_stored": False,
            "tokens_stored": False,
            "session_ids_stored": False,
            "user_ids_collected": False,
            "personal_data_collected": False,
        },
        "safety": {
            "automatic_caching_forbidden": True,
            "automatic_modification_forbidden": True,
            "auth_bypass_forbidden": True,
            "rest_permission_change_forbidden": True,
            "block_rule_forbidden": True,
            "reason": (
                "The identity endpoint can carry authenticated context, so Phase 10.22 stays "
                "diagnostic and repairs only causes outside authentication semantics."
            ),
        },
        "repairability": "OWNER_REVIEW_ONLY",
        "automatic_repair_allowed": False,
        "missing_evidence": [
            "per-path temporal distribution",
            "referer class",
            "cookie/authorization presence (forbidden to collect)",
        ],
    }
    findings = privacy_scan(analysis["evidence"])
    analysis["privacy"]["forbidden_field_findings"] = findings
    analysis["privacy"]["privacy_status"] = "USERS_ME_PRIVACY_OK" if not findings else "USERS_ME_PRIVACY_VIOLATION"
    return analysis


# --------------------------------------------------------------------------- #
# Failure graph and repairability
# --------------------------------------------------------------------------- #

def layer_state(status: Any, evidence: str) -> str:
    if evidence in {EVIDENCE_INSUFFICIENT, EVIDENCE_NOT_COLLECTED} or status in (None, "unknown", "NOT_PROBED"):
        return "unknown"
    text = str(status).upper()
    if "TIMEOUT" in text or "UNREACHABLE" in text or "SERVER_ERROR" in text:
        return "failing"
    if "CHALLENGE" in text or "OTHER" in text:
        return "warning"
    return "healthy"


def build_failure_graph(route_map: Dict[str, Any], baseline: Dict[str, Any]) -> Dict[str, Any]:
    nodes: List[Dict[str, Any]] = []
    for route in route_map.get("routes", []):
        path = route.get("endpoint")
        endpoint_baseline = baseline.get("endpoints", {}).get(path, {})
        if not int(endpoint_baseline.get("total_5xx", 0)):
            continue
        chain = []
        for step in route.get("chain", []):
            chain.append({
                "layer": step["layer"],
                "observed": step["status"],
                "state": layer_state(step["status"], step["evidence_level"]),
                "evidence_level": step["evidence_level"],
            })
        failing = [step for step in chain if step["state"] == "failing"]
        unknown = [step for step in chain if step["state"] == "unknown"]
        nodes.append({
            "endpoint": path,
            "hostname": route.get("hostname"),
            "current_504": endpoint_baseline.get("count_504"),
            "current_5xx": endpoint_baseline.get("total_5xx"),
            "chain": chain,
            "failing_layers": [step["layer"] for step in failing],
            "unknown_layers": [step["layer"] for step in unknown],
            "first_failing_layer": failing[0]["layer"] if failing else None,
            "causality_status": route.get("causality_status"),
            "evidence_level": route.get("evidence_level"),
        })
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "status": "ORIGIN_FAILURE_GRAPH_OK" if nodes else "ORIGIN_FAILURE_GRAPH_EMPTY",
        "report_classification": REPORT_CLASSIFICATION,
        "execution_boundaries": EXECUTION_BOUNDARIES,
        "legend": ["healthy", "warning", "failing", "unknown"],
        "endpoints": sorted(nodes, key=lambda row: -int(row.get("current_5xx") or 0)),
        "counts": {
            "endpoints_with_failures": len(nodes),
            "endpoints_with_proven_failing_layer": sum(1 for row in nodes if row["first_failing_layer"]),
        },
    }


def repair_target_for(path: str) -> Optional[Dict[str, Any]]:
    for target in SENTINEL_OWNED_REPAIR_TARGETS:
        if target["endpoint"] == path:
            return target
    return None


def build_repairability(
    matrix: Dict[str, Any], graph: Dict[str, Any], baseline: Dict[str, Any], users_me: Dict[str, Any]
) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    graph_by_endpoint = {row["endpoint"]: row for row in graph.get("endpoints", [])}
    for row in matrix.get("endpoints", []):
        path = row["endpoint"]
        endpoint_baseline = baseline.get("endpoints", {}).get(path, {})
        failure_count = int(endpoint_baseline.get("total_5xx", 0))
        graph_row = graph_by_endpoint.get(path, {})
        target = repair_target_for(path)
        cause_known = row.get("evidence_level") == EVIDENCE_PROVEN and bool(graph_row.get("first_failing_layer"))
        origin_known = row.get("origin_evidence_level") == EVIDENCE_PROVEN
        origin_local = bool(row.get("origin_local_to_sentinel_host"))

        if path == WP_USERS_ME_PATH:
            repair_class = None
            allowed = False
            owner_review = True
            reason = users_me.get("safety", {}).get("reason", "Identity endpoint stays diagnostic.")
        elif not origin_known:
            repair_class, allowed, owner_review = None, False, True
            reason = "No authoritative origin record."
        elif not origin_local:
            repair_class, allowed, owner_review = None, False, True
            reason = (
                f"The authoritative origin {row.get('origin')} is not this Sentinel host and no "
                "verified access profile exists."
            )
        elif target is None:
            repair_class, allowed, owner_review = None, False, True
            reason = "No Sentinel-owned repair target is registered for this endpoint."
        elif not cause_known:
            repair_class, allowed, owner_review = None, False, True
            reason = "The failing layer is not PROVEN; a repair would be a guess."
        else:
            repair_class = target["repair_classes"][0]
            allowed = True
            owner_review = False
            reason = "Origin is local, cause is proven and a Sentinel-owned target exists."

        rows.append({
            "endpoint": path,
            "hostname": row.get("hostname"),
            "failure_count": failure_count,
            "current_504": int(endpoint_baseline.get("count_504", 0)),
            "primary_failure_mode": row.get("causality_status"),
            "origin": row.get("origin"),
            "origin_known": origin_known,
            "origin_local_to_sentinel_host": origin_local,
            "cause_known": cause_known,
            "first_failing_layer": graph_row.get("first_failing_layer"),
            "repair_class": repair_class,
            "repair_target": target["path"] if target and allowed else None,
            "automatic_repair_allowed": allowed,
            "owner_review_required": owner_review,
            "rollback_available": bool(target) and allowed,
            "reason": reason,
        })

    allowed_rows = [row for row in rows if row["automatic_repair_allowed"]]
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "status": "REPAIRABILITY_MATRIX_OK",
        "report_classification": REPORT_CLASSIFICATION,
        "execution_boundaries": EXECUTION_BOUNDARIES,
        "repair_classes": REPAIR_CLASSES,
        "forbidden_repair_subjects": list(FORBIDDEN_REPAIR_SUBJECTS),
        "endpoints": sorted(rows, key=lambda row: -row["failure_count"]),
        "automatic_repair_candidates": [row["endpoint"] for row in allowed_rows],
        "counts": {
            "endpoints": len(rows),
            "automatic_repair_allowed": len(allowed_rows),
            "owner_review_required": sum(1 for row in rows if row["owner_review_required"]),
        },
    }


# --------------------------------------------------------------------------- #
# Failure budget and primary focus
# --------------------------------------------------------------------------- #

def build_failure_budget(baseline: Dict[str, Any], endpoint_path: str) -> Dict[str, Any]:
    endpoint = baseline.get("endpoints", {}).get(endpoint_path, {})
    rate_15m = endpoint.get("rates", {}).get("15m", {})
    observed = rate_15m.get("new_errors_lower_bound")
    if not isinstance(observed, int):
        return {
            "endpoint": endpoint_path,
            "status": "FAILURE_BUDGET_EVIDENCE_MISSING",
            "reason": "No observed 15-minute rate is available.",
        }
    target = max(0, int(observed * 0.5))
    return {
        "endpoint": endpoint_path,
        "status": "FAILURE_BUDGET_SET",
        "baseline_504_rate_15m": observed,
        "target_504_rate_15m": target,
        "minimum_improvement_percent": 50,
        "maximum_allowed_health_regressions": 0,
        "measurement_basis": "observed net change of the 24h rolling counter, lower bound",
    }


def primary_failure_focus(baseline: Dict[str, Any], repairability: Dict[str, Any]) -> Dict[str, Any]:
    """Rank by current new-error contribution first, not by the 24h total alone."""
    candidates: List[Dict[str, Any]] = []
    for path, endpoint in baseline.get("endpoints", {}).items():
        rate_15m = endpoint.get("rates", {}).get("15m", {})
        new_lower_bound = rate_15m.get("new_errors_lower_bound")
        requests = endpoint.get("requests_24h") or 0
        repair_row = next(
            (row for row in repairability.get("endpoints", []) if row["endpoint"] == path), {}
        )
        candidates.append({
            "endpoint": path,
            "new_errors_lower_bound_15m": new_lower_bound if isinstance(new_lower_bound, int) else 0,
            "current_504": int(endpoint.get("count_504", 0)),
            "failure_ratio_percent": endpoint.get("failure_ratio_percent") or 0.0,
            "requests_24h": requests,
            "safely_repairable": bool(repair_row.get("automatic_repair_allowed")),
        })
    ranked = sorted(
        candidates,
        key=lambda row: (
            -row["new_errors_lower_bound_15m"],
            -row["failure_ratio_percent"],
            -row["current_504"],
            not row["safely_repairable"],
        ),
    )
    top = ranked[0] if ranked else {}
    focus_map = {
        NOWPLAYING_PATH: "AI_RADIO_NOWPLAYING_RECOVERY",
        "/api/time": "AI_RADIO_API_STABILITY",
        WP_USERS_ME_PATH: "WORDPRESS_REST_IDENTITY_TIMEOUT_REVIEW",
    }
    return {
        "primary_failure_focus": focus_map.get(top.get("endpoint"), "WEBSITE_ORIGIN_STABILITY"),
        "endpoint": top.get("endpoint"),
        "ranking_basis": [
            "largest current new error contribution",
            "highest 504 failure ratio",
            "largest confirmed user impact",
            "safely repairable cause",
        ],
        "ranked": ranked[:5],
    }


# --------------------------------------------------------------------------- #
# Repair transaction
# --------------------------------------------------------------------------- #

def repair_decision_gate(repairability: Dict[str, Any]) -> Dict[str, Any]:
    """Every condition must hold. Otherwise NO_SAFE_AUTOMATIC_REPAIR."""
    candidates = [row for row in repairability.get("endpoints", []) if row["automatic_repair_allowed"]]
    blockers: List[str] = []
    if not candidates:
        blockers.append("no endpoint has a proven cause with a local Sentinel-owned target")
    selected = candidates[0] if candidates else None
    if selected:
        if selected.get("repair_class") not in REPAIR_CLASSES:
            blockers.append("repair class is not in the allowlist")
        if not selected.get("rollback_available"):
            blockers.append("no rollback is available")
        if not selected.get("origin_local_to_sentinel_host"):
            blockers.append("origin is not this host")
        if not selected.get("cause_known"):
            blockers.append("cause is not PROVEN")
    return {
        "status": "REPAIR_GATE_OPEN" if selected and not blockers else "NO_SAFE_AUTOMATIC_REPAIR",
        "selected_endpoint": selected.get("endpoint") if selected else None,
        "repair_class": selected.get("repair_class") if selected else None,
        "repair_target": selected.get("repair_target") if selected else None,
        "blockers": blockers,
        "required_conditions": [
            "causality evidence=PROVEN",
            "repairability=SAFE",
            "repair_class in [R1,R2,R3,R4]",
            "rollback_ready=true",
            "scope_exact=true",
        ],
    }


def run_fixed_command(command_id: str, timeout: int = 30) -> Dict[str, Any]:
    command = FIXED_COMMANDS.get(command_id)
    if command is None:
        return {"command_id": command_id, "returncode": 126, "stderr": "command_not_allowlisted"}
    try:
        result = subprocess.run(
            list(command), capture_output=True, text=True, timeout=timeout, shell=False, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"command_id": command_id, "returncode": 127, "stderr": type(exc).__name__}
    return {
        "command_id": command_id,
        "returncode": result.returncode,
        "stdout": result.stdout.strip()[:600],
        "stderr": result.stderr.strip()[:600],
    }


def new_transaction(gate: Dict[str, Any], baseline: Dict[str, Any]) -> Dict[str, Any]:
    endpoint = gate.get("selected_endpoint")
    target_path = gate.get("repair_target")
    transaction_id = f"repair-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{sha256_text(str(endpoint))[:8]}"
    return {
        "transaction_id": transaction_id,
        "created_at_utc": utc_now(),
        "repair_class": gate.get("repair_class"),
        "target_origin": "local_sentinel_host",
        "target_file": target_path,
        "target_endpoint": endpoint,
        "evidence": {"gate_status": gate.get("status"), "blockers": gate.get("blockers", [])},
        "baseline": build_failure_budget(baseline, endpoint) if endpoint else None,
        "backup": None,
        "before_hash": sha256_file(Path(target_path)) if target_path else None,
        "candidate_hash": None,
        "validation": None,
        "apply": None,
        "after_hash": None,
        "health_canary": None,
        "effect_measurement": None,
        "rollback": {"available": False, "executed": False},
        "audit": [],
        "status": "TRANSACTION_PREPARED" if gate.get("status") == "REPAIR_GATE_OPEN" else "TRANSACTION_BLOCKED",
    }


def prepare_repair() -> Dict[str, Any]:
    baseline = load_dict(BASELINE_JSON) or build_baseline()
    repairability = load_dict(REPAIRABILITY_JSON)
    if not repairability:
        return {
            "status": "NO_SAFE_AUTOMATIC_REPAIR",
            "reason": "Run --build-repairability first.",
            "transaction": None,
        }
    gate = repair_decision_gate(repairability)
    transaction = new_transaction(gate, baseline)
    return {
        "status": gate["status"],
        "gate": gate,
        "transaction": transaction,
        "reason": (
            "; ".join(gate["blockers"]) if gate["blockers"]
            else "A proven, scoped repair candidate exists."
        ),
    }


def validate_repair(prepared: Dict[str, Any]) -> Dict[str, Any]:
    """Configuration validation before anything is applied."""
    if prepared.get("status") != "REPAIR_GATE_OPEN":
        return {
            "status": "REPAIR_VALIDATION_SKIPPED",
            "reason": prepared.get("reason", "No open repair gate."),
            "nginx_test": None,
        }
    test = run_fixed_command("nginx_test_sudo")
    if test["returncode"] != 0:
        test = run_fixed_command("nginx_test")
    return {
        "status": "REPAIR_VALIDATION_OK" if test["returncode"] == 0 else "REPAIR_VALIDATION_FAILED",
        "nginx_test": test,
        "reason": "Configuration must validate before and after any candidate is written.",
    }


# --------------------------------------------------------------------------- #
# Effect measurement and false-success guards
# --------------------------------------------------------------------------- #

def evaluate_effect(
    baseline: Dict[str, Any],
    endpoint_path: Optional[str] = None,
    recorded_baseline: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Compare the current window against the recorded baseline, with guards.

    `recorded_baseline` overrides the stored state, which keeps the comparison
    deterministic for tests and for an explicit before/after evaluation.
    """
    if recorded_baseline is not None:
        recorded = recorded_baseline
        endpoint_path = endpoint_path or NOWPLAYING_PATH
    else:
        state = load_dict(STATE_JSON)
        recorded = state.get("baseline") if isinstance(state.get("baseline"), dict) else {}
        endpoint_path = endpoint_path or state.get("dominant_endpoint") or NOWPLAYING_PATH
    current = baseline.get("endpoints", {}).get(endpoint_path, {})
    previous = recorded.get("endpoints", {}).get(endpoint_path, {}) if recorded else {}

    if not previous:
        return {
            "schema_version": SCHEMA_VERSION,
            "generated_at_utc": utc_now(),
            "status": "EFFECT_BASELINE_MISSING",
            "endpoint": endpoint_path,
            "reason": "No earlier baseline is stored for comparison.",
        }

    baseline_rate = previous.get("rates", {}).get("15m", {}).get("new_errors_lower_bound")
    post_rate = current.get("rates", {}).get("15m", {}).get("new_errors_lower_bound")
    baseline_requests = previous.get("requests_24h", 0)
    post_requests = current.get("requests_24h", 0)

    if not isinstance(baseline_rate, int) or not isinstance(post_rate, int):
        return {
            "schema_version": SCHEMA_VERSION,
            "generated_at_utc": utc_now(),
            "status": "EFFECT_EVIDENCE_INSUFFICIENT",
            "endpoint": endpoint_path,
            "reason": "No comparable observed rates.",
        }

    absolute_delta = post_rate - baseline_rate
    relative = round((absolute_delta / baseline_rate) * 100, 2) if baseline_rate else None

    guards: List[Dict[str, Any]] = []

    def guard(name: str, triggered: bool, detail: str) -> None:
        guards.append({"guard": name, "triggered": bool(triggered), "detail": detail})

    traffic_collapsed = post_requests <= max(1, int(baseline_requests * 0.2)) and baseline_requests > 0
    guard(
        "traffic_disappeared", traffic_collapsed,
        f"requests 24h went from {baseline_requests} to {post_requests}",
    )
    guard(
        "monitor_stale",
        baseline.get("snapshot_id") == recorded.get("snapshot_id"),
        "the current snapshot is identical to the baseline snapshot",
    )
    migration = status_migration(recorded, baseline)
    guard(
        "error_migration", migration["migrated"],
        f"503 delta {migration['delta_503']}, 522 delta {migration['delta_522']}, "
        f"526 delta {migration['delta_526']} against 504 delta {migration['delta_504']}",
    )
    endpoint_unreachable = post_requests == 0 and baseline_requests > 0
    guard("endpoint_unreachable", endpoint_unreachable, "no requests observed at all")

    triggered = [row for row in guards if row["triggered"]]
    if triggered:
        status = "NOT_PROVEN_SUCCESS" if not migration["migrated"] else "RECOVERY_REGRESSION"
    elif absolute_delta < 0:
        status = "RECOVERY_EFFECT_POSITIVE"
    elif absolute_delta == 0:
        status = "RECOVERY_EFFECT_NEUTRAL"
    else:
        status = "RECOVERY_EFFECT_NEGATIVE"

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "status": status,
        "report_classification": REPORT_CLASSIFICATION,
        "endpoint": endpoint_path,
        "baseline_snapshot": recorded.get("snapshot_id"),
        "current_snapshot": baseline.get("snapshot_id"),
        "baseline_rate": baseline_rate,
        "post_apply_rate": post_rate,
        "absolute_delta": absolute_delta,
        "relative_delta_percent": relative,
        "window_minutes": current.get("rates", {}).get("15m", {}).get("window_minutes"),
        "confidence": EVIDENCE_PROVEN if not triggered else EVIDENCE_INSUFFICIENT,
        "baseline_requests_24h": baseline_requests,
        "post_requests_24h": post_requests,
        "guards": guards,
        "triggered_guards": [row["guard"] for row in triggered],
        "error_migration": migration,
        "rolling_window_decay": (
            "PENDING" if current.get("count_504", 0) > 0 else "CONFIRMED"
        ),
    }


def status_migration(previous_baseline: Dict[str, Any], current_baseline: Dict[str, Any]) -> Dict[str, Any]:
    """Errors that merely change status code are not a recovery."""
    def total(payload: Dict[str, Any], key: str) -> int:
        return int(payload.get(key, 0) or 0)

    delta_504 = total(current_baseline, "total_504") - total(previous_baseline, "total_504")
    delta_503 = total(current_baseline, "total_503") - total(previous_baseline, "total_503")
    delta_522 = total(current_baseline, "total_522") - total(previous_baseline, "total_522")
    delta_526 = total(current_baseline, "total_526") - total(previous_baseline, "total_526")
    compensating = delta_503 + delta_522 + delta_526
    migrated = delta_504 < 0 and compensating >= abs(delta_504) * 0.8 and compensating > 0
    return {
        "delta_504": delta_504,
        "delta_503": delta_503,
        "delta_522": delta_522,
        "delta_526": delta_526,
        "compensating_growth": compensating,
        "migrated": migrated,
        "interpretation": (
            "Reduced 504s are matched by equivalent growth in other error classes."
            if migrated else "No equivalent compensating error growth observed."
        ),
    }


def counterfactual(dominant: Dict[str, Any], gate: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "without_change": (
            "The observed new-error production for the dominant endpoint continues at the "
            "measured baseline rate."
        ),
        "should_change_if_hypothesis_correct": [
            "new targeted 504 lower bound falls materially below baseline",
            "target endpoint keeps answering at the origin",
        ],
        "should_remain_unchanged": [
            "request volume for the endpoint",
            "503/522/526 totals",
            "homepage and robots availability",
        ],
        "applies_to": dominant.get("endpoint"),
        "repair_gate": gate.get("status"),
        "evaluated": gate.get("status") == "REPAIR_GATE_OPEN",
    }


# --------------------------------------------------------------------------- #
# Assembly
# --------------------------------------------------------------------------- #

def build_recovery(persist_outputs: bool = True) -> Dict[str, Any]:
    ensure_dirs()
    baseline = build_baseline()
    route_map = load_dict(route_mapper.ROUTE_MAP_JSON)
    matrix = load_dict(route_mapper.ENDPOINT_MATRIX_JSON)
    chain = load_dict(route_mapper.NOWPLAYING_CHAIN_JSON)
    users_me = analyze_users_me(baseline, matrix)
    graph = build_failure_graph(route_map, baseline)
    repairability = build_repairability(matrix, graph, baseline, users_me)
    gate = repair_decision_gate(repairability)
    focus = primary_failure_focus(baseline, repairability)
    budget = build_failure_budget(baseline, focus.get("endpoint") or NOWPLAYING_PATH)
    effect = evaluate_effect(baseline)
    # Without an applied repair there is nothing whose effect could be measured.
    # The comparison is still kept, but as observed drift, never as a repair effect.
    previous_state = load_dict(STATE_JSON)
    if not previous_state.get("last_repair"):
        effect = {
            **effect,
            "status": "NO_REPAIR_APPLIED_EFFECT_NOT_APPLICABLE",
            "repair_applied": False,
            "observed_drift_status": effect.get("status"),
            "reason": (
                "No repair transaction has been applied, so the window comparison below is "
                "observed drift between snapshots, not a repair effect."
            ),
        }

    dominant = max(
        baseline.get("endpoints", {}).items(),
        key=lambda item: int(item[1].get("count_504", 0)),
        default=(None, {}),
    )
    dominant_path, dominant_row = dominant
    dominant_matrix = next(
        (row for row in matrix.get("endpoints", []) if row.get("endpoint") == dominant_path), {}
    )
    total_504 = int(baseline.get("total_504", 0))
    dominant_share = (
        round(int(dominant_row.get("count_504", 0)) / total_504 * 100, 2) if total_504 else None
    )

    recovery = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "status": (
            "ORIGIN_RECOVERY_OWNER_ACTION_REQUIRED" if gate["status"] == "NO_SAFE_AUTOMATIC_REPAIR"
            else "ORIGIN_RECOVERY_REPAIR_CANDIDATE_READY"
        ),
        "report_classification": REPORT_CLASSIFICATION,
        "execution_boundaries": EXECUTION_BOUNDARIES,
        "route_map_status": route_map.get("status", "NOT_RUN"),
        "baseline": baseline,
        "dominant_504_endpoint": dominant_path,
        "dominant_504_count": int(dominant_row.get("count_504", 0)) if dominant_row else 0,
        "dominant_504_share_percent": dominant_share,
        "dominant_504_origin": dominant_matrix.get("origin"),
        "dominant_origin_evidence": dominant_matrix.get("origin_evidence_level"),
        "primary_failure_focus": focus,
        "failure_budget": budget,
        "nowplaying_chain": {
            "failure_class": chain.get("failure_class"),
            "failure_evidence_level": chain.get("failure_evidence_level"),
            "failure_reason": chain.get("failure_reason"),
            "origin_target": chain.get("origin_target"),
            "origin_local_to_sentinel_host": chain.get("origin_local_to_sentinel_host"),
            "cache_layer_verdict": chain.get("cache_layer", {}).get("verdict"),
            "repairability": chain.get("repairability"),
        },
        "users_me": {
            "primary_classification": users_me.get("primary_classification"),
            "secondary_signals": users_me.get("secondary_signals"),
            "authenticated_request_evidence": users_me.get("evidence", {}).get("authenticated_request_evidence"),
            "repairability": users_me.get("repairability"),
        },
        "failure_graph": graph,
        "repairability_matrix": repairability,
        "repair_gate": gate,
        "counterfactual": counterfactual(focus, gate),
        "effect": effect,
        "owner_action_required": gate["status"] == "NO_SAFE_AUTOMATIC_REPAIR",
        "remaining_evidence_gaps": evidence_gaps(matrix, chain, users_me),
        "breach": False,
    }

    if persist_outputs:
        persist(recovery, baseline, graph, repairability, users_me, effect)
    return recovery


def evidence_gaps(matrix: Dict[str, Any], chain: Dict[str, Any], users_me: Dict[str, Any]) -> List[str]:
    gaps: List[str] = []
    if chain.get("failure_evidence_level") != EVIDENCE_PROVEN:
        gaps.append(
            "origin-side reverse proxy and upstream logs for the NowPlaying endpoint "
            "(required to prove which layer times out)"
        )
    for row in matrix.get("endpoints", []):
        if row.get("origin_evidence_level") != EVIDENCE_PROVEN:
            gaps.append(f"authoritative origin evidence for {row.get('endpoint')}")
    gaps.extend(users_me.get("missing_evidence", []))
    gaps.append("per-request timestamps for 5-minute windows (monitor cadence is 15 minutes)")
    return sorted(set(gaps))


def persist(
    recovery: Dict[str, Any],
    baseline: Dict[str, Any],
    graph: Dict[str, Any],
    repairability: Dict[str, Any],
    users_me: Dict[str, Any],
    effect: Dict[str, Any],
) -> None:
    write_json(BASELINE_JSON, baseline)
    write_text(BASELINE_MD, render_baseline(baseline))
    write_json(RECOVERY_JSON, recovery)
    write_text(RECOVERY_MD, render_recovery(recovery))
    write_json(FAILURE_GRAPH_JSON, graph)
    write_text(FAILURE_GRAPH_MD, render_failure_graph(graph))
    write_json(REPAIRABILITY_JSON, repairability)
    write_text(REPAIRABILITY_MD, render_repairability(repairability))
    write_json(USERS_ME_JSON, users_me)
    write_text(USERS_ME_MD, render_users_me(users_me))
    write_json(EFFECT_JSON, effect)
    write_text(EFFECT_MD, render_effect(effect))
    write_text(OWNER_SUMMARY_MD, render_owner_summary(recovery))
    for name, kind in PLAYBOOKS.items():
        write_json(PLAYBOOK_DIR / name, build_playbook(kind))

    state = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": recovery["generated_at_utc"],
        "status": recovery["status"],
        "baseline": baseline,
        "current": {
            "snapshot_id": baseline.get("snapshot_id"),
            "total_5xx": baseline.get("total_5xx"),
            "total_504": baseline.get("total_504"),
        },
        "dominant_endpoint": recovery["dominant_504_endpoint"],
        "dominant_origin": recovery["dominant_504_origin"],
        "causality": recovery["nowplaying_chain"],
        "repairability": {
            "automatic_repair_candidates": repairability.get("automatic_repair_candidates", []),
            "owner_review_required": repairability.get("counts", {}).get("owner_review_required"),
        },
        "active_transaction": None,
        "last_repair": None,
        "effect": {"status": effect.get("status")},
        "rollback": {"available": False, "executed": False},
    }
    write_json(STATE_JSON, state)
    history, status = read_json(HISTORY_JSON)
    if status != "ok" or not isinstance(history, list):
        history = []
    history.append({
        "generated_at_utc": state["generated_at_utc"],
        "status": state["status"],
        "snapshot_id": baseline.get("snapshot_id"),
        "total_504": baseline.get("total_504"),
        "dominant_endpoint": state["dominant_endpoint"],
        "repair_gate": recovery["repair_gate"]["status"],
    })
    write_json(HISTORY_JSON, history[-300:])
    append_jsonl(AUDIT_JSONL, {
        "timestamp_utc": state["generated_at_utc"],
        "event": "504_recovery_evaluated",
        "status": state["status"],
        "dominant_endpoint": state["dominant_endpoint"],
        "repair_gate": recovery["repair_gate"]["status"],
        "repair_applied": False,
        "rollback_executed": False,
        "cloudflare_writes": 0,
        "nginx_changes": 0,
    })


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

def private_header(title: str) -> List[str]:
    return [f"# {title}", "", "Classification: " + " | ".join(REPORT_CLASSIFICATION), ""]


def render_baseline(baseline: Dict[str, Any]) -> str:
    lines = private_header("Sentinel 504 Baseline")
    lines += [
        f"- status: `{baseline.get('status')}`",
        f"- snapshot: `{baseline.get('snapshot_id')}`",
        f"- baseline at: `{baseline.get('baseline_at')}`",
        f"- series depth: `{baseline.get('series_depth')}`",
        "",
        "## Rolling Totals (24h window)",
        "",
        f"- total 5xx: `{baseline.get('total_5xx')}`",
        f"- 504: `{baseline.get('total_504')}`",
        f"- 503: `{baseline.get('total_503')}`",
        f"- 522: `{baseline.get('total_522')}`",
        f"- 526: `{baseline.get('total_526')}`",
        "",
        "## Current Error Production",
        "",
        "The 24h counter is not current error production. Only the change between "
        "consecutive snapshots is directly observed.",
        "",
        f"- 5m window: `{baseline.get('new_504_last_5m')}`",
        "",
        "| Endpoint | 504 | 5xx | Requests | Fail% | 15m net delta | 15m new lower bound | 60m net delta |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for path, row in baseline.get("endpoints", {}).items():
        rate15 = row.get("rates", {}).get("15m", {})
        rate60 = row.get("rates", {}).get("60m", {})
        lines.append(
            f"| `{path}` | {row.get('count_504')} | {row.get('total_5xx')} | "
            f"{row.get('requests_24h') or '-'} | {row.get('failure_ratio_percent') if row.get('failure_ratio_percent') is not None else '-'} | "
            f"{rate15.get('net_delta', '-')} | {rate15.get('new_errors_lower_bound', '-')} | "
            f"{rate60.get('net_delta', '-')} |"
        )
    lines += [
        "",
        "## Measurement Policy",
        "",
        "- directly observed: net change of the 24h rolling counter between snapshots",
        "- proven lower bound for new errors: `max(0, net_delta)`",
        "- a net delta of zero or less is consistent with no new errors",
        "- never interpolated: 5-minute windows, per-request timestamps",
    ]
    return "\n".join(lines)


def render_failure_graph(graph: Dict[str, Any]) -> str:
    lines = private_header("Sentinel Origin Failure Graph")
    lines += [
        f"- status: `{graph.get('status')}`",
        f"- generated: `{graph.get('generated_at_utc')}`",
        f"- legend: `{', '.join(graph.get('legend', []))}`",
        "",
    ]
    for row in graph.get("endpoints", []):
        lines += [
            f"## `{row['endpoint']}`",
            "",
            f"- current 504: `{row['current_504']}` of `{row['current_5xx']}` 5xx",
            f"- causality: `{row['causality_status']}` (`{row['evidence_level']}`)",
            f"- first failing layer: `{row['first_failing_layer'] or 'not proven'}`",
            f"- unknown layers: `{', '.join(row['unknown_layers']) or 'none'}`",
            "",
            "```text",
        ]
        for index, step in enumerate(row["chain"]):
            arrow = "" if index == 0 else "  -> "
            lines.append(f"{arrow}{step['layer']}: {step['state']} ({step['evidence_level']})")
        lines += ["```", ""]
    return "\n".join(lines)


def render_repairability(repairability: Dict[str, Any]) -> str:
    lines = private_header("Sentinel Repairability Matrix")
    lines += [
        f"- status: `{repairability.get('status')}`",
        f"- automatic repair candidates: `{', '.join(repairability.get('automatic_repair_candidates', [])) or 'none'}`",
        "",
        "| Endpoint | 5xx | 504 | Origin | Origin known | Local | Cause known | Class | Auto | Owner review | Rollback |",
        "|---|---:|---:|---|---|---|---|---|---|---|---|",
    ]
    for row in repairability.get("endpoints", []):
        lines.append(
            f"| `{row['endpoint']}` | {row['failure_count']} | {row['current_504']} | "
            f"`{row['origin']}` | `{str(row['origin_known']).lower()}` | "
            f"`{str(row['origin_local_to_sentinel_host']).lower()}` | `{str(row['cause_known']).lower()}` | "
            f"`{row['repair_class'] or '-'}` | `{str(row['automatic_repair_allowed']).lower()}` | "
            f"`{str(row['owner_review_required']).lower()}` | `{str(row['rollback_available']).lower()}` |"
        )
    lines += ["", "## Reasons", ""]
    for row in repairability.get("endpoints", []):
        lines.append(f"- `{row['endpoint']}`: {row['reason']}")
    lines += [
        "",
        "## Repair Classes",
        "",
    ]
    for key, value in repairability.get("repair_classes", {}).items():
        lines.append(f"- `{key}`: {value}")
    lines += ["", "## Always Owner Review", ""]
    for subject in repairability.get("forbidden_repair_subjects", []):
        lines.append(f"- `{subject}`")
    return "\n".join(lines)


def render_users_me(analysis: Dict[str, Any]) -> str:
    evidence = analysis.get("evidence", {})
    lines = private_header("Sentinel WordPress REST Identity Analysis")
    lines += [
        f"- endpoint: `{analysis.get('endpoint')}`",
        f"- primary classification: `{analysis.get('primary_classification')}`",
        f"- secondary signals: `{', '.join(analysis.get('secondary_signals', [])) or 'none'}`",
        f"- repairability: `{analysis.get('repairability')}`",
        f"- automatic repair allowed: `{str(analysis.get('automatic_repair_allowed')).lower()}`",
        "",
        analysis.get("primary_reason", ""),
        "",
        "## Evidence",
        "",
        f"- current 504: `{evidence.get('current_504')}`",
        f"- current 401: `{evidence.get('current_401')}`",
        f"- current 200: `{evidence.get('current_200')}`",
        f"- requests 24h: `{evidence.get('requests_24h')}`",
        f"- failure ratio: `{evidence.get('failure_ratio_percent')}%`",
        f"- country classes: `{', '.join(evidence.get('country_classes', [])) or 'unknown'}`",
        f"- authenticated request evidence: `{evidence.get('authenticated_request_evidence')}` "
        f"(`{evidence.get('authenticated_request_evidence_level')}`)",
        f"- cookie presence: `{evidence.get('cookie_present_evidence')}`",
        f"- authorization header presence: `{evidence.get('authorization_header_present_evidence')}`",
        f"- temporal clustering: `{evidence.get('temporal_clustering')}`",
        f"- origin: `{evidence.get('origin')}` (`{evidence.get('origin_evidence_level')}`)",
        "",
        "## Candidate Signals",
        "",
        "| Classification | Matched | Evidence | Reason |",
        "|---|---|---|---|",
    ]
    for row in analysis.get("candidate_signals", []):
        lines.append(
            f"| `{row['classification']}` | `{str(row['matched']).lower()}` | "
            f"`{row['evidence_level']}` | {row['reason']} |"
        )
    safety = analysis.get("safety", {})
    privacy = analysis.get("privacy", {})
    lines += [
        "",
        "## Safety",
        "",
        f"- automatic caching forbidden: `{str(safety.get('automatic_caching_forbidden')).lower()}`",
        f"- automatic modification forbidden: `{str(safety.get('automatic_modification_forbidden')).lower()}`",
        f"- auth bypass forbidden: `{str(safety.get('auth_bypass_forbidden')).lower()}`",
        f"- REST permission change forbidden: `{str(safety.get('rest_permission_change_forbidden')).lower()}`",
        f"- block rule forbidden: `{str(safety.get('block_rule_forbidden')).lower()}`",
        f"- {safety.get('reason')}",
        "",
        "## Privacy",
        "",
        f"- privacy status: `{privacy.get('privacy_status')}`",
        f"- cookies stored: `{str(privacy.get('cookies_stored')).lower()}`",
        f"- authorization headers stored: `{str(privacy.get('authorization_headers_stored')).lower()}`",
        f"- tokens stored: `{str(privacy.get('tokens_stored')).lower()}`",
        f"- user ids collected: `{str(privacy.get('user_ids_collected')).lower()}`",
        "",
        "## Missing Evidence",
        "",
    ]
    for item in analysis.get("missing_evidence", []):
        lines.append(f"- {item}")
    return "\n".join(lines)


def render_effect(effect: Dict[str, Any]) -> str:
    lines = private_header("Sentinel Origin Recovery Effect")
    lines += [
        f"- status: `{effect.get('status')}`",
        f"- endpoint: `{effect.get('endpoint')}`",
        f"- generated: `{effect.get('generated_at_utc')}`",
    ]
    if effect.get("status") == "NO_REPAIR_APPLIED_EFFECT_NOT_APPLICABLE":
        lines += [
            f"- repair applied: `false`",
            f"- observed drift status: `{effect.get('observed_drift_status')}`",
            f"- reason: {effect.get('reason')}",
        ]
    if effect.get("status") in {"EFFECT_BASELINE_MISSING", "EFFECT_EVIDENCE_INSUFFICIENT"}:
        lines += ["", f"- reason: {effect.get('reason')}"]
        return "\n".join(lines)
    lines += [
        f"- baseline snapshot: `{effect.get('baseline_snapshot')}`",
        f"- current snapshot: `{effect.get('current_snapshot')}`",
        f"- baseline rate: `{effect.get('baseline_rate')}`",
        f"- post rate: `{effect.get('post_apply_rate')}`",
        f"- absolute delta: `{effect.get('absolute_delta')}`",
        f"- relative delta: `{effect.get('relative_delta_percent')}%`",
        f"- window minutes: `{effect.get('window_minutes')}`",
        f"- confidence: `{effect.get('confidence')}`",
        f"- rolling window decay: `{effect.get('rolling_window_decay')}`",
        "",
        "## False Success Guards",
        "",
        "| Guard | Triggered | Detail |",
        "|---|---|---|",
    ]
    for row in effect.get("guards", []):
        lines.append(f"| `{row['guard']}` | `{str(row['triggered']).lower()}` | {row['detail']} |")
    migration = effect.get("error_migration", {})
    lines += [
        "",
        "## Error Migration",
        "",
        f"- 504 delta: `{migration.get('delta_504')}`",
        f"- 503 delta: `{migration.get('delta_503')}`",
        f"- 522 delta: `{migration.get('delta_522')}`",
        f"- 526 delta: `{migration.get('delta_526')}`",
        f"- migrated: `{str(migration.get('migrated')).lower()}`",
        f"- {migration.get('interpretation')}",
    ]
    return "\n".join(lines)


def render_recovery(recovery: Dict[str, Any]) -> str:
    lines = private_header("Sentinel 504 Recovery")
    gate = recovery.get("repair_gate", {})
    chain = recovery.get("nowplaying_chain", {})
    focus = recovery.get("primary_failure_focus", {})
    lines += [
        f"- status: `{recovery.get('status')}`",
        f"- route map: `{recovery.get('route_map_status')}`",
        f"- dominant 504 endpoint: `{recovery.get('dominant_504_endpoint')}` "
        f"(`{recovery.get('dominant_504_count')}`, `{recovery.get('dominant_504_share_percent')}%` of 504)",
        f"- dominant 504 origin: `{recovery.get('dominant_504_origin')}` "
        f"(`{recovery.get('dominant_origin_evidence')}`)",
        f"- primary failure focus: `{focus.get('primary_failure_focus')}`",
        f"- owner action required: `{str(recovery.get('owner_action_required')).lower()}`",
        "",
        "## Repair Gate",
        "",
        f"- status: `{gate.get('status')}`",
        f"- selected endpoint: `{gate.get('selected_endpoint') or 'none'}`",
        f"- repair class: `{gate.get('repair_class') or 'none'}`",
        "",
        "Blockers:",
        "",
    ]
    for blocker in gate.get("blockers", []) or ["none"]:
        lines.append(f"- {blocker}")
    lines += [
        "",
        "## NowPlaying Chain",
        "",
        f"- failure class: `{chain.get('failure_class')}` (`{chain.get('failure_evidence_level')}`)",
        f"- origin: `{chain.get('origin_target')}`",
        f"- local to Sentinel host: `{str(chain.get('origin_local_to_sentinel_host')).lower()}`",
        f"- cache layer: `{chain.get('cache_layer_verdict')}`",
        f"- {chain.get('failure_reason')}",
        "",
        "## Failure Budget",
        "",
        f"```json\n{json.dumps(recovery.get('failure_budget', {}), indent=2, sort_keys=True)}\n```",
        "",
        "## Counterfactual",
        "",
        f"```json\n{json.dumps(recovery.get('counterfactual', {}), indent=2, sort_keys=True)}\n```",
        "",
        "## Remaining Evidence Gaps",
        "",
    ]
    for gap in recovery.get("remaining_evidence_gaps", []):
        lines.append(f"- {gap}")
    return "\n".join(lines)


def render_owner_summary(recovery: Dict[str, Any]) -> str:
    baseline = recovery.get("baseline", {})
    chain = recovery.get("nowplaying_chain", {})
    users_me = recovery.get("users_me", {})
    gate = recovery.get("repair_gate", {})
    lines = private_header("Sentinel Phase 10.22 Owner Summary")
    lines += [
        f"- status: `{recovery.get('status')}`",
        f"- generated: `{recovery.get('generated_at_utc')}`",
        "",
        "## What is proven",
        "",
        f"- The dominant 504 endpoint is `{recovery.get('dominant_504_endpoint')}` with "
        f"`{recovery.get('dominant_504_count')}` of `{baseline.get('total_504')}` current 504 "
        f"(`{recovery.get('dominant_504_share_percent')}%`).",
        f"- Its authoritative origin is `{chain.get('origin_target')}`, which is "
        f"`{'this Sentinel host' if chain.get('origin_local_to_sentinel_host') else 'NOT this Sentinel host'}`.",
        f"- The Sentinel cache lane at that origin is `{chain.get('cache_layer_verdict')}`.",
        f"- The WordPress identity endpoint classifies as `{users_me.get('primary_classification')}` "
        f"with `{users_me.get('authenticated_request_evidence')}`.",
        "",
        "## What is not proven",
        "",
        f"- {chain.get('failure_reason')}",
        "",
        "## Why no automatic repair ran",
        "",
    ]
    for blocker in gate.get("blockers", []) or ["the repair gate was open"]:
        lines.append(f"- {blocker}")
    lines += [
        "",
        "## Owner actions that would close the evidence gap",
        "",
    ]
    for gap in recovery.get("remaining_evidence_gaps", []):
        lines.append(f"- {gap}")
    lines += [
        "",
        "## Safety",
        "",
        "- No Cloudflare, DNS, TLS or WAF change was made.",
        "- No WordPress, database or global nginx change was made.",
        "- No timeout was increased to hide a 504.",
        "- No authenticated REST endpoint was cached.",
    ]
    return "\n".join(lines)


def build_playbook(kind: str) -> Dict[str, Any]:
    base = {
        "schema_version": SCHEMA_VERSION,
        "status": "PLAYBOOK_ACTIVE",
        "principle": "evidence first, repair second, measurement third, rollback always",
        "execution_boundaries": EXECUTION_BOUNDARIES,
    }
    if kind == "recovery":
        base.update({
            "name": "sentinel-504-evidence-guided-recovery",
            "sequence": [
                "collect-baseline", "classify", "build-failure-graph", "build-repairability",
                "prepare-repair", "validate-repair", "apply-approved-repair",
                "validate-post-apply", "evaluate-effect",
            ],
            "gate": [
                "causality evidence=PROVEN", "repairability=SAFE",
                "repair_class in [R1,R2,R3,R4]", "rollback_ready=true", "scope_exact=true",
            ],
            "valid_outcomes": [
                "SAFE_REPAIR_APPLIED", "NO_SAFE_AUTOMATIC_REPAIR", "CAUSE_EVIDENCE_INSUFFICIENT",
            ],
        })
    elif kind == "nowplaying":
        base.update({
            "name": "sentinel-nowplaying-origin-recovery",
            "endpoint": NOWPLAYING_PATH,
            "probe_ladder": ["edge", "origin_with_host_header", "reverse_proxy", "upstream", "application"],
            "classes": list(route_mapper.NOWPLAYING_CLASSES),
            "rule": "a historical cache confirmation is never current evidence",
        })
    elif kind == "users_me":
        base.update({
            "name": "sentinel-wordpress-users-me-diagnostics",
            "endpoint": WP_USERS_ME_PATH,
            "classes": list(USERS_ME_CLASSES),
            "forbidden": [
                "caching", "public response storage", "auth bypass", "ignoring cookies",
                "REST permission change", "WordPress code change", "challenge rule", "block rule",
            ],
            "never_stored": ["cookies", "authorization headers", "tokens", "session ids", "user ids"],
        })
    elif kind == "transaction":
        base.update({
            "name": "sentinel-origin-repair-transaction",
            "fields": [
                "transaction_id", "repair_class", "target_origin", "target_file", "target_endpoint",
                "evidence", "baseline", "backup", "before_hash", "candidate_hash", "validation",
                "apply", "after_hash", "health_canary", "effect_measurement", "rollback", "audit",
            ],
            "repair_classes": REPAIR_CLASSES,
            "allowed_targets": [target["path"] for target in SENTINEL_OWNED_REPAIR_TARGETS],
            "rollback_triggers": [
                "config validation failure", "reload failure", "target endpoint regression",
                "homepage regression", "robots failure", "TLS failure", "redirect drift",
                "new 5xx spike", "new 504 rate worse than baseline", "unexpected path impact",
                "hash mismatch", "scope expansion", "audit failure",
            ],
        })
    else:
        base.update({
            "name": "sentinel-504-effect-validation",
            "windows": ["T+0", "T+15s", "T+60s", "T+3m", "T+15m"],
            "success_levels": ["immediate_green", "short_term_green", "strong_green", "24h_confirmed"],
            "false_success_guards": [
                "traffic_disappeared", "monitor_stale", "error_migration", "endpoint_unreachable",
            ],
            "rule": "the 24h counter alone never proves success or failure",
        })
    return base


# --------------------------------------------------------------------------- #
# Self-test
# --------------------------------------------------------------------------- #

def _fixture_series(counts: List[int], requests: Optional[List[int]] = None) -> List[Dict[str, Any]]:
    key = f"{NOWPLAYING_HOST}{NOWPLAYING_PATH}"
    series = []
    for index, value in enumerate(counts):
        minute = index * SNAPSHOT_NOMINAL_MINUTES
        timestamp = datetime(2026, 8, 12, 0, 0, tzinfo=timezone.utc).replace(
            minute=minute % 60, hour=minute // 60
        )
        series.append({
            "snapshot_id": timestamp.strftime("%Y%m%d-%H%M%S"),
            "snapshot_at": timestamp.isoformat().replace("+00:00", "Z"),
            "endpoints": {
                key: {
                    "hostname": NOWPLAYING_HOST,
                    "path": NOWPLAYING_PATH,
                    "total_5xx": value,
                    "status_counts": {"504": value},
                    "requests_24h": (requests[index] if requests else 1000),
                }
            },
            "totals": {"total_5xx": value, "504": value, "503": 0, "522": 0, "526": 0},
            "read_status": "ok",
        })
    return series


def run_self_test() -> Dict[str, Any]:
    checks: Dict[str, Any] = {}
    key = f"{NOWPLAYING_HOST}{NOWPLAYING_PATH}"

    # Test C — old errors stay in the window while new production has stopped.
    stopped = _fixture_series([500, 495, 490, 485, 480])
    rate = window_rate(stopped, key, 1)
    checks["test_c_no_new_errors_lower_bound"] = rate["new_errors_lower_bound"] == 0
    checks["test_c_decay_consistent"] = rate["decay_consistent_with_zero_new_errors"] is True
    checks["test_c_rolling_still_high"] = rate["rolling_count_now"] == 480
    growing = _fixture_series([400, 420, 450])
    checks["test_c_growth_is_proven"] = window_rate(growing, key, 1)["new_errors_lower_bound"] == 30

    # 5-minute windows are never interpolated.
    checks["no_5m_interpolation"] = (
        endpoint_rates(stopped, key)["5m"]["evidence"] == EVIDENCE_NOT_COLLECTED
    )
    checks["short_series_not_invented"] = (
        window_rate(_fixture_series([100]), key, 1)["evidence"] == EVIDENCE_NOT_COLLECTED
    )

    # Test I — traffic disappears, so a zero error count proves nothing.
    baseline_before = {
        "snapshot_id": "20260812-120000", "total_504": 500, "total_503": 10, "total_522": 0, "total_526": 0,
        "endpoints": {NOWPLAYING_PATH: {
            "requests_24h": 700, "count_504": 300,
            "rates": {"15m": {"new_errors_lower_bound": 20, "window_minutes": 15.0}},
        }},
    }
    baseline_after_no_traffic = {
        "snapshot_id": "20260812-121500", "total_504": 480, "total_503": 10, "total_522": 0, "total_526": 0,
        "endpoints": {NOWPLAYING_PATH: {
            "requests_24h": 0, "count_504": 280,
            "rates": {"15m": {"new_errors_lower_bound": 0, "window_minutes": 15.0}},
        }},
    }
    effect_no_traffic = _effect_with_state(baseline_before, baseline_after_no_traffic)
    checks["test_i_traffic_disappeared"] = (
        effect_no_traffic["status"] == "NOT_PROVEN_SUCCESS"
        and "traffic_disappeared" in effect_no_traffic["triggered_guards"]
    )

    # Test J — errors merely migrate to another status class.
    baseline_migrated = {
        "snapshot_id": "20260812-121500", "total_504": 400, "total_503": 110, "total_522": 0, "total_526": 0,
        "endpoints": {NOWPLAYING_PATH: {
            "requests_24h": 700, "count_504": 200,
            "rates": {"15m": {"new_errors_lower_bound": 2, "window_minutes": 15.0}},
        }},
    }
    effect_migrated = _effect_with_state(baseline_before, baseline_migrated)
    checks["test_j_error_migration"] = effect_migrated["status"] == "RECOVERY_REGRESSION"
    checks["test_j_migration_detected"] = effect_migrated["error_migration"]["migrated"] is True

    # A genuine improvement with stable traffic and no migration.
    baseline_improved = {
        "snapshot_id": "20260812-121500", "total_504": 480, "total_503": 10, "total_522": 0, "total_526": 0,
        "endpoints": {NOWPLAYING_PATH: {
            "requests_24h": 690, "count_504": 280,
            "rates": {"15m": {"new_errors_lower_bound": 3, "window_minutes": 15.0}},
        }},
    }
    effect_good = _effect_with_state(baseline_before, baseline_improved)
    checks["genuine_improvement_detected"] = (
        effect_good["status"] == "RECOVERY_EFFECT_POSITIVE"
        and effect_good["relative_delta_percent"] == -85.0
        and not effect_good["triggered_guards"]
    )
    checks["rolling_decay_pending_while_counter_high"] = effect_good["rolling_window_decay"] == "PENDING"

    # Test D/E — the gate decides, not the wish to repair.
    remote_matrix = {"endpoints": [{
        "endpoint": NOWPLAYING_PATH, "hostname": NOWPLAYING_HOST, "origin": "203.0.113.10",
        "origin_evidence_level": EVIDENCE_PROVEN, "origin_local_to_sentinel_host": False,
        "evidence_level": EVIDENCE_PROVEN, "causality_status": "ORIGIN_TIMEOUT_REPRODUCED",
        "country_mix": {},
    }]}
    graph_fixture = {"endpoints": [{
        "endpoint": NOWPLAYING_PATH, "first_failing_layer": "origin_host", "unknown_layers": [],
    }]}
    baseline_fixture = {"endpoints": {NOWPLAYING_PATH: {"total_5xx": 300, "count_504": 300}}}
    users_me_fixture = {"safety": {"reason": "identity endpoint"}, "missing_evidence": []}
    remote_repairability = build_repairability(remote_matrix, graph_fixture, baseline_fixture, users_me_fixture)
    remote_gate = repair_decision_gate(remote_repairability)
    checks["test_a_remote_origin_blocks_repair"] = (
        remote_gate["status"] == "NO_SAFE_AUTOMATIC_REPAIR"
        and remote_repairability["endpoints"][0]["automatic_repair_allowed"] is False
    )

    local_matrix = json.loads(json.dumps(remote_matrix))
    local_matrix["endpoints"][0]["origin_local_to_sentinel_host"] = True
    local_repairability = build_repairability(local_matrix, graph_fixture, baseline_fixture, users_me_fixture)
    local_gate = repair_decision_gate(local_repairability)
    checks["test_d_local_proven_cause_opens_gate"] = (
        local_gate["status"] == "REPAIR_GATE_OPEN" and local_gate["repair_class"] in REPAIR_CLASSES
    )
    checks["gate_target_is_allowlisted"] = local_gate["repair_target"] in {
        target["path"] for target in SENTINEL_OWNED_REPAIR_TARGETS
    }

    unproven_matrix = json.loads(json.dumps(local_matrix))
    unproven_matrix["endpoints"][0]["evidence_level"] = EVIDENCE_STRONG
    unproven_gate = repair_decision_gate(
        build_repairability(unproven_matrix, graph_fixture, baseline_fixture, users_me_fixture)
    )
    checks["test_h_unproven_cause_blocks_repair"] = unproven_gate["status"] == "NO_SAFE_AUTOMATIC_REPAIR"

    # Test F — the identity endpoint is never automatically repairable.
    users_me_matrix = {"endpoints": [{
        "endpoint": WP_USERS_ME_PATH, "hostname": ZONE_APEX, "origin": "203.0.113.20",
        "origin_evidence_level": EVIDENCE_PROVEN, "origin_local_to_sentinel_host": True,
        "evidence_level": EVIDENCE_PROVEN, "causality_status": "ORIGIN_TIMEOUT_REPRODUCED",
        "country_mix": {"US": 20, "VN": 7, "IN": 4},
    }]}
    users_me_repairability = build_repairability(
        users_me_matrix,
        {"endpoints": [{"endpoint": WP_USERS_ME_PATH, "first_failing_layer": "origin_host", "unknown_layers": []}]},
        {"endpoints": {WP_USERS_ME_PATH: {"total_5xx": 62, "count_504": 62}}},
        users_me_fixture,
    )
    checks["test_f_users_me_never_automatic"] = (
        users_me_repairability["endpoints"][0]["automatic_repair_allowed"] is False
        and users_me_repairability["endpoints"][0]["owner_review_required"] is True
    )

    # Test G — a bot signal without causality stays secondary and creates no rule.
    users_me_baseline = {"endpoints": {WP_USERS_ME_PATH: {
        "count_504": 62, "total_5xx": 62, "requests_24h": 102,
        "status_mix": {"401": 51, "504": 51}, "failure_ratio_percent": 60.8,
        "rates": {"15m": {"new_errors_lower_bound": 1, "request_net_delta": 2}},
    }}}
    users_me_analysis = analyze_users_me(users_me_baseline, users_me_matrix)
    checks["test_g_bot_is_secondary_only"] = (
        "WP_USERS_ME_BOT_OR_SCANNER" in users_me_analysis["secondary_signals"]
        and users_me_analysis["primary_classification"] != "WP_USERS_ME_BOT_OR_SCANNER"
        and users_me_analysis["automatic_repair_allowed"] is False
    )
    checks["test_f_auth_evidence_from_401"] = (
        users_me_analysis["evidence"]["authenticated_request_evidence"]
        == "ANONYMOUS_REQUESTS_PROVEN_BY_401_RESPONSES"
    )
    checks["users_me_privacy_clean"] = (
        users_me_analysis["privacy"]["privacy_status"] == "USERS_ME_PRIVACY_OK"
    )
    checks["users_me_classes_declared"] = (
        users_me_analysis["primary_classification"] in USERS_ME_CLASSES
        and all(row["classification"] in USERS_ME_CLASSES for row in users_me_analysis["candidate_signals"])
        and set(USERS_ME_PRIMARY_PRIORITY) == set(USERS_ME_CLASSES)
    )
    checks["actor_class_never_primary_over_cause"] = (
        USERS_ME_PRIMARY_PRIORITY.index("WP_USERS_ME_BOT_OR_SCANNER")
        > USERS_ME_PRIMARY_PRIORITY.index("WP_USERS_ME_ORIGIN_TIMEOUT")
    )
    checks["privacy_scan_detects_identity_keys"] = privacy_scan(
        {"rows": [{"cookie": "x"}, {"user_id": 7}]}
    ) != []
    checks["privacy_scan_allows_boolean_markers"] = privacy_scan(
        {"cookie_present_evidence": "EVIDENCE_NOT_COLLECTED", "tokens_stored": False}
    ) == []

    # Failure budget must come from observed data, never from a wish.
    budget = build_failure_budget(
        {"endpoints": {NOWPLAYING_PATH: {"rates": {"15m": {"new_errors_lower_bound": 12}}}}},
        NOWPLAYING_PATH,
    )
    checks["failure_budget_dynamic"] = (
        budget["baseline_504_rate_15m"] == 12 and budget["target_504_rate_15m"] == 6
    )
    checks["failure_budget_requires_evidence"] = (
        build_failure_budget({"endpoints": {}}, NOWPLAYING_PATH)["status"]
        == "FAILURE_BUDGET_EVIDENCE_MISSING"
    )

    # Focus ranks current production above the 24h total.
    focus = primary_failure_focus(
        {"endpoints": {
            "/big-old": {"count_504": 900, "requests_24h": 1000, "failure_ratio_percent": 90.0,
                         "rates": {"15m": {"new_errors_lower_bound": 0}}},
            NOWPLAYING_PATH: {"count_504": 100, "requests_24h": 300, "failure_ratio_percent": 33.0,
                              "rates": {"15m": {"new_errors_lower_bound": 25}}},
        }},
        {"endpoints": []},
    )
    checks["focus_prefers_current_production"] = focus["endpoint"] == NOWPLAYING_PATH

    # Structural safety.
    source_text = Path(__file__).read_text(encoding="utf-8")
    checks["no_shell_true"] = not re.search(r"shell\s*=\s*True", source_text)
    checks["fixed_commands_only"] = all(isinstance(value, tuple) for value in FIXED_COMMANDS.values())
    checks["no_nginx_restart"] = "restart" not in " ".join(
        " ".join(command) for command in FIXED_COMMANDS.values()
    )
    checks["repair_targets_fixed"] = all(
        target["sentinel_owned"] and target["path"].startswith("/etc/nginx/")
        for target in SENTINEL_OWNED_REPAIR_TARGETS
    )
    checks["execution_boundaries_closed"] = all(
        value is False for key, value in EXECUTION_BOUNDARIES.items() if isinstance(value, bool)
    )
    checks["no_free_cli_targets"] = not re.search(r'add_argument\(\s*"--(?:host|url|path|target|file)"', source_text)

    findings = [name for name, value in checks.items() if not value]
    return {
        "status": "504_RECOVERY_SELF_TEST_OK" if not findings else "504_RECOVERY_SELF_TEST_FAILED",
        "checks": checks,
        "findings": findings,
        "breach": False,
    }


def _effect_with_state(previous: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
    """Effect evaluation against an explicit earlier baseline."""
    return evaluate_effect(current, NOWPLAYING_PATH, recorded_baseline=previous)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Sentinel evidence-guided 504 recovery (Phase 10.22)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--collect-baseline", action="store_true")
    group.add_argument("--classify", action="store_true")
    group.add_argument("--build-failure-graph", action="store_true")
    group.add_argument("--build-repairability", action="store_true")
    group.add_argument("--prepare-repair", action="store_true")
    group.add_argument("--validate-repair", action="store_true")
    group.add_argument("--apply-approved-repair", action="store_true")
    group.add_argument("--validate-post-apply", action="store_true")
    group.add_argument("--evaluate-effect", action="store_true")
    group.add_argument("--rollback", action="store_true")
    group.add_argument("--status", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        result = run_self_test()
        print(result["status"])
        for name in result["findings"]:
            print(f"finding={name}")
        return 0 if not result["findings"] else 1

    if args.collect_baseline:
        ensure_dirs()
        baseline = build_baseline()
        write_json(BASELINE_JSON, baseline)
        write_text(BASELINE_MD, render_baseline(baseline))
        print(baseline["status"])
        print(f"snapshot={baseline.get('snapshot_id')}")
        print(f"total_5xx={baseline.get('total_5xx')} total_504={baseline.get('total_504')}")
        print(f"new_504_last_5m={baseline.get('new_504_last_5m')}")
        print(f"new_504_last_15m={baseline.get('new_504_last_15m')}")
        print(f"new_504_last_60m={baseline.get('new_504_last_60m')}")
        return 0 if baseline["status"] == "BASELINE_VALID" else 2

    if args.classify:
        recovery = build_recovery()
        print(recovery["status"])
        print(f"dominant_endpoint={recovery['dominant_504_endpoint']}")
        print(f"dominant_share_percent={recovery['dominant_504_share_percent']}")
        print(f"nowplaying_class={recovery['nowplaying_chain']['failure_class']}")
        print(f"nowplaying_evidence={recovery['nowplaying_chain']['failure_evidence_level']}")
        print(f"users_me_class={recovery['users_me']['primary_classification']}")
        print(f"primary_failure_focus={recovery['primary_failure_focus']['primary_failure_focus']}")
        return 0

    if args.build_failure_graph:
        recovery = build_recovery()
        graph = recovery["failure_graph"]
        print(graph["status"])
        for row in graph.get("endpoints", []):
            print(
                f"{row['endpoint']} 504={row['current_504']} "
                f"first_failing_layer={row['first_failing_layer'] or 'not_proven'} "
                f"unknown={','.join(row['unknown_layers']) or 'none'}"
            )
        return 0

    if args.build_repairability:
        recovery = build_recovery()
        matrix = recovery["repairability_matrix"]
        print(matrix["status"])
        for row in matrix.get("endpoints", []):
            print(
                f"{row['endpoint']} class={row['repair_class'] or 'none'} "
                f"auto={str(row['automatic_repair_allowed']).lower()} "
                f"owner_review={str(row['owner_review_required']).lower()} reason={row['reason']}"
            )
        print(f"repair_gate={recovery['repair_gate']['status']}")
        return 0

    if args.prepare_repair:
        prepared = prepare_repair()
        print(prepared["status"])
        print(f"reason={prepared['reason']}")
        if prepared.get("transaction"):
            print(f"transaction_id={prepared['transaction']['transaction_id']}")
            print(f"transaction_status={prepared['transaction']['status']}")
        return 0 if prepared["status"] == "REPAIR_GATE_OPEN" else 3

    if args.validate_repair:
        prepared = prepare_repair()
        validation = validate_repair(prepared)
        print(validation["status"])
        print(f"reason={validation['reason']}")
        return 0 if validation["status"] in {"REPAIR_VALIDATION_OK", "REPAIR_VALIDATION_SKIPPED"} else 2

    if args.apply_approved_repair:
        prepared = prepare_repair()
        if prepared["status"] != "REPAIR_GATE_OPEN":
            print("NO_SAFE_AUTOMATIC_REPAIR")
            print(f"reason={prepared['reason']}")
            print("repair_applied=false")
            append_jsonl(AUDIT_JSONL, {
                "timestamp_utc": utc_now(),
                "event": "apply_refused",
                "reason": prepared["reason"],
                "repair_applied": False,
            })
            return 3
        print("REPAIR_APPLY_REQUIRES_PREPARED_CANDIDATE_CONTENT")
        print("reason=No candidate configuration content is generated without a proven repair plan.")
        print("repair_applied=false")
        return 3

    if args.validate_post_apply:
        state = load_dict(STATE_JSON)
        transaction = state.get("active_transaction")
        if not transaction:
            print("POST_APPLY_VALIDATION_SKIPPED")
            print("reason=No active repair transaction.")
            return 0
        print("POST_APPLY_VALIDATION_PENDING")
        return 0

    if args.evaluate_effect:
        baseline = build_baseline()
        effect = evaluate_effect(baseline)
        ensure_dirs()
        write_json(EFFECT_JSON, effect)
        write_text(EFFECT_MD, render_effect(effect))
        print(effect["status"])
        for key in ("endpoint", "baseline_rate", "post_apply_rate", "relative_delta_percent", "confidence"):
            if key in effect:
                print(f"{key}={effect.get(key)}")
        if effect.get("triggered_guards"):
            print(f"triggered_guards={','.join(effect['triggered_guards'])}")
        return 0

    if args.rollback:
        state = load_dict(STATE_JSON)
        rollback = state.get("rollback", {}) if isinstance(state.get("rollback"), dict) else {}
        if not rollback.get("available"):
            print("ROLLBACK_NOT_APPLICABLE")
            print("reason=No applied repair transaction exists.")
            return 0
        print("ROLLBACK_PENDING")
        return 0

    state = load_dict(STATE_JSON)
    if not state:
        print("504_RECOVERY_NOT_RUN")
        return 1
    print(state.get("status", "NOT_RUN"))
    print(f"snapshot={state.get('current', {}).get('snapshot_id')}")
    print(f"total_504={state.get('current', {}).get('total_504')}")
    print(f"dominant_endpoint={state.get('dominant_endpoint')}")
    print(f"dominant_origin={state.get('dominant_origin')}")
    print(f"automatic_repair_candidates={state.get('repairability', {}).get('automatic_repair_candidates')}")
    print(f"effect={state.get('effect', {}).get('status')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
