#!/usr/bin/env python3
"""Build a local, shadow-only operational evidence twin for Sentinel.

The twin normalizes existing local evidence, fingerprints incident regimes,
builds a provenance graph, evaluates a provisional technical reliability
budget, and replays action policy in shadow mode. It has no network, shell,
remote-write, scheduler, credential, or production mutation capability.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import statistics
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


PROJECT_DIR = Path(__file__).resolve().parent
SCHEMA_VERSION = "sentinel-operational-evidence-twin-1"

CONFIG_PATH = PROJECT_DIR / "config/operational-evidence-twin-policy.json"
CLOUDFLARE_ROOT = PROJECT_DIR / "cloudflare-monitor"
REPORT_DIR = PROJECT_DIR / "reports/latest"
STATE_DIR = PROJECT_DIR / "state/adaptive-learning"
AUDIT_DIR = PROJECT_DIR / "audit"
PLAYBOOK_DIR = PROJECT_DIR / "playbooks"

MASTER_JSON = REPORT_DIR / "sentinel-master-consistency.json"
ORIGIN_JSON = REPORT_DIR / "sentinel-origin-failure-diagnostics.json"
IONOS_JSON = REPORT_DIR / "sentinel-ionos-webspace-owner-evidence.json"
RUNTIME_JSON = REPORT_DIR / "sentinel-guarded-runtime-activation.json"
ORIGIN_HISTORY_JSON = STATE_DIR / "origin_failure_diagnostics_history.json"

REPORT_JSON = REPORT_DIR / "sentinel-operational-evidence-twin.json"
REPORT_MD = REPORT_DIR / "sentinel-operational-evidence-twin.md"
EVENTS_JSON = REPORT_DIR / "sentinel-normalized-evidence-events.json"
GRAPH_JSON = REPORT_DIR / "sentinel-incident-evidence-graph.json"
GRAPH_MD = REPORT_DIR / "sentinel-incident-evidence-graph.md"
REGIME_MD = REPORT_DIR / "sentinel-operational-regime-analysis.md"
RELIABILITY_MD = REPORT_DIR / "sentinel-reliability-budget.md"
SHADOW_JSON = REPORT_DIR / "sentinel-counterfactual-shadow-replay.json"
SHADOW_MD = REPORT_DIR / "sentinel-counterfactual-shadow-replay.md"
OWNER_MD = REPORT_DIR / "sentinel-evidence-twin-owner-plan.md"
PUBLIC_MD = REPORT_DIR / "sentinel-evidence-twin-public-summary.md"
VALIDATION_MD = REPORT_DIR / "sentinel-operational-evidence-twin-validation.md"

STATE_JSON = STATE_DIR / "operational_evidence_twin.json"
LATEST_STATE_JSON = STATE_DIR / "latest_operational_evidence_twin.json"
HISTORY_JSON = STATE_DIR / "operational_evidence_twin_history.json"
FINGERPRINTS_JSON = STATE_DIR / "operational_incident_fingerprints.json"
AUDIT_JSONL = AUDIT_DIR / "sentinel-operational-evidence-twin.jsonl"

PLAYBOOKS = (
    PLAYBOOK_DIR / "sentinel-operational-evidence-twin.playbook.json",
    PLAYBOOK_DIR / "sentinel-evidence-normalization.playbook.json",
    PLAYBOOK_DIR / "sentinel-counterfactual-replay.playbook.json",
    PLAYBOOK_DIR / "sentinel-reliability-budget.playbook.json",
)

OUTPUT_JSONS = (
    REPORT_JSON,
    EVENTS_JSON,
    GRAPH_JSON,
    SHADOW_JSON,
    STATE_JSON,
    LATEST_STATE_JSON,
    HISTORY_JSON,
    FINGERPRINTS_JSON,
    *PLAYBOOKS,
)
OUTPUT_MARKDOWN = (
    REPORT_MD,
    GRAPH_MD,
    REGIME_MD,
    RELIABILITY_MD,
    SHADOW_MD,
    OWNER_MD,
    PUBLIC_MD,
    VALIDATION_MD,
)

REPORT_CLASSIFICATION = [
    "PRIVATE_OWNER_OPERATIONAL_REPORT",
    "NOT_FOR_PUBLIC_RELEASE",
    "NOT_FOR_GIT",
    "CONTAINS_INFRASTRUCTURE_METADATA",
]

SAFETY = {
    "mode": "SHADOW_ONLY",
    "live_apply": False,
    "remote_write": False,
    "network_access": False,
    "shell_execution": False,
    "scheduler_install": False,
    "medium_executable": False,
    "high_executable": False,
    "breach": False,
}

RECOMMENDED_GIT_FILES = [
    "sentinel_operational_evidence_twin.py",
    "config/operational-evidence-twin-policy.json",
    "docs/architecture/OPERATIONAL-EVIDENCE-TWIN.md",
    "playbooks/sentinel-operational-evidence-twin.playbook.json",
    "playbooks/sentinel-evidence-normalization.playbook.json",
    "playbooks/sentinel-counterfactual-replay.playbook.json",
    "playbooks/sentinel-reliability-budget.playbook.json",
]

SNAPSHOT_RE = re.compile(r"^\d{8}-\d{6}$")
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
FQDN_RE = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b")
PRIVATE_PATH_RE = re.compile(r"/(?:srv|etc|var|home|root|opt|mnt|tmp)/[^\s\]})>,\"']+")
SECRET_RE = re.compile(
    r"(?i)(?:password|passwd|secret|api[_-]?key|access[_-]?token|private[_-]?key)\s*[:=]\s*[^\s,;]+"
)
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


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
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def iso_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(PROJECT_DIR))
    except (OSError, ValueError):
        return str(path)


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (OSError, ValueError):
        return False


def read_json(path: Path) -> Tuple[Any, str]:
    if path.is_symlink() or not is_within(path, PROJECT_DIR):
        return None, "blocked_path"
    if not path.exists():
        return None, "missing"
    try:
        if path.stat().st_size > 16 * 1024 * 1024:
            return None, "too_large"
        return json.loads(path.read_text(encoding="utf-8")), "ok"
    except (OSError, json.JSONDecodeError):
        return None, "invalid"


def load_dict(path: Path) -> Dict[str, Any]:
    value, status = read_json(path)
    return value if status == "ok" and isinstance(value, dict) else {}


def ensure_output_dirs() -> None:
    for path in (REPORT_DIR, STATE_DIR, AUDIT_DIR):
        path.mkdir(parents=True, exist_ok=True)


def output_path_allowed(path: Path) -> bool:
    return any(is_within(path, root) for root in (REPORT_DIR, STATE_DIR, AUDIT_DIR))


def write_text(path: Path, text: str) -> None:
    if path.is_symlink() or not output_path_allowed(path):
        raise ValueError(f"blocked output path: {path.name}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    if temporary.is_symlink():
        raise ValueError(f"blocked temporary path: {temporary.name}")
    temporary.write_text(text.rstrip() + "\n", encoding="utf-8")
    temporary.replace(path)


def write_json(path: Path, data: Any) -> None:
    write_text(path, json.dumps(data, indent=2, sort_keys=True, ensure_ascii=True))


def append_jsonl(path: Path, row: Dict[str, Any]) -> None:
    if path.is_symlink() or not output_path_allowed(path):
        raise ValueError(f"blocked audit path: {path.name}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True, ensure_ascii=True) + "\n")


def canonical_hash(value: Any, length: int = 24) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:length]


def nested_get(data: Any, *keys: str, default: Any = None) -> Any:
    current = data
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
    return current


def validate_policy(policy: Dict[str, Any]) -> Dict[str, Any]:
    findings: List[str] = []
    if policy.get("mode") != "SHADOW_ONLY":
        findings.append("policy_mode_not_shadow_only")
    if policy.get("runtime_network_enabled") is not False:
        findings.append("policy_network_enabled")
    if policy.get("automatic_apply_enabled") is not False:
        findings.append("policy_apply_enabled")
    if as_int(policy.get("maximum_snapshots"), 0) not in range(4, 97):
        findings.append("policy_snapshot_limit_invalid")
    fixed_inputs = policy.get("fixed_inputs", [])
    if not isinstance(fixed_inputs, list) or not fixed_inputs:
        findings.append("policy_fixed_inputs_missing")
    else:
        for item in fixed_inputs:
            candidate = Path(str(item))
            if candidate.is_absolute() or ".." in candidate.parts:
                findings.append("policy_input_path_not_relative")
    if policy.get("cloudflare_snapshot_root") != "cloudflare-monitor":
        findings.append("policy_snapshot_root_changed")
    denominator_tolerance = as_float(nested_get(
        policy,
        "provisional_reliability_reference",
        "status_denominator_tolerance_percent",
        default=-1.0,
    ))
    if not 0.0 <= denominator_tolerance <= 100.0:
        findings.append("policy_denominator_tolerance_invalid")
    coalesce_minutes = as_float(nested_get(
        policy, "regime_detection", "change_episode_coalesce_minutes", default=-1.0
    ))
    if not 0.0 <= coalesce_minutes <= 1440.0:
        findings.append("policy_change_episode_window_invalid")
    actions = policy.get("shadow_actions", [])
    action_ids = [item.get("action_id") for item in actions if isinstance(item, dict)]
    if len(action_ids) != len(set(action_ids)) or not action_ids:
        findings.append("policy_action_registry_invalid")
    if any(item.get("auto_execute") is not False for item in actions if isinstance(item, dict)):
        findings.append("policy_action_auto_execute")
    safety = policy.get("safety", {})
    if any(safety.get(key) is not False for key in (
        "live_apply", "remote_write", "network_access", "shell_execution",
        "scheduler_install", "medium_executable", "high_executable", "breach",
    )):
        findings.append("policy_safety_drift")
    return {
        "status": "EVIDENCE_TWIN_POLICY_VALID" if not findings else "EVIDENCE_TWIN_POLICY_INVALID",
        "findings": findings,
    }


def load_policy() -> Tuple[Dict[str, Any], Dict[str, Any]]:
    policy = load_dict(CONFIG_PATH)
    validation = validate_policy(policy) if policy else {
        "status": "EVIDENCE_TWIN_POLICY_INVALID",
        "findings": ["policy_missing_or_invalid_json"],
    }
    return policy, validation


def freshness(generated_at: Any, policy: Dict[str, Any], now: datetime) -> Dict[str, Any]:
    parsed = parse_timestamp(generated_at)
    if parsed is None:
        return {
            "status": "INVALID_TIMESTAMP",
            "age_seconds": None,
            "included_in_current_state": False,
        }
    age = max(0.0, (now - parsed).total_seconds())
    current_limit = as_int(nested_get(policy, "freshness_seconds", "current"), 86400)
    stale_limit = as_int(nested_get(policy, "freshness_seconds", "stale_informational"), 604800)
    if age <= current_limit:
        status = "CURRENT"
        included = True
    elif age <= stale_limit:
        status = "STALE_INFORMATIONAL"
        included = False
    else:
        status = "STALE_EXCLUDED_FROM_CURRENT_STATE"
        included = False
    return {
        "status": status,
        "age_seconds": round(age, 2),
        "included_in_current_state": included,
    }


def snapshot_directories(policy: Dict[str, Any]) -> Tuple[List[Path], List[str]]:
    findings: List[str] = []
    if not CLOUDFLARE_ROOT.exists() or CLOUDFLARE_ROOT.is_symlink():
        return [], ["cloudflare_snapshot_root_missing_or_symlink"]
    candidates: List[Path] = []
    for child in CLOUDFLARE_ROOT.iterdir():
        if child.is_symlink():
            findings.append(f"snapshot_symlink_blocked:{child.name}")
            continue
        if child.is_dir() and SNAPSHOT_RE.fullmatch(child.name) and is_within(child, CLOUDFLARE_ROOT):
            candidates.append(child)
    maximum = as_int(policy.get("maximum_snapshots"), 48)
    return sorted(candidates, key=lambda item: item.name)[-maximum:], findings


def status_counts(status_doc: Dict[str, Any]) -> Dict[int, int]:
    rows = nested_get(status_doc, "data", "viewer", "zones", default=[])
    if not isinstance(rows, list) or not rows or not isinstance(rows[0], dict):
        return {}
    groups = rows[0].get("httpRequestsAdaptiveGroups", [])
    result: Dict[int, int] = {}
    for row in groups:
        if not isinstance(row, dict):
            continue
        code = as_int(nested_get(row, "dimensions", "edgeResponseStatus"), -1)
        if 100 <= code <= 599:
            result[code] = as_int(row.get("count"))
    return result


def classify_path(path: str) -> str:
    value = str(path or "unknown").split("?", 1)[0].lower().rstrip("/") or "/"
    if value == "/":
        return "frontpage"
    if value.startswith("/wp-login.php"):
        return "wordpress_login"
    if value.startswith("/wp-admin/"):
        return "wordpress_admin"
    if re.fullmatch(r"/page/\d+", value):
        return "wordpress_pagination"
    if any(marker in value for marker in (
        "/.env", "/.git", "wp-config", "alfacgiapi", "phpunit", "phpinfo",
        "wp-plain.php", "/apikey.php", "/apismtp.php", "/fix/up.php", "/seotheme/db.php",
    )):
        return "scanner_probe"
    if re.search(r"\.(?:css|js|png|jpg|jpeg|gif|svg|webp|ico|woff2?)$", value):
        return "static_asset"
    return "public_or_unknown"


def top_error_paths(errors_doc: Dict[str, Any], limit: int = 8) -> List[Dict[str, Any]]:
    zones = nested_get(errors_doc, "data", "viewer", "zones", default=[])
    if not isinstance(zones, list) or not zones or not isinstance(zones[0], dict):
        return []
    groups = zones[0].get("httpRequestsAdaptiveGroups", [])
    rows: List[Dict[str, Any]] = []
    for row in groups:
        if not isinstance(row, dict):
            continue
        dimensions = row.get("dimensions", {})
        if not isinstance(dimensions, dict):
            continue
        path = str(dimensions.get("clientRequestPath") or "unknown")
        rows.append({
            "status": as_int(dimensions.get("edgeResponseStatus"), -1),
            "count": as_int(row.get("count")),
            "path": path,
            "path_class": classify_path(path),
            "cache_status": str(dimensions.get("cacheStatus") or "unknown").lower(),
            "country": str(dimensions.get("clientCountryName") or "unknown"),
        })
    return sorted(rows, key=lambda item: (-item["count"], item["status"], item["path"]))[:limit]


def load_snapshot(directory: Path, policy: Dict[str, Any], now: datetime) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    findings: List[str] = []
    required_names = policy.get("cloudflare_snapshot_files", [])
    docs: Dict[str, Dict[str, Any]] = {}
    for name in required_names:
        path = directory / str(name)
        if path.is_symlink() or not is_within(path, directory):
            findings.append(f"snapshot_path_blocked:{directory.name}/{name}")
            continue
        value, status = read_json(path)
        if status == "ok" and isinstance(value, dict):
            docs[str(name)] = value
        elif name in {"meta.json", "metrics.json", "status-24h.json"}:
            findings.append(f"snapshot_required_input_{status}:{directory.name}/{name}")
    meta = docs.get("meta.json", {})
    metrics = docs.get("metrics.json", {})
    status_doc = docs.get("status-24h.json", {})
    if not meta or not metrics or not status_doc:
        return None, findings
    generated_at = meta.get("generated_at_utc") or metrics.get("generated_at_utc")
    counts = status_counts(status_doc)
    status_response_total = sum(counts.values())
    status_5xx = sum(count for code, count in counts.items() if 500 <= code <= 599)
    metric_5xx = as_int(metrics.get("total_5xx"), status_5xx)
    metric_requests = as_int(metrics.get("requests"))
    denominator_difference = metric_requests - status_response_total
    denominator_base = max(metric_requests, status_response_total, 1)
    denominator_difference_percent = abs(denominator_difference) / denominator_base * 100.0
    denominator_tolerance = as_float(nested_get(
        policy,
        "provisional_reliability_reference",
        "status_denominator_tolerance_percent",
        default=5.0,
    ))
    snapshot = {
        "snapshot_id": directory.name,
        "generated_at": generated_at,
        "freshness": freshness(generated_at, policy, now),
        "requests": metric_requests,
        "status_response_total": status_response_total,
        "pageviews": as_int(metrics.get("pageviews")),
        "total_5xx": metric_5xx,
        "status_counts": {str(code): count for code, count in sorted(counts.items())},
        "status_503": counts.get(503, 0),
        "status_504": counts.get(504, 0),
        "status_522": counts.get(522, 0),
        "status_526": counts.get(526, 0),
        "root_504": as_int(metrics.get("root_504")),
        "sitelock_requests": as_int(metrics.get("sitelock_top_user_agent_requests")),
        "cache_request_percent": as_float(metrics.get("cache_request_pct")),
        "threats": as_int(metrics.get("threats")),
        "top_error_paths": top_error_paths(docs.get("errors-5xx-24h.json", {})),
        "source_consistency": {
            "metric_total_5xx": metric_5xx,
            "status_total_5xx": status_5xx,
            "difference": metric_5xx - status_5xx,
            "consistent": metric_5xx == status_5xx,
            "metric_requests": metric_requests,
            "status_response_total": status_response_total,
            "request_denominator_difference": denominator_difference,
            "request_denominator_difference_percent": round(denominator_difference_percent, 4),
            "request_denominator_aligned": denominator_difference_percent <= denominator_tolerance,
            "reliability_denominator_source": "status_code_aggregate",
        },
        "source_files": [f"cloudflare-monitor/{directory.name}/{name}" for name in docs],
    }
    return snapshot, findings


def discover_inputs(policy: Dict[str, Any], now: datetime) -> Dict[str, Any]:
    found: List[str] = []
    missing: List[str] = []
    blocked: List[str] = []
    for relative in policy.get("fixed_inputs", []):
        path = PROJECT_DIR / str(relative)
        if path.is_symlink() or not is_within(path, PROJECT_DIR):
            blocked.append(str(relative))
        elif path.exists():
            found.append(str(relative))
        else:
            missing.append(str(relative))
    directories, directory_findings = snapshot_directories(policy)
    snapshots: List[Dict[str, Any]] = []
    snapshot_findings: List[str] = list(directory_findings)
    for directory in directories:
        snapshot, findings = load_snapshot(directory, policy, now)
        snapshot_findings.extend(findings)
        if snapshot:
            snapshots.append(snapshot)
    return {
        "status": "EVIDENCE_TWIN_INPUTS_OK" if snapshots and not blocked else "EVIDENCE_TWIN_INPUTS_PARTIAL",
        "fixed_inputs_found": found,
        "missing_inputs": missing,
        "blocked_inputs": blocked,
        "snapshot_count": len(snapshots),
        "snapshot_findings": snapshot_findings,
        "snapshots": snapshots,
        "latest_snapshot_id": snapshots[-1]["snapshot_id"] if snapshots else None,
        "outside_project_reads": 0,
    }


def ratio_band(value: float) -> str:
    if value <= 0:
        return "ZERO"
    if value < 0.001:
        return "TRACE"
    if value < 0.01:
        return "LOW"
    if value < 0.05:
        return "ELEVATED"
    return "HIGH"


def count_band(value: int) -> str:
    if value <= 0:
        return "ZERO"
    if value <= 2:
        return "TRACE"
    if value < 25:
        return "LOW"
    if value < 100:
        return "ELEVATED"
    return "HIGH"


def trend(current: int, previous: Optional[int], threshold: int) -> str:
    if previous is None:
        return "INSUFFICIENT_HISTORY"
    delta = current - previous
    if delta >= threshold:
        return "SIGNIFICANT_GROWTH"
    if delta > 0:
        return "LOW_GROWTH"
    if delta <= -threshold:
        return "SIGNIFICANT_DECREASE"
    if delta < 0:
        return "DECREASING"
    return "STABLE"


def fingerprint_snapshot(
    snapshot: Dict[str, Any], previous: Optional[Dict[str, Any]], policy: Dict[str, Any]
) -> Dict[str, Any]:
    thresholds = nested_get(policy, "regime_detection", "absolute_thresholds", default={})
    requests = max(0, as_int(snapshot.get("status_response_total"), as_int(snapshot.get("requests"))))
    total_5xx = max(0, as_int(snapshot.get("total_5xx")))
    error_ratio = total_5xx / requests if requests else 0.0
    status_values = {
        code: as_int(snapshot.get(f"status_{code}")) for code in (503, 504, 522, 526)
    }
    dominant = max(status_values, key=status_values.get) if any(status_values.values()) else None
    previous_values = previous or {}
    signature = {
        "dominant_failure_code": dominant,
        "total_5xx_ratio_band": ratio_band(error_ratio),
        "status_bands": {str(code): count_band(value) for code, value in status_values.items()},
        "trends": {
            str(code): trend(
                value,
                as_int(previous_values.get(f"status_{code}")) if previous else None,
                as_int(thresholds.get(f"status_{code}"), 1),
            )
            for code, value in status_values.items()
        },
        "root_timeout_dominant": as_int(snapshot.get("root_504")) >= max(1, int(total_5xx * 0.5)),
        "tls_signal_present": status_values[526] > 0,
        "scanner_volume_band": count_band(as_int(snapshot.get("sitelock_requests"))),
        "top_path_classes": sorted({
            str(row.get("path_class")) for row in snapshot.get("top_error_paths", [])[:5]
            if row.get("path_class")
        }),
    }
    return {
        "fingerprint_id": "fp-" + canonical_hash(signature, 20),
        "signature": signature,
        "causality_proven": False,
        "verified_user_impact": "unknown",
    }


def normalize_events(
    snapshots: Sequence[Dict[str, Any]], policy: Dict[str, Any], observed_at: str
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    events: List[Dict[str, Any]] = []
    fingerprints: List[Dict[str, Any]] = []
    previous: Optional[Dict[str, Any]] = None
    for snapshot in snapshots:
        fingerprint = fingerprint_snapshot(snapshot, previous, policy)
        fingerprints.append({
            "snapshot_id": snapshot["snapshot_id"],
            "generated_at": snapshot.get("generated_at"),
            **fingerprint,
        })
        metric_requests = as_int(snapshot.get("requests"))
        status_response_total = as_int(snapshot.get("status_response_total"), metric_requests)
        total_5xx = as_int(snapshot.get("total_5xx"))
        error_ratio = total_5xx / status_response_total if status_response_total else None
        if snapshot.get("status_526", 0) > 0 or (error_ratio is not None and error_ratio >= 0.05):
            severity = "ERROR"
            severity_number = 17
        elif total_5xx > 0:
            severity = "WARN"
            severity_number = 13
        else:
            severity = "INFO"
            severity_number = 9
        event_identity = {
            "source": "cloudflare_monitor",
            "snapshot_id": snapshot["snapshot_id"],
            "timestamp": snapshot.get("generated_at"),
            "counts": {code: snapshot.get(f"status_{code}") for code in (503, 504, 522, 526)},
        }
        events.append({
            "event_id": "evt-" + canonical_hash(event_identity, 24),
            "event_name": "sentinel.website.edge_snapshot.observed",
            "timestamp": snapshot.get("generated_at"),
            "observed_timestamp": observed_at,
            "severity_text": severity,
            "severity_number": severity_number,
            "body": {
                "summary": "Aggregated website edge and origin-failure telemetry snapshot.",
                "content_stored": False,
            },
            "resource": {
                "service.name": "sentinel-defense",
                "service.namespace": "owner-local-operations",
                "deployment.environment.name": "owner-controlled",
            },
            "attributes": {
                "sentinel.snapshot.id": snapshot["snapshot_id"],
                "sentinel.evidence.source": "cloudflare_monitor",
                "sentinel.evidence.freshness": snapshot["freshness"]["status"],
                "sentinel.http.requests": metric_requests,
                "sentinel.http.status_aggregate_responses": status_response_total,
                "sentinel.http.responses.5xx": total_5xx,
                "sentinel.http.responses.503": snapshot.get("status_503", 0),
                "sentinel.http.responses.504": snapshot.get("status_504", 0),
                "sentinel.http.responses.522": snapshot.get("status_522", 0),
                "sentinel.http.responses.526": snapshot.get("status_526", 0),
                "sentinel.http.error_ratio": round(error_ratio, 8) if error_ratio is not None else None,
                "sentinel.incident.fingerprint_id": fingerprint["fingerprint_id"],
                "sentinel.causality_proven": False,
                "sentinel.verified_user_impact": "unknown",
            },
            "provenance": {
                "source_snapshot_id": snapshot["snapshot_id"],
                "source_timestamp_present": parse_timestamp(snapshot.get("generated_at")) is not None,
                "source_consistency": snapshot.get("source_consistency", {}),
                "error_ratio_denominator": "sentinel.http.status_aggregate_responses",
                "transformation": "loss-minimized normalized aggregate",
            },
            "schema_alignment": {
                "opentelemetry_log_data_model": "aligned_subset",
                "ocsf": "vendor_neutral_conceptual_mapping",
                "ocsf_category": "network_activity",
                "ocsf_event_class": "http_activity",
                "normative_ocsf_event": False,
            },
        })
        previous = snapshot
    return events, fingerprints


def coalesce_regime_changes(
    changes: Sequence[Dict[str, Any]], policy: Dict[str, Any]
) -> List[Dict[str, Any]]:
    window_minutes = as_float(nested_get(
        policy, "regime_detection", "change_episode_coalesce_minutes", default=90.0
    ))
    window_seconds = max(0.0, window_minutes * 60.0)
    episodes: List[Dict[str, Any]] = []
    active: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for change in sorted(changes, key=lambda item: (item.get("generated_at") or "", item["metric"])):
        key = (str(change["metric"]), str(change["direction"]))
        current_time = parse_timestamp(change.get("generated_at"))
        prior = active.get(key)
        prior_time = parse_timestamp(prior.get("last_seen")) if prior else None
        same_episode = bool(
            prior
            and current_time
            and prior_time
            and 0 <= (current_time - prior_time).total_seconds() <= window_seconds
        )
        if not same_episode:
            episode = dict(change)
            episode.update({
                "first_seen": change.get("generated_at"),
                "last_seen": change.get("generated_at"),
                "supporting_points": 1,
                "snapshot_ids": [change.get("snapshot_id")],
                "peak_abs_delta": abs(as_float(change.get("delta_from_baseline"))),
                "episode_coalesce_minutes": window_minutes,
            })
            episodes.append(episode)
            active[key] = episode
            continue
        prior["last_seen"] = change.get("generated_at")
        prior["supporting_points"] = as_int(prior.get("supporting_points"), 1) + 1
        prior["snapshot_ids"].append(change.get("snapshot_id"))
        candidate_peak = abs(as_float(change.get("delta_from_baseline")))
        if candidate_peak > as_float(prior.get("peak_abs_delta")):
            prior["peak_abs_delta"] = round(candidate_peak, 4)
            prior["peak_snapshot_id"] = change.get("snapshot_id")
            prior["peak_observed_value"] = change.get("observed_value")
        if change.get("significance") == "HIGH":
            prior["significance"] = "HIGH"
    return episodes


def robust_regime_changes(snapshots: Sequence[Dict[str, Any]], policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    config = policy.get("regime_detection", {})
    baseline_window = as_int(config.get("baseline_window"), 8)
    minimum = as_int(config.get("minimum_baseline_points"), 4)
    multiplier = as_float(config.get("mad_multiplier"), 6.0)
    thresholds = config.get("absolute_thresholds", {})
    metrics = {
        "total_5xx": "total_5xx",
        "status_503": "status_503",
        "status_504": "status_504",
        "status_522": "status_522",
        "status_526": "status_526",
        "sitelock_requests": "sitelock_requests",
    }
    changes: List[Dict[str, Any]] = []
    for metric_name, snapshot_key in metrics.items():
        values = [as_float(item.get(snapshot_key)) for item in snapshots]
        for index in range(minimum, len(values)):
            baseline = values[max(0, index - baseline_window):index]
            if len(baseline) < minimum:
                continue
            center = statistics.median(baseline)
            deviations = [abs(value - center) for value in baseline]
            mad = statistics.median(deviations)
            robust_sigma = 1.4826 * mad
            floor = as_float(thresholds.get(metric_name), 1.0)
            threshold = max(floor, multiplier * robust_sigma)
            delta = values[index] - center
            if abs(delta) < threshold or delta == 0:
                continue
            changes.append({
                "change_id": "chg-" + canonical_hash({
                    "metric": metric_name,
                    "snapshot": snapshots[index]["snapshot_id"],
                    "center": center,
                    "value": values[index],
                }, 20),
                "metric": metric_name,
                "snapshot_id": snapshots[index]["snapshot_id"],
                "generated_at": snapshots[index].get("generated_at"),
                "baseline_median": round(center, 4),
                "baseline_mad": round(mad, 4),
                "observed_value": values[index],
                "delta_from_baseline": round(delta, 4),
                "threshold": round(threshold, 4),
                "direction": "INCREASE" if delta > 0 else "DECREASE",
                "significance": "HIGH" if abs(delta) >= threshold * 2 else "MODERATE",
                "method": "ROBUST_MEDIAN_MAD_ONLINE_REPLAY",
                "probabilistic_claim": False,
                "causality_proven": False,
            })
    return coalesce_regime_changes(changes, policy)


def source_quality(
    origin: Dict[str, Any], ionos: Dict[str, Any], runtime: Dict[str, Any], snapshots: Sequence[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    latest = snapshots[-1] if snapshots else {}
    ionos_freshness = nested_get(ionos, "freshness_status", default="INVALID_TIMESTAMP")
    if not ionos_freshness:
        ionos_freshness = "INVALID_TIMESTAMP"
    origin_direct = as_int(nested_get(origin, "evidence_hierarchy", "direct_evidence_count"), 0)
    rows = [
        {
            "source_id": "cloudflare_monitor",
            "freshness": nested_get(latest, "freshness", "status", default="MISSING"),
            "evidence_level": "B_STRONG_CORRELATION",
            "quality_score": 85 if latest else 0,
            "limitations": ["aggregated_telemetry", "human_user_impact_not_attributable"],
        },
        {
            "source_id": "origin_failure_diagnostics",
            "freshness": "CURRENT" if origin else "MISSING",
            "evidence_level": "A_DIRECT" if origin_direct else "B_STRONG_CORRELATION",
            "quality_score": 90 if origin_direct else 72 if origin else 0,
            "limitations": [] if origin_direct else ["direct_origin_logs_missing"],
        },
        {
            "source_id": "ionos_owner_evidence",
            "freshness": ionos_freshness,
            "evidence_level": nested_get(ionos, "assessment", "evidence_level", default="C_WEAK_CORRELATION"),
            "quality_score": 45 if ionos else 0,
            "limitations": ["source_timestamp_missing", "source_window_missing"] if ionos else ["source_missing"],
        },
        {
            "source_id": "guarded_runtime",
            "freshness": "CURRENT" if runtime else "MISSING",
            "evidence_level": "A_LOCAL_RUNTIME_STATE" if runtime else "MISSING",
            "quality_score": 90 if runtime else 0,
            "limitations": [] if runtime else ["runtime_state_missing"],
        },
    ]
    return rows


def reliability_budget(latest: Dict[str, Any], policy: Dict[str, Any]) -> Dict[str, Any]:
    reference = policy.get("provisional_reliability_reference", {})
    target = as_float(reference.get("technical_availability_target"), 0.99)
    metric_requests = as_int(latest.get("requests"))
    status_response_total = as_int(latest.get("status_response_total"))
    requests = status_response_total if status_response_total > 0 else metric_requests
    denominator_source = "status_code_aggregate" if status_response_total > 0 else "metric_requests_fallback"
    bad = as_int(latest.get("total_5xx"))
    minimum = as_int(reference.get("minimum_requests"), 100)
    if requests < minimum or not 0 < target < 1:
        return {
            "status": "RELIABILITY_REFERENCE_INSUFFICIENT_DATA",
            "owner_approved": bool(reference.get("owner_approved")),
            "human_user_slo_available": False,
            "automatic_policy_effect": False,
        }
    bad_ratio = bad / requests
    availability = max(0.0, 1.0 - bad_ratio)
    budget_ratio = 1.0 - target
    burn_rate = bad_ratio / budget_ratio if budget_ratio else None
    allowed_bad = requests * budget_ratio
    consumed = (bad / allowed_bad) * 100.0 if allowed_bad else None
    if consumed is not None and consumed > 100:
        state = "PROVISIONAL_TECHNICAL_BUDGET_EXHAUSTED"
        decision = "PRIORITIZE_RELIABILITY_OVER_OPTIMIZATION"
    elif consumed is not None and consumed >= 50:
        state = "PROVISIONAL_TECHNICAL_BUDGET_AT_RISK"
        decision = "LIMIT_CHANGE_AND_REVIEW_RELIABILITY"
    else:
        state = "PROVISIONAL_TECHNICAL_BUDGET_AVAILABLE"
        decision = "CONTINUE_EVIDENCE_GATED_OPERATIONS"
    return {
        "status": state,
        "reference_type": "PROVISIONAL_TECHNICAL_EDGE_SLI_NOT_USER_SLO",
        "owner_approved": bool(reference.get("owner_approved")),
        "window": reference.get("window"),
        "requests": metric_requests,
        "status_aggregate_responses": status_response_total,
        "reliability_denominator": requests,
        "reliability_denominator_source": denominator_source,
        "bad_5xx_responses": bad,
        "technical_availability": round(availability, 8),
        "technical_availability_percent": round(availability * 100.0, 4),
        "target": target,
        "allowed_bad_responses_at_target": round(allowed_bad, 2),
        "error_budget_consumed_percent": round(consumed, 2) if consumed is not None else None,
        "burn_rate": round(burn_rate, 2) if burn_rate is not None else None,
        "decision": decision,
        "human_user_slo_available": False,
        "verified_user_impact": "unknown",
        "multiwindow_burn_rate_status": "INSUFFICIENT_NON_OVERLAPPING_DENOMINATOR_WINDOWS",
        "automatic_policy_effect": False,
        "note": "Rolling aggregate snapshots cannot establish a human-user SLO or a causal impact claim.",
    }


def evaluate_shadow_actions(
    policy: Dict[str, Any], latest: Dict[str, Any], origin: Dict[str, Any], runtime: Dict[str, Any]
) -> Dict[str, Any]:
    direct_count = as_int(nested_get(origin, "evidence_hierarchy", "direct_evidence_count"), 0)
    ionos_analysis = origin.get("ionos_webspace_evidence", {}) if isinstance(origin, dict) else {}
    sequences = ionos_analysis.get("synchronized_sequences", []) if isinstance(ionos_analysis, dict) else []
    strong_sequence = any(item.get("correlation_strength") == "STRONG" for item in sequences if isinstance(item, dict))
    ionos_current = nested_get(ionos_analysis, "freshness", "freshness_status") == "CURRENT"
    write_status = nested_get(runtime, "write_canary", "status", default="MISSING")
    rollback_ready = bool(nested_get(runtime, "rollback", "ready", default=False)) or (
        nested_get(runtime, "rollback", "status") in {"ROLLBACK_READY", "GUARDED_AUTONOMY_ROLLBACK_TEST_OK"}
    )
    total_5xx = as_int(latest.get("total_5xx"))
    results: List[Dict[str, Any]] = []
    for action in policy.get("shadow_actions", []):
        action_id = str(action.get("action_id"))
        present: List[str] = []
        missing: List[str] = []
        decision = "SHADOW_NOT_RECOMMENDED"
        reason = "No matching evidence-gated condition is present."
        if action_id == "MONITOR_AND_CORRELATE":
            if latest:
                present.append("current_snapshot")
                decision = "SHADOW_RECOMMENDED"
                reason = "Current telemetry exists and monitoring has no productive side effect."
            else:
                missing.append("current_snapshot")
        elif action_id == "REQUEST_DIRECT_ORIGIN_EVIDENCE":
            if total_5xx > 0:
                present.append("origin_failure_signal")
            else:
                missing.append("origin_failure_signal")
            if direct_count == 0:
                present.append("direct_evidence_gap")
            if total_5xx > 0 and direct_count == 0:
                decision = "SHADOW_RECOMMENDED"
                reason = "Origin failures remain visible while direct origin-side evidence is absent."
            elif direct_count > 0:
                decision = "SHADOW_SATISFIED_BY_EXISTING_EVIDENCE"
                reason = "Direct origin evidence is already represented in the local evidence hierarchy."
        elif action_id == "REVIEW_SITELOCK_SCAN_SCHEDULE":
            if strong_sequence:
                present.append("synchronized_sequence")
            else:
                missing.append("synchronized_sequence")
            if ionos_current:
                present.append("timestamp_correlation")
            else:
                missing.append("timestamp_correlation")
            if strong_sequence:
                decision = "SHADOW_REVIEW_WITH_EVIDENCE_GAP"
                reason = "The repeated path sequence is strong correlation, but its source timestamp is missing."
        elif action_id == "EXACT_SCANNER_CHALLENGE_CANARY":
            if ionos_current:
                present.append("fresh_exact_path_trigger")
            else:
                missing.append("fresh_exact_path_trigger")
            if write_status == "CLOUDFLARE_WRITE_CANARY_OK":
                present.append("write_canary_ok")
            else:
                missing.append("write_canary_ok")
            if rollback_ready:
                present.append("rollback_ready")
            else:
                missing.append("rollback_ready")
            decision = "SHADOW_BLOCKED"
            reason = "A productive scanner challenge remains blocked until every fixed adapter and evidence gate is green."
        elif action_id == "ANONYMOUS_MICROCACHE_CANARY":
            missing.extend(["anonymous_get_proof", "cookie_exclusions", "adapter_validation"])
            if rollback_ready:
                present.append("rollback_ready")
            else:
                missing.append("rollback_ready")
            decision = "SHADOW_BLOCKED"
            reason = "The aggregate timeout signal is insufficient to prove cache safety or user neutrality."
        results.append({
            "action_id": action_id,
            "risk": action.get("risk"),
            "shadow_decision": decision,
            "evidence_present": present,
            "missing_evidence": list(dict.fromkeys(missing)),
            "reason": reason,
            "causal_effect_proven": False,
            "would_execute": False,
            "auto_execute": False,
            "forbidden_effects": action.get("forbidden_effects", []),
        })
    selected = "REQUEST_DIRECT_ORIGIN_EVIDENCE" if any(
        row["action_id"] == "REQUEST_DIRECT_ORIGIN_EVIDENCE" and row["shadow_decision"] == "SHADOW_RECOMMENDED"
        for row in results
    ) else "MONITOR_AND_CORRELATE"
    return {
        "mode": "COUNTERFACTUAL_SHADOW_ONLY",
        "selected_shadow_action": selected,
        "candidate_results": results,
        "write_canary_status": write_status,
        "rollback_ready": rollback_ready,
        "actions_executed": 0,
        "causal_effect_proven": False,
    }


def replay_shadow_policy(events: Sequence[Dict[str, Any]], policy: Dict[str, Any]) -> Dict[str, Any]:
    decisions: List[Dict[str, Any]] = []
    previous_526: Optional[int] = None
    target = as_float(nested_get(policy, "provisional_reliability_reference", "technical_availability_target"), 0.99)
    budget_ratio = max(0.000001, 1.0 - target)
    for event in events:
        attributes = event.get("attributes", {})
        requests = as_int(
            attributes.get("sentinel.http.status_aggregate_responses"),
            as_int(attributes.get("sentinel.http.requests")),
        )
        total_5xx = as_int(attributes.get("sentinel.http.responses.5xx"))
        current_526 = as_int(attributes.get("sentinel.http.responses.526"))
        error_ratio = total_5xx / requests if requests else 0.0
        if previous_526 is not None and current_526 > previous_526:
            decision = "PAUSE_CHANGE_CANDIDATES"
            reason = "New status-526 growth would pause every change candidate."
        elif error_ratio > budget_ratio:
            decision = "REQUEST_DIRECT_ORIGIN_EVIDENCE"
            reason = "The provisional technical error ratio exceeds its reference budget."
        else:
            decision = "MONITOR_AND_CORRELATE"
            reason = "No evidence-gated productive action is justified."
        decisions.append({
            "event_id": event["event_id"],
            "timestamp": event.get("timestamp"),
            "fingerprint_id": attributes.get("sentinel.incident.fingerprint_id"),
            "shadow_decision": decision,
            "reason": reason,
            "would_execute": False,
            "causal_effect_proven": False,
        })
        previous_526 = current_526
    counts: Dict[str, int] = {}
    for item in decisions:
        counts[item["shadow_decision"]] = counts.get(item["shadow_decision"], 0) + 1
    return {
        "status": "COUNTERFACTUAL_SHADOW_REPLAY_OK" if decisions else "COUNTERFACTUAL_SHADOW_REPLAY_INSUFFICIENT_DATA",
        "event_count": len(decisions),
        "decision_counts": counts,
        "decisions": decisions,
        "productive_actions_executed": 0,
        "policy_gate_violations": 0,
        "causal_effect_estimation": "NOT_AVAILABLE_FROM_OBSERVATIONAL_AGGREGATES",
        "verified_user_impact": "unknown",
    }


def build_graph(
    events: Sequence[Dict[str, Any]],
    fingerprints: Sequence[Dict[str, Any]],
    changes: Sequence[Dict[str, Any]],
    quality: Sequence[Dict[str, Any]],
    action_results: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    for source in quality:
        nodes.append({
            "node_id": "source:" + source["source_id"],
            "node_type": "EVIDENCE_SOURCE",
            "attributes": source,
        })
    fingerprint_ids = set()
    for item in fingerprints:
        fingerprint_id = item["fingerprint_id"]
        if fingerprint_id not in fingerprint_ids:
            nodes.append({
                "node_id": "fingerprint:" + fingerprint_id,
                "node_type": "INCIDENT_FINGERPRINT",
                "attributes": item["signature"],
            })
            fingerprint_ids.add(fingerprint_id)
    fingerprint_by_snapshot = {item["snapshot_id"]: item["fingerprint_id"] for item in fingerprints}
    for index, event in enumerate(events):
        nodes.append({
            "node_id": "event:" + event["event_id"],
            "node_type": "OBSERVATION_EVENT",
            "attributes": {
                "timestamp": event.get("timestamp"),
                "severity_text": event.get("severity_text"),
            },
        })
        edges.append({
            "source": "source:cloudflare_monitor",
            "target": "event:" + event["event_id"],
            "relation": "PRODUCED",
        })
        fingerprint_id = event.get("attributes", {}).get("sentinel.incident.fingerprint_id")
        edges.append({
            "source": "event:" + event["event_id"],
            "target": "fingerprint:" + str(fingerprint_id),
            "relation": "HAS_FINGERPRINT",
        })
        if index:
            edges.append({
                "source": "event:" + events[index - 1]["event_id"],
                "target": "event:" + event["event_id"],
                "relation": "PRECEDES",
            })
    event_by_snapshot = {
        str(event.get("attributes", {}).get("sentinel.snapshot.id")): event["event_id"] for event in events
    }
    for change in changes:
        nodes.append({
            "node_id": "change:" + change["change_id"],
            "node_type": "REGIME_CHANGE",
            "attributes": change,
        })
        event_id = event_by_snapshot.get(change["snapshot_id"])
        if event_id:
            edges.append({
                "source": "event:" + event_id,
                "target": "change:" + change["change_id"],
                "relation": "DETECTED_AS",
            })
    latest_fingerprint = fingerprint_by_snapshot.get(fingerprints[-1]["snapshot_id"]) if fingerprints else None
    for action in action_results:
        node_id = "action:" + action["action_id"]
        nodes.append({
            "node_id": node_id,
            "node_type": "SHADOW_ACTION_CANDIDATE",
            "attributes": {
                "decision": action["shadow_decision"],
                "risk": action.get("risk"),
                "would_execute": False,
            },
        })
        if latest_fingerprint:
            edges.append({
                "source": "fingerprint:" + latest_fingerprint,
                "target": node_id,
                "relation": "SHADOW_EVALUATED_AGAINST",
            })
    if latest_fingerprint:
        edges.extend([
            {
                "source": "source:origin_failure_diagnostics",
                "target": "fingerprint:" + latest_fingerprint,
                "relation": "SUPPORTS_WITH_CORRELATION",
            },
            {
                "source": "source:ionos_owner_evidence",
                "target": "fingerprint:" + latest_fingerprint,
                "relation": "SUPPORTS_WITH_STALE_CONTEXT",
            },
        ])
    node_ids = {node["node_id"] for node in nodes}
    invalid_edges = [edge for edge in edges if edge["source"] not in node_ids or edge["target"] not in node_ids]
    return {
        "schema_version": "sentinel-evidence-graph-1",
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": nodes,
        "edges": edges,
        "invalid_edge_count": len(invalid_edges),
        "graph_semantics": "PROVENANCE_AND_CORRELATION_NOT_CAUSAL_GRAPH",
        "causality_proven": False,
    }


def sanitize_public(text: str) -> str:
    text = PRIVATE_PATH_RE.sub("[private path redacted]", text)
    text = IP_RE.sub("[address redacted]", text)
    text = FQDN_RE.sub("[hostname redacted]", text)
    return text


def public_findings(text: str) -> List[str]:
    checks = {
        "ip": IP_RE,
        "hostname": FQDN_RE,
        "private_path": PRIVATE_PATH_RE,
        "secret": SECRET_RE,
        "private_key": PRIVATE_KEY_RE,
    }
    return [name for name, pattern in checks.items() if pattern.search(text)]


def build_public_summary(report: Dict[str, Any]) -> str:
    reliability = report.get("reliability_budget", {})
    text = f"""# Sentinel Operational Evidence Twin - Public Summary

Sentinel now maintains a local shadow-only evidence twin that normalizes operational observations, tracks incident fingerprints, and replays policy decisions without executing productive changes.

The current technical reliability reference is `{reliability.get('status', 'UNAVAILABLE')}`. This is an aggregate technical signal, not proof of human-user impact. Direct origin evidence remains the preferred next diagnostic input.

No live apply, remote write, scheduler installation, firewall change, cache change, credential access, or autonomous risk expansion is performed by the twin.
"""
    return sanitize_public(text)


def build_report() -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any], str]:
    generated_at = utc_now()
    now = parse_timestamp(generated_at) or datetime.now(timezone.utc)
    policy, policy_validation = load_policy()
    discovery = discover_inputs(policy, now) if policy else {
        "status": "EVIDENCE_TWIN_INPUTS_PARTIAL",
        "snapshots": [],
        "snapshot_count": 0,
        "missing_inputs": [],
        "blocked_inputs": [],
        "snapshot_findings": ["policy_unavailable"],
    }
    snapshots = discovery.pop("snapshots", [])
    origin = load_dict(ORIGIN_JSON)
    ionos = load_dict(IONOS_JSON)
    runtime = load_dict(RUNTIME_JSON)
    events, fingerprints = normalize_events(snapshots, policy, generated_at) if policy else ([], [])
    changes = robust_regime_changes(snapshots, policy) if policy else []
    quality = source_quality(origin, ionos, runtime, snapshots)
    latest = snapshots[-1] if snapshots else {}
    reliability = reliability_budget(latest, policy) if policy else {
        "status": "RELIABILITY_REFERENCE_INSUFFICIENT_DATA",
        "automatic_policy_effect": False,
    }
    shadow = evaluate_shadow_actions(policy, latest, origin, runtime) if policy else {
        "mode": "COUNTERFACTUAL_SHADOW_ONLY",
        "candidate_results": [],
        "selected_shadow_action": "MONITOR_AND_CORRELATE",
        "actions_executed": 0,
        "causal_effect_proven": False,
    }
    replay = replay_shadow_policy(events, policy) if policy else {
        "status": "COUNTERFACTUAL_SHADOW_REPLAY_INSUFFICIENT_DATA",
        "decisions": [],
        "productive_actions_executed": 0,
    }
    graph = build_graph(events, fingerprints, changes, quality, shadow.get("candidate_results", []))
    direct_count = as_int(nested_get(origin, "evidence_hierarchy", "direct_evidence_count"), 0)
    minimum = as_int(policy.get("minimum_snapshots_for_regime_analysis"), 4) if policy else 4
    if policy_validation["status"] != "EVIDENCE_TWIN_POLICY_VALID" or graph["invalid_edge_count"]:
        status = "EVIDENCE_TWIN_RED"
        reason = "Policy or graph validation failed."
    elif len(snapshots) < minimum or direct_count == 0 or any(row["freshness"] == "INVALID_TIMESTAMP" for row in quality):
        status = "EVIDENCE_TWIN_YELLOW"
        reason = "The twin is operational, but direct origin evidence or fully fresh source evidence remains incomplete."
    else:
        status = "EVIDENCE_TWIN_GREEN"
        reason = "Evidence normalization, graph construction, regime analysis, and shadow replay are complete."
    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "status": status,
        "reason": reason,
        "report_classification": REPORT_CLASSIFICATION,
        "selected_global_step": "OPERATIONAL_EVIDENCE_TWIN_WITH_COUNTERFACTUAL_SHADOW_REPLAY",
        "policy": {
            "path": rel(CONFIG_PATH),
            "validation": policy_validation,
            "mode": policy.get("mode") if policy else None,
            "policy_version": policy.get("policy_version") if policy else None,
        },
        "input_discovery": discovery,
        "source_quality": quality,
        "normalized_event_count": len(events),
        "incident_fingerprint_count": len({item["fingerprint_id"] for item in fingerprints}),
        "regime_change_count": len(changes),
        "latest_fingerprint": fingerprints[-1] if fingerprints else None,
        "regime_changes": changes,
        "reliability_budget": reliability,
        "shadow_evaluation": shadow,
        "counterfactual_replay": replay,
        "evidence_graph_summary": {
            "node_count": graph["node_count"],
            "edge_count": graph["edge_count"],
            "invalid_edge_count": graph["invalid_edge_count"],
            "semantics": graph["graph_semantics"],
        },
        "owner_decision": {
            "selected_priority": shadow.get("selected_shadow_action"),
            "reason": "Direct origin evidence closes the largest causal gap without increasing production risk.",
            "suppressed_actions": [
                row["action_id"] for row in shadow.get("candidate_results", [])
                if row["shadow_decision"] == "SHADOW_BLOCKED"
            ],
            "productive_action_authorized": False,
        },
        "research_alignment": [
            {
                "standard": "OpenTelemetry Logs Data Model",
                "alignment": "Timestamp, observed timestamp, severity, body, resource, attributes, event name, and provenance-aware normalization.",
                "url": "https://opentelemetry.io/docs/specs/otel/logs/data-model/",
            },
            {
                "standard": "Open Cybersecurity Schema Framework",
                "alignment": "Vendor-neutral JSON event vocabulary and explicit non-normative HTTP activity mapping.",
                "url": "https://ocsf.io/",
            },
            {
                "standard": "NIST IR 8356",
                "alignment": "Electronic representation of operational states and transitions with explicit trust boundaries.",
                "url": "https://doi.org/10.6028/NIST.IR.8356",
            },
            {
                "standard": "Google SRE Error Budgets",
                "alignment": "Reliability-first prioritization using a provisional technical SLI reference without claiming a user SLO.",
                "url": "https://sre.google/workbook/error-budget-policy/",
            },
            {
                "standard": "NIST AI RMF",
                "alignment": "Continuous govern-map-measure-manage loop, documented oversight, and deactivation boundaries.",
                "url": "https://airc.nist.gov/airmf-resources/airmf/5-sec-core/",
            },
            {
                "standard": "Bayesian Online Changepoint Detection research",
                "alignment": "Conceptual inspiration for online regime awareness; this implementation uses deterministic median/MAD replay and makes no Bayesian probability claim.",
                "url": "https://arxiv.org/abs/0710.3742",
            },
        ],
        "safety": SAFETY,
        "git_checkpoint": {
            "recommended_files": RECOMMENDED_GIT_FILES,
            "excluded_prefixes": ["reports/", "state/", "audit/", "exports/", "backups/", "snapshots/", "cloudflare-monitor/"],
        },
        "validation": {"status": "NOT_RUN", "findings": []},
    }
    public_text = build_public_summary(report)
    return report, {"events": events, "fingerprints": fingerprints}, graph, public_text


def private_header(title: str) -> List[str]:
    return [
        f"# {title}",
        "",
        "Classification: PRIVATE_OWNER_OPERATIONAL_REPORT | NOT_FOR_PUBLIC_RELEASE | NOT_FOR_GIT | CONTAINS_INFRASTRUCTURE_METADATA",
        "",
    ]


def render_main(report: Dict[str, Any]) -> str:
    reliability = report["reliability_budget"]
    shadow = report["shadow_evaluation"]
    lines = private_header("Sentinel Operational Evidence Twin")
    lines += [
        f"- Twin status: `{report['status']}`",
        f"- Reason: {report['reason']}",
        f"- Mode: `{report['safety']['mode']}`",
        f"- Normalized events: `{report['normalized_event_count']}`",
        f"- Incident fingerprints: `{report['incident_fingerprint_count']}`",
        f"- Regime changes: `{report['regime_change_count']}`",
        f"- Evidence graph: `{report['evidence_graph_summary']['node_count']}` nodes / `{report['evidence_graph_summary']['edge_count']}` edges",
        f"- Reliability reference: `{reliability.get('status')}`",
        f"- Technical availability: `{reliability.get('technical_availability_percent')}` percent",
        f"- Shadow action: `{shadow.get('selected_shadow_action')}`",
        f"- Productive actions executed: `{shadow.get('actions_executed', 0)}`",
        f"- Causality proven: `{str(shadow.get('causal_effect_proven', False)).lower()}`",
        f"- Verified user impact: `unknown`",
        "",
        "## Source Quality",
        "",
        "| Source | Freshness | Evidence level | Quality | Limitations |",
        "|---|---|---|---:|---|",
    ]
    for source in report["source_quality"]:
        limitations = ", ".join(source["limitations"]) or "none"
        lines.append(
            f"| `{source['source_id']}` | `{source['freshness']}` | `{source['evidence_level']}` | "
            f"{source['quality_score']} | {limitations} |"
        )
    lines += [
        "",
        "## Interpretation",
        "",
        "The twin separates observation, correlation, reliability pressure, policy eligibility, and causal proof. Shadow replay never executes an action and cannot infer a counterfactual effect from aggregate observational data.",
    ]
    return "\n".join(lines)


def render_graph(graph: Dict[str, Any]) -> str:
    lines = private_header("Sentinel Incident Evidence Graph")
    lines += [
        f"- Nodes: `{graph['node_count']}`",
        f"- Edges: `{graph['edge_count']}`",
        f"- Invalid edges: `{graph['invalid_edge_count']}`",
        f"- Semantics: `{graph['graph_semantics']}`",
        f"- Causality proven: `false`",
        "",
        "## Node Types",
        "",
    ]
    counts: Dict[str, int] = {}
    for node in graph["nodes"]:
        counts[node["node_type"]] = counts.get(node["node_type"], 0) + 1
    lines.extend(f"- `{key}`: `{value}`" for key, value in sorted(counts.items()))
    lines += [
        "",
        "The graph records provenance, order, shared fingerprints, regime changes, and shadow evaluation. It is explicitly not a causal graph.",
    ]
    return "\n".join(lines)


def render_regimes(report: Dict[str, Any]) -> str:
    lines = private_header("Sentinel Operational Regime Analysis")
    lines += [
        f"- Detected changes: `{report['regime_change_count']}`",
        "- Method: `ROBUST_MEDIAN_MAD_ONLINE_REPLAY`",
        "- Bayesian probability claim: `false`",
        "- Causality proven: `false`",
        "",
        "| First seen | Last seen | Metric | Direction | Baseline | Observed | Delta | Points | Significance |",
        "|---|---|---|---|---:|---:|---:|---:|---|",
    ]
    for item in report["regime_changes"][-30:]:
        lines.append(
            f"| `{item.get('first_seen')}` | `{item.get('last_seen')}` | `{item['metric']}` | "
            f"`{item['direction']}` | {item['baseline_median']} | {item['observed_value']} | "
            f"{item['delta_from_baseline']} | {item.get('supporting_points', 1)} | `{item['significance']}` |"
        )
    if not report["regime_changes"]:
        lines.append("| - | - | - | - | - | - | - | - | `NO_CHANGE_DETECTED` |")
    return "\n".join(lines)


def render_reliability(report: Dict[str, Any]) -> str:
    item = report["reliability_budget"]
    lines = private_header("Sentinel Reliability Budget")
    for key in (
        "status", "reference_type", "owner_approved", "window", "requests",
        "status_aggregate_responses", "reliability_denominator",
        "reliability_denominator_source",
        "bad_5xx_responses", "technical_availability_percent", "target",
        "allowed_bad_responses_at_target", "error_budget_consumed_percent",
        "burn_rate", "decision", "human_user_slo_available",
        "multiwindow_burn_rate_status", "automatic_policy_effect",
    ):
        lines.append(f"- {key}: `{item.get(key)}`")
    lines += [
        "",
        item.get("note", ""),
        "",
        "This provisional technical reference controls only shadow prioritization. It is not an owner-approved SLO and does not prove human-user impact.",
    ]
    return "\n".join(lines)


def render_shadow(report: Dict[str, Any]) -> str:
    shadow = report["shadow_evaluation"]
    replay = report["counterfactual_replay"]
    lines = private_header("Sentinel Counterfactual Shadow Replay")
    lines += [
        f"- Mode: `{shadow['mode']}`",
        f"- Selected action: `{shadow['selected_shadow_action']}`",
        f"- Historical events replayed: `{replay.get('event_count', 0)}`",
        f"- Productive actions executed: `0`",
        f"- Causal effect available: `false`",
        f"- Verified user impact: `unknown`",
        "",
        "| Candidate | Risk | Decision | Missing evidence | Would execute |",
        "|---|---|---|---|---|",
    ]
    for row in shadow.get("candidate_results", []):
        missing = ", ".join(row["missing_evidence"]) or "none"
        lines.append(
            f"| `{row['action_id']}` | `{row['risk']}` | `{row['shadow_decision']}` | {missing} | `false` |"
        )
    lines += ["", "## Replay Decisions", ""]
    for decision, count in sorted(replay.get("decision_counts", {}).items()):
        lines.append(f"- `{decision}`: `{count}`")
    lines += [
        "",
        "The replay validates policy gates against historical observations. It does not estimate treatment effect because no randomized or matched action outcome evidence exists.",
    ]
    return "\n".join(lines)


def render_owner(report: Dict[str, Any]) -> str:
    owner = report["owner_decision"]
    lines = private_header("Sentinel Evidence Twin Owner Plan")
    lines += [
        f"- Selected priority: `{owner['selected_priority']}`",
        f"- Productive action authorized: `false`",
        f"- Reason: {owner['reason']}",
        "",
        "## Next Safe Operations",
        "",
        "1. Acquire timestamp-aligned read-only origin, PHP, WordPress, or hosting error evidence without credentials entering reports.",
        "2. Feed that evidence into the normalized event model and re-run fingerprint and regime analysis.",
        "3. Keep the synchronized SiteLock sequence as correlation until source timestamps match origin failures.",
        "4. Use shadow replay to test exact scanner and microcache policy gates; do not infer benefit without outcome evidence.",
        "5. Keep SEO and feature optimization below technical reliability while the provisional budget is exhausted.",
        "",
        "## Suppressed Productive Candidates",
        "",
    ]
    lines.extend(f"- `{item}`" for item in owner["suppressed_actions"])
    lines += [
        "",
        "No live apply, remote log retrieval, WAF change, cache change, scheduler installation, or autonomy expansion is part of this plan.",
    ]
    return "\n".join(lines)


def render_validation(report: Dict[str, Any]) -> str:
    validation = report["validation"]
    lines = private_header("Sentinel Operational Evidence Twin Validation")
    lines += [
        f"- Status: `{validation['status']}`",
        f"- Findings: `{len(validation['findings'])}`",
        f"- JSON: `{validation.get('json_status')}`",
        f"- Markdown: `{validation.get('markdown_status')}`",
        f"- Public summary: `{validation.get('public_sanitization')}`",
        f"- Productive actions: `0`",
        f"- breach: `false`",
    ]
    if validation["findings"]:
        lines += ["", "## Findings", ""] + [f"- {item}" for item in validation["findings"]]
    return "\n".join(lines)


def logical_validation(
    report: Dict[str, Any], event_bundle: Dict[str, Any], graph: Dict[str, Any], public_text: str
) -> Dict[str, Any]:
    findings: List[str] = []
    if report.get("safety") != SAFETY:
        findings.append("safety_drift")
    if report.get("policy", {}).get("validation", {}).get("status") != "EVIDENCE_TWIN_POLICY_VALID":
        findings.append("policy_invalid")
    events = event_bundle.get("events", [])
    required_event_fields = {
        "event_id", "event_name", "timestamp", "observed_timestamp", "severity_text",
        "severity_number", "body", "resource", "attributes", "provenance", "schema_alignment",
    }
    for index, event in enumerate(events):
        if not required_event_fields.issubset(event):
            findings.append(f"event_{index}_missing_fields")
        if event.get("attributes", {}).get("sentinel.causality_proven") is not False:
            findings.append(f"event_{index}_causality_claim")
        if event.get("attributes", {}).get("sentinel.verified_user_impact") != "unknown":
            findings.append(f"event_{index}_user_impact_claim")
    timestamps = [parse_timestamp(event.get("timestamp")) for event in events]
    valid_times = [item for item in timestamps if item is not None]
    if valid_times != sorted(valid_times):
        findings.append("events_not_chronological")
    if graph.get("invalid_edge_count"):
        findings.append("graph_invalid_edges")
    shadow = report.get("shadow_evaluation", {})
    if shadow.get("actions_executed") != 0:
        findings.append("shadow_action_executed")
    if any(row.get("would_execute") is not False or row.get("auto_execute") is not False for row in shadow.get("candidate_results", [])):
        findings.append("shadow_candidate_executable")
    replay = report.get("counterfactual_replay", {})
    if replay.get("productive_actions_executed") != 0:
        findings.append("replay_productive_action")
    reliability = report.get("reliability_budget", {})
    if reliability.get("human_user_slo_available") is not False:
        findings.append("unsupported_human_user_slo")
    if reliability.get("automatic_policy_effect") is not False:
        findings.append("reliability_automatic_effect")
    if reliability.get("status") != "RELIABILITY_REFERENCE_INSUFFICIENT_DATA":
        if reliability.get("reliability_denominator_source") != "status_code_aggregate":
            findings.append("reliability_denominator_not_status_aligned")
        if as_int(reliability.get("reliability_denominator")) < as_int(reliability.get("bad_5xx_responses")):
            findings.append("reliability_denominator_below_bad_responses")
    public_issues = public_findings(public_text)
    findings.extend(f"public:{item}" for item in public_issues)
    if any(path.startswith(("reports/", "state/", "audit/", "exports/", "cloudflare-monitor/")) for path in report["git_checkpoint"]["recommended_files"]):
        findings.append("unsafe_git_recommendation")
    return {
        "status": "OPERATIONAL_EVIDENCE_TWIN_VALIDATION_OK" if not findings else "OPERATIONAL_EVIDENCE_TWIN_VALIDATION_FAILED",
        "findings": findings,
        "json_status": "PENDING_WRITE_VALIDATION",
        "markdown_status": "PENDING_WRITE_VALIDATION",
        "public_sanitization": "PUBLIC_SUMMARY_SANITIZED" if not public_issues else "PUBLIC_SUMMARY_UNSAFE",
        "secret_findings": 0,
        "forbidden_findings": len(findings),
    }


def write_outputs(
    report: Dict[str, Any], event_bundle: Dict[str, Any], graph: Dict[str, Any], public_text: str, record: bool
) -> None:
    ensure_output_dirs()
    events_doc = {
        "schema_version": "sentinel-normalized-evidence-events-1",
        "generated_at": report["generated_at"],
        "event_count": len(event_bundle["events"]),
        "events": event_bundle["events"],
    }
    fingerprints_doc = {
        "schema_version": "sentinel-operational-incident-fingerprints-1",
        "generated_at": report["generated_at"],
        "fingerprint_count": len(event_bundle["fingerprints"]),
        "fingerprints": event_bundle["fingerprints"],
    }
    shadow_doc = {
        "schema_version": "sentinel-counterfactual-shadow-replay-1",
        "generated_at": report["generated_at"],
        "shadow_evaluation": report["shadow_evaluation"],
        "counterfactual_replay": report["counterfactual_replay"],
    }
    write_json(REPORT_JSON, report)
    write_json(EVENTS_JSON, events_doc)
    write_json(GRAPH_JSON, graph)
    write_json(SHADOW_JSON, shadow_doc)
    write_json(STATE_JSON, report)
    write_json(LATEST_STATE_JSON, report)
    write_json(FINGERPRINTS_JSON, fingerprints_doc)
    write_text(REPORT_MD, render_main(report))
    write_text(GRAPH_MD, render_graph(graph))
    write_text(REGIME_MD, render_regimes(report))
    write_text(RELIABILITY_MD, render_reliability(report))
    write_text(SHADOW_MD, render_shadow(report))
    write_text(OWNER_MD, render_owner(report))
    write_text(PUBLIC_MD, public_text)
    write_text(VALIDATION_MD, render_validation(report))
    history, history_status = read_json(HISTORY_JSON)
    if history_status != "ok" or not isinstance(history, list):
        history = []
    if record:
        history.append({
            "generated_at": report["generated_at"],
            "status": report["status"],
            "validation_status": report["validation"]["status"],
            "normalized_event_count": report["normalized_event_count"],
            "fingerprint_id": nested_get(report, "latest_fingerprint", "fingerprint_id"),
            "reliability_status": nested_get(report, "reliability_budget", "status"),
            "selected_shadow_action": nested_get(report, "owner_decision", "selected_priority"),
            "productive_actions": 0,
            "breach": False,
        })
    write_json(HISTORY_JSON, history)
    if record:
        append_jsonl(AUDIT_JSONL, {
            "timestamp": report["generated_at"],
            "event": "operational_evidence_twin_built",
            "status": report["status"],
            "validation_status": report["validation"]["status"],
            "event_count": report["normalized_event_count"],
            "selected_shadow_action": nested_get(report, "owner_decision", "selected_priority"),
            "actions_executed": 0,
            "live_apply": False,
            "breach": False,
        })


def validate_written_outputs() -> Dict[str, Any]:
    findings: List[str] = []
    for path in OUTPUT_JSONS:
        if not path.exists():
            findings.append(f"missing_json:{rel(path)}")
            continue
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            findings.append(f"invalid_json:{rel(path)}")
    for path in OUTPUT_MARKDOWN:
        try:
            if not path.read_text(encoding="utf-8").strip():
                findings.append(f"empty_markdown:{rel(path)}")
        except OSError:
            findings.append(f"missing_markdown:{rel(path)}")
    public_text = PUBLIC_MD.read_text(encoding="utf-8") if PUBLIC_MD.exists() else ""
    findings.extend(f"public:{item}" for item in public_findings(public_text))
    return {
        "status": "EVIDENCE_TWIN_OUTPUTS_VALID" if not findings else "EVIDENCE_TWIN_OUTPUTS_INVALID",
        "findings": findings,
    }


def run_pipeline(record: bool = False) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    report, event_bundle, graph, public_text = build_report()
    report["validation"] = logical_validation(report, event_bundle, graph, public_text)
    write_outputs(report, event_bundle, graph, public_text, record=record)
    output_validation = validate_written_outputs()
    report["validation"]["output_validation"] = output_validation
    report["validation"]["json_status"] = "JSON_VALID" if not any("json:" in item for item in output_validation["findings"]) else "JSON_INVALID"
    report["validation"]["markdown_status"] = "MARKDOWN_NONEMPTY" if not any("markdown:" in item for item in output_validation["findings"]) else "MARKDOWN_INVALID"
    if output_validation["status"] != "EVIDENCE_TWIN_OUTPUTS_VALID":
        report["validation"]["status"] = "OPERATIONAL_EVIDENCE_TWIN_VALIDATION_FAILED"
        report["validation"]["findings"].extend(output_validation["findings"])
    write_outputs(report, event_bundle, graph, public_text, record=False)
    return report, event_bundle, graph


def self_test() -> Dict[str, Any]:
    policy, policy_validation = load_policy()
    base_time = datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc)
    totals = [10, 11, 9, 10, 200, 198]
    synthetic_snapshots: List[Dict[str, Any]] = []
    for index, total in enumerate(totals):
        timestamp = iso_utc(base_time.replace(minute=index * 5))
        synthetic_snapshots.append({
            "snapshot_id": f"20260716-12{index * 5:02d}00",
            "generated_at": timestamp,
            "freshness": {"status": "CURRENT"},
            "requests": 10000,
            "status_response_total": 10000,
            "pageviews": 5000,
            "total_5xx": total,
            "status_503": total // 2,
            "status_504": total - (total // 2),
            "status_522": 0,
            "status_526": 0,
            "root_504": total - (total // 2),
            "sitelock_requests": 20,
            "cache_request_percent": 35.0,
            "threats": 1,
            "top_error_paths": [{"path_class": "frontpage"}],
            "source_consistency": {
                "consistent": True,
                "difference": 0,
                "request_denominator_aligned": True,
                "reliability_denominator_source": "status_code_aggregate",
            },
        })
    events, fingerprints = normalize_events(synthetic_snapshots, policy, iso_utc(base_time))
    changes = robust_regime_changes(synthetic_snapshots, policy)
    synthetic_origin = {
        "evidence_hierarchy": {"direct_evidence_count": 0},
        "ionos_webspace_evidence": {
            "freshness": {"freshness_status": "INVALID_TIMESTAMP"},
            "synchronized_sequences": [{"correlation_strength": "STRONG"}],
        },
    }
    synthetic_runtime = {
        "write_canary": {"status": "CLOUDFLARE_WRITE_CANARY_BLOCKED"},
        "rollback": {"ready": True},
    }
    shadow = evaluate_shadow_actions(policy, synthetic_snapshots[-1], synthetic_origin, synthetic_runtime)
    replay = replay_shadow_policy(events, policy)
    quality = source_quality(synthetic_origin, {}, synthetic_runtime, synthetic_snapshots)
    graph = build_graph(events, fingerprints, changes, quality, shadow["candidate_results"])
    budget = reliability_budget(
        {"requests": 9000, "status_response_total": 10000, "total_5xx": 200}, policy
    )
    sanitized = sanitize_public(
        "198.51.100.10 origin.private.example /srv/private/site remains under review."
    )
    source = Path(__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports: List[str] = []
    command_calls: List[str] = []
    function_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.append(node.module)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function_names.add(node.name)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {
            "Popen", "run", "call", "check_call", "check_output", "system",
        }:
            command_calls.append(node.func.attr)
    forbidden_imports = {
        "requests", "urllib", "http.client", "socket", "smtplib", "paramiko", "cloudflare", "subprocess",
    }
    network_imports = sorted(
        name for name in imports if any(name == blocked or name.startswith(blocked + ".") for blocked in forbidden_imports)
    )
    dangerous_functions = {
        "apply", "live_apply", "remote_write", "cloudflare_write", "wordpress_write",
        "database_write", "sftp_write", "nginx_write", "install_timer", "install_cron",
        "enable_systemd", "git_push", "git_tag", "send_email", "execute_command",
    }
    scanner_candidate = next(
        row for row in shadow["candidate_results"] if row["action_id"] == "EXACT_SCANNER_CHALLENGE_CANARY"
    )
    tests = {
        "policy_valid": policy_validation["status"] == "EVIDENCE_TWIN_POLICY_VALID",
        "policy_shadow_only": policy.get("mode") == "SHADOW_ONLY" and policy.get("automatic_apply_enabled") is False,
        "otel_aligned_event_fields": bool(events) and all(
            key in events[0] for key in (
                "event_name", "timestamp", "observed_timestamp", "severity_text", "body",
                "resource", "attributes", "provenance",
            )
        ),
        "event_body_not_stored": all(event["body"]["content_stored"] is False for event in events),
        "fingerprint_deterministic": (
            fingerprint_snapshot(synthetic_snapshots[0], None, policy)["fingerprint_id"]
            == fingerprint_snapshot(synthetic_snapshots[0], None, policy)["fingerprint_id"]
        ),
        "fingerprint_changes_with_regime": fingerprints[0]["fingerprint_id"] != fingerprints[-1]["fingerprint_id"],
        "robust_regime_change_detected": any(
            row["metric"] == "total_5xx" and row["direction"] == "INCREASE" for row in changes
        ),
        "regime_change_episode_coalesced": any(
            row["metric"] == "total_5xx" and row.get("supporting_points", 0) >= 2 for row in changes
        ),
        "regime_detector_makes_no_probability_claim": all(row["probabilistic_claim"] is False for row in changes),
        "graph_references_valid": graph["invalid_edge_count"] == 0,
        "graph_not_causal": graph["causality_proven"] is False,
        "reliability_math": (
            budget["technical_availability_percent"] == 98.0
            and budget["error_budget_consumed_percent"] == 200.0
            and budget["burn_rate"] == 2.0
            and budget["requests"] == 9000
            and budget["reliability_denominator"] == 10000
            and budget["reliability_denominator_source"] == "status_code_aggregate"
        ),
        "reliability_not_human_slo": budget["human_user_slo_available"] is False,
        "shadow_write_gate_blocks_live_candidate": (
            scanner_candidate["shadow_decision"] == "SHADOW_BLOCKED"
            and scanner_candidate["would_execute"] is False
        ),
        "shadow_replay_executes_nothing": replay["productive_actions_executed"] == 0,
        "shadow_causality_not_claimed": shadow["causal_effect_proven"] is False,
        "public_sanitized": not public_findings(sanitized),
        "no_network_imports": not network_imports,
        "no_command_execution": not command_calls,
        "no_shell_true": ("shell" + "=True") not in source and ("shell" + " = True") not in source,
        "no_dangerous_functions": not (function_names & dangerous_functions),
        "outside_output_path_blocked": not output_path_allowed(PROJECT_DIR.parent / "outside.json"),
        "snapshot_name_allowlist": bool(SNAPSHOT_RE.fullmatch("20260716-120000")) and not SNAPSHOT_RE.fullmatch("latest"),
        "git_recommendation_safe": not any(
            path.startswith(("reports/", "state/", "audit/", "exports/", "cloudflare-monitor/"))
            for path in RECOMMENDED_GIT_FILES
        ),
        "safety_invariants": (
            SAFETY["mode"] == "SHADOW_ONLY"
            and SAFETY["live_apply"] is False
            and SAFETY["remote_write"] is False
            and SAFETY["network_access"] is False
            and SAFETY["medium_executable"] is False
            and SAFETY["high_executable"] is False
            and SAFETY["breach"] is False
        ),
        "json_serializable": isinstance(json.loads(json.dumps(graph)), dict),
    }
    findings = [name for name, passed in tests.items() if not passed]
    return {
        "status": "OPERATIONAL_EVIDENCE_TWIN_SELF_TEST_OK" if not findings else "OPERATIONAL_EVIDENCE_TWIN_SELF_TEST_FAILED",
        "checks": tests,
        "findings": findings,
        "network_imports": network_imports,
        "command_calls": command_calls,
        "breach": False,
    }


def print_status(report: Dict[str, Any]) -> None:
    if not report:
        print("OPERATIONAL_EVIDENCE_TWIN_NOT_BUILT")
        return
    print(report.get("status", "EVIDENCE_TWIN_UNKNOWN"))
    print(report.get("validation", {}).get("status", "OPERATIONAL_EVIDENCE_TWIN_NOT_VALIDATED"))
    print(report.get("policy", {}).get("validation", {}).get("status", "EVIDENCE_TWIN_POLICY_UNKNOWN"))
    print(f"NORMALIZED_EVENTS_{report.get('normalized_event_count', 0)}")
    print(f"INCIDENT_FINGERPRINTS_{report.get('incident_fingerprint_count', 0)}")
    print(f"REGIME_CHANGES_{report.get('regime_change_count', 0)}")
    print(report.get("reliability_budget", {}).get("status", "RELIABILITY_REFERENCE_UNKNOWN"))
    print(f"SHADOW_ACTION_{report.get('owner_decision', {}).get('selected_priority', 'UNKNOWN')}")
    print("PRODUCTIVE_ACTIONS_EXECUTED_0")
    print("CAUSALITY_PROVEN_FALSE")
    print("VERIFIED_USER_IMPACT_UNKNOWN")
    print("LIVE_APPLY_FALSE")
    print("REMOTE_WRITE_FALSE")
    print("BREACH_FALSE")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Local shadow-only Sentinel operational evidence twin")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--discover-inputs", action="store_true")
    group.add_argument("--normalize-evidence", action="store_true")
    group.add_argument("--build-twin", action="store_true")
    group.add_argument("--detect-regimes", action="store_true")
    group.add_argument("--build-incident-graph", action="store_true")
    group.add_argument("--evaluate-reliability-budget", action="store_true")
    group.add_argument("--run-shadow-replay", action="store_true")
    group.add_argument("--build-owner-plan", action="store_true")
    group.add_argument("--build-public-summary", action="store_true")
    group.add_argument("--validate", action="store_true")
    group.add_argument("--status", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        result = self_test()
        print(result["status"])
        if result["findings"]:
            print(json.dumps(result["findings"]))
        return 0 if not result["findings"] else 1
    if args.status:
        print_status(load_dict(REPORT_JSON))
        return 0 if REPORT_JSON.exists() else 1

    report, event_bundle, graph = run_pipeline(record=args.build_twin)
    if args.discover_inputs:
        print(report["input_discovery"]["status"])
        print(f"SNAPSHOTS_{report['input_discovery']['snapshot_count']}")
    elif args.normalize_evidence:
        print(f"NORMALIZED_EVIDENCE_EVENTS_{len(event_bundle['events'])}")
    elif args.build_twin:
        print("OPERATIONAL_EVIDENCE_TWIN_BUILT")
    elif args.detect_regimes:
        print(f"OPERATIONAL_REGIME_CHANGES_{report['regime_change_count']}")
    elif args.build_incident_graph:
        print(f"INCIDENT_EVIDENCE_GRAPH_{graph['node_count']}_NODES_{graph['edge_count']}_EDGES")
    elif args.evaluate_reliability_budget:
        print(report["reliability_budget"]["status"])
    elif args.run_shadow_replay:
        print(report["counterfactual_replay"]["status"])
        print(f"SHADOW_ACTION_{report['owner_decision']['selected_priority']}")
    elif args.build_owner_plan:
        print(f"OWNER_PRIORITY_{report['owner_decision']['selected_priority']}")
    elif args.build_public_summary:
        print(report["validation"]["public_sanitization"])
    elif args.validate:
        print(report["validation"]["status"])
    return 0 if report["validation"]["status"] == "OPERATIONAL_EVIDENCE_TWIN_VALIDATION_OK" else 1


if __name__ == "__main__":
    raise SystemExit(main())
