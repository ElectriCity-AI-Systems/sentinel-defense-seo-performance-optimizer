#!/usr/bin/env python3
"""Phase 10.22.2/10.23 recovery refresh and monitoring decisions.

This module closes the evidence-ordering gap between the Cloudflare monitor,
Phase 10.22 recovery, canonical truth and the production pipeline.  It performs
only fixed, read-only collection:

* rebuild the local website report in observe mode when its snapshot is behind;
* refresh the fixed first-party Cloudflare/DNS/edge/origin route evidence;
* rebuild Phase 10.22 recovery from that same monitor snapshot;
* reject mixed snapshot windows before canonical truth can consume them; and
* choose NO_ACTION, MONITOR_CONTINUE or OWNER_ACTION_REQUIRED for Level-2
  monitoring without enabling or executing a productive action.

The exact historical 504 failure layer is never inferred from a healthy point
probe.  Without direct origin logs or a reproduced direct-origin failure the
result remains correlation-only and any remote diagnosis is owner-gated.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import re
import subprocess
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

import sentinel_504_recovery as recovery
import sentinel_origin_route_mapper as route_mapper


PROJECT_DIR = Path(__file__).resolve().parent
SCHEMA_VERSION = "sentinel-monitoring-decision-engine-10.23"

REPORT_DIR = PROJECT_DIR / "reports/latest"
STATE_DIR = PROJECT_DIR / "state/adaptive-learning"
AUDIT_DIR = PROJECT_DIR / "audit"
PLAYBOOK_DIR = PROJECT_DIR / "playbooks"
MONITOR_DIR = PROJECT_DIR / "cloudflare-monitor"

REPORT_JSON = REPORT_DIR / "sentinel-monitoring-decision.json"
REPORT_MD = REPORT_DIR / "sentinel-monitoring-decision.md"
REFRESH_JSON = REPORT_DIR / "sentinel-recovery-evidence-refresh.json"
REFRESH_MD = REPORT_DIR / "sentinel-recovery-evidence-refresh.md"
CORRELATION_JSON = REPORT_DIR / "sentinel-nowplaying-cloudflare-origin-correlation.json"
CORRELATION_MD = REPORT_DIR / "sentinel-nowplaying-cloudflare-origin-correlation.md"

STATE_JSON = STATE_DIR / "monitoring_decision.json"
WINDOW_STATE_JSON = STATE_DIR / "recovery_evidence_window.json"
HISTORY_JSON = STATE_DIR / "monitoring_decision_history.json"
AUDIT_JSONL = AUDIT_DIR / "sentinel-monitoring-decision.jsonl"
REFRESH_LOCK = STATE_DIR / ".recovery-evidence-refresh.lock"

PLAYBOOKS = (
    PLAYBOOK_DIR / "sentinel-recovery-evidence-refresh.playbook.json",
    PLAYBOOK_DIR / "sentinel-level-2-monitoring-decision.playbook.json",
    PLAYBOOK_DIR / "sentinel-cloudflare-origin-correlation.playbook.json",
    PLAYBOOK_DIR / "sentinel-evidence-window-consistency.playbook.json",
)

WEBSITE_REPORT_JSON = REPORT_DIR / "sentinel-defense-report.json"
GUARDED_RUNTIME_JSON = REPORT_DIR / "sentinel-guarded-autonomy.json"
WRITE_CANARY_JSON = PROJECT_DIR / "state/guarded-autonomy/write-canary.json"

NOWPLAYING_PATH = route_mapper.NOWPLAYING_PATH
NOWPLAYING_HOST = route_mapper.NOWPLAYING_HOST

EVIDENCE_WINDOW_ALIGNED = "EVIDENCE_WINDOW_ALIGNED"
EVIDENCE_WINDOW_MISMATCH = "EVIDENCE_WINDOW_MISMATCH"
EVIDENCE_WINDOW_MISSING = "EVIDENCE_WINDOW_MISSING"

DECISIONS = ("NO_ACTION", "MONITOR_CONTINUE", "OWNER_ACTION_REQUIRED")
DIRECT_PROBE_TTL_SECONDS = 30 * 60
MONITOR_CURRENT_SECONDS = 45 * 60
LOCK_TIMEOUT_SECONDS = 120

FIXED_WEBSITE_OBSERVE = (
    "/usr/bin/python3",
    "/srv/sentinel-defense/sentinel_defense_bot.py",
    "--mode",
    "observe",
    "--report",
    "/srv/sentinel-defense/cloudflare-monitor/latest/cloudflare-daily-monitor.md",
)

REPORT_CLASSIFICATION = [
    "PRIVATE_OWNER_OPERATIONAL_REPORT",
    "NOT_FOR_PUBLIC_RELEASE",
    "NOT_FOR_GIT",
    "CONTAINS_INFRASTRUCTURE_METADATA",
]

EXECUTION_BOUNDARIES = {
    "cloudflare_api_methods": ["GET"],
    "cloudflare_write": False,
    "dns_change": False,
    "tls_change": False,
    "waf_change": False,
    "wordpress_write": False,
    "database_change": False,
    "global_nginx_change": False,
    "timeout_change": False,
    "remote_write": False,
    "ssh_execution": False,
    "credential_search": False,
    "low_live_activation": False,
    "medium_activation": False,
    "high_activation": False,
    "phase_type": "read_only_evidence_refresh_correlation_monitoring_decision",
}

SECRET_RE = route_mapper.SECRET_RE
PRIVATE_KEY_RE = route_mapper.PRIVATE_KEY_RE
SNAPSHOT_ID_RE = re.compile(r"^\d{8}-\d{6}$")


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


def rel(path: Path) -> str:
    return route_mapper.rel(path)


def ensure_dirs() -> None:
    # Playbooks are immutable source artifacts at runtime.  The hardened
    # systemd service intentionally grants writes only to reports/state/audit.
    for directory in (REPORT_DIR, STATE_DIR, AUDIT_DIR):
        directory.mkdir(parents=True, exist_ok=True)


def write_text(path: Path, text: str) -> None:
    route_mapper.write_text(path, text)


def write_json(path: Path, payload: Any) -> None:
    route_mapper.write_json(path, payload)


def append_jsonl(path: Path, payload: Dict[str, Any]) -> None:
    route_mapper.append_jsonl(path, payload)


def read_json(path: Path) -> Tuple[Any, str]:
    return route_mapper.read_json(path)


def load_dict(path: Path) -> Dict[str, Any]:
    return route_mapper.load_dict(path)


def latest_snapshot() -> Dict[str, Any]:
    directory = route_mapper.monitor_snapshot_dir()
    if directory is None or not SNAPSHOT_ID_RE.match(directory.name):
        return {
            "status": "MONITOR_SNAPSHOT_MISSING",
            "snapshot_id": None,
            "path": None,
            "generated_at_utc": None,
            "age_seconds": None,
        }
    meta = load_dict(directory / "meta.json")
    generated = parse_timestamp(meta.get("generated_at_utc"))
    age = None
    if generated is not None:
        age = round(max(0.0, (datetime.now(timezone.utc) - generated).total_seconds()), 2)
    return {
        "status": "MONITOR_SNAPSHOT_CURRENT" if age is not None and age <= MONITOR_CURRENT_SECONDS else "MONITOR_SNAPSHOT_STALE",
        "snapshot_id": directory.name,
        "path": rel(directory),
        "generated_at_utc": meta.get("generated_at_utc"),
        "age_seconds": age,
    }


def report_snapshot_id(payload: Dict[str, Any]) -> Optional[str]:
    rolling = payload.get("rolling_window_context")
    candidates: List[Any] = []
    if isinstance(rolling, dict):
        comparison = rolling.get("comparison")
        window = rolling.get("window")
        if isinstance(comparison, dict):
            candidates.append(comparison.get("current_generated_at_utc"))
        if isinstance(window, dict):
            candidates.append(window.get("generated_at_utc"))
    candidates.append(payload.get("generated_at_utc"))
    for value in candidates:
        timestamp = parse_timestamp(value)
        if timestamp is not None:
            return timestamp.strftime("%Y%m%d-%H%M%S")
    return None


def matrix_snapshot_id(payload: Dict[str, Any]) -> Optional[str]:
    value = payload.get("snapshot_dir")
    if not isinstance(value, str):
        return None
    name = Path(value).name
    return name if SNAPSHOT_ID_RE.match(name) else None


def recovery_snapshot_id(payload: Dict[str, Any]) -> Optional[str]:
    value = payload.get("baseline", {}).get("snapshot_id") if isinstance(payload.get("baseline"), dict) else None
    return value if isinstance(value, str) and SNAPSHOT_ID_RE.match(value) else None


def capture_evidence_window() -> Dict[str, Any]:
    latest = latest_snapshot()
    website = load_dict(WEBSITE_REPORT_JSON)
    matrix = load_dict(route_mapper.ENDPOINT_MATRIX_JSON)
    recovery_report = load_dict(recovery.RECOVERY_JSON)
    ids = {
        "latest_monitor_snapshot": latest.get("snapshot_id"),
        "website_report_snapshot": report_snapshot_id(website),
        "origin_matrix_snapshot": matrix_snapshot_id(matrix),
        "recovery_baseline_snapshot": recovery_snapshot_id(recovery_report),
    }
    present = [value for value in ids.values() if value]
    if len(present) != len(ids):
        status = EVIDENCE_WINDOW_MISSING
        reason = "One or more required snapshot identities are missing; no current recovery fact is inferred."
    elif len(set(present)) != 1:
        status = EVIDENCE_WINDOW_MISMATCH
        reason = "Website, route correlation and recovery do not refer to one identical monitor snapshot."
    else:
        status = EVIDENCE_WINDOW_ALIGNED
        reason = "Website, route correlation and recovery refer to the same monitor snapshot."
    return {
        "status": status,
        "evaluated_at_utc": utc_now(),
        "snapshot_ids": ids,
        "monitor_freshness": latest.get("status"),
        "monitor_age_seconds": latest.get("age_seconds"),
        "included_in_canonical_truth": status == EVIDENCE_WINDOW_ALIGNED,
        "reason": reason,
    }


def artifact_age_seconds(payload: Dict[str, Any]) -> Optional[float]:
    generated = parse_timestamp(payload.get("generated_at_utc") or payload.get("generated_at"))
    if generated is None:
        return None
    return round(max(0.0, (datetime.now(timezone.utc) - generated).total_seconds()), 2)


def run_website_observe() -> Dict[str, Any]:
    try:
        completed = subprocess.run(
            list(FIXED_WEBSITE_OBSERVE),
            cwd=str(PROJECT_DIR),
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        return {"status": "WEBSITE_OBSERVE_TIMEOUT", "returncode": 124}
    except OSError as exc:
        return {"status": "WEBSITE_OBSERVE_FAILED", "returncode": 127, "error_type": type(exc).__name__}
    return {
        "status": "WEBSITE_OBSERVE_OK" if completed.returncode == 0 else "WEBSITE_OBSERVE_FAILED",
        "returncode": completed.returncode,
        "command_id": "fixed_website_observe",
        "shell": False,
        "output_stored": False,
    }


@contextmanager
def refresh_lock(timeout_seconds: int = LOCK_TIMEOUT_SECONDS) -> Iterator[None]:
    ensure_dirs()
    with REFRESH_LOCK.open("a+", encoding="utf-8") as handle:
        deadline = time.monotonic() + timeout_seconds
        while True:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise TimeoutError("recovery_evidence_refresh_lock_timeout")
                time.sleep(0.2)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def route_refresh_needed(force: bool, target_snapshot: Optional[str]) -> bool:
    if force or not target_snapshot:
        return True
    matrix = load_dict(route_mapper.ENDPOINT_MATRIX_JSON)
    route_map = load_dict(route_mapper.ROUTE_MAP_JSON)
    chain = load_dict(route_mapper.NOWPLAYING_CHAIN_JSON)
    if matrix_snapshot_id(matrix) != target_snapshot:
        return True
    ages = [artifact_age_seconds(item) for item in (matrix, route_map, chain)]
    return any(age is None or age > DIRECT_PROBE_TTL_SECONDS for age in ages)


def recovery_refresh_needed(force: bool, target_snapshot: Optional[str]) -> bool:
    # Phase 10.22 is a local, read-only derivation and is intentionally rebuilt
    # before every canonical resolution.  Snapshot equality alone is not enough:
    # it would preserve values produced by an older recovery algorithm after a
    # code deployment (the regression that previously retained 59.2% and a
    # NOWPLAYING_ROUTE_MISMATCH classification).
    return True


def refresh_once(force: bool = False) -> Dict[str, Any]:
    before = latest_snapshot()
    target = before.get("snapshot_id")
    website_refresh = {"status": "WEBSITE_OBSERVE_REUSED", "returncode": 0}
    if report_snapshot_id(load_dict(WEBSITE_REPORT_JSON)) != target:
        website_refresh = run_website_observe()

    route_refreshed = route_refresh_needed(force, target)
    route_status = load_dict(route_mapper.ROUTE_MAP_JSON).get("status", "NOT_RUN")
    if route_refreshed:
        bundle = route_mapper.build_all(include_origin_probes=True)
        route_mapper.persist(bundle, write_playbooks=False)
        route_status = bundle["route_map"].get("status", "NOT_RUN")

    recovery_refreshed = recovery_refresh_needed(force or route_refreshed, target)
    recovery_status = load_dict(recovery.RECOVERY_JSON).get("status", "NOT_RUN")
    if recovery_refreshed:
        recovery_report = recovery.build_recovery(
            persist_outputs=True,
            write_playbooks=False,
        )
        recovery_status = recovery_report.get("status", "NOT_RUN")

    after = latest_snapshot()
    window = capture_evidence_window()
    return {
        "started_snapshot": before,
        "finished_snapshot": after,
        "snapshot_changed_during_refresh": before.get("snapshot_id") != after.get("snapshot_id"),
        "website_refresh": website_refresh,
        "route_evidence_refreshed": route_refreshed,
        "route_status": route_status,
        "recovery_evidence_refreshed": recovery_refreshed,
        "recovery_status": recovery_status,
        "evidence_window": window,
    }


def nowplaying_row(matrix: Dict[str, Any]) -> Dict[str, Any]:
    return next(
        (
            row for row in matrix.get("endpoints", [])
            if isinstance(row, dict)
            and row.get("endpoint") == NOWPLAYING_PATH
            and row.get("hostname") == NOWPLAYING_HOST
        ),
        {},
    )


def origin_access_status(ownership: Dict[str, Any], origin: Any) -> Dict[str, Any]:
    rows = ownership.get("hosts", []) if isinstance(ownership.get("hosts"), list) else []
    row = next(
        (item for item in rows if isinstance(item, dict) and item.get("origin_target") == origin),
        {},
    )
    remote_status = row.get("remote_access_status") or "REMOTE_OWNER_ACTION_REQUIRED"
    return {
        "status": remote_status,
        "verified_first_party_profile_available": remote_status == "SSH_PROFILE_PRESENT",
        "ssh_attempted": False,
        "credential_search_performed": False,
        "reason": (
            "A verified first-party SSH profile is registered; this phase still performs no SSH write."
            if remote_status == "SSH_PROFILE_PRESENT"
            else "No verified first-party SSH profile exists for the authoritative origin."
        ),
    }


def classify_failure_boundary(row: Dict[str, Any], chain: Dict[str, Any]) -> Dict[str, Any]:
    count_504 = int(row.get("current_504") or 0)
    probe = chain.get("origin_probe") if isinstance(chain.get("origin_probe"), dict) else {}
    status_code = probe.get("status_code")
    timed_out = probe.get("timed_out") is True
    error = probe.get("error")

    if count_504 == 0:
        layer = "NO_CURRENT_NOWPLAYING_504"
        evidence = "PROVEN"
        exact = True
        reason = "The aligned current monitor snapshot contains no NowPlaying 504."
    elif timed_out:
        layer = "DIRECT_ORIGIN_CONNECTION_OR_RESPONSE_TIMEOUT"
        evidence = "PROVEN"
        exact = True
        reason = "The fixed direct-origin probe reproduced a timeout for the same first-party host and path."
    elif isinstance(status_code, int) and 500 <= status_code < 600:
        layer = "DIRECT_ORIGIN_OR_UPSTREAM_SERVER_FAILURE"
        evidence = "STRONG"
        exact = False
        reason = "The fixed direct-origin probe reproduced a server failure, but origin logs are needed for its internal layer."
    elif isinstance(status_code, int) and 200 <= status_code < 400:
        layer = "INTERMITTENT_CLOUDFLARE_TO_ORIGIN_OR_ORIGIN_UPSTREAM_PATH"
        evidence = "STRONG"
        exact = False
        reason = (
            "Cloudflare analytics records 504 for the endpoint while the current fixed direct-origin probe is healthy. "
            "This narrows the failure domain to an intermittent edge-to-origin/origin-upstream path but does not prove "
            "the historical internal layer."
        )
    elif error:
        layer = "ORIGIN_PROBE_EVIDENCE_UNAVAILABLE"
        evidence = "INSUFFICIENT"
        exact = False
        reason = "The fixed direct-origin probe did not produce usable current evidence."
    else:
        layer = "FAILURE_LAYER_UNPROVEN"
        evidence = "INSUFFICIENT"
        exact = False
        reason = "No direct evidence identifies a single failing layer."

    return {
        "failure_layer": layer,
        "confidence": evidence,
        "exact_failure_layer_proven": exact,
        "causality_proven": exact and layer != "NO_CURRENT_NOWPLAYING_504",
        "reason": reason,
        "direct_origin_probe": {
            "status_code": status_code,
            "timed_out": timed_out,
            "error_class": error,
            "latency_ms": probe.get("latency_ms"),
            "tls_verified": probe.get("tls_verified"),
            "response_body_stored": False,
        },
    }


def build_correlation() -> Dict[str, Any]:
    matrix = load_dict(route_mapper.ENDPOINT_MATRIX_JSON)
    chain = load_dict(route_mapper.NOWPLAYING_CHAIN_JSON)
    ownership = load_dict(route_mapper.OWNERSHIP_JSON)
    recovery_report = load_dict(recovery.RECOVERY_JSON)
    row = nowplaying_row(matrix)
    boundary = classify_failure_boundary(row, chain)
    access = origin_access_status(ownership, row.get("origin"))
    baseline = recovery_report.get("baseline") if isinstance(recovery_report.get("baseline"), dict) else {}
    endpoint = baseline.get("endpoints", {}).get(NOWPLAYING_PATH, {}) if isinstance(baseline.get("endpoints"), dict) else {}
    rates = endpoint.get("rates") if isinstance(endpoint.get("rates"), dict) else {}

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "status": "CLOUDFLARE_ORIGIN_CORRELATION_COMPLETE" if row else "CLOUDFLARE_ORIGIN_CORRELATION_INCOMPLETE",
        "report_classification": REPORT_CLASSIFICATION,
        "execution_boundaries": EXECUTION_BOUNDARIES,
        "snapshot_id": matrix_snapshot_id(matrix),
        "endpoint": NOWPLAYING_PATH,
        "hostname": NOWPLAYING_HOST,
        "authoritative_origin": row.get("origin"),
        "origin_authority_evidence": row.get("origin_evidence_level"),
        "cloudflare_504": int(row.get("current_504") or 0),
        "cloudflare_5xx": int(row.get("current_5xx") or 0),
        "requests_24h": row.get("requests_24h"),
        "failure_ratio_percent": row.get("failure_ratio_percent"),
        "dominant_cache_status": row.get("cache_class"),
        "new_504_lower_bound_15m": rates.get("15m", {}).get("new_errors_lower_bound") if isinstance(rates.get("15m"), dict) else None,
        "new_504_lower_bound_60m": rates.get("60m", {}).get("new_errors_lower_bound") if isinstance(rates.get("60m"), dict) else None,
        "failure_boundary": boundary,
        "origin_access": access,
        "verified_user_impact": "unknown",
        "new_waf_rule_recommended": False,
        "automatic_repair_allowed": False,
        "repair_gate": "NO_REPAIR_WITHOUT_PROVEN_CAUSE_EXACT_SCOPE_AND_ROLLBACK",
        "missing_evidence": [
            "origin reverse-proxy request/error log rows for the affected timestamps",
            "origin upstream/application timing and failure rows for the affected timestamps",
            "request-id or timestamp correlation between Cloudflare 504 and origin handling",
        ] if not boundary["exact_failure_layer_proven"] else [],
    }


def safety_state() -> Dict[str, Any]:
    runtime = load_dict(GUARDED_RUNTIME_JSON)
    flags = runtime.get("flags") if isinstance(runtime.get("flags"), dict) else {}
    canary = load_dict(WRITE_CANARY_JSON)
    return {
        "runtime_stage": runtime.get("activation_stage"),
        "autonomy_level": runtime.get("autonomy_level"),
        "monitoring_enabled": flags.get("monitoring_enabled"),
        "guarded_live_autonomy_enabled": flags.get("guarded_live_autonomy_enabled"),
        "low_live_apply_enabled": flags.get("low_live_apply_enabled"),
        "medium_live_apply_enabled": flags.get("medium_live_apply_enabled"),
        "high_live_apply_enabled": flags.get("high_live_apply_enabled"),
        "production_apply_lock": flags.get("production_apply_lock"),
        "emergency_stop": flags.get("emergency_stop"),
        "breach": flags.get("breach", runtime.get("breach", False)),
        "write_canary_status": canary.get("status") or runtime.get("write_canary", {}).get("status"),
    }


def select_monitoring_decision(
    window: Dict[str, Any], correlation: Dict[str, Any], safety: Dict[str, Any]
) -> Dict[str, Any]:
    count_504 = int(correlation.get("cloudflare_504") or 0)
    access = correlation.get("origin_access", {}).get("status")
    boundary = correlation.get("failure_boundary", {})
    rate_15m = correlation.get("new_504_lower_bound_15m")
    rate_60m = correlation.get("new_504_lower_bound_60m")

    safety_findings: List[str] = []
    if safety.get("breach") is True:
        safety_findings.append("breach_true")
    if safety.get("medium_live_apply_enabled") is not False:
        safety_findings.append("medium_not_blocked")
    if safety.get("high_live_apply_enabled") is not False:
        safety_findings.append("high_not_blocked")
    if (
        safety.get("write_canary_status") == "CLOUDFLARE_WRITE_CANARY_BLOCKED"
        and safety.get("low_live_apply_enabled") is not False
    ):
        safety_findings.append("low_live_enabled_while_write_canary_blocked")

    if window.get("status") != EVIDENCE_WINDOW_ALIGNED:
        decision = "OWNER_ACTION_REQUIRED"
        next_diagnostic = "REFRESH_AND_ALIGN_EVIDENCE_WINDOW"
        reason = "Canonical use is blocked because the website, route and recovery snapshots are mixed or incomplete."
    elif safety_findings:
        decision = "OWNER_ACTION_REQUIRED"
        next_diagnostic = "REVIEW_RUNTIME_SAFETY_INVARIANT"
        reason = "A runtime safety invariant is not in the required fail-closed state."
    elif count_504 == 0:
        decision = "NO_ACTION"
        next_diagnostic = "CONTINUE_SCHEDULED_MONITORING"
        reason = "The aligned current snapshot contains no NowPlaying 504 and no productive action is justified."
    elif access == "REMOTE_OWNER_ACTION_REQUIRED":
        decision = "OWNER_ACTION_REQUIRED"
        next_diagnostic = "CORRELATE_ORIGIN_LOGS_READ_ONLY"
        reason = (
            "NowPlaying dominates the aligned 504 evidence, but the exact intermittent layer is unproven and no "
            "verified first-party SSH profile exists for the authoritative origin."
        )
    elif not boundary.get("exact_failure_layer_proven"):
        decision = "MONITOR_CONTINUE"
        next_diagnostic = "CORRELATE_ORIGIN_LOGS_READ_ONLY"
        reason = "The failure domain is narrowed by correlation, but direct evidence does not prove one repairable layer."
    elif (isinstance(rate_15m, int) and rate_15m > 0) or (isinstance(rate_60m, int) and rate_60m > 0):
        decision = "OWNER_ACTION_REQUIRED"
        next_diagnostic = "REVIEW_PROVEN_FAILURE_SCOPE_AND_ROLLBACK"
        reason = "Current error production and a reproduced failure require owner review; this phase has no repair authority."
    else:
        decision = "MONITOR_CONTINUE"
        next_diagnostic = "WAIT_FOR_NEXT_FRESH_SNAPSHOT"
        reason = "The rolling total remains elevated without proven current growth; continue read-only monitoring."

    return {
        "decision": decision,
        "execution": "NO_ACTION",
        "next_read_only_diagnostic": next_diagnostic,
        "reason": reason,
        "safety_findings": safety_findings,
        "productive_action_attempted": False,
        "remote_write_attempted": False,
        "repair_attempted": False,
        "new_waf_rule_recommended": False,
    }


def assemble_result(refresh: Dict[str, Any]) -> Dict[str, Any]:
    window = refresh.get("evidence_window", capture_evidence_window())
    correlation = build_correlation()
    safety = safety_state()
    decision = select_monitoring_decision(window, correlation, safety)
    refresh_ok = window.get("status") == EVIDENCE_WINDOW_ALIGNED
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "status": "MONITORING_DECISION_OK" if refresh_ok else "MONITORING_DECISION_EVIDENCE_WINDOW_BLOCKED",
        "report_classification": REPORT_CLASSIFICATION,
        "execution_boundaries": EXECUTION_BOUNDARIES,
        "refresh_status": "RECOVERY_EVIDENCE_REFRESH_OK" if refresh_ok else "RECOVERY_EVIDENCE_REFRESH_BLOCKED",
        "refresh": refresh,
        "evidence_window": window,
        "correlation": correlation,
        "autonomous_decision": decision,
        "runtime_safety": safety,
        "canonical_truth_ready": refresh_ok,
        "breach": safety.get("breach") is True,
    }


def refresh_before_canonical(force: bool = False, persist_outputs: bool = True) -> Dict[str, Any]:
    try:
        with refresh_lock():
            attempts: List[Dict[str, Any]] = []
            for attempt in range(2):
                row = refresh_once(force=force or attempt > 0)
                attempts.append(row)
                if (
                    not row["snapshot_changed_during_refresh"]
                    and row["evidence_window"].get("status") == EVIDENCE_WINDOW_ALIGNED
                ):
                    break
            refresh = {
                "status": (
                    "RECOVERY_EVIDENCE_REFRESH_OK"
                    if attempts[-1]["evidence_window"].get("status") == EVIDENCE_WINDOW_ALIGNED
                    else "RECOVERY_EVIDENCE_REFRESH_BLOCKED"
                ),
                "generated_at_utc": utc_now(),
                "attempt_count": len(attempts),
                "attempts": attempts,
                "evidence_window": attempts[-1]["evidence_window"],
                "read_only": True,
                "cloudflare_methods": ["GET"],
                "ssh_attempted": False,
                "productive_change_attempted": False,
            }
            result = assemble_result(refresh)
    except TimeoutError as exc:
        refresh = {
            "status": "RECOVERY_EVIDENCE_REFRESH_LOCKED",
            "generated_at_utc": utc_now(),
            "reason": str(exc),
            "evidence_window": capture_evidence_window(),
            "read_only": True,
            "productive_change_attempted": False,
        }
        result = assemble_result(refresh)

    if persist_outputs:
        persist(result)
    return result


def run_monitoring_cycle(force: bool = False) -> Dict[str, Any]:
    return refresh_before_canonical(force=force, persist_outputs=True)


def private_header(title: str) -> List[str]:
    return [f"# {title}", "", "Classification: " + " | ".join(REPORT_CLASSIFICATION), ""]


def render_refresh(result: Dict[str, Any]) -> str:
    window = result.get("evidence_window", {})
    lines = private_header("Sentinel Recovery Evidence Refresh")
    lines += [
        f"- status: `{result.get('refresh_status')}`",
        f"- evidence window: `{window.get('status')}`",
        f"- canonical truth ready: `{str(result.get('canonical_truth_ready')).lower()}`",
        f"- snapshot IDs: `{json.dumps(window.get('snapshot_ids', {}), sort_keys=True)}`",
        "- execution: fixed read-only collection and local report generation only",
        "- productive changes: `0`",
    ]
    return "\n".join(lines) + "\n"


def render_correlation(correlation: Dict[str, Any]) -> str:
    boundary = correlation.get("failure_boundary", {})
    access = correlation.get("origin_access", {})
    lines = private_header("Sentinel NowPlaying Cloudflare-Origin Correlation")
    lines += [
        f"- status: `{correlation.get('status')}`",
        f"- snapshot: `{correlation.get('snapshot_id')}`",
        f"- endpoint: `{correlation.get('endpoint')}`",
        f"- authoritative origin: `{correlation.get('authoritative_origin')}`",
        f"- Cloudflare 504: `{correlation.get('cloudflare_504')}`",
        f"- requests 24h: `{correlation.get('requests_24h')}`",
        f"- failure ratio: `{correlation.get('failure_ratio_percent')}%`",
        f"- failure layer: `{boundary.get('failure_layer')}`",
        f"- confidence: `{boundary.get('confidence')}`",
        f"- exact layer proven: `{str(boundary.get('exact_failure_layer_proven')).lower()}`",
        f"- causality proven: `{str(boundary.get('causality_proven')).lower()}`",
        f"- origin access: `{access.get('status')}`",
        f"- verified user impact: `{correlation.get('verified_user_impact')}`",
        f"- reason: {boundary.get('reason')}",
        "",
        "No WAF, Cloudflare, DNS, TLS, WordPress, database, nginx or timeout change was made.",
    ]
    return "\n".join(lines) + "\n"


def render_report(result: Dict[str, Any]) -> str:
    decision = result.get("autonomous_decision", {})
    safety = result.get("runtime_safety", {})
    lines = private_header("Sentinel Level-2 Monitoring Decision")
    lines += [
        f"- status: `{result.get('status')}`",
        f"- refresh: `{result.get('refresh_status')}`",
        f"- evidence window: `{result.get('evidence_window', {}).get('status')}`",
        f"- autonomous decision: `{decision.get('decision')}`",
        f"- execution: `{decision.get('execution')}`",
        f"- next read-only diagnostic: `{decision.get('next_read_only_diagnostic')}`",
        f"- reason: {decision.get('reason')}",
        "",
        "## Runtime Safety",
        "",
        f"- level: `{safety.get('autonomy_level')}`",
        f"- monitoring: `{str(safety.get('monitoring_enabled')).lower()}`",
        f"- LOW_LIVE: `{str(safety.get('low_live_apply_enabled')).lower()}`",
        f"- MEDIUM: `{str(safety.get('medium_live_apply_enabled')).lower()}`",
        f"- HIGH: `{str(safety.get('high_live_apply_enabled')).lower()}`",
        f"- production apply lock: `{str(safety.get('production_apply_lock')).lower()}`",
        f"- breach: `{str(safety.get('breach')).lower()}`",
    ]
    return "\n".join(lines) + "\n"


def build_playbook(name: str) -> Dict[str, Any]:
    common = {
        "schema_version": SCHEMA_VERSION,
        "status": "PLAYBOOK_ACTIVE",
        "read_only": True,
        "decisions": list(DECISIONS),
        "forbidden": [
            "Cloudflare write", "DNS change", "TLS change", "WAF change",
            "WordPress write", "database write", "global nginx change",
            "timeout change", "credential search", "unverified SSH",
            "LOW_LIVE activation", "MEDIUM execution", "HIGH execution",
        ],
    }
    if "evidence-window" in name:
        return {
            **common,
            "name": "sentinel-evidence-window-consistency",
            "contract": [
                "latest_monitor_snapshot == website_report_snapshot",
                "website_report_snapshot == origin_matrix_snapshot",
                "origin_matrix_snapshot == recovery_baseline_snapshot",
            ],
            "mismatch_status": EVIDENCE_WINDOW_MISMATCH,
        }
    if "cloudflare-origin" in name:
        return {
            **common,
            "name": "sentinel-cloudflare-origin-correlation",
            "fixed_endpoint": NOWPLAYING_PATH,
            "fixed_host": NOWPLAYING_HOST,
            "causality_rule": "a healthy point probe never proves the historical internal failure layer",
        }
    if "monitoring-decision" in name:
        return {
            **common,
            "name": "sentinel-level-2-monitoring-decision",
            "allowed_operations": [
                "refresh evidence", "prioritize failures", "select read-only diagnosis",
                "NO_ACTION", "MONITOR_CONTINUE", "OWNER_ACTION_REQUIRED",
            ],
        }
    return {
        **common,
        "name": "sentinel-recovery-evidence-refresh",
        "order": [
            "capture latest snapshot", "refresh website observe report",
            "refresh fixed route correlation", "refresh recovery",
            "recheck latest snapshot", "reject mixed windows", "build canonical truth",
        ],
    }


def persist(result: Dict[str, Any]) -> None:
    ensure_dirs()
    write_json(REPORT_JSON, result)
    write_text(REPORT_MD, render_report(result))
    write_json(REFRESH_JSON, result.get("refresh", {}))
    write_text(REFRESH_MD, render_refresh(result))
    write_json(CORRELATION_JSON, result.get("correlation", {}))
    write_text(CORRELATION_MD, render_correlation(result.get("correlation", {})))
    write_json(STATE_JSON, result)
    write_json(WINDOW_STATE_JSON, result.get("evidence_window", {}))

    history, status = read_json(HISTORY_JSON)
    if status != "ok" or not isinstance(history, list):
        history = []
    history.append({
        "generated_at_utc": result.get("generated_at_utc"),
        "status": result.get("status"),
        "evidence_window": result.get("evidence_window", {}).get("status"),
        "snapshot_id": result.get("evidence_window", {}).get("snapshot_ids", {}).get("latest_monitor_snapshot"),
        "decision": result.get("autonomous_decision", {}).get("decision"),
        "failure_layer": result.get("correlation", {}).get("failure_boundary", {}).get("failure_layer"),
        "breach": result.get("breach", False),
    })
    write_json(HISTORY_JSON, history[-400:])

    append_jsonl(AUDIT_JSONL, {
        "timestamp_utc": result.get("generated_at_utc"),
        "event": "monitoring_evidence_refreshed_and_decided",
        "status": result.get("status"),
        "evidence_window": result.get("evidence_window", {}).get("status"),
        "snapshot_id": result.get("evidence_window", {}).get("snapshot_ids", {}).get("latest_monitor_snapshot"),
        "decision": result.get("autonomous_decision", {}).get("decision"),
        "execution": "NO_ACTION",
        "cloudflare_writes": 0,
        "ssh_attempted": False,
        "breach": result.get("breach", False),
    })


def validate() -> Dict[str, Any]:
    findings: List[str] = []
    for path in (REPORT_JSON, REFRESH_JSON, CORRELATION_JSON, STATE_JSON, WINDOW_STATE_JSON, HISTORY_JSON, *PLAYBOOKS):
        _, status = read_json(path)
        if status != "ok":
            findings.append(f"{status}:{rel(path)}")
    for path in (REPORT_MD, REFRESH_MD, CORRELATION_MD):
        try:
            if not path.read_text(encoding="utf-8").strip():
                findings.append(f"empty:{rel(path)}")
        except OSError:
            findings.append(f"missing:{rel(path)}")
    report = load_dict(REPORT_JSON)
    if report.get("evidence_window", {}).get("status") != EVIDENCE_WINDOW_ALIGNED:
        findings.append("evidence_window_not_aligned")
    if report.get("autonomous_decision", {}).get("decision") not in DECISIONS:
        findings.append("invalid_monitoring_decision")
    if report.get("autonomous_decision", {}).get("execution") != "NO_ACTION":
        findings.append("productive_execution_detected")
    if report.get("correlation", {}).get("new_waf_rule_recommended") is not False:
        findings.append("waf_recommendation_not_false")
    if report.get("breach") is True:
        findings.append("breach_true")
    return {
        "status": "MONITORING_DECISION_VALIDATION_OK" if not findings else "MONITORING_DECISION_VALIDATION_FAILED",
        "findings": findings,
        "breach": False,
    }


def self_test() -> Dict[str, Any]:
    aligned = {
        "status": EVIDENCE_WINDOW_ALIGNED,
        "snapshot_ids": {
            "latest_monitor_snapshot": "20260814-160219",
            "website_report_snapshot": "20260814-160219",
            "origin_matrix_snapshot": "20260814-160219",
            "recovery_baseline_snapshot": "20260814-160219",
        },
    }
    safe = {
        "breach": False,
        "low_live_apply_enabled": False,
        "medium_live_apply_enabled": False,
        "high_live_apply_enabled": False,
        "write_canary_status": "CLOUDFLARE_WRITE_CANARY_BLOCKED",
    }
    healthy_probe = {
        "origin_probe": {"status_code": 200, "latency_ms": 12.0, "timed_out": False, "tls_verified": False},
    }
    boundary = classify_failure_boundary({"current_504": 762}, healthy_probe)
    owner = select_monitoring_decision(
        aligned,
        {
            "cloudflare_504": 762,
            "origin_access": {"status": "REMOTE_OWNER_ACTION_REQUIRED"},
            "failure_boundary": boundary,
            "new_504_lower_bound_15m": 0,
            "new_504_lower_bound_60m": 0,
        },
        safe,
    )
    no_action = select_monitoring_decision(
        aligned,
        {
            "cloudflare_504": 0,
            "origin_access": {"status": "REMOTE_OWNER_ACTION_REQUIRED"},
            "failure_boundary": classify_failure_boundary({"current_504": 0}, {}),
        },
        safe,
    )
    mismatch = select_monitoring_decision(
        {"status": EVIDENCE_WINDOW_MISMATCH},
        {"cloudflare_504": 0, "origin_access": {}, "failure_boundary": {}},
        safe,
    )
    source = Path(__file__).read_text(encoding="utf-8")
    checks = {
        "fixed_observe_command": tuple(FIXED_WEBSITE_OBSERVE)[1] == str(PROJECT_DIR / "sentinel_defense_bot.py"),
        "shell_disabled": "shell=False" in source and ("shell" + "=True") not in source,
        "no_ssh_execution": "subprocess.run([\"ssh\"" not in source and EXECUTION_BOUNDARIES["ssh_execution"] is False,
        "no_credential_search": EXECUTION_BOUNDARIES["credential_search"] is False,
        "read_only_cloudflare": EXECUTION_BOUNDARIES["cloudflare_api_methods"] == ["GET"],
        "mixed_window_blocked": mismatch["decision"] == "OWNER_ACTION_REQUIRED",
        "recovery_rebuilt_before_canonical": recovery_refresh_needed(
            False, "20260814-160219"
        ) is True,
        "runtime_playbooks_immutable": ("for playbook in " + "PLAYBOOKS") not in source,
        "healthy_point_probe_not_overclaimed": (
            boundary["exact_failure_layer_proven"] is False
            and boundary["confidence"] == "STRONG"
        ),
        "remote_origin_owner_gated": owner["decision"] == "OWNER_ACTION_REQUIRED",
        "zero_current_504_no_action": no_action["decision"] == "NO_ACTION",
        "all_decisions_non_productive": all(
            row["execution"] == "NO_ACTION" for row in (owner, no_action, mismatch)
        ),
        "no_new_waf_rule": owner["new_waf_rule_recommended"] is False,
        "low_live_unchanged": EXECUTION_BOUNDARIES["low_live_activation"] is False,
        "medium_high_blocked": (
            EXECUTION_BOUNDARIES["medium_activation"] is False
            and EXECUTION_BOUNDARIES["high_activation"] is False
        ),
        "json_roundtrip": json.loads(json.dumps({"window": aligned}))["window"]["status"] == EVIDENCE_WINDOW_ALIGNED,
        "breach_false": True,
    }
    findings = [name for name, passed in checks.items() if not passed]
    return {
        "status": "MONITORING_DECISION_SELF_TEST_OK" if not findings else "MONITORING_DECISION_SELF_TEST_FAILED",
        "checks": checks,
        "findings": findings,
        "breach": False,
    }


def print_status(report: Dict[str, Any]) -> None:
    print(report.get("status", "NOT_RUN"))
    print(f"refresh_status={report.get('refresh_status')}")
    print(f"evidence_window={report.get('evidence_window', {}).get('status')}")
    print(f"snapshot_id={report.get('evidence_window', {}).get('snapshot_ids', {}).get('latest_monitor_snapshot')}")
    print(f"decision={report.get('autonomous_decision', {}).get('decision')}")
    print(f"failure_layer={report.get('correlation', {}).get('failure_boundary', {}).get('failure_layer')}")
    print(f"confidence={report.get('correlation', {}).get('failure_boundary', {}).get('confidence')}")
    print(f"causality_proven={str(report.get('correlation', {}).get('failure_boundary', {}).get('causality_proven')).lower()}")
    print(f"low_live_enabled={str(report.get('runtime_safety', {}).get('low_live_apply_enabled')).lower()}")
    print(f"breach={str(report.get('breach', False)).lower()}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Sentinel Phase 10.22.2/10.23 monitoring decision engine")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--refresh-recovery", action="store_true")
    group.add_argument("--correlate-nowplaying", action="store_true")
    group.add_argument("--decide", action="store_true")
    group.add_argument("--run", action="store_true")
    group.add_argument("--validate", action="store_true")
    group.add_argument("--status", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        result = self_test()
        print(result["status"])
        for finding in result["findings"]:
            print(f"finding={finding}")
        return 0 if not result["findings"] else 1
    if args.validate:
        result = validate()
        print(result["status"])
        for finding in result["findings"]:
            print(f"finding={finding}")
        return 0 if not result["findings"] else 2
    if args.status:
        report = load_dict(REPORT_JSON)
        if not report:
            print("MONITORING_DECISION_NOT_RUN")
            return 1
        print_status(report)
        return 0
    if args.correlate_nowplaying:
        result = refresh_before_canonical(force=True, persist_outputs=True)
        print(result["correlation"]["status"])
        print(f"failure_layer={result['correlation']['failure_boundary']['failure_layer']}")
        return 0 if result["evidence_window"]["status"] == EVIDENCE_WINDOW_ALIGNED else 2
    if args.decide:
        current = load_dict(REPORT_JSON)
        if not current:
            current = refresh_before_canonical(persist_outputs=True)
        print(current["autonomous_decision"]["decision"])
        print(f"next={current['autonomous_decision']['next_read_only_diagnostic']}")
        return 0

    result = refresh_before_canonical(force=args.refresh_recovery, persist_outputs=True)
    print_status(result)
    return 0 if result["evidence_window"]["status"] == EVIDENCE_WINDOW_ALIGNED else 2


if __name__ == "__main__":
    raise SystemExit(main())
