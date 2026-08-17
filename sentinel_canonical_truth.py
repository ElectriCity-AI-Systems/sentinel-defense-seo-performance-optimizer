#!/usr/bin/env python3
"""Sentinel canonical truth resolver — Phase 10.21.

One operational fact = one canonical current value = one authoritative source =
traceable provenance.

This module is a pure resolver. It does not create a new runtime state machine:
every canonical field is read from the component that already owns that domain,
ranked by a fixed source precedence, and labelled with freshness plus full
provenance. Historical modules are preserved and classified
(CURRENT / SUPERSEDED / STALE_INFORMATIONAL / STALE_EXCLUDED_FROM_MASTER_STATUS /
MISSING / INVALID), but a legacy value can never overwrite a current operational
value.

Fail-closed: if a required canonical field cannot be resolved from a current
authoritative source, the field stays UNKNOWN and the snapshot reports
CANONICAL_TRUTH_INCOMPLETE with the missing fields named. Legacy values are never
promoted to current truth to fill a gap.

Read-only. No Cloudflare/WAF/DNS/TLS write, no systemd change, no timer change,
no LOW/MEDIUM/HIGH activation, no WordPress/database/nginx write, no credential
output, no cookie or Authorization header storage. Outputs stay under
reports/latest, state/adaptive-learning, snapshots, audit and playbooks.
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import sentinel_monitoring_decision_engine as monitoring_decision


PROJECT_DIR = Path(__file__).resolve().parent
SCHEMA_VERSION = "sentinel-canonical-truth-10.21"

REPORT_DIR = PROJECT_DIR / "reports/latest"
STATE_DIR = PROJECT_DIR / "state/adaptive-learning"
GUARDED_STATE_DIR = PROJECT_DIR / "state/guarded-autonomy"
SNAPSHOT_DIR = PROJECT_DIR / "snapshots"
AUDIT_DIR = PROJECT_DIR / "audit"
PLAYBOOK_DIR = PROJECT_DIR / "playbooks"
MONITOR_DIR = PROJECT_DIR / "cloudflare-monitor"

REPORT_JSON = REPORT_DIR / "sentinel-canonical-truth.json"
REPORT_MD = REPORT_DIR / "sentinel-canonical-truth.md"
LEGACY_JSON = REPORT_DIR / "sentinel-legacy-supersession.json"
LEGACY_MD = REPORT_DIR / "sentinel-legacy-supersession.md"
DAILY_HEADER_MD = REPORT_DIR / "sentinel-canonical-daily-header.md"

STATE_JSON = STATE_DIR / "canonical_truth.json"
HISTORY_JSON = STATE_DIR / "canonical_truth_history.json"
AUDIT_JSONL = AUDIT_DIR / "sentinel-canonical-truth.jsonl"

PLAYBOOKS = (
    PLAYBOOK_DIR / "sentinel-canonical-runtime-truth.playbook.json",
    PLAYBOOK_DIR / "sentinel-legacy-supersession.playbook.json",
    PLAYBOOK_DIR / "sentinel-runtime-source-precedence.playbook.json",
)

OUTPUT_JSONS = (REPORT_JSON, LEGACY_JSON, STATE_JSON, HISTORY_JSON, *PLAYBOOKS)
OUTPUT_MARKDOWN = (REPORT_MD, LEGACY_MD, DAILY_HEADER_MD)

# --------------------------------------------------------------------------- #
# Freshness vocabulary (Phase 10.21 adds SUPERSEDED)
# --------------------------------------------------------------------------- #

CURRENT = "CURRENT"
STALE_INFORMATIONAL = "STALE_INFORMATIONAL"
STALE_EXCLUDED = "STALE_EXCLUDED_FROM_MASTER_STATUS"
MISSING = "MISSING"
INVALID = "INVALID"
SUPERSEDED = "SUPERSEDED"

FRESHNESS_VOCABULARY = (
    CURRENT,
    STALE_INFORMATIONAL,
    STALE_EXCLUDED,
    MISSING,
    INVALID,
    SUPERSEDED,
)

FRESHNESS_DEFINITIONS = {
    CURRENT: "Within the source-specific current window and usable as canonical input.",
    STALE_INFORMATIONAL: "Older than the current window; informational only, no operational effect.",
    STALE_EXCLUDED: "Far older than the current window; excluded from master status.",
    MISSING: "Expected source is absent; no current fact is inferred from it.",
    INVALID: "Source is unreadable or its timestamp is unusable.",
    SUPERSEDED: (
        "Source may still be time-wise reasonably fresh, but for this specific field it has "
        "been replaced by a more authoritative source."
    ),
}

UNKNOWN = "UNKNOWN"
WP_USERS_ME_EVIDENCE_INSUFFICIENT = "WP_USERS_ME_EVIDENCE_INSUFFICIENT"
NOWPLAYING_EVIDENCE_INSUFFICIENT = "NOWPLAYING_EVIDENCE_INSUFFICIENT"

# Source kinds decide how a timestamp is interpreted.
KIND_RUNTIME_CYCLE = "RUNTIME_CYCLE"          # rewritten by the 2-minute guarded timer
KIND_ROLLING_METRIC = "ROLLING_METRIC"        # 24h measurement window
KIND_STATE_OF_RECORD = "STATE_OF_RECORD"      # last recorded transition, valid until changed
KIND_LEGACY_DIAGNOSTIC = "LEGACY_DIAGNOSTIC"  # historical investigation

KIND_TTL_SECONDS = {
    KIND_RUNTIME_CYCLE: 2 * 60 * 60,
    KIND_ROLLING_METRIC: 24 * 60 * 60,
    KIND_STATE_OF_RECORD: 30 * 24 * 60 * 60,
    KIND_LEGACY_DIAGNOSTIC: 24 * 60 * 60,
}

STALE_EXCLUDED_FACTOR = 7  # beyond ttl * factor a source is excluded from master status

# Source classes, ordered by the binding Phase 10.21 precedence.
CLASS_RUNTIME = "CURRENT_RUNTIME"
CLASS_SCHEDULER = "CURRENT_SCHEDULER_STATE"
CLASS_PIPELINE = "CURRENT_PRODUCTION_PIPELINE"
CLASS_WEBSITE = "CURRENT_WEBSITE_EVIDENCE"
CLASS_ORIGIN = "CURRENT_ORIGIN_DIAGNOSTICS"
CLASS_RECOVERY = "CURRENT_RECOVERY_MODULE"
CLASS_CONSISTENCY = "CURRENT_CONSISTENCY_EVALUATION"
CLASS_LEGACY = "LEGACY_HISTORICAL"

PRECEDENCE_TIERS = (
    (1, CLASS_RUNTIME, "current live runtime state"),
    (2, CLASS_SCHEDULER, "current scheduler state"),
    (3, CLASS_PIPELINE, "current production pipeline"),
    (4, CLASS_WEBSITE, "current website monitor evidence"),
    (5, CLASS_ORIGIN, "current origin diagnostics"),
    (6, CLASS_RECOVERY, "current recovery modules"),
    (7, CLASS_CONSISTENCY, "current consistency evaluation"),
    (8, CLASS_LEGACY, "stale legacy reports, informational only"),
)

CLASS_TIER = {name: tier for tier, name, _ in PRECEDENCE_TIERS}

TIMESTAMP_KEYS = (
    "generated_at_utc",
    "generated_at",
    "evaluated_at",
    "timestamp_utc",
    "checked_at",
    "created_at_utc",
)

SECRET_RE = re.compile(
    r"(?i)(?:password|passwd|secret|api[_-]?key|access[_-]?token|bearer|authorization|cookie|"
    r"private[_-]?key)\s*[:=]\s*[^\s,;]+"
)
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----")

EXECUTION_BOUNDARIES = {
    "cloudflare_write": False,
    "waf_rule_change": False,
    "dns_change": False,
    "tls_change": False,
    "systemd_change": False,
    "timer_change": False,
    "low_live_activation": False,
    "medium_activation": False,
    "high_activation": False,
    "wordpress_write": False,
    "database_change": False,
    "nginx_change": False,
    "credential_output": False,
    "cookie_storage": False,
    "authorization_header_storage": False,
    "phase_type": "reporting_state_resolution_source_precedence_diagnostic_validation",
}

REPORT_CLASSIFICATION = [
    "PRIVATE_OWNER_OPERATIONAL_REPORT",
    "NOT_FOR_PUBLIC_RELEASE",
    "NOT_FOR_GIT",
    "CONTAINS_INFRASTRUCTURE_METADATA",
]

NOWPLAYING_PATH = "/api/nowplaying/electri-city-ai-electro-radio"
WP_USERS_ME_PATH = "/wp-json/wp/v2/users/me"


# --------------------------------------------------------------------------- #
# Canonical source registry
# --------------------------------------------------------------------------- #

class Source:
    """One registered canonical source file."""

    def __init__(
        self,
        source_id: str,
        path: Path,
        source_class: str,
        kind: str,
        role: str,
        description: str,
    ) -> None:
        self.source_id = source_id
        self.path = path
        self.source_class = source_class
        self.kind = kind
        self.role = role
        self.description = description

    @property
    def tier(self) -> int:
        return CLASS_TIER[self.source_class]

    @property
    def ttl_seconds(self) -> int:
        return KIND_TTL_SECONDS[self.kind]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            "path": rel(self.path),
            "source_class": self.source_class,
            "precedence_tier": self.tier,
            "kind": self.kind,
            "role": self.role,
            "ttl_seconds": self.ttl_seconds,
            "description": self.description,
        }


SOURCE_LIST: Tuple[Source, ...] = (
    # Tier 1 — current live runtime state
    Source(
        "runtime_guarded_autonomy",
        REPORT_DIR / "sentinel-guarded-autonomy.json",
        CLASS_RUNTIME,
        KIND_RUNTIME_CYCLE,
        "primary",
        "Guarded autonomy runtime report, rewritten by the permanent 2-minute timer.",
    ),
    Source(
        "runtime_guarded_state",
        STATE_DIR / "guarded_autonomy.json",
        CLASS_RUNTIME,
        KIND_RUNTIME_CYCLE,
        "secondary",
        "Guarded autonomy runtime state twin under state/adaptive-learning.",
    ),
    Source(
        "runtime_activation",
        REPORT_DIR / "sentinel-guarded-runtime-activation.json",
        CLASS_RUNTIME,
        KIND_STATE_OF_RECORD,
        "secondary",
        "Guarded runtime activation report (stage, gates, systemd, canary).",
    ),
    Source(
        "runtime_monitoring_activation",
        GUARDED_STATE_DIR / "monitoring-activation.json",
        CLASS_RUNTIME,
        KIND_STATE_OF_RECORD,
        "secondary",
        "Monitoring activation state of record for the LEVEL_2 monitoring stage.",
    ),
    Source(
        "runtime_promotion",
        GUARDED_STATE_DIR / "runtime-promotion.json",
        CLASS_RUNTIME,
        KIND_STATE_OF_RECORD,
        "promotion",
        "Runtime promotion state of record incl. promotion blockers.",
    ),
    Source(
        "runtime_write_canary",
        GUARDED_STATE_DIR / "write-canary.json",
        CLASS_RUNTIME,
        KIND_STATE_OF_RECORD,
        "write_canary",
        "Cloudflare write canary state of record.",
    ),
    Source(
        "runtime_circuit_breaker",
        GUARDED_STATE_DIR / "circuit-breaker.json",
        CLASS_RUNTIME,
        KIND_STATE_OF_RECORD,
        "secondary",
        "Circuit breaker state of record.",
    ),
    # Tier 2 — current scheduler state
    Source(
        "scheduler_cycles",
        GUARDED_STATE_DIR / "scheduler-cycles.json",
        CLASS_SCHEDULER,
        KIND_STATE_OF_RECORD,
        "primary",
        "Scheduler cycle verification state of record (verified green cycles).",
    ),
    Source(
        "scheduler_verification",
        GUARDED_STATE_DIR / "scheduler-verification.json",
        CLASS_SCHEDULER,
        KIND_STATE_OF_RECORD,
        "legacy_scheduler",
        "Earlier scheduler verification state, superseded by scheduler-cycles.",
    ),
    # Tier 3 — current production pipeline
    Source(
        "production_pipeline",
        REPORT_DIR / "sentinel-production-pipeline.json",
        CLASS_PIPELINE,
        KIND_ROLLING_METRIC,
        "primary",
        "Production pipeline orchestrator report.",
    ),
    # Tier 4 — current website monitor evidence
    Source(
        "website",
        REPORT_DIR / "sentinel-defense-report.json",
        CLASS_WEBSITE,
        KIND_ROLLING_METRIC,
        "primary",
        "Website defense report from the current Cloudflare 24h monitor snapshot.",
    ),
    Source(
        "local",
        PROJECT_DIR / "inbox/local/local-defense-report.json",
        CLASS_WEBSITE,
        KIND_ROLLING_METRIC,
        "local",
        "Hetzner local agent report (required master input).",
    ),
    # Tier 5 — current origin diagnostics
    Source(
        "origin_diagnostics",
        REPORT_DIR / "sentinel-origin-failure-diagnostics.json",
        CLASS_ORIGIN,
        KIND_ROLLING_METRIC,
        "primary",
        "Origin failure diagnostics (503/504/522/526 correlation, TLS diagnostic).",
    ),
    # Tier 5 — current origin diagnostics
    Source(
        "origin_route_map",
        REPORT_DIR / "sentinel-origin-route-map.json",
        CLASS_ORIGIN,
        KIND_STATE_OF_RECORD,
        "route_map",
        "Origin route map from authoritative Cloudflare DNS plus edge and origin probes.",
    ),
    # The Phase 10.20 report is historical. It may remain auditable but must
    # never replace refreshed Phase 10.22 evidence in current truth.
    Source(
        "nowplaying_recovery",
        REPORT_DIR / "sentinel-nowplaying-recovery.json",
        CLASS_LEGACY,
        KIND_LEGACY_DIAGNOSTIC,
        "legacy_nowplaying",
        "Historical NowPlaying route-mismatch classification, informational only.",
    ),
    # Tier 6 — current recovery module
    Source(
        "origin_504_recovery",
        REPORT_DIR / "sentinel-504-recovery.json",
        CLASS_RECOVERY,
        KIND_ROLLING_METRIC,
        "origin_504_recovery",
        "Evidence-guided 504 recovery: dominant endpoint, repairability and repair gate.",
    ),
    # Tier 7 — current consistency evaluation
    Source(
        "consistency",
        REPORT_DIR / "sentinel-master-consistency.json",
        CLASS_CONSISTENCY,
        KIND_ROLLING_METRIC,
        "primary",
        "Master report consistency evaluation.",
    ),
    # Tier 8 — legacy / historical modules
    Source(
        "legacy_autonomy_policy",
        REPORT_DIR / "autonomy-policy-report.json",
        CLASS_LEGACY,
        KIND_LEGACY_DIAGNOSTIC,
        "legacy",
        "Phase 1.5 autonomy policy report (LEVEL_1_DRAFT_ONLY era).",
    ),
    Source(
        "legacy_autonomy_runtime_lock",
        REPORT_DIR / "autonomy-runtime-lock-report.json",
        CLASS_LEGACY,
        KIND_LEGACY_DIAGNOSTIC,
        "legacy",
        "Phase 3.5 owner runtime lock report (emergency stop era).",
    ),
    Source(
        "legacy_scheduler_plan",
        REPORT_DIR / "safe-draft-autonomy-scheduler-plan.json",
        CLASS_LEGACY,
        KIND_LEGACY_DIAGNOSTIC,
        "legacy",
        "Phase 3.8 review-only scheduler plan (timer not installed era).",
    ),
    Source(
        "legacy_timer_draft",
        REPORT_DIR / "safe-draft-autonomy-timer-draft-report.json",
        CLASS_LEGACY,
        KIND_LEGACY_DIAGNOSTIC,
        "legacy",
        "Phase 3.9 review-only systemd timer draft.",
    ),
    Source(
        "legacy_owner_daily_action",
        REPORT_DIR / "owner-daily-action-summary.json",
        CLASS_LEGACY,
        KIND_LEGACY_DIAGNOSTIC,
        "legacy",
        "Phase 2.8 owner daily action summary (SEO checklist era).",
    ),
    Source(
        "legacy_sourcemap",
        REPORT_DIR / "sourcemap-prevention-report.json",
        CLASS_LEGACY,
        KIND_LEGACY_DIAGNOSTIC,
        "legacy",
        "SourceMap prevention diagnostic from the .map-404 era.",
    ),
    Source(
        "legacy_ai_radio",
        REPORT_DIR / "ai-radio-api-timeout-diagnosis.json",
        CLASS_LEGACY,
        KIND_LEGACY_DIAGNOSTIC,
        "legacy",
        "AI-Radio API timeout diagnosis from the microcache deployment era.",
    ),
    Source(
        "legacy_microcache_status",
        REPORT_DIR / "ai-radio-nowplaying-microcache-status.json",
        CLASS_LEGACY,
        KIND_LEGACY_DIAGNOSTIC,
        "legacy",
        "NowPlaying microcache deployment status record.",
    ),
)

SOURCES: Dict[str, Source] = {source.source_id: source for source in SOURCE_LIST}

LEGACY_SOURCE_IDS = tuple(
    source.source_id for source in SOURCE_LIST if source.source_class == CLASS_LEGACY
) + ("scheduler_verification",)


def canonical_source_registry() -> Dict[str, Any]:
    """Registry grouped by domain, as required by Phase 10.21 section 7."""
    def group(*source_ids: str) -> Dict[str, str]:
        return {
            SOURCES[source_id].role: rel(SOURCES[source_id].path)
            for source_id in source_ids
            if source_id in SOURCES
        }

    return {
        "runtime": group(
            "runtime_guarded_autonomy",
            "runtime_activation",
            "runtime_promotion",
            "runtime_write_canary",
        ),
        "scheduler": group("scheduler_cycles", "scheduler_verification"),
        "pipeline": group("production_pipeline"),
        "website": group("website", "local"),
        "origin": group("origin_diagnostics", "origin_route_map", "origin_504_recovery"),
        "nowplaying": group("origin_504_recovery", "nowplaying_recovery"),
        "consistency": group("consistency"),
        "legacy": {
            SOURCES[source_id].source_id: rel(SOURCES[source_id].path)
            for source_id in LEGACY_SOURCE_IDS
            if source_id in SOURCES
        },
    }


# --------------------------------------------------------------------------- #
# Filesystem and safety helpers
# --------------------------------------------------------------------------- #

def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(PROJECT_DIR.resolve()))
    except (OSError, ValueError):
        return str(path)


def is_within_project(path: Path) -> bool:
    try:
        path.resolve().relative_to(PROJECT_DIR.resolve())
        return True
    except (OSError, ValueError):
        return False


def ensure_dirs() -> None:
    for directory in (REPORT_DIR, STATE_DIR, SNAPSHOT_DIR, AUDIT_DIR, PLAYBOOK_DIR):
        directory.mkdir(parents=True, exist_ok=True)


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


def format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def dotted(data: Any, dotted_key: str) -> Any:
    """Read a dotted path out of nested dicts without raising."""
    current = data
    for part in dotted_key.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


# --------------------------------------------------------------------------- #
# Freshness engine
# --------------------------------------------------------------------------- #

def source_timestamp(source: Source, data: Any) -> Tuple[Optional[datetime], Optional[str], Any]:
    """Find the most usable timestamp for a source document."""
    if not isinstance(data, dict):
        return None, None, None
    for key in TIMESTAMP_KEYS:
        parsed = parse_timestamp(data.get(key))
        if parsed is not None:
            return parsed, key, data.get(key)
    # Runtime state twins record only their last cycle timestamp.
    for key in ("last_cycle.timestamp", "gates.health.checked_at", "window.generated_at_utc"):
        raw = dotted(data, key)
        parsed = parse_timestamp(raw)
        if parsed is not None:
            return parsed, key, raw
    return None, None, None


def evaluate_source_freshness(source: Source, as_of: datetime) -> Dict[str, Any]:
    """Load one registered source and classify its freshness."""
    data, read_status = read_json(source.path)
    row: Dict[str, Any] = {
        **source.to_dict(),
        "read_status": read_status,
        "generated_at": None,
        "timestamp_field": None,
        "age_seconds": None,
        "freshness": MISSING,
        "usable_as_canonical_input": False,
        "reason": "",
    }
    if read_status == "missing":
        row["reason"] = "Registered source file is absent; no current fact is inferred from it."
        return {**row, "data": None}
    if read_status != "ok" or not isinstance(data, dict):
        row["freshness"] = INVALID
        row["reason"] = f"Source read status is {read_status}; it cannot be canonical input."
        return {**row, "data": None}

    timestamp, field, raw = source_timestamp(source, data)
    row["generated_at"] = raw
    row["timestamp_field"] = field
    if timestamp is None:
        row["freshness"] = INVALID
        row["reason"] = "Source has no usable timestamp."
        return {**row, "data": data}

    age = (as_of - timestamp).total_seconds()
    if age < -300:
        row["freshness"] = INVALID
        row["age_seconds"] = round(age, 2)
        row["reason"] = "Source timestamp lies in the future."
        return {**row, "data": data}

    age = max(0.0, age)
    row["age_seconds"] = round(age, 2)
    ttl = source.ttl_seconds
    if age <= ttl:
        row["freshness"] = CURRENT
        row["usable_as_canonical_input"] = True
        row["reason"] = f"Within the {source.kind} current window of {ttl} seconds."
    elif age <= ttl * STALE_EXCLUDED_FACTOR:
        row["freshness"] = STALE_INFORMATIONAL
        row["reason"] = f"Older than the {source.kind} window of {ttl} seconds; informational only."
    else:
        row["freshness"] = STALE_EXCLUDED
        row["reason"] = (
            f"Older than {ttl * STALE_EXCLUDED_FACTOR} seconds; excluded from master status."
        )
    return {**row, "data": data}


def load_sources(as_of: Optional[datetime] = None) -> Dict[str, Dict[str, Any]]:
    moment = as_of or datetime.now(timezone.utc)
    return {source.source_id: evaluate_source_freshness(source, moment) for source in SOURCE_LIST}


# --------------------------------------------------------------------------- #
# Field extractors
# --------------------------------------------------------------------------- #

def website_metrics(data: Any) -> Dict[str, int]:
    result: Dict[str, int] = {}
    metrics = data.get("metrics") if isinstance(data, dict) else None
    if not isinstance(metrics, list):
        return result
    for item in metrics:
        if not isinstance(item, dict) or not isinstance(item.get("key"), str):
            continue
        value = item.get("value")
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            result[item["key"]] = int(value)
    return result


def website_path_rows(data: Any) -> List[Dict[str, Any]]:
    origin = data.get("origin_pressure_breakdown") if isinstance(data, dict) else None
    rows = origin.get("top_5xx_paths") if isinstance(origin, dict) else None
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def website_status_code_counts(data: Any) -> Dict[int, int]:
    origin = data.get("origin_pressure_breakdown") if isinstance(data, dict) else None
    rows = origin.get("top_5xx_status_codes") if isinstance(origin, dict) else None
    counts: Dict[int, int] = {}
    for item in rows if isinstance(rows, list) else []:
        if not isinstance(item, dict):
            continue
        try:
            counts[int(item.get("status"))] = int(item.get("count", 0) or 0)
        except (TypeError, ValueError):
            continue
    return counts


def path_status_count(data: Any, path: str, code: int) -> Optional[int]:
    for row in website_path_rows(data):
        if row.get("path") != path:
            continue
        statuses = row.get("statuses")
        total = 0
        found = False
        for item in statuses if isinstance(statuses, list) else []:
            if not isinstance(item, dict):
                continue
            try:
                if int(item.get("status")) == code:
                    total += int(item.get("count", 0) or 0)
                    found = True
            except (TypeError, ValueError):
                continue
        return total if found else 0
    return None


def metric_extractor(key: str) -> Callable[[Any], Any]:
    def extract(data: Any) -> Any:
        return website_metrics(data).get(key)
    return extract


def status_code_extractor(code: int) -> Callable[[Any], Any]:
    def extract(data: Any) -> Any:
        return website_status_code_counts(data).get(code)
    return extract


def path_status_extractor(path: str, code: int) -> Callable[[Any], Any]:
    def extract(data: Any) -> Any:
        return path_status_count(data, path, code)
    return extract


def dotted_extractor(dotted_key: str) -> Callable[[Any], Any]:
    def extract(data: Any) -> Any:
        return dotted(data, dotted_key)
    return extract


def top_failure_paths_extractor(limit: int = 10) -> Callable[[Any], Any]:
    def extract(data: Any) -> Any:
        rows = website_path_rows(data)
        if not rows:
            return None
        result = []
        for row in sorted(rows, key=lambda item: -int(item.get("count", 0) or 0))[:limit]:
            statuses = {}
            for item in row.get("statuses", []) if isinstance(row.get("statuses"), list) else []:
                if isinstance(item, dict) and item.get("status") is not None:
                    statuses[str(item.get("status"))] = int(item.get("count", 0) or 0)
            result.append({
                "path": row.get("path"),
                "count": int(row.get("count", 0) or 0),
                "statuses": statuses,
            })
        return result
    return extract


def snapshot_id_extractor(data: Any) -> Any:
    """Derive the monitor snapshot id the website report was built from."""
    rolling = data.get("rolling_window_context") if isinstance(data, dict) else None
    candidates: List[Any] = []
    if isinstance(rolling, dict):
        comparison = rolling.get("comparison")
        if isinstance(comparison, dict):
            candidates.append(comparison.get("current_generated_at_utc"))
        window = rolling.get("window")
        if isinstance(window, dict):
            candidates.append(window.get("generated_at_utc"))
    candidates.append(data.get("generated_at_utc") if isinstance(data, dict) else None)
    for candidate in candidates:
        parsed = parse_timestamp(candidate)
        if parsed is None:
            continue
        snapshot_id = parsed.strftime("%Y%m%d-%H%M%S")
        if (MONITOR_DIR / snapshot_id).is_dir():
            return snapshot_id
    for candidate in candidates:
        parsed = parse_timestamp(candidate)
        if parsed is not None:
            return parsed.strftime("%Y%m%d-%H%M%S")
    return None


GROWTH_STATUSES = {"NEW_GROWTH_PRESENT", "RECENT_SIGNIFICANT_GROWTH"}


def current_growth_extractor(data: Any) -> Any:
    """Growth verdict of the current rolling window, from current evidence only."""
    rolling = data.get("rolling_window_context") if isinstance(data, dict) else None
    if not isinstance(rolling, dict):
        return None
    status = rolling.get("status")
    if not isinstance(status, str):
        return None
    if status in GROWTH_STATUSES:
        return "GROWTH_PRESENT"
    if rolling.get("ok_eligible") is True:
        return "NO_GROWTH_OBSERVED"
    return "GROWTH_UNDETERMINED"


def scheduler_timer_active_extractor(data: Any) -> Any:
    checks = dotted(data, "checks.timer_active")
    return checks if isinstance(checks, bool) else None


# --------------------------------------------------------------------------- #
# Field ownership — which source owns which canonical field, in which order
# --------------------------------------------------------------------------- #

class Candidate:
    def __init__(
        self,
        source_id: str,
        extractor: Callable[[Any], Any],
        expression: str,
        allow_stale_informational: bool = False,
    ) -> None:
        self.source_id = source_id
        self.extractor = extractor
        self.expression = expression
        self.allow_stale_informational = allow_stale_informational


def cand(source_id: str, dotted_key: str, allow_stale: bool = False) -> Candidate:
    return Candidate(source_id, dotted_extractor(dotted_key), dotted_key, allow_stale)


def cand_fn(
    source_id: str,
    extractor: Callable[[Any], Any],
    expression: str,
    allow_stale: bool = False,
) -> Candidate:
    return Candidate(source_id, extractor, expression, allow_stale)


# Runtime fields — never read from the Level-1 modules while a current guarded
# runtime state exists.
RUNTIME_FIELDS: Dict[str, List[Candidate]] = {
    "runtime_stage": [
        cand("runtime_guarded_autonomy", "activation_stage"),
        cand("runtime_guarded_state", "activation_stage"),
        cand("runtime_promotion", "runtime_stage", allow_stale=True),
        cand("runtime_monitoring_activation", "activation_stage", allow_stale=True),
    ],
    "autonomy_level": [
        cand("runtime_guarded_autonomy", "autonomy_level"),
        cand("runtime_guarded_state", "autonomy_level"),
        cand("runtime_activation", "autonomy_level", allow_stale=True),
    ],
    "monitoring_enabled": [
        cand("runtime_guarded_autonomy", "flags.monitoring_enabled"),
        cand("runtime_guarded_state", "flags.monitoring_enabled"),
        cand("runtime_monitoring_activation", "monitoring_enabled", allow_stale=True),
    ],
    "systemd_timer_active": [
        cand("runtime_guarded_autonomy", "systemd.timer_active"),
        cand("runtime_activation", "systemd.timer_active", allow_stale=True),
        cand("runtime_monitoring_activation", "timer_active", allow_stale=True),
        cand_fn("scheduler_cycles", scheduler_timer_active_extractor, "checks.timer_active", True),
    ],
    "systemd_timer_enabled": [
        cand("runtime_guarded_autonomy", "systemd.timer_enabled"),
        cand("runtime_activation", "systemd.install_status", allow_stale=True),
    ],
    "guarded_live_autonomy_enabled": [
        cand("runtime_guarded_autonomy", "flags.guarded_live_autonomy_enabled"),
        cand("runtime_guarded_state", "flags.guarded_live_autonomy_enabled"),
    ],
    "low_live_apply_enabled": [
        cand("runtime_guarded_autonomy", "flags.low_live_apply_enabled"),
        cand("runtime_guarded_state", "flags.low_live_apply_enabled"),
        cand("runtime_promotion", "low_live_apply_enabled", allow_stale=True),
    ],
    "medium_live_apply_enabled": [
        cand("runtime_guarded_autonomy", "flags.medium_live_apply_enabled"),
        cand("runtime_guarded_state", "flags.medium_live_apply_enabled"),
    ],
    "high_live_apply_enabled": [
        cand("runtime_guarded_autonomy", "flags.high_live_apply_enabled"),
        cand("runtime_guarded_state", "flags.high_live_apply_enabled"),
    ],
    "production_apply_lock": [
        cand("runtime_guarded_autonomy", "flags.production_apply_lock"),
        cand("runtime_guarded_state", "flags.production_apply_lock"),
        cand("runtime_promotion", "production_apply_lock", allow_stale=True),
    ],
    "emergency_stop": [
        cand("runtime_guarded_autonomy", "flags.emergency_stop"),
        cand("runtime_guarded_state", "flags.emergency_stop"),
        cand("runtime_monitoring_activation", "emergency_stop", allow_stale=True),
    ],
    "breach": [
        cand("runtime_guarded_autonomy", "flags.breach"),
        cand("runtime_guarded_state", "flags.breach"),
        cand("runtime_monitoring_activation", "breach", allow_stale=True),
    ],
    "circuit_breaker_status": [
        cand("runtime_guarded_autonomy", "circuit_breaker.status"),
        cand("runtime_guarded_state", "last_cycle.circuit_breaker.status"),
        cand("runtime_circuit_breaker", "status", allow_stale=True),
    ],
    "rollback_status": [
        cand("runtime_guarded_autonomy", "rollback_status.status"),
        cand("runtime_activation", "rollback.status", allow_stale=True),
    ],
    "promotion_status": [
        cand("runtime_promotion", "status", allow_stale=True),
        cand("runtime_activation", "promotion.status", allow_stale=True),
    ],
    "promotion_blockers": [
        cand("runtime_promotion", "blockers", allow_stale=True),
        cand("runtime_activation", "promotion.blockers", allow_stale=True),
    ],
    "write_canary_status": [
        cand("runtime_write_canary", "status", allow_stale=True),
        cand("runtime_activation", "write_canary.status", allow_stale=True),
    ],
    "last_cycle_id": [
        cand("runtime_guarded_autonomy", "last_cycle.cycle_id"),
        cand("runtime_guarded_state", "last_cycle.cycle_id"),
    ],
    "last_decision": [
        cand("runtime_guarded_autonomy", "last_cycle.decision"),
        cand("runtime_guarded_state", "last_cycle.decision"),
    ],
    "scheduler_verification_status": [
        cand("scheduler_cycles", "status", allow_stale=True),
        cand("runtime_promotion", "scheduler_verification_status", allow_stale=True),
        cand("scheduler_verification", "status", allow_stale=True),
    ],
    "scheduler_successful_cycles": [
        cand("scheduler_cycles", "successful_cycles", allow_stale=True),
        cand("runtime_promotion", "scheduler_successful_cycles", allow_stale=True),
    ],
}

# Website fields — current monitor snapshots only.
WEBSITE_FIELDS: Dict[str, List[Candidate]] = {
    "website_status": [cand("website", "overall_status")],
    "website_correlation_status": [cand("website", "correlation_status")],
    "local_status": [cand("local", "overall_status")],
    "total_5xx": [cand_fn("website", metric_extractor("total_5xx"), "metrics[total_5xx]")],
    "http_504": [cand_fn("website", status_code_extractor(504), "top_5xx_status_codes[504]")],
    "http_503": [cand_fn("website", status_code_extractor(503), "top_5xx_status_codes[503]")],
    "http_522": [cand_fn("website", status_code_extractor(522), "top_5xx_status_codes[522]")],
    "http_526": [cand_fn("website", status_code_extractor(526), "top_5xx_status_codes[526]")],
    "rolling_window_status": [cand("website", "rolling_window_context.status")],
    "current_snapshot_id": [cand_fn("website", snapshot_id_extractor, "derived_monitor_snapshot_id")],
    "top_failure_paths": [cand_fn("website", top_failure_paths_extractor(), "top_5xx_paths[top10]")],
    "current_growth": [cand_fn("website", current_growth_extractor, "rolling_window_context.growth")],
    "source_map_404": [cand_fn("website", metric_extractor("map_404"), "metrics[map_404]")],
    "nowplaying_504": [
        cand_fn("website", path_status_extractor(NOWPLAYING_PATH, 504), f"top_5xx_paths[{NOWPLAYING_PATH}][504]"),
    ],
    "wp_users_me_504": [
        cand_fn("website", path_status_extractor(WP_USERS_ME_PATH, 504), f"top_5xx_paths[{WP_USERS_ME_PATH}][504]"),
    ],
}

# Diagnostic and recovery fields.
DIAGNOSTIC_FIELDS: Dict[str, List[Candidate]] = {
    "origin_diagnostic_status": [cand("origin_diagnostics", "status")],
    "origin_tls_status": [cand("origin_diagnostics", "origin_tls_diagnostic.status")],
    "wp_users_me_classification": [
        cand("origin_diagnostics", "wp_users_me_diagnostic.classification"),
    ],
    "wp_users_me_diagnostic_504": [
        cand(
            "origin_diagnostics",
            "wp_users_me_diagnostic.evidence.request_frequency.status_504_24h",
        ),
    ],
    "nowplaying_classification": [
        # Phase 10.22 evidence-guided recovery is the only current source. The
        # older route-mismatch report is retained as legacy but never selected.
        cand("origin_504_recovery", "nowplaying_chain.failure_class"),
    ],
    "nowplaying_recovery_504": [
        cand("origin_504_recovery", "baseline.nowplaying_504"),
    ],
    "nowplaying_automatic_repair_allowed": [
        cand("origin_504_recovery", "nowplaying_chain.automatic_repair_allowed"),
    ],
    "nowplaying_repair_applied": [
        cand("origin_504_recovery", "effect.repair_applied"),
    ],
    "consistency_status": [cand("consistency", "status")],
    # Phase 10.22 — evidence-guided origin recovery
    "origin_recovery_status": [cand("origin_504_recovery", "status")],
    "dominant_504_endpoint": [cand("origin_504_recovery", "dominant_504_endpoint")],
    "dominant_504_origin": [cand("origin_504_recovery", "dominant_504_origin")],
    # The recovery report identifies the dominant endpoint, but its percentage
    # belongs to that report's older baseline snapshot. The live percentage is
    # derived later from current website evidence.
    "dominant_504_share_percent": [cand("origin_504_recovery", "dominant_504_share_percent")],
    "origin_504_repairability": [cand("origin_504_recovery", "repair_gate.status")],
    "primary_failure_focus": [
        cand("origin_504_recovery", "primary_failure_focus.primary_failure_focus"),
    ],
    "origin_route_map_status": [cand("origin_route_map", "status", allow_stale=True)],
    "last_origin_repair": [cand("origin_504_recovery", "repair_gate.selected_endpoint")],
    "last_origin_repair_effect": [cand("origin_504_recovery", "effect.status")],
}

FIELD_OWNERSHIP: Dict[str, List[Candidate]] = {
    **RUNTIME_FIELDS,
    **WEBSITE_FIELDS,
    **DIAGNOSTIC_FIELDS,
}

FIELD_DOMAIN = {
    **{name: "runtime" for name in RUNTIME_FIELDS},
    **{name: "website" for name in WEBSITE_FIELDS},
    **{name: "diagnostic" for name in DIAGNOSTIC_FIELDS},
}

# Fields that must resolve, otherwise the snapshot is CANONICAL_TRUTH_INCOMPLETE.
REQUIRED_FIELDS = (
    "runtime_stage",
    "autonomy_level",
    "monitoring_enabled",
    "systemd_timer_active",
    "scheduler_verification_status",
    "low_live_apply_enabled",
    "production_apply_lock",
    "emergency_stop",
    "breach",
    "write_canary_status",
    "promotion_status",
    "website_status",
    "total_5xx",
    "rolling_window_status",
)

# Legacy claims kept for provenance: which legacy source claims which canonical field.
LEGACY_FIELD_CLAIMS: Dict[str, List[Tuple[str, str]]] = {
    "autonomy_level": [
        ("legacy_autonomy_policy", "current_autonomy_level"),
    ],
    "emergency_stop": [
        ("legacy_autonomy_runtime_lock", "emergency_stop"),
        ("legacy_scheduler_plan", "emergency_stop"),
    ],
    "low_live_apply_enabled": [
        ("legacy_autonomy_runtime_lock", "live_apply_enabled"),
    ],
    "systemd_timer_active": [
        ("legacy_scheduler_plan", "timer_installation_status"),
        ("legacy_timer_draft", "timer_installation_status"),
    ],
    "scheduler_verification_status": [
        ("scheduler_verification", "status"),
    ],
    "nowplaying_504": [
        ("legacy_ai_radio", "nowplaying_504"),
    ],
    "source_map_404": [
        ("legacy_sourcemap", "map_404_metric.value"),
    ],
    "owner_priority": [
        ("legacy_owner_daily_action", "recommended_next_owner_action"),
    ],
}


# --------------------------------------------------------------------------- #
# Resolution
# --------------------------------------------------------------------------- #

def resolve_field(
    field: str,
    candidates: Sequence[Candidate],
    loaded: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    """Resolve one canonical field with full provenance and supersession."""
    attempts: List[Dict[str, Any]] = []
    winner: Optional[Dict[str, Any]] = None

    for candidate in candidates:
        row = loaded.get(candidate.source_id)
        source = SOURCES.get(candidate.source_id)
        if row is None or source is None:
            attempts.append({
                "source": candidate.source_id,
                "expression": candidate.expression,
                "outcome": "SOURCE_NOT_REGISTERED",
            })
            continue
        attempt: Dict[str, Any] = {
            "source": rel(source.path),
            "source_id": source.source_id,
            "source_class": source.source_class,
            "precedence_tier": source.tier,
            "expression": candidate.expression,
            "generated_at": row.get("generated_at"),
            "freshness": row.get("freshness"),
        }
        if row.get("data") is None:
            attempt["outcome"] = f"UNUSABLE_{row.get('freshness')}"
            attempts.append(attempt)
            continue
        try:
            value = candidate.extractor(row["data"])
        except Exception:  # defensive: a malformed source must not abort resolution
            attempt["outcome"] = "EXTRACTION_ERROR"
            attempts.append(attempt)
            continue
        if value is None:
            attempt["outcome"] = "NO_VALUE"
            attempts.append(attempt)
            continue
        attempt["value"] = value
        freshness = row.get("freshness")
        usable = freshness == CURRENT or (
            freshness == STALE_INFORMATIONAL and candidate.allow_stale_informational
        )
        if winner is None and usable:
            attempt["outcome"] = "SELECTED"
            winner = attempt
        elif winner is not None:
            attempt["outcome"] = SUPERSEDED
            attempt["superseded_by"] = winner["source"]
        else:
            attempt["outcome"] = f"EXCLUDED_{freshness}"
        attempts.append(attempt)

    if winner is None:
        return {
            "field": field,
            "domain": FIELD_DOMAIN.get(field, "derived"),
            "value": None,
            "resolution": "UNRESOLVED",
            "source": None,
            "source_class": None,
            "generated_at": None,
            "freshness": MISSING,
            "operational_effect": False,
            "candidates": attempts,
            "reason": "No current authoritative source provided a value; fail-closed as UNKNOWN.",
        }

    superseded = [row for row in attempts if row.get("outcome") == SUPERSEDED]
    return {
        "field": field,
        "domain": FIELD_DOMAIN.get(field, "derived"),
        "value": winner.get("value"),
        "resolution": "RESOLVED",
        "source": winner["source"],
        "source_id": winner["source_id"],
        "source_class": winner["source_class"],
        "precedence_tier": winner["precedence_tier"],
        "expression": winner["expression"],
        "generated_at": winner.get("generated_at"),
        "freshness": winner.get("freshness"),
        "operational_effect": True,
        "superseded_sources": [row["source"] for row in superseded],
        "candidates": attempts,
    }


def resolve_fields(loaded: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {
        field: resolve_field(field, candidates, loaded)
        for field, candidates in FIELD_OWNERSHIP.items()
    }


def value_of(fields: Dict[str, Dict[str, Any]], field: str, default: Any = None) -> Any:
    row = fields.get(field)
    if not isinstance(row, dict) or row.get("resolution") != "RESOLVED":
        return default
    return row.get("value")


def provenance(
    fields: Dict[str, Dict[str, Any]],
    field: str,
    unknown_value: Any = UNKNOWN,
) -> Dict[str, Any]:
    """Compact provenance block for the canonical snapshot."""
    row = fields.get(field)
    if not isinstance(row, dict) or row.get("resolution") != "RESOLVED":
        return {
            "value": unknown_value,
            "source": None,
            "source_class": None,
            "generated_at": None,
            "freshness": row.get("freshness", MISSING) if isinstance(row, dict) else MISSING,
            "operational_effect": False,
            "resolution": "UNRESOLVED",
        }
    return {
        "value": row.get("value"),
        "source": row.get("source"),
        "source_class": row.get("source_class"),
        "generated_at": row.get("generated_at"),
        "freshness": row.get("freshness"),
        "operational_effect": True,
        "resolution": "RESOLVED",
    }


def derived_provenance(
    value: Any,
    inputs: Sequence[str],
    rule: str,
    resolved: bool = True,
) -> Dict[str, Any]:
    return {
        "value": value,
        "source": "sentinel_canonical_truth.py (derived)",
        "source_class": "CANONICAL_DERIVATION",
        "derived_from": list(inputs),
        "rule": rule,
        "generated_at": None,
        "freshness": CURRENT if resolved else MISSING,
        "operational_effect": bool(resolved),
        "resolution": "RESOLVED" if resolved else "UNRESOLVED",
    }


def normalize_promotion_blockers_value(value: Any) -> Any:
    """Return UNKNOWN or a real list; never treat a scalar string as a sequence."""
    if isinstance(value, str):
        blocker = value.strip()
        if not blocker or blocker.upper() == UNKNOWN:
            return UNKNOWN
        return [blocker]
    if isinstance(value, (list, tuple, set)):
        items = list(value)
        if isinstance(value, set):
            items = sorted(items, key=str)
        if any(not isinstance(item, str) or not item.strip() for item in items):
            return UNKNOWN
        return [item.strip() for item in items]
    return UNKNOWN


def promotion_blockers_provenance(fields: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    block = provenance(fields, "promotion_blockers")
    normalized = normalize_promotion_blockers_value(block.get("value"))
    if normalized == UNKNOWN:
        return {
            **block,
            "value": UNKNOWN,
            "operational_effect": False,
            "resolution": "UNRESOLVED",
            "normalization": "SCALAR_UNKNOWN_PRESERVED",
        }
    return {
        **block,
        "value": normalized,
        "normalization": "BLOCKER_LIST_NORMALIZED",
    }


def format_promotion_blockers(value: Any) -> str:
    normalized = normalize_promotion_blockers_value(value)
    if normalized == UNKNOWN:
        return UNKNOWN
    return ", ".join(normalized) or "none"


def derive_wp_users_me_classification(
    fields: Dict[str, Dict[str, Any]],
    generated_at: str,
) -> Dict[str, Any]:
    """Bind a concrete users/me diagnosis to the current compatible path count."""
    classification = provenance(fields, "wp_users_me_classification")
    current_count = value_of(fields, "wp_users_me_504")
    diagnostic_count = value_of(fields, "wp_users_me_diagnostic_504")
    current_count_resolved = (
        isinstance(current_count, (int, float)) and not isinstance(current_count, bool)
    )
    diagnostic_count_resolved = (
        isinstance(diagnostic_count, (int, float)) and not isinstance(diagnostic_count, bool)
    )
    compatible = bool(
        current_count_resolved
        and diagnostic_count_resolved
        and current_count > 0
        and float(current_count) == float(diagnostic_count)
    )
    metadata = {
        "current_504_count": current_count if current_count_resolved else UNKNOWN,
        "diagnostic_504_count": diagnostic_count if diagnostic_count_resolved else UNKNOWN,
        "compatible_current_evidence": compatible,
    }
    value = classification.get("value")
    if value == WP_USERS_ME_EVIDENCE_INSUFFICIENT:
        return {**classification, **metadata}
    if classification.get("resolution") == "RESOLVED" and compatible:
        return {**classification, **metadata}

    fail_closed = derived_provenance(
        WP_USERS_ME_EVIDENCE_INSUFFICIENT,
        ["wp_users_me_504", "wp_users_me_diagnostic_504", "wp_users_me_classification"],
        (
            "A concrete users/me classification requires a resolved positive current 504 "
            "count and a matching current diagnostic count. Missing or mismatched evidence "
            "is classified as insufficient."
        ),
    )
    fail_closed["generated_at"] = generated_at
    return {**fail_closed, **metadata}


def derive_nowplaying_classification(
    fields: Dict[str, Dict[str, Any]],
    generated_at: str,
) -> Dict[str, Any]:
    """Allow NOWPLAYING_HEALTHY only with matching explicit current zero evidence."""
    classification = provenance(fields, "nowplaying_classification")
    current_count = value_of(fields, "nowplaying_504")
    recovery_count = value_of(fields, "nowplaying_recovery_504")
    current_resolved = (
        isinstance(current_count, (int, float)) and not isinstance(current_count, bool)
    )
    recovery_resolved = (
        isinstance(recovery_count, (int, float)) and not isinstance(recovery_count, bool)
    )
    counts_match = bool(
        current_resolved
        and recovery_resolved
        and float(current_count) == float(recovery_count)
    )
    value = classification.get("value")
    compatible = bool(
        counts_match
        and (
            (value == "NOWPLAYING_HEALTHY" and float(current_count) == 0)
            or (
                value not in {None, UNKNOWN, "NOWPLAYING_HEALTHY", NOWPLAYING_EVIDENCE_INSUFFICIENT}
                and float(current_count) > 0
            )
        )
    )
    metadata = {
        "current_504_count": current_count if current_resolved else UNKNOWN,
        "recovery_504_count": recovery_count if recovery_resolved else UNKNOWN,
        "compatible_current_evidence": compatible,
    }
    if value == NOWPLAYING_EVIDENCE_INSUFFICIENT:
        return {**classification, **metadata}
    if classification.get("resolution") == "RESOLVED" and compatible:
        return {**classification, **metadata}

    fail_closed = derived_provenance(
        NOWPLAYING_EVIDENCE_INSUFFICIENT,
        ["nowplaying_504", "nowplaying_recovery_504", "nowplaying_classification"],
        (
            "NOWPLAYING_HEALTHY requires matching explicit current and recovery 504 counts "
            "equal to zero. Other concrete classifications require matching positive counts."
        ),
    )
    fail_closed["generated_at"] = generated_at
    return {**fail_closed, **metadata}


# --------------------------------------------------------------------------- #
# Derived canonical status
# --------------------------------------------------------------------------- #

STATUS_RANK = {"OK": 0, "WARNING": 1, "CRITICAL": 2}


def derive_overall_status(fields: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Worst of the required current inputs, escalated by an active breach."""
    website_status = value_of(fields, "website_status")
    local_status = value_of(fields, "local_status")
    breach = value_of(fields, "breach")
    inputs = ["website_status", "local_status", "breach"]
    if breach is True:
        return derived_provenance(
            "CRITICAL", inputs, "An active breach forces CRITICAL."
        )
    statuses = [
        str(website_status).upper() if isinstance(website_status, str) else UNKNOWN,
        str(local_status).upper() if isinstance(local_status, str) else UNKNOWN,
    ]
    if UNKNOWN in statuses or any(status not in STATUS_RANK for status in statuses):
        return derived_provenance(
            UNKNOWN,
            inputs,
            "A required status input is missing; overall status stays UNKNOWN (fail-closed).",
            resolved=False,
        )
    worst = max(statuses, key=lambda status: STATUS_RANK[status])
    return derived_provenance(
        worst,
        inputs,
        "Worst of website and local status; sub-module findings may only escalate OK to WARNING.",
    )


def derive_runtime_status(fields: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    inputs = [
        "breach",
        "emergency_stop",
        "runtime_stage",
        "monitoring_enabled",
        "systemd_timer_active",
        "scheduler_verification_status",
    ]
    breach = value_of(fields, "breach")
    emergency_stop = value_of(fields, "emergency_stop")
    stage = value_of(fields, "runtime_stage")
    monitoring = value_of(fields, "monitoring_enabled")
    timer = value_of(fields, "systemd_timer_active")
    scheduler = value_of(fields, "scheduler_verification_status")
    if stage is None or monitoring is None or timer is None:
        return derived_provenance(
            UNKNOWN,
            inputs,
            "Current runtime source is unavailable; runtime status stays UNKNOWN (fail-closed).",
            resolved=False,
        )
    if breach is True:
        return derived_provenance("RUNTIME_BREACH", inputs, "Breach flag is active.")
    if emergency_stop is True:
        return derived_provenance(
            "RUNTIME_EMERGENCY_STOP", inputs, "Emergency stop is active in the current runtime."
        )
    if monitoring is True and timer is True and scheduler == "SCHEDULER_VERIFICATION_GREEN":
        return derived_provenance(
            "RUNTIME_HEALTHY_MONITORING",
            inputs,
            "Monitoring enabled, systemd timer active, scheduler verification green.",
        )
    if monitoring is True and timer is True:
        return derived_provenance(
            "RUNTIME_MONITORING_UNVERIFIED_SCHEDULER",
            inputs,
            "Monitoring and timer are active, scheduler verification is not green.",
        )
    return derived_provenance(
        "RUNTIME_DEGRADED",
        inputs,
        "Monitoring or systemd timer is not active in the current runtime.",
    )


def derive_source_map_status(fields: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    inputs = ["source_map_404"]
    map_404 = value_of(fields, "source_map_404")
    if map_404 is None:
        return derived_provenance(
            UNKNOWN,
            inputs,
            "No current .map 404 evidence; status stays UNKNOWN instead of reusing a legacy warning.",
            resolved=False,
        )
    if int(map_404) == 0:
        return derived_provenance(
            "OK", inputs, "Current website evidence reports zero .map 404 hits."
        )
    return derived_provenance(
        "WARNING",
        inputs,
        f"Current website evidence reports {int(map_404)} .map 404 hits.",
    )


# --------------------------------------------------------------------------- #
# Owner priority hierarchy (Phase 10.21 section 19)
# --------------------------------------------------------------------------- #

OWNER_PRIORITY_LADDER = (
    (1, "SAFETY_BREACH_ESCALATION", "breach or emergency state"),
    (2, "WEBSITE_ORIGIN_STABILITY", "website outage or CRITICAL website status"),
    (3, "WEBSITE_ORIGIN_STABILITY", "dominant current origin failures"),
    (4, "RUNTIME_STABILITY_REVIEW", "runtime or scheduler failure"),
    (5, "ORIGIN_TLS_REVIEW", "current TLS failure"),
    (6, "AI_RADIO_NOWPLAYING_RECOVERY", "NowPlaying or API origin stability"),
    (7, "PERFORMANCE_DEGRADATION_REVIEW", "performance degradation"),
    (8, "SECURITY_DIAGNOSTIC_REVIEW", "security diagnostic review"),
    (9, "SEO_TITLE_REVIEW", "SEO or editorial work"),
)

ORIGIN_DOMINANCE_MIN_5XX = 50


def lower_priorities_below(rank: int, selected: str) -> List[str]:
    """Every ladder entry below the selected rank, without repeating the winner."""
    result: List[str] = []
    for level, name, _ in OWNER_PRIORITY_LADDER:
        if level > rank and name != selected and name not in result:
            result.append(name)
    return result


def derive_owner_priority(fields: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Strict rank order: a lower rank number always wins."""
    breach = value_of(fields, "breach")
    emergency_stop = value_of(fields, "emergency_stop")
    website_status = str(value_of(fields, "website_status", UNKNOWN)).upper()
    total_5xx = value_of(fields, "total_5xx")
    nowplaying_504 = value_of(fields, "nowplaying_504") or 0
    wp_users_me_504 = value_of(fields, "wp_users_me_504") or 0
    runtime_status = derive_runtime_status(fields)["value"]
    scheduler_status = value_of(fields, "scheduler_verification_status")
    tls_status = value_of(fields, "origin_tls_status")
    rolling_status = value_of(fields, "rolling_window_status")

    origin_5xx_present = isinstance(total_5xx, int) and total_5xx >= ORIGIN_DOMINANCE_MIN_5XX
    inputs = {
        "breach": breach,
        "emergency_stop": emergency_stop,
        "website_status": website_status,
        "total_5xx": total_5xx,
        "nowplaying_504": nowplaying_504,
        "wp_users_me_504": wp_users_me_504,
        "runtime_status": runtime_status,
        "scheduler_verification_status": scheduler_status,
        "origin_tls_status": tls_status,
        "rolling_window_status": rolling_status,
    }

    rank: int
    selected: str
    reason: str
    if breach is True or emergency_stop is True:
        rank, selected = 1, "SAFETY_BREACH_ESCALATION"
        reason = "A breach or emergency state is active; no lower-priority work is recommended."
    elif website_status == "CRITICAL":
        rank, selected = 2, "WEBSITE_ORIGIN_STABILITY"
        reason = (
            f"Website status is CRITICAL with {total_5xx} current 5xx in the 24h window; "
            "website and origin stability lead all optimization work."
        )
    elif website_status == "WARNING" and origin_5xx_present:
        rank, selected = 3, "WEBSITE_ORIGIN_STABILITY"
        reason = (
            f"Website status is WARNING and current origin failures dominate ({total_5xx} 5xx "
            "in the 24h window)."
        )
    elif runtime_status in {"RUNTIME_DEGRADED", "RUNTIME_MONITORING_UNVERIFIED_SCHEDULER", UNKNOWN}:
        rank, selected = 4, "RUNTIME_STABILITY_REVIEW"
        reason = f"Runtime or scheduler state is not healthy ({runtime_status})."
    elif isinstance(tls_status, str) and "FAILURE" in tls_status.upper():
        rank, selected = 5, "ORIGIN_TLS_REVIEW"
        reason = f"Current TLS diagnostic reports {tls_status}."
    elif int(nowplaying_504 or 0) > 0 or int(wp_users_me_504 or 0) > 0:
        rank, selected = 6, "AI_RADIO_NOWPLAYING_RECOVERY"
        reason = (
            f"NowPlaying/API origin stability: {nowplaying_504} NowPlaying 504 and "
            f"{wp_users_me_504} {WP_USERS_ME_PATH} 504 in the current window."
        )
    elif website_status == "WARNING":
        rank, selected = 7, "PERFORMANCE_DEGRADATION_REVIEW"
        reason = "Website status is WARNING without dominant current origin failures."
    elif website_status == "OK":
        rank, selected = 9, "SEO_TITLE_REVIEW"
        reason = (
            "Website is OK, runtime is healthy and no higher operational priority exists; "
            "SEO/editorial work may lead."
        )
    else:
        rank, selected = 8, "SECURITY_DIAGNOSTIC_REVIEW"
        reason = "Website status is unknown; establish current evidence before optimization."

    seo_allowed = selected == "SEO_TITLE_REVIEW"
    return {
        "value": selected,
        "rank": rank,
        "rank_reason": reason,
        "ladder": [
            {"rank": level, "priority": name, "condition": condition}
            for level, name, condition in OWNER_PRIORITY_LADDER
        ],
        "suppressed_lower_priorities": lower_priorities_below(rank, selected),
        "legacy_seo_checklist_allowed": seo_allowed,
        "legacy_seo_checklist_reason": (
            "Website OK, runtime healthy and no higher operational priority exists."
            if seo_allowed
            else "A higher operational priority exists; the legacy SEO checklist item cannot lead."
        ),
        "inputs": inputs,
        "source": "sentinel_canonical_truth.py (derived)",
        "source_class": "CANONICAL_DERIVATION",
        "freshness": CURRENT,
        "operational_effect": True,
        "resolution": "RESOLVED",
        "generated_at": None,
    }


# --------------------------------------------------------------------------- #
# Legacy supersession
# --------------------------------------------------------------------------- #

def build_legacy_supersession(
    fields: Dict[str, Dict[str, Any]],
    loaded: Dict[str, Dict[str, Any]],
    owner_priority: Dict[str, Any],
) -> Dict[str, Any]:
    """Classify every legacy claim without deleting or hiding it."""
    entries: List[Dict[str, Any]] = []
    for field, claims in sorted(LEGACY_FIELD_CLAIMS.items()):
        canonical_row = fields.get(field)
        if field == "owner_priority":
            canonical_value: Any = owner_priority.get("value")
            canonical_source = owner_priority.get("source")
        else:
            canonical_value = canonical_row.get("value") if isinstance(canonical_row, dict) else None
            canonical_source = canonical_row.get("source") if isinstance(canonical_row, dict) else None
        for source_id, expression in claims:
            row = loaded.get(source_id)
            source = SOURCES.get(source_id)
            if row is None or source is None:
                continue
            legacy_value = dotted(row.get("data"), expression) if row.get("data") is not None else None
            canonical_available = canonical_value is not None
            if row.get("freshness") == MISSING:
                classification = MISSING
            elif row.get("freshness") == INVALID:
                classification = INVALID
            elif canonical_available:
                classification = SUPERSEDED
            else:
                classification = row.get("freshness", STALE_INFORMATIONAL)
            entries.append({
                "legacy_source": rel(source.path),
                "legacy_source_id": source_id,
                "legacy_module": source.description,
                "canonical_field": field,
                "legacy_expression": expression,
                "legacy_value": legacy_value,
                "legacy_generated_at": row.get("generated_at"),
                "time_freshness": row.get("freshness"),
                "freshness": classification,
                "superseded_by": canonical_source if canonical_available else None,
                "canonical_value": canonical_value,
                "operational_effect": False,
                "conflicts_with_canonical": (
                    canonical_available
                    and legacy_value is not None
                    and not _values_equal(legacy_value, canonical_value)
                ),
            })

    legacy_rows = [
        {
            "legacy_source": rel(SOURCES[source_id].path),
            "legacy_source_id": source_id,
            "module": SOURCES[source_id].description,
            "generated_at": loaded.get(source_id, {}).get("generated_at"),
            "freshness": (
                SUPERSEDED
                if any(
                    entry["legacy_source_id"] == source_id and entry["freshness"] == SUPERSEDED
                    for entry in entries
                )
                else loaded.get(source_id, {}).get("freshness", MISSING)
            ),
            "superseded_by": sorted({
                entry["superseded_by"]
                for entry in entries
                if entry["legacy_source_id"] == source_id and entry["superseded_by"]
            }),
            "operational_effect": False,
        }
        for source_id in LEGACY_SOURCE_IDS
        if source_id in SOURCES
    ]

    conflicts = [entry for entry in entries if entry["conflicts_with_canonical"]]
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "status": "LEGACY_SUPERSESSION_OK",
        "policy": (
            "Legacy modules stay documented and auditable. They can never overwrite a current "
            "runtime field, owner priority, systemd state, emergency stop state, autonomy level "
            "or website metric."
        ),
        "retention": "no historical component, report or state file is deleted",
        "legacy_modules": legacy_rows,
        "field_claims": entries,
        "superseded_field_claims": [entry for entry in entries if entry["freshness"] == SUPERSEDED],
        "conflicting_field_claims": conflicts,
        "counts": {
            "legacy_modules": len(legacy_rows),
            "field_claims": len(entries),
            "superseded": sum(1 for entry in entries if entry["freshness"] == SUPERSEDED),
            "conflicts_neutralized": len(conflicts),
        },
    }


def _values_equal(left: Any, right: Any) -> bool:
    if isinstance(left, bool) or isinstance(right, bool):
        return left is right
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return float(left) == float(right)
    return str(left) == str(right)


# --------------------------------------------------------------------------- #
# Canonical snapshot
# --------------------------------------------------------------------------- #

def assemble_canonical(
    fields: Dict[str, Dict[str, Any]],
    generated_at: str,
) -> Dict[str, Any]:
    """Build the canonical field map with provenance for every operational value."""
    owner_priority = derive_owner_priority(fields)
    overall = derive_overall_status(fields)
    runtime_status = derive_runtime_status(fields)
    source_map_status = derive_source_map_status(fields)

    # Phase 10.22.1:
    # Recovery modules determine WHICH endpoint/origin is dominant, while the
    # share is always recalculated from the newest canonical website snapshot.
    current_nowplaying_504 = fields.get("nowplaying_504", {}).get("value")
    current_http_504 = fields.get("http_504", {}).get("value")
    current_dominant_504_endpoint = fields.get("dominant_504_endpoint", {}).get("value")

    if (
        current_dominant_504_endpoint == NOWPLAYING_PATH
        and isinstance(current_nowplaying_504, (int, float))
        and isinstance(current_http_504, (int, float))
        and current_http_504 > 0
    ):
        live_dominant_504_share = {
            **derived_provenance(
                round((current_nowplaying_504 / current_http_504) * 100, 2),
                ["dominant_504_endpoint", "nowplaying_504", "http_504"],
                "Live dominant 504 share recalculated from the current website snapshot.",
            ),
            "generated_at": generated_at,
        }
    else:
        # Until a generic current-path counter is available, keep the recovery
        # module's own share when the dominant endpoint is not NowPlaying.
        live_dominant_504_share = provenance(fields, "dominant_504_share_percent")

    return {
        "generated_at": derived_provenance(
            generated_at, [], "Snapshot creation time of this canonical resolution."
        ),
        "overall_status": overall,
        "website_status": provenance(fields, "website_status"),
        "website_correlation_status": provenance(fields, "website_correlation_status"),
        "local_status": provenance(fields, "local_status"),
        "runtime_status": runtime_status,
        "runtime_stage": provenance(fields, "runtime_stage"),
        "autonomy_level": provenance(fields, "autonomy_level"),
        "monitoring_enabled": provenance(fields, "monitoring_enabled"),
        "timer_active": provenance(fields, "systemd_timer_active"),
        "timer_enabled": provenance(fields, "systemd_timer_enabled"),
        "scheduler_status": provenance(fields, "scheduler_verification_status"),
        "scheduler_successful_cycles": provenance(fields, "scheduler_successful_cycles"),
        "guarded_live_autonomy_enabled": provenance(fields, "guarded_live_autonomy_enabled"),
        "low_live_enabled": provenance(fields, "low_live_apply_enabled"),
        "medium_live_enabled": provenance(fields, "medium_live_apply_enabled"),
        "high_live_enabled": provenance(fields, "high_live_apply_enabled"),
        "production_apply_lock": provenance(fields, "production_apply_lock"),
        "emergency_stop": provenance(fields, "emergency_stop"),
        "breach": provenance(fields, "breach"),
        "circuit_breaker_status": provenance(fields, "circuit_breaker_status"),
        "rollback_status": provenance(fields, "rollback_status"),
        "write_canary_status": provenance(fields, "write_canary_status"),
        "promotion_status": provenance(fields, "promotion_status"),
        "promotion_blockers": promotion_blockers_provenance(fields),
        "last_cycle_id": provenance(fields, "last_cycle_id"),
        "last_decision": provenance(fields, "last_decision"),
        "owner_priority": owner_priority,
        "total_5xx": provenance(fields, "total_5xx"),
        "http_504": provenance(fields, "http_504"),
        "http_503": provenance(fields, "http_503"),
        "http_522": provenance(fields, "http_522"),
        "http_526": provenance(fields, "http_526"),
        "nowplaying_504": provenance(fields, "nowplaying_504"),
        "wp_users_me_504": provenance(fields, "wp_users_me_504"),
        "source_map_404": provenance(fields, "source_map_404"),
        "source_map_status": source_map_status,
        "rolling_window_status": provenance(fields, "rolling_window_status"),
        "current_snapshot_id": provenance(fields, "current_snapshot_id"),
        "current_growth": provenance(fields, "current_growth"),
        "top_failure_paths": provenance(fields, "top_failure_paths"),
        "origin_diagnostic_status": provenance(fields, "origin_diagnostic_status"),
        "origin_tls_status": provenance(fields, "origin_tls_status"),
        "wp_users_me_classification": derive_wp_users_me_classification(fields, generated_at),
        "nowplaying_classification": derive_nowplaying_classification(fields, generated_at),
        "nowplaying_automatic_repair_allowed": provenance(fields, "nowplaying_automatic_repair_allowed"),
        "nowplaying_repair_applied": provenance(fields, "nowplaying_repair_applied"),
        "consistency_status": provenance(fields, "consistency_status"),
        "origin_recovery_status": provenance(fields, "origin_recovery_status"),
        "origin_route_map_status": provenance(fields, "origin_route_map_status"),
        "dominant_504_endpoint": provenance(fields, "dominant_504_endpoint"),
        "dominant_504_origin": provenance(fields, "dominant_504_origin"),
        "dominant_504_share_percent": live_dominant_504_share,
        "origin_504_repairability": provenance(fields, "origin_504_repairability"),
        "primary_failure_focus": provenance(fields, "primary_failure_focus"),
        "last_origin_repair": provenance(fields, "last_origin_repair"),
        "last_origin_repair_effect": provenance(fields, "last_origin_repair_effect"),
    }


def enforce_evidence_window(
    loaded: Dict[str, Dict[str, Any]], refresh_result: Dict[str, Any]
) -> Dict[str, Any]:
    """Fail closed when website, route and recovery snapshots are mixed."""
    window = refresh_result.get("evidence_window") if isinstance(refresh_result, dict) else None
    status = (
        window.get("status")
        if isinstance(window, dict)
        else monitoring_decision.EVIDENCE_WINDOW_MISMATCH
    )
    if status == monitoring_decision.EVIDENCE_WINDOW_ALIGNED:
        return {
            "status": status,
            "excluded_sources": [],
            "reason": window.get("reason"),
        }

    excluded: List[str] = []
    for source_id in ("website", "origin_route_map", "origin_504_recovery"):
        row = loaded.get(source_id)
        if not isinstance(row, dict):
            continue
        row["freshness"] = STALE_EXCLUDED
        row["usable_as_canonical_input"] = False
        row["evidence_window_status"] = monitoring_decision.EVIDENCE_WINDOW_MISMATCH
        row["reason"] = (
            "EVIDENCE_WINDOW_MISMATCH: current website, route and recovery snapshot IDs are not identical."
        )
        excluded.append(source_id)
    return {
        "status": monitoring_decision.EVIDENCE_WINDOW_MISMATCH,
        "excluded_sources": excluded,
        "reason": (
            window.get("reason") if isinstance(window, dict)
            else "Recovery refresh did not provide a valid evidence-window contract."
        ),
    }


def build_canonical_truth(
    refresh_result: Optional[Dict[str, Any]] = None,
    refresh_recovery: bool = True,
) -> Dict[str, Any]:
    if refresh_result is None:
        if refresh_recovery:
            refresh_result = monitoring_decision.refresh_before_canonical(
                force=False, persist_outputs=True
            )
        else:
            refresh_result = {
                "status": "RECOVERY_EVIDENCE_REFRESH_NOT_RUN",
                "evidence_window": {
                    "status": monitoring_decision.EVIDENCE_WINDOW_MISMATCH
                },
            }
    as_of = datetime.now(timezone.utc)
    loaded = load_sources(as_of)
    evidence_window = enforce_evidence_window(loaded, refresh_result)
    fields = resolve_fields(loaded)
    generated_at = utc_now()
    canonical = assemble_canonical(fields, generated_at)
    decision = refresh_result.get("autonomous_decision", {})
    refresh_window = refresh_result.get("evidence_window", {})
    canonical["recovery_evidence_window_status"] = {
        **derived_provenance(
            evidence_window["status"],
            ["current_snapshot_id", "dominant_504_endpoint"],
            "Snapshot identity contract evaluated before canonical resolution.",
        ),
        "generated_at": generated_at,
    }
    canonical["recovery_snapshot_id"] = {
        **derived_provenance(
            refresh_window.get("snapshot_ids", {}).get("recovery_baseline_snapshot"),
            ["recovery_evidence_window_status"],
            "Phase 10.22 recovery baseline snapshot accepted by the evidence-window gate.",
        ),
        "generated_at": generated_at,
    }
    canonical["autonomous_monitoring_decision"] = {
        **derived_provenance(
            decision.get("decision") or UNKNOWN,
            ["recovery_evidence_window_status", "primary_failure_focus"],
            "Read-only Level-2 monitoring decision; never a productive apply instruction.",
        ),
        "generated_at": generated_at,
    }
    owner_priority = canonical["owner_priority"]
    legacy = build_legacy_supersession(fields, loaded, owner_priority)

    missing_fields = [
        field for field in REQUIRED_FIELDS
        if fields.get(field, {}).get("resolution") != "RESOLVED"
    ]
    if canonical["overall_status"]["resolution"] != "RESOLVED":
        missing_fields.append("overall_status")
    if canonical["runtime_status"]["resolution"] != "RESOLVED":
        missing_fields.append("runtime_status")
    missing_fields = sorted(set(missing_fields))

    if evidence_window["status"] != monitoring_decision.EVIDENCE_WINDOW_ALIGNED:
        status = "CANONICAL_TRUTH_EVIDENCE_WINDOW_MISMATCH"
    else:
        status = "CANONICAL_TRUTH_OK" if not missing_fields else "CANONICAL_TRUTH_INCOMPLETE"

    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": generated_at,
        "status": status,
        "report_classification": REPORT_CLASSIFICATION,
        "execution_boundaries": EXECUTION_BOUNDARIES,
        "recovery_evidence_refresh": {
            "status": refresh_result.get("refresh_status") or refresh_result.get("status"),
            "evidence_window": refresh_result.get("evidence_window"),
            "autonomous_decision": decision,
            "productive_change_attempted": False,
        },
        "evidence_window": evidence_window,
        "resolver_role": "resolver_only_no_new_runtime_state_machine",
        "precedence": [
            {"tier": tier, "source_class": name, "description": description}
            for tier, name, description in PRECEDENCE_TIERS
        ],
        "freshness_vocabulary": {
            name: FRESHNESS_DEFINITIONS[name] for name in FRESHNESS_VOCABULARY
        },
        "source_registry": canonical_source_registry(),
        "sources": [
            {key: row[key] for key in row if key != "data"}
            for row in sorted(loaded.values(), key=lambda item: (item["precedence_tier"], item["source_id"]))
        ],
        "canonical": canonical,
        "field_resolution": fields,
        "legacy_supersession": legacy,
        "missing_fields": missing_fields,
        "incomplete_detail": [
            {
                "field": field,
                "reason": fields.get(field, {}).get(
                    "reason", "No current authoritative source available."
                ),
                "source_missing": [
                    attempt.get("source")
                    for attempt in fields.get(field, {}).get("candidates", [])
                    if attempt.get("outcome", "").startswith("UNUSABLE")
                    or attempt.get("outcome") == "NO_VALUE"
                ],
            }
            for field in missing_fields
            if field in fields
        ],
        "counts": {
            "registered_sources": len(SOURCE_LIST),
            "current_sources": sum(1 for row in loaded.values() if row["freshness"] == CURRENT),
            "stale_informational_sources": sum(
                1 for row in loaded.values() if row["freshness"] == STALE_INFORMATIONAL
            ),
            "stale_excluded_sources": sum(
                1 for row in loaded.values() if row["freshness"] == STALE_EXCLUDED
            ),
            "missing_sources": sum(1 for row in loaded.values() if row["freshness"] == MISSING),
            "invalid_sources": sum(1 for row in loaded.values() if row["freshness"] == INVALID),
            "resolved_fields": sum(
                1 for row in fields.values() if row["resolution"] == "RESOLVED"
            ),
            "unresolved_fields": sum(
                1 for row in fields.values() if row["resolution"] != "RESOLVED"
            ),
        },
        "breach": bool(value_of(fields, "breach") is True),
    }
    report["daily_summary_blocks"] = build_daily_summary_blocks(report)
    return report


# --------------------------------------------------------------------------- #
# Canonical report blocks used by every downstream report
# --------------------------------------------------------------------------- #

def show(block: Dict[str, Any], unknown: str = UNKNOWN) -> str:
    if not isinstance(block, dict):
        return unknown
    if block.get("resolution") != "RESOLVED":
        return unknown
    value = block.get("value")
    if value is None:
        return unknown
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def enabled_text(block: Dict[str, Any]) -> str:
    if block.get("resolution") != "RESOLVED":
        return UNKNOWN
    return "ENABLED" if block.get("value") is True else "DISABLED"


def active_text(block: Dict[str, Any]) -> str:
    if block.get("resolution") != "RESOLVED":
        return UNKNOWN
    return "ACTIVE" if block.get("value") is True else "INACTIVE"


def build_daily_summary_blocks(report: Dict[str, Any]) -> Dict[str, Any]:
    """The single canonical text blocks every daily report must reuse verbatim."""
    canonical = report.get("canonical", {})

    def c(name: str) -> Dict[str, Any]:
        """Missing canonical keys resolve to UNKNOWN instead of raising."""
        block = canonical.get(name)
        return block if isinstance(block, dict) else {}

    incomplete = report.get("status") != "CANONICAL_TRUTH_OK"

    header = [
        "Sentinel Daily Summary",
        "",
        "Generated:",
        show(c("generated_at")),
        "",
        "Canonical Truth:",
        report["status"],
        "",
        "Overall Master Status:",
        show(c("overall_status")),
        "",
        "Website Status:",
        show(c("website_status")),
        "",
        "Runtime:",
        show(c("autonomy_level")),
        "",
        "24/7 Monitoring:",
        active_text(c("monitoring_enabled")),
        "",
        "Scheduler:",
        show(c("scheduler_status")),
        "",
        "LOW_LIVE:",
        enabled_text(c("low_live_enabled")),
        "",
        "Production Apply:",
        "LOCKED" if c("production_apply_lock").get("value") is True else (
            UNKNOWN if c("production_apply_lock").get("resolution") != "RESOLVED" else "UNLOCKED"
        ),
        "",
        "Emergency Stop:",
        show(c("emergency_stop")).upper(),
        "",
        "Breach:",
        show(c("breach")).upper(),
        "",
        "Owner Priority:",
        show(c("owner_priority")),
    ]
    if incomplete:
        header.extend([
            "",
            "Canonical Truth Incomplete — missing fields:",
            ", ".join(report.get("missing_fields", [])) or "unknown",
            "No legacy value is substituted for a missing current value.",
        ])

    runtime_section = [
        "Runtime Status",
        "",
        "Autonomy Level:",
        show(c("autonomy_level")),
        "",
        "Runtime Stage:",
        show(c("runtime_stage")),
        "",
        "Runtime Health:",
        show(c("runtime_status")),
        "",
        "Monitoring:",
        "active" if c("monitoring_enabled").get("value") is True else show(c("monitoring_enabled")),
        "",
        "systemd Timer:",
        "active" if c("timer_active").get("value") is True else show(c("timer_active")),
        "",
        "Scheduler:",
        show(c("scheduler_status")),
        "",
        "LOW_LIVE:",
        "disabled" if c("low_live_enabled").get("value") is False else show(c("low_live_enabled")),
        "",
        "MEDIUM:",
        "disabled" if c("medium_live_enabled").get("value") is False else show(c("medium_live_enabled")),
        "",
        "HIGH:",
        "disabled" if c("high_live_enabled").get("value") is False else show(c("high_live_enabled")),
        "",
        "Production Apply Lock:",
        "enabled" if c("production_apply_lock").get("value") is True else show(c("production_apply_lock")),
        "",
        "Circuit Breaker:",
        show(c("circuit_breaker_status")),
        "",
        "Rollback:",
        show(c("rollback_status")),
        "",
        "Write Canary:",
        show(c("write_canary_status")),
        "",
        "Promotion:",
        show(c("promotion_status")),
        "",
        "Promotion Blockers:",
        format_promotion_blockers(c("promotion_blockers").get("value")),
        "",
        "Last Cycle:",
        show(c("last_cycle_id")),
        "",
        "Last Decision:",
        show(c("last_decision")),
        "",
        "Emergency Stop:",
        show(c("emergency_stop")),
        "",
        "Breach:",
        show(c("breach")),
    ]

    website_section = [
        "Current Website Evidence",
        "",
        f"Snapshot: {show(canonical['current_snapshot_id'])}",
        f"Website status: {show(canonical['website_status'])}",
        f"Correlation status: {show(canonical['website_correlation_status'])}",
        f"Local status: {show(canonical['local_status'])}",
        f"Total 5xx (24h): {show(canonical['total_5xx'])}",
        f"504: {show(canonical['http_504'])}",
        f"503: {show(canonical['http_503'])}",
        f"522: {show(canonical['http_522'])}",
        f"526: {show(canonical['http_526'])}",
        f"Rolling window: {show(canonical['rolling_window_status'])}",
        f"Current growth: {show(canonical['current_growth'])}",
        "",
        f"Current NowPlaying 504: {show(canonical['nowplaying_504'])}",
        f"Recovery classification: {show(canonical['nowplaying_classification'])}",
        f"Automatic local repair: {show(canonical['nowplaying_automatic_repair_allowed'])}",
        f"Current {WP_USERS_ME_PATH} 504: {show(canonical['wp_users_me_504'])}",
        f"wp-json users/me classification: {show(canonical['wp_users_me_classification'])}",
        f"Current SourceMap 404: {show(canonical['source_map_404'])}",
        f"Current SourceMap Status: {show(canonical['source_map_status'])}",
    ]

    legacy_section = ["Legacy / Historical Modules", ""]
    for row in report.get("legacy_supersession", {}).get("legacy_modules", []):
        legacy_section.extend([
            f"- {row['legacy_source_id']}",
            f"  legacy status: {row['module']}",
            f"  generated_at: {row['generated_at'] or 'unknown'}",
            f"  freshness: {row['freshness']}",
            f"  superseded_by: {', '.join(row['superseded_by']) or 'none'}",
            "  operational_effect=false",
        ])
    if len(legacy_section) == 2:
        legacy_section.append("- no legacy module registered")

    priority_section = [
        "Owner Priority",
        "",
        f"Selected: {show(c('owner_priority'))}",
        f"Rank: {c('owner_priority').get('rank')}",
        f"Reason: {c('owner_priority').get('rank_reason')}",
        f"Suppressed: {', '.join(c('owner_priority').get('suppressed_lower_priorities', [])) or 'none'}",
        f"Legacy SEO checklist may lead: "
        f"{str(c('owner_priority').get('legacy_seo_checklist_allowed')).lower()}",
        "",
        "Primary Failure Focus:",
        show(c("primary_failure_focus")),
        "",
        f"Dominant 504 endpoint: {show(c('dominant_504_endpoint'))} "
        f"({show(c('dominant_504_share_percent'))}% of current 504)",
        f"Dominant 504 origin: {show(c('dominant_504_origin'))}",
        f"Origin recovery: {show(c('origin_recovery_status'))}",
        f"504 repairability: {show(c('origin_504_repairability'))}",
        f"Recovery evidence window: {show(c('recovery_evidence_window_status'))}",
        f"Recovery snapshot: {show(c('recovery_snapshot_id'))}",
        f"Autonomous monitoring decision: {show(c('autonomous_monitoring_decision'))}",
    ]

    return {
        "status_badge": show(c("overall_status")),
        "header": header,
        "runtime_section": runtime_section,
        "website_section": website_section,
        "owner_priority_section": priority_section,
        "legacy_section": legacy_section,
    }


# --------------------------------------------------------------------------- #
# Markdown rendering
# --------------------------------------------------------------------------- #

def private_header(title: str) -> List[str]:
    return [
        f"# {title}",
        "",
        "Classification: " + " | ".join(REPORT_CLASSIFICATION),
        "",
    ]


def render_canonical_md(report: Dict[str, Any]) -> str:
    canonical = report["canonical"]
    blocks = report["daily_summary_blocks"]
    lines = private_header("Sentinel Canonical Runtime Truth")
    lines.extend([
        f"- schema: `{report['schema_version']}`",
        f"- generated: `{report['generated_at_utc']}`",
        f"- status: `{report['status']}`",
        f"- resolver role: `{report['resolver_role']}`",
        "",
        "## Canonical Fields",
        "",
        "| Field | Value | Source | Freshness | Operational effect |",
        "|---|---|---|---|---|",
    ])
    for name, block in canonical.items():
        if not isinstance(block, dict):
            continue
        value = block.get("value")
        if isinstance(value, (list, dict)):
            rendered = f"{type(value).__name__}({len(value)})"
        else:
            rendered = show(block)
        lines.append(
            f"| `{name}` | `{rendered}` | `{block.get('source') or '-'}` | "
            f"`{block.get('freshness')}` | `{str(block.get('operational_effect')).lower()}` |"
        )

    lines.extend(["", "## Source Precedence", "", "| Tier | Source class | Description |", "|---|---|---|"])
    for row in report["precedence"]:
        lines.append(f"| {row['tier']} | `{row['source_class']}` | {row['description']} |")

    lines.extend([
        "",
        "## Registered Sources",
        "",
        "| Tier | Source | Kind | Generated | Freshness | Usable |",
        "|---|---|---|---|---|---|",
    ])
    for row in report["sources"]:
        lines.append(
            f"| {row['precedence_tier']} | `{row['path']}` | `{row['kind']}` | "
            f"`{row['generated_at'] or '-'}` | `{row['freshness']}` | "
            f"`{str(row['usable_as_canonical_input']).lower()}` |"
        )

    if report["missing_fields"]:
        lines.extend(["", "## Canonical Truth Incomplete", ""])
        lines.append("Missing current authoritative values (no legacy substitution):")
        lines.append("")
        for row in report["incomplete_detail"]:
            lines.append(f"- `{row['field']}`: {row['reason']}")
        for field in report["missing_fields"]:
            if not any(row["field"] == field for row in report["incomplete_detail"]):
                lines.append(f"- `{field}`: derived value could not be computed.")

    lines.extend(["", "## Canonical Daily Header", "", "```text"])
    lines.extend(blocks["header"])
    lines.extend(["```", "", "## Canonical Runtime Section", "", "```text"])
    lines.extend(blocks["runtime_section"])
    lines.extend(["```", "", "## Canonical Website Evidence", "", "```text"])
    lines.extend(blocks["website_section"])
    lines.extend(["```", "", "## Canonical Owner Priority", "", "```text"])
    lines.extend(blocks["owner_priority_section"])
    lines.extend(["```", ""])
    lines.extend([
        "## Safety",
        "",
        "- Phase type: reporting, state resolution, source precedence, diagnostic, validation.",
        "- No Cloudflare write, no WAF/DNS/TLS change, no systemd or timer change.",
        "- No LOW_LIVE/MEDIUM/HIGH activation, no WordPress/database/nginx write.",
        "- No credential output, no cookie storage, no Authorization header storage.",
    ])
    return "\n".join(lines) + "\n"


def render_legacy_md(legacy: Dict[str, Any]) -> str:
    lines = private_header("Sentinel Legacy Supersession")
    lines.extend([
        f"- status: `{legacy['status']}`",
        f"- generated: `{legacy['generated_at_utc']}`",
        f"- retention: {legacy['retention']}",
        "",
        legacy["policy"],
        "",
        "## Legacy / Historical Modules",
        "",
        "| Module | Generated | Freshness | Superseded by | Operational effect |",
        "|---|---|---|---|---|",
    ])
    for row in legacy["legacy_modules"]:
        lines.append(
            f"| `{row['legacy_source']}` | `{row['generated_at'] or '-'}` | `{row['freshness']}` | "
            f"`{', '.join(row['superseded_by']) or '-'}` | `false` |"
        )
    lines.extend([
        "",
        "## Field Claims",
        "",
        "| Canonical field | Legacy value | Canonical value | Freshness | Conflict neutralized |",
        "|---|---|---|---|---|",
    ])
    for entry in legacy["field_claims"]:
        legacy_value = entry["legacy_value"]
        canonical_value = entry["canonical_value"]
        if isinstance(legacy_value, (dict, list)):
            legacy_value = type(legacy_value).__name__
        if isinstance(canonical_value, (dict, list)):
            canonical_value = type(canonical_value).__name__
        lines.append(
            f"| `{entry['canonical_field']}` | `{legacy_value}` | `{canonical_value}` | "
            f"`{entry['freshness']}` | `{str(entry['conflicts_with_canonical']).lower()}` |"
        )
    lines.extend([
        "",
        "## Retention Policy",
        "",
        "- No historical component is deleted.",
        "- No old report is deleted.",
        "- No old state file is deleted.",
        "- Classification only: CURRENT / SUPERSEDED / STALE_INFORMATIONAL / STALE_EXCLUDED.",
    ])
    return "\n".join(lines) + "\n"


def render_daily_header_md(report: Dict[str, Any]) -> str:
    blocks = report["daily_summary_blocks"]
    lines = private_header("Sentinel Canonical Daily Header")
    lines.append("This header is the only permitted source for the daily summary top section.")
    lines.append("")
    for title, key in (
        ("Executive Header", "header"),
        ("Runtime Status", "runtime_section"),
        ("Current Website Evidence", "website_section"),
        ("Owner Priority", "owner_priority_section"),
        ("Legacy / Historical Modules", "legacy_section"),
    ):
        lines.extend([f"## {title}", "", "```text"])
        lines.extend(blocks[key])
        lines.extend(["```", ""])
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #
# Playbooks
# --------------------------------------------------------------------------- #

def build_playbooks() -> Dict[str, Dict[str, Any]]:
    return {
        "sentinel-canonical-runtime-truth.playbook.json": {
            "schema_version": SCHEMA_VERSION,
            "name": "sentinel-canonical-runtime-truth",
            "status": "PLAYBOOK_ACTIVE",
            "principle": "one operational fact = one canonical current value = one authoritative source = traceable provenance",
            "pipeline": [
                "evidence",
                "freshness",
                "source_precedence",
                "canonical_truth",
                "invariant_validation",
                "owner_priority",
                "master_report",
                "daily_summary",
                "public_summary",
            ],
            "required_fields": list(REQUIRED_FIELDS),
            "fail_closed": {
                "status": "CANONICAL_TRUTH_INCOMPLETE",
                "rule": "name the missing fields; never substitute a legacy value",
            },
            "forbidden": [
                "legacy overwrite of current runtime fields",
                "legacy overwrite of owner priority",
                "legacy overwrite of systemd state",
                "legacy overwrite of emergency stop state",
                "legacy overwrite of autonomy level",
                "legacy overwrite of website metrics",
                "stale measurements presented as current measurements",
            ],
            "execution_boundaries": EXECUTION_BOUNDARIES,
        },
        "sentinel-legacy-supersession.playbook.json": {
            "schema_version": SCHEMA_VERSION,
            "name": "sentinel-legacy-supersession",
            "status": "PLAYBOOK_ACTIVE",
            "freshness_vocabulary": {
                name: FRESHNESS_DEFINITIONS[name] for name in FRESHNESS_VOCABULARY
            },
            "retention": [
                "never delete historical components",
                "never delete old reports",
                "never delete old state files",
                "classify only: CURRENT / SUPERSEDED / STALE_INFORMATIONAL / STALE_EXCLUDED",
            ],
            "legacy_modules": [
                {
                    "source": rel(SOURCES[source_id].path),
                    "description": SOURCES[source_id].description,
                }
                for source_id in LEGACY_SOURCE_IDS
                if source_id in SOURCES
            ],
            "field_claims": {
                field: [
                    {"source": rel(SOURCES[source_id].path), "expression": expression}
                    for source_id, expression in claims
                    if source_id in SOURCES
                ]
                for field, claims in LEGACY_FIELD_CLAIMS.items()
            },
        },
        "sentinel-runtime-source-precedence.playbook.json": {
            "schema_version": SCHEMA_VERSION,
            "name": "sentinel-runtime-source-precedence",
            "status": "PLAYBOOK_ACTIVE",
            "precedence": [
                {"tier": tier, "source_class": name, "description": description}
                for tier, name, description in PRECEDENCE_TIERS
            ],
            "source_registry": canonical_source_registry(),
            "field_ownership": {
                field: [
                    {
                        "source": rel(SOURCES[candidate.source_id].path),
                        "expression": candidate.expression,
                        "source_class": SOURCES[candidate.source_id].source_class,
                        "allow_stale_informational": candidate.allow_stale_informational,
                    }
                    for candidate in candidates
                    if candidate.source_id in SOURCES
                ]
                for field, candidates in FIELD_OWNERSHIP.items()
            },
            "owner_priority_ladder": [
                {"rank": rank, "priority": name, "condition": condition}
                for rank, name, condition in OWNER_PRIORITY_LADDER
            ],
        },
    }


# --------------------------------------------------------------------------- #
# Persistence
# --------------------------------------------------------------------------- #

def persist(report: Dict[str, Any]) -> None:
    ensure_dirs()
    write_json(REPORT_JSON, report)
    write_text(REPORT_MD, render_canonical_md(report))
    write_json(LEGACY_JSON, report["legacy_supersession"])
    write_text(LEGACY_MD, render_legacy_md(report["legacy_supersession"]))
    write_text(DAILY_HEADER_MD, render_daily_header_md(report))

    canonical = report["canonical"]
    state = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": report["generated_at_utc"],
        "status": report["status"],
        "overall_status": canonical["overall_status"].get("value"),
        "website_status": canonical["website_status"].get("value"),
        "runtime_status": canonical["runtime_status"].get("value"),
        "runtime_stage": canonical["runtime_stage"].get("value"),
        "autonomy_level": canonical["autonomy_level"].get("value"),
        "monitoring_enabled": canonical["monitoring_enabled"].get("value"),
        "timer_active": canonical["timer_active"].get("value"),
        "scheduler_status": canonical["scheduler_status"].get("value"),
        "low_live_enabled": canonical["low_live_enabled"].get("value"),
        "production_apply_lock": canonical["production_apply_lock"].get("value"),
        "emergency_stop": canonical["emergency_stop"].get("value"),
        "breach": canonical["breach"].get("value"),
        "write_canary_status": canonical["write_canary_status"].get("value"),
        "promotion_status": canonical["promotion_status"].get("value"),
        "owner_priority": canonical["owner_priority"].get("value"),
        "total_5xx": canonical["total_5xx"].get("value"),
        "nowplaying_504": canonical["nowplaying_504"].get("value"),
        "wp_users_me_504": canonical["wp_users_me_504"].get("value"),
        "source_map_404": canonical["source_map_404"].get("value"),
        "rolling_window_status": canonical["rolling_window_status"].get("value"),
        "recovery_evidence_window_status": canonical["recovery_evidence_window_status"].get("value"),
        "recovery_snapshot_id": canonical["recovery_snapshot_id"].get("value"),
        "autonomous_monitoring_decision": canonical["autonomous_monitoring_decision"].get("value"),
        "missing_fields": report["missing_fields"],
    }
    write_json(STATE_JSON, state)

    history, read_status = read_json(HISTORY_JSON)
    if read_status != "ok" or not isinstance(history, list):
        history = []
    history.append(state)
    write_json(HISTORY_JSON, history[-400:])

    snapshot = SNAPSHOT_DIR / f"sentinel-canonical-truth-{report['generated_at_utc'].replace(':', '').replace('-', '')}.json"
    write_json(snapshot, state)

    for name, payload in build_playbooks().items():
        write_json(PLAYBOOK_DIR / name, payload)

    append_jsonl(AUDIT_JSONL, {
        "timestamp_utc": report["generated_at_utc"],
        "event": "canonical_truth_resolved",
        "status": report["status"],
        "overall_status": state["overall_status"],
        "website_status": state["website_status"],
        "runtime_stage": state["runtime_stage"],
        "autonomy_level": state["autonomy_level"],
        "timer_active": state["timer_active"],
        "emergency_stop": state["emergency_stop"],
        "breach": state["breach"],
        "owner_priority": state["owner_priority"],
        "recovery_evidence_window_status": state["recovery_evidence_window_status"],
        "recovery_snapshot_id": state["recovery_snapshot_id"],
        "autonomous_monitoring_decision": state["autonomous_monitoring_decision"],
        "missing_fields": report["missing_fields"],
    })


def load_canonical_truth() -> Dict[str, Any]:
    """Public accessor used by the pipeline, master report and mailer."""
    data, read_status = read_json(REPORT_JSON)
    if read_status != "ok" or not isinstance(data, dict):
        return {}
    return data


# A persisted snapshot older than this is not treated as current truth; callers
# get a freshly resolved in-memory snapshot instead of stale values.
SNAPSHOT_MAX_AGE_SECONDS = 10 * 60


def load_or_resolve(max_age_seconds: int = SNAPSHOT_MAX_AGE_SECONDS) -> Dict[str, Any]:
    """Current canonical snapshot for reports that run on their own timer.

    Returns a young persisted snapshot only while its aligned recovery snapshot
    still equals the newest monitor snapshot.  Otherwise it runs the fixed,
    read-only recovery refresh before resolving current truth.  Generated
    reports/state remain local artifacts; no productive action is performed.
    """
    snapshot = load_canonical_truth()
    generated = parse_timestamp(snapshot.get("generated_at_utc")) if snapshot else None
    if snapshot and generated is not None:
        age = (datetime.now(timezone.utc) - generated).total_seconds()
        window = snapshot.get("recovery_evidence_refresh", {}).get("evidence_window", {})
        snapshot_ids = window.get("snapshot_ids", {}) if isinstance(window, dict) else {}
        latest = monitoring_decision.latest_snapshot().get("snapshot_id")
        persisted_is_aligned = (
            window.get("status") == monitoring_decision.EVIDENCE_WINDOW_ALIGNED
            and latest is not None
            and snapshot_ids.get("latest_monitor_snapshot") == latest
            and snapshot_ids.get("website_report_snapshot") == latest
            and snapshot_ids.get("origin_matrix_snapshot") == latest
            and snapshot_ids.get("recovery_baseline_snapshot") == latest
        )
        if -300 <= age <= max_age_seconds and persisted_is_aligned:
            snapshot["snapshot_origin"] = "PERSISTED_SNAPSHOT"
            snapshot["snapshot_age_seconds"] = round(max(0.0, age), 2)
            return snapshot
    fresh = build_canonical_truth()
    fresh["snapshot_origin"] = "RESOLVED_IN_MEMORY_STALE_SNAPSHOT"
    fresh["snapshot_age_seconds"] = 0.0
    return fresh


RUNTIME_FLAG_FIELDS = (
    "runtime_stage",
    "autonomy_level",
    "monitoring_enabled",
    "systemd_timer_active",
    "low_live_apply_enabled",
    "medium_live_apply_enabled",
    "high_live_apply_enabled",
    "production_apply_lock",
    "emergency_stop",
    "breach",
    "scheduler_verification_status",
    "write_canary_status",
    "promotion_status",
)


def resolve_runtime_flags() -> Dict[str, Any]:
    """Live runtime flags for other modules, resolved from the current runtime sources.

    Modules must call this instead of hardcoding runtime state or reading a
    Level-1 report. Unresolvable flags stay None and are named in
    `unresolved_fields`, so callers can fail closed instead of inventing a value.
    """
    loaded = load_sources()
    resolved = {
        field: resolve_field(field, FIELD_OWNERSHIP[field], loaded)
        for field in RUNTIME_FLAG_FIELDS
    }
    flags = {field: row.get("value") if row["resolution"] == "RESOLVED" else None
             for field, row in resolved.items()}
    unresolved = sorted(field for field, row in resolved.items() if row["resolution"] != "RESOLVED")
    return {
        "status": "RUNTIME_FLAGS_RESOLVED" if not unresolved else "RUNTIME_FLAGS_INCOMPLETE",
        "flags": flags,
        "provenance": {
            field: {
                "source": row.get("source"),
                "source_class": row.get("source_class"),
                "generated_at": row.get("generated_at"),
                "freshness": row.get("freshness"),
            }
            for field, row in resolved.items()
        },
        "unresolved_fields": unresolved,
        "resolved_at_utc": utc_now(),
    }


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #

def validate_report(report: Dict[str, Any]) -> Dict[str, Any]:
    findings: List[str] = []
    canonical = report.get("canonical", {})

    for field in REQUIRED_FIELDS:
        block = canonical.get(_canonical_key(field))
        if not isinstance(block, dict):
            continue
        if block.get("resolution") == "RESOLVED" and block.get("source_class") == CLASS_LEGACY:
            findings.append(f"{field} resolved from a legacy source")

    for entry in report.get("legacy_supersession", {}).get("field_claims", []):
        if entry.get("operational_effect"):
            findings.append(f"legacy claim has operational effect: {entry.get('legacy_source')}")

    for name, block in canonical.items():
        if not isinstance(block, dict):
            continue
        if block.get("freshness") not in FRESHNESS_VOCABULARY:
            findings.append(f"{name} has freshness outside the canonical vocabulary")

    blockers = canonical.get("promotion_blockers", {})
    blocker_value = blockers.get("value") if isinstance(blockers, dict) else None
    if blocker_value != UNKNOWN and not (
        isinstance(blocker_value, list)
        and all(isinstance(item, str) and item for item in blocker_value)
    ):
        findings.append("promotion_blockers must be UNKNOWN or a list of blocker strings")

    wp_count = canonical.get("wp_users_me_504", {})
    wp_classification = canonical.get("wp_users_me_classification", {})
    wp_classification_value = (
        wp_classification.get("value") if isinstance(wp_classification, dict) else UNKNOWN
    )
    concrete_wp_classification = wp_classification_value not in {
        UNKNOWN,
        WP_USERS_ME_EVIDENCE_INSUFFICIENT,
    }
    if concrete_wp_classification and not (
        isinstance(wp_count, dict)
        and wp_count.get("resolution") == "RESOLVED"
        and isinstance(wp_count.get("value"), (int, float))
        and not isinstance(wp_count.get("value"), bool)
        and wp_count.get("value") > 0
        and wp_classification.get("compatible_current_evidence") is True
    ):
        findings.append(
            "concrete wp_users_me classification lacks compatible current 504 evidence"
        )

    nowplaying_count = canonical.get("nowplaying_504", {})
    nowplaying_classification = canonical.get("nowplaying_classification", {})
    nowplaying_value = (
        nowplaying_classification.get("value")
        if isinstance(nowplaying_classification, dict)
        else UNKNOWN
    )
    nowplaying_count_resolved = bool(
        isinstance(nowplaying_count, dict)
        and nowplaying_count.get("resolution") == "RESOLVED"
        and isinstance(nowplaying_count.get("value"), (int, float))
        and not isinstance(nowplaying_count.get("value"), bool)
    )
    if not nowplaying_count_resolved and nowplaying_value != NOWPLAYING_EVIDENCE_INSUFFICIENT:
        findings.append(
            "unresolved NowPlaying 504 count must use NOWPLAYING_EVIDENCE_INSUFFICIENT"
        )
    if nowplaying_value == "NOWPLAYING_HEALTHY" and not (
        nowplaying_count_resolved
        and float(nowplaying_count.get("value")) == 0
        and nowplaying_classification.get("compatible_current_evidence") is True
    ):
        findings.append(
            "NOWPLAYING_HEALTHY lacks compatible explicit current zero evidence"
        )
    concrete_nowplaying = nowplaying_value not in {
        UNKNOWN,
        "NOWPLAYING_HEALTHY",
        NOWPLAYING_EVIDENCE_INSUFFICIENT,
    }
    if concrete_nowplaying and not (
        nowplaying_count_resolved
        and nowplaying_count.get("value") > 0
        and nowplaying_classification.get("compatible_current_evidence") is True
    ):
        findings.append(
            "concrete NowPlaying classification lacks compatible current 504 evidence"
        )

    if report.get("status") == "CANONICAL_TRUTH_OK" and report.get("missing_fields"):
        findings.append("status is OK while required fields are missing")
    if report.get("status") == "CANONICAL_TRUTH_INCOMPLETE" and not report.get("missing_fields"):
        findings.append("status is INCOMPLETE without naming missing fields")

    return {
        "status": "CANONICAL_TRUTH_VALIDATION_OK" if not findings else "CANONICAL_TRUTH_VALIDATION_FAILED",
        "findings": findings,
        "checked_fields": len(canonical),
    }


_CANONICAL_KEY_ALIASES = {
    "systemd_timer_active": "timer_active",
    "systemd_timer_enabled": "timer_enabled",
    "low_live_apply_enabled": "low_live_enabled",
    "medium_live_apply_enabled": "medium_live_enabled",
    "high_live_apply_enabled": "high_live_enabled",
    "scheduler_verification_status": "scheduler_status",
}


def _canonical_key(field: str) -> str:
    return _CANONICAL_KEY_ALIASES.get(field, field)


# --------------------------------------------------------------------------- #
# Self-test — deterministic Phase 10.21 tests A..H
# --------------------------------------------------------------------------- #

PROCESS_MODULES = frozenset({"sub" "process", "os", "shutil", "pty", "multiprocessing"})
NETWORK_MODULES = frozenset({"requests", "urllib", "http", "socket", "ssl", "smtplib", "ftplib"})


def imported_module_roots() -> frozenset:
    """Top-level module names this file imports, read from its own AST."""
    import ast

    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".")[0])
    return frozenset(roots)

def _synthetic_sources(**overrides: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Build in-memory source rows for deterministic tests."""
    rows: Dict[str, Dict[str, Any]] = {}
    for source in SOURCE_LIST:
        rows[source.source_id] = {
            **source.to_dict(),
            "read_status": "missing",
            "generated_at": None,
            "timestamp_field": None,
            "age_seconds": None,
            "freshness": MISSING,
            "usable_as_canonical_input": False,
            "reason": "synthetic test source not provided",
            "data": None,
        }
    for source_id, payload in overrides.items():
        source = SOURCES[source_id]
        freshness = payload.pop("__freshness__", CURRENT)
        rows[source_id] = {
            **source.to_dict(),
            "read_status": "ok",
            "generated_at": payload.get("generated_at") or payload.get("generated_at_utc") or "2026-08-12T00:00:00Z",
            "timestamp_field": "generated_at",
            "age_seconds": 0.0,
            "freshness": freshness,
            "usable_as_canonical_input": freshness == CURRENT,
            "reason": "synthetic test source",
            "data": payload,
        }
    return rows


def run_self_test() -> Dict[str, Any]:
    checks: Dict[str, Any] = {}

    # Test A — runtime conflict: legacy LEVEL_1_DRAFT_ONLY vs current LEVEL_2.
    loaded = _synthetic_sources(
        runtime_guarded_autonomy={
            "generated_at": "2026-08-12T14:00:00Z",
            "activation_stage": "LEVEL_2_MONITORING_ACTIVE",
            "autonomy_level": "LEVEL_2_MONITORING_ACTIVE",
            "flags": {"monitoring_enabled": True, "emergency_stop": False, "breach": False},
            "systemd": {"timer_active": True, "timer_enabled": True},
        },
        legacy_autonomy_policy={
            "generated_at_utc": "2026-06-10T13:07:13Z",
            "current_autonomy_level": "LEVEL_1_DRAFT_ONLY",
            "__freshness__": STALE_EXCLUDED,
        },
    )
    fields = resolve_fields(loaded)
    priority = derive_owner_priority(fields)
    legacy = build_legacy_supersession(fields, loaded, priority)
    checks["test_a_canonical_runtime_level"] = value_of(fields, "autonomy_level") == "LEVEL_2_MONITORING_ACTIVE"
    checks["test_a_legacy_superseded"] = any(
        entry["canonical_field"] == "autonomy_level"
        and entry["legacy_value"] == "LEVEL_1_DRAFT_ONLY"
        and entry["freshness"] == SUPERSEDED
        and entry["operational_effect"] is False
        for entry in legacy["field_claims"]
    )

    # Test B — emergency stop conflict: legacy true vs current false.
    loaded = _synthetic_sources(
        runtime_guarded_autonomy={
            "generated_at": "2026-08-12T14:00:00Z",
            "flags": {"emergency_stop": False, "breach": False, "monitoring_enabled": True},
        },
        legacy_autonomy_runtime_lock={
            "generated_at_utc": "2026-06-11T04:26:24Z",
            "emergency_stop": True,
            "__freshness__": STALE_EXCLUDED,
        },
    )
    fields = resolve_fields(loaded)
    checks["test_b_emergency_stop_false"] = value_of(fields, "emergency_stop") is False

    # Test C — timer conflict: legacy not_installed vs current systemd timer true.
    loaded = _synthetic_sources(
        runtime_guarded_autonomy={
            "generated_at": "2026-08-12T14:00:00Z",
            "systemd": {"timer_active": True, "timer_enabled": True},
        },
        legacy_scheduler_plan={
            "generated_at_utc": "2026-06-11T04:52:01Z",
            "timer_installation_status": "not_installed",
            "__freshness__": STALE_EXCLUDED,
        },
    )
    fields = resolve_fields(loaded)
    checks["test_c_timer_active"] = value_of(fields, "systemd_timer_active") is True

    # Test D — NowPlaying conflict: legacy 0 vs current 133.
    website_payload = {
        "generated_at_utc": "2026-08-12T14:00:00Z",
        "overall_status": "WARNING",
        "metrics": [{"key": "total_5xx", "value": 451}, {"key": "map_404", "value": 0}],
        "rolling_window_context": {"status": "NEW_GROWTH_PRESENT"},
        "origin_pressure_breakdown": {
            "top_5xx_status_codes": [
                {"status": 504, "count": 285},
                {"status": 503, "count": 163},
                {"status": 522, "count": 2},
                {"status": 526, "count": 1},
            ],
            "top_5xx_paths": [
                {"path": NOWPLAYING_PATH, "count": 133, "statuses": [{"status": 504, "count": 133}]},
                {"path": WP_USERS_ME_PATH, "count": 62, "statuses": [{"status": 504, "count": 62}]},
            ],
        },
    }
    loaded = _synthetic_sources(
        website=dict(website_payload),
        legacy_ai_radio={
            "generated_at_utc": "2026-06-09T14:43:28Z",
            "nowplaying_504": 0,
            "__freshness__": STALE_EXCLUDED,
        },
    )
    fields = resolve_fields(loaded)
    legacy = build_legacy_supersession(fields, loaded, derive_owner_priority(fields))
    checks["test_d_nowplaying_current"] = value_of(fields, "nowplaying_504") == 133
    checks["test_d_legacy_informational"] = any(
        entry["canonical_field"] == "nowplaying_504"
        and entry["freshness"] == SUPERSEDED
        and entry["operational_effect"] is False
        for entry in legacy["field_claims"]
    )
    checks["test_d_wp_users_me"] = value_of(fields, "wp_users_me_504") == 62

    # Regression: a scalar UNKNOWN blocker is rendered as one scalar, never as
    # the character sequence U, N, K, N, O, W, N. A real scalar blocker is
    # normalized to a one-item list.
    unresolved_blockers = promotion_blockers_provenance({})
    scalar_blocker_fields = resolve_fields(_synthetic_sources(
        runtime_promotion={
            "generated_at": "2026-08-12T14:00:00Z",
            "blockers": "cloudflare_write_canary",
        },
    ))
    scalar_blockers = promotion_blockers_provenance(scalar_blocker_fields)
    checks["test_d_blocker_unknown_not_character_iterable"] = (
        unresolved_blockers["value"] == UNKNOWN
        and format_promotion_blockers(unresolved_blockers["value"]) == UNKNOWN
    )
    checks["test_d_scalar_blocker_normalized_to_list"] = (
        scalar_blockers["value"] == ["cloudflare_write_canary"]
        and format_promotion_blockers(scalar_blockers["value"])
        == "cloudflare_write_canary"
    )

    # Regression: a concrete users/me timeout requires a current path count
    # matching the diagnostic count. Missing or mismatched counts fail closed.
    compatible_wp_fields = resolve_fields(_synthetic_sources(
        website=dict(website_payload),
        origin_diagnostics={
            "generated_at_utc": "2026-08-12T14:01:00Z",
            "wp_users_me_diagnostic": {
                "classification": "WP_USERS_ME_ORIGIN_TIMEOUT",
                "evidence": {
                    "request_frequency": {"status_504_24h": 62},
                },
            },
        },
    ))
    compatible_wp = derive_wp_users_me_classification(
        compatible_wp_fields, "2026-08-12T14:02:00Z"
    )
    missing_wp_payload = {
        **website_payload,
        "origin_pressure_breakdown": {
            **website_payload["origin_pressure_breakdown"],
            "top_5xx_paths": [
                {
                    "path": NOWPLAYING_PATH,
                    "count": 133,
                    "statuses": [{"status": 504, "count": 133}],
                },
            ],
        },
    }
    missing_wp_fields = resolve_fields(_synthetic_sources(
        website=missing_wp_payload,
        origin_diagnostics={
            "generated_at_utc": "2026-08-12T14:01:00Z",
            "wp_users_me_diagnostic": {
                "classification": "WP_USERS_ME_ORIGIN_TIMEOUT",
                "evidence": {
                    "request_frequency": {"status_504_24h": 62},
                },
            },
        },
    ))
    missing_wp = derive_wp_users_me_classification(
        missing_wp_fields, "2026-08-12T14:02:00Z"
    )
    mismatched_wp_fields = resolve_fields(_synthetic_sources(
        website=dict(website_payload),
        origin_diagnostics={
            "generated_at_utc": "2026-08-12T14:01:00Z",
            "wp_users_me_diagnostic": {
                "classification": "WP_USERS_ME_ORIGIN_TIMEOUT",
                "evidence": {
                    "request_frequency": {"status_504_24h": 61},
                },
            },
        },
    ))
    mismatched_wp = derive_wp_users_me_classification(
        mismatched_wp_fields, "2026-08-12T14:02:00Z"
    )
    checks["test_d_wp_concrete_classification_requires_compatible_count"] = (
        compatible_wp["value"] == "WP_USERS_ME_ORIGIN_TIMEOUT"
        and compatible_wp["compatible_current_evidence"] is True
    )
    checks["test_d_wp_missing_count_fails_closed"] = (
        value_of(missing_wp_fields, "wp_users_me_504") is None
        and missing_wp["value"] == WP_USERS_ME_EVIDENCE_INSUFFICIENT
        and missing_wp["compatible_current_evidence"] is False
    )
    checks["test_d_wp_mismatched_count_fails_closed"] = (
        mismatched_wp["value"] == WP_USERS_ME_EVIDENCE_INSUFFICIENT
        and mismatched_wp["compatible_current_evidence"] is False
    )

    # Regression: absence from endpoint-specific 5xx evidence is UNKNOWN, not
    # an implicit zero. Healthy is valid only when both current and recovery
    # evidence explicitly carry the same zero count.
    missing_nowplaying_payload = {
        **website_payload,
        "origin_pressure_breakdown": {
            **website_payload["origin_pressure_breakdown"],
            "top_5xx_paths": [
                {
                    "path": WP_USERS_ME_PATH,
                    "count": 62,
                    "statuses": [{"status": 504, "count": 62}],
                },
            ],
        },
    }
    missing_nowplaying_fields = resolve_fields(_synthetic_sources(
        website=missing_nowplaying_payload,
        origin_504_recovery={
            "generated_at_utc": "2026-08-12T14:01:00Z",
            "nowplaying_chain": {"failure_class": "NOWPLAYING_HEALTHY"},
            "baseline": {"nowplaying_504": None},
        },
    ))
    missing_nowplaying = derive_nowplaying_classification(
        missing_nowplaying_fields, "2026-08-12T14:02:00Z"
    )
    explicit_zero_payload = {
        **website_payload,
        "origin_pressure_breakdown": {
            **website_payload["origin_pressure_breakdown"],
            "top_5xx_paths": [
                {
                    "path": NOWPLAYING_PATH,
                    "count": 0,
                    "statuses": [{"status": 504, "count": 0}],
                },
            ],
        },
    }
    explicit_zero_fields = resolve_fields(_synthetic_sources(
        website=explicit_zero_payload,
        origin_504_recovery={
            "generated_at_utc": "2026-08-12T14:01:00Z",
            "nowplaying_chain": {"failure_class": "NOWPLAYING_HEALTHY"},
            "baseline": {"nowplaying_504": 0},
        },
    ))
    explicit_zero_nowplaying = derive_nowplaying_classification(
        explicit_zero_fields, "2026-08-12T14:02:00Z"
    )
    checks["test_d_nowplaying_missing_count_fails_closed"] = (
        value_of(missing_nowplaying_fields, "nowplaying_504") is None
        and missing_nowplaying["value"] == NOWPLAYING_EVIDENCE_INSUFFICIENT
        and missing_nowplaying["compatible_current_evidence"] is False
    )
    checks["test_d_nowplaying_explicit_zero_can_be_healthy"] = (
        value_of(explicit_zero_fields, "nowplaying_504") == 0
        and explicit_zero_nowplaying["value"] == "NOWPLAYING_HEALTHY"
        and explicit_zero_nowplaying["compatible_current_evidence"] is True
    )

    # Test D2 — Phase 10.22 recovery evidence supersedes the older route-mismatch
    # classification, and the live NowPlaying share is recalculated from the
    # newest website snapshot instead of the recovery module's older baseline.
    recovery_website_payload = {
        "generated_at_utc": "2026-08-13T09:53:51Z",
        "overall_status": "CRITICAL",
        "metrics": [
            {"key": "total_5xx", "value": 728},
            {"key": "map_404", "value": 0},
        ],
        "rolling_window_context": {"status": "RECENT_SIGNIFICANT_GROWTH"},
        "origin_pressure_breakdown": {
            "top_5xx_status_codes": [
                {"status": 504, "count": 581},
                {"status": 503, "count": 144},
                {"status": 526, "count": 1},
            ],
            "top_5xx_paths": [
                {
                    "path": NOWPLAYING_PATH,
                    "count": 374,
                    "statuses": [{"status": 504, "count": 374}],
                },
                {
                    "path": WP_USERS_ME_PATH,
                    "count": 53,
                    "statuses": [{"status": 504, "count": 53}],
                },
            ],
        },
    }

    loaded_recovery = _synthetic_sources(
        website=recovery_website_payload,
        origin_504_recovery={
            "generated_at_utc": "2026-08-12T16:12:51Z",
            "status": "ORIGIN_RECOVERY_OWNER_ACTION_REQUIRED",
            "dominant_504_endpoint": NOWPLAYING_PATH,
            "dominant_504_count": 370,
            "dominant_504_share_percent": 59.2,
            "dominant_504_origin": "204.168.173.77",
            "nowplaying_chain": {
                "failure_class": "NOWPLAYING_EVIDENCE_INSUFFICIENT",
                "failure_evidence_level": "INSUFFICIENT",
                "origin_target": "204.168.173.77",
                "repairability": "REMOTE_OWNER_ACTION_REQUIRED",
            },
            "repair_gate": {"status": "NO_SAFE_AUTOMATIC_REPAIR"},
            "primary_failure_focus": {
                "primary_failure_focus": "AI_RADIO_NOWPLAYING_RECOVERY"
            },
        },
        nowplaying_recovery={
            "generated_at_utc": "2026-08-01T15:02:10Z",
            "classification": {
                "classification": "NOWPLAYING_ROUTE_MISMATCH",
                "automatic_repair_allowed": False,
            },
            "repair_applied": False,
            "status": "NOWPLAYING_ROUTE_MISMATCH",
        },
    )

    recovery_fields = resolve_fields(loaded_recovery)
    recovery_canonical = assemble_canonical(
        recovery_fields,
        "2026-08-13T10:00:00Z",
    )

    checks["test_d2_recovery_classification_precedence"] = (
        value_of(recovery_fields, "nowplaying_classification")
        == "NOWPLAYING_EVIDENCE_INSUFFICIENT"
    )
    checks["test_d2_old_route_mismatch_not_selected"] = (
        value_of(recovery_fields, "nowplaying_classification")
        != "NOWPLAYING_ROUTE_MISMATCH"
    )
    checks["test_d2_old_report_is_legacy_only"] = (
        SOURCES["nowplaying_recovery"].source_class == CLASS_LEGACY
        and all(
            candidate.source_id != "nowplaying_recovery"
            for candidate in DIAGNOSTIC_FIELDS["nowplaying_classification"]
        )
    )
    checks["test_d2_live_share_recalculated"] = (
        recovery_canonical["dominant_504_share_percent"]["value"] == 64.37
    )
    checks["test_d2_old_recovery_share_not_live"] = (
        recovery_canonical["dominant_504_share_percent"]["value"] != 59.2
    )
    checks["test_d2_live_share_provenance"] = (
        recovery_canonical["dominant_504_share_percent"]["source_class"]
        == "CANONICAL_DERIVATION"
        and recovery_canonical["dominant_504_share_percent"]["generated_at"]
        == "2026-08-13T10:00:00Z"
        and recovery_canonical["dominant_504_share_percent"]["derived_from"]
        == ["dominant_504_endpoint", "nowplaying_504", "http_504"]
    )

    mixed_loaded = _synthetic_sources(
        website=recovery_website_payload,
        origin_504_recovery={
            "generated_at_utc": "2026-08-12T16:12:51Z",
            "nowplaying_chain": {"failure_class": "NOWPLAYING_EVIDENCE_INSUFFICIENT"},
            "dominant_504_endpoint": NOWPLAYING_PATH,
        },
        nowplaying_recovery={
            "generated_at_utc": "2026-08-01T15:02:10Z",
            "classification": {"classification": "NOWPLAYING_ROUTE_MISMATCH"},
        },
    )
    mixed_gate = enforce_evidence_window(
        mixed_loaded,
        {"evidence_window": {"status": monitoring_decision.EVIDENCE_WINDOW_MISMATCH}},
    )
    mixed_fields = resolve_fields(mixed_loaded)
    checks["test_d3_mixed_window_excluded"] = (
        mixed_gate["status"] == monitoring_decision.EVIDENCE_WINDOW_MISMATCH
        and mixed_loaded["origin_504_recovery"]["usable_as_canonical_input"] is False
    )
    checks["test_d3_legacy_route_mismatch_never_fallback"] = (
        value_of(mixed_fields, "nowplaying_classification") is None
    )

    # Guard against silently treating NowPlaying as dominant forever.
    # If the recovery module selects another endpoint, retain its own share
    # until a generic current-path-count resolver exists.
    loaded_other_dominant = _synthetic_sources(
        website=recovery_website_payload,
        origin_504_recovery={
            "generated_at_utc": "2026-08-12T16:12:51Z",
            "status": "ORIGIN_RECOVERY_OWNER_ACTION_REQUIRED",
            "dominant_504_endpoint": "/api/time",
            "dominant_504_count": 57,
            "dominant_504_share_percent": 9.81,
            "dominant_504_origin": "204.168.173.77",
            "nowplaying_chain": {
                "failure_class": "NOWPLAYING_EVIDENCE_INSUFFICIENT",
            },
            "repair_gate": {"status": "NO_SAFE_AUTOMATIC_REPAIR"},
            "primary_failure_focus": {
                "primary_failure_focus": "WEBSITE_ORIGIN_STABILITY"
            },
        },
    )

    other_fields = resolve_fields(loaded_other_dominant)
    other_canonical = assemble_canonical(
        other_fields,
        "2026-08-13T10:00:00Z",
    )

    checks["test_d2_non_nowplaying_dominant_guard"] = (
        other_canonical["dominant_504_share_percent"]["value"] == 9.81
        and other_canonical["dominant_504_share_percent"]["source_class"]
        == "CURRENT_RECOVERY_MODULE"
    )

    # Test E — SourceMap conflict: legacy warning/70 vs current 0.
    loaded = _synthetic_sources(
        website=dict(website_payload),
        legacy_sourcemap={
            "generated_at_utc": "2026-05-28T13:27:33Z",
            "status": "WARNING",
            "map_404_metric": {"value": 70, "status": "WARNING"},
            "__freshness__": STALE_EXCLUDED,
        },
    )
    fields = resolve_fields(loaded)
    legacy = build_legacy_supersession(fields, loaded, derive_owner_priority(fields))
    checks["test_e_map_404_current"] = value_of(fields, "source_map_404") == 0
    checks["test_e_source_map_status_ok"] = derive_source_map_status(fields)["value"] == "OK"
    checks["test_e_legacy_excluded"] = all(
        entry["operational_effect"] is False
        for entry in legacy["field_claims"]
        if entry["canonical_field"] == "source_map_404"
    )

    # Test F — owner priority: website WARNING with origin failures beats SEO.
    loaded = _synthetic_sources(
        runtime_guarded_autonomy={
            "generated_at": "2026-08-12T14:00:00Z",
            "activation_stage": "LEVEL_2_MONITORING_ACTIVE",
            "autonomy_level": "LEVEL_2_MONITORING_ACTIVE",
            "flags": {"monitoring_enabled": True, "emergency_stop": False, "breach": False},
            "systemd": {"timer_active": True, "timer_enabled": True},
        },
        scheduler_cycles={
            "generated_at": "2026-08-12T13:00:00Z",
            "status": "SCHEDULER_VERIFICATION_GREEN",
        },
        website=dict(website_payload),
        legacy_owner_daily_action={
            "generated_at_utc": "2026-06-10T16:33:48Z",
            "recommended_next_owner_action": "manual_check:draft-exec-seo-title",
            "__freshness__": STALE_EXCLUDED,
        },
    )
    fields = resolve_fields(loaded)
    priority = derive_owner_priority(fields)
    checks["test_f_owner_priority"] = priority["value"] == "WEBSITE_ORIGIN_STABILITY"
    checks["test_f_seo_suppressed"] = (
        "SEO_TITLE_REVIEW" in priority["suppressed_lower_priorities"]
        and priority["legacy_seo_checklist_allowed"] is False
    )

    # Test F2 — website CRITICAL also selects origin stability above NowPlaying.
    critical_payload = dict(website_payload)
    critical_payload["overall_status"] = "CRITICAL"
    loaded_critical = _synthetic_sources(
        runtime_guarded_autonomy={
            "generated_at": "2026-08-12T14:00:00Z",
            "flags": {"monitoring_enabled": True, "emergency_stop": False, "breach": False},
            "systemd": {"timer_active": True},
            "activation_stage": "LEVEL_2_MONITORING_ACTIVE",
            "autonomy_level": "LEVEL_2_MONITORING_ACTIVE",
        },
        scheduler_cycles={"generated_at": "2026-08-12T13:00:00Z", "status": "SCHEDULER_VERIFICATION_GREEN"},
        runtime_promotion={
            "generated_at": "2026-08-12T13:00:00Z",
            "status": "RUNTIME_PROMOTION_BLOCKED_BY_WRITE_CANARY",
            "blockers": ["cloudflare_write_canary"],
        },
        runtime_write_canary={
            "generated_at": "2026-08-12T13:00:00Z",
            "status": "CLOUDFLARE_WRITE_CANARY_BLOCKED",
        },
        website=critical_payload,
        local={"generated_at_utc": "2026-08-12T14:00:00Z", "overall_status": "OK"},
    )
    checks["test_f2_critical_priority"] = (
        derive_owner_priority(resolve_fields(loaded_critical))["value"] == "WEBSITE_ORIGIN_STABILITY"
    )
    checks["test_f2_overall_status"] = (
        derive_overall_status(resolve_fields(loaded_critical))["value"] == "CRITICAL"
    )

    # Test G — missing current runtime must not fall back to a legacy level.
    loaded = _synthetic_sources(
        website=dict(website_payload),
        legacy_autonomy_policy={
            "generated_at_utc": "2026-06-10T13:07:13Z",
            "current_autonomy_level": "LEVEL_1_DRAFT_ONLY",
            "__freshness__": STALE_EXCLUDED,
        },
    )
    fields = resolve_fields(loaded)
    runtime_status = derive_runtime_status(fields)
    checks["test_g_runtime_unknown"] = (
        value_of(fields, "autonomy_level") is None
        and runtime_status["value"] == UNKNOWN
        and runtime_status["operational_effect"] is False
    )
    checks["test_g_no_legacy_fallback"] = fields["autonomy_level"]["resolution"] == "UNRESOLVED"

    # Structural checks.
    checks["freshness_vocabulary_complete"] = SUPERSEDED in FRESHNESS_VOCABULARY and len(
        FRESHNESS_VOCABULARY
    ) == 6
    checks["precedence_tiers_ordered"] = [tier for tier, _, _ in PRECEDENCE_TIERS] == list(range(1, 9))
    checks["all_sources_within_project"] = all(
        is_within_project(source.path) for source in SOURCE_LIST
    )
    checks["runtime_fields_never_legacy"] = all(
        SOURCES[candidate.source_id].source_class != CLASS_LEGACY
        for candidates in RUNTIME_FIELDS.values()
        for candidate in candidates
    )
    checks["website_fields_only_monitor"] = all(
        SOURCES[candidate.source_id].source_class in {CLASS_WEBSITE}
        for candidates in WEBSITE_FIELDS.values()
        for candidate in candidates
    )
    checks["required_fields_have_owners"] = all(
        field in FIELD_OWNERSHIP for field in REQUIRED_FIELDS
    )
    # Every required field must be exposed under its canonical key, and every
    # section 12 field of the snapshot contract must exist.
    sample_canonical = assemble_canonical(resolve_fields(loaded_critical), "2026-08-12T14:00:00Z")
    checks["canonical_key_aliases_valid"] = all(
        _canonical_key(field) in sample_canonical for field in REQUIRED_FIELDS
    )
    checks["snapshot_contract_complete"] = all(
        key in sample_canonical
        for key in (
            "generated_at", "overall_status", "website_status", "runtime_status",
            "runtime_stage", "autonomy_level", "monitoring_enabled", "timer_active",
            "scheduler_status", "low_live_enabled", "production_apply_lock",
            "emergency_stop", "breach", "write_canary_status", "promotion_status",
            "owner_priority", "total_5xx", "nowplaying_504", "wp_users_me_504",
            "source_map_404", "rolling_window_status",
        )
    )
    checks["snapshot_fields_carry_provenance"] = all(
        isinstance(block, dict)
        and {"value", "source", "freshness", "operational_effect"} <= set(block)
        for block in sample_canonical.values()
    )
    # Test H prerequisite: the canonical blocks are one shared text source.
    sample_report = {
        "status": "CANONICAL_TRUTH_OK",
        "missing_fields": [],
        "canonical": sample_canonical,
        "legacy_supersession": build_legacy_supersession(
            resolve_fields(loaded_critical), loaded_critical, sample_canonical["owner_priority"]
        ),
    }
    blocks = build_daily_summary_blocks(sample_report)
    unknown_blocker_canonical = dict(sample_canonical)
    unknown_blocker_canonical["promotion_blockers"] = {
        "value": UNKNOWN,
        "source": None,
        "source_class": None,
        "generated_at": None,
        "freshness": MISSING,
        "operational_effect": False,
        "resolution": "UNRESOLVED",
    }
    unknown_blocker_report = {
        **sample_report,
        "canonical": unknown_blocker_canonical,
    }
    unknown_blocker_blocks = build_daily_summary_blocks(unknown_blocker_report)
    checks["test_h_shared_blocks"] = (
        "LEVEL_2_MONITORING_ACTIVE" in blocks["header"]
        and "LEVEL_2_MONITORING_ACTIVE" in blocks["runtime_section"]
        and blocks["status_badge"] == "CRITICAL"
        and "LEVEL_1_DRAFT_ONLY" not in blocks["header"]
        and "not_installed" not in blocks["header"]
    )
    checks["test_h_unknown_blocker_rendered_atomically"] = (
        unknown_blocker_blocks["runtime_section"][
            unknown_blocker_blocks["runtime_section"].index("Promotion Blockers:") + 1
        ] == UNKNOWN
        and "U, N, K, N, O, W, N" not in unknown_blocker_blocks["runtime_section"]
    )
    imported = imported_module_roots()
    checks["no_process_execution_import"] = not (imported & PROCESS_MODULES)
    checks["no_network_client_import"] = not (imported & NETWORK_MODULES)
    checks["snapshot_max_age_bounded"] = 60 <= SNAPSHOT_MAX_AGE_SECONDS <= 3600

    findings = [name for name, value in checks.items() if not value]
    return {
        "status": "CANONICAL_TRUTH_SELF_TEST_OK" if not findings else "CANONICAL_TRUTH_SELF_TEST_FAILED",
        "checks": checks,
        "findings": findings,
        "breach": False,
    }


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def print_status(report: Dict[str, Any]) -> None:
    canonical = report.get("canonical", {})
    print(report.get("status", "NOT_RUN"))
    for name in (
        "overall_status",
        "website_status",
        "runtime_status",
        "runtime_stage",
        "autonomy_level",
        "monitoring_enabled",
        "timer_active",
        "scheduler_status",
        "low_live_enabled",
        "production_apply_lock",
        "emergency_stop",
        "breach",
        "write_canary_status",
        "promotion_status",
        "owner_priority",
        "total_5xx",
        "nowplaying_504",
        "wp_users_me_504",
        "source_map_404",
        "rolling_window_status",
    ):
        block = canonical.get(name)
        if isinstance(block, dict):
            print(f"{name}={show(block)}")
    if report.get("missing_fields"):
        print("missing_fields=" + ",".join(report["missing_fields"]))


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Sentinel canonical truth resolver (Phase 10.21)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--discover", action="store_true")
    group.add_argument("--resolve", action="store_true")
    group.add_argument("--validate", action="store_true")
    group.add_argument("--status", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        result = run_self_test()
        print(result["status"])
        for finding in result["findings"]:
            print(f"finding={finding}")
        return 0 if not result["findings"] else 1

    if args.discover:
        as_of = datetime.now(timezone.utc)
        rows = load_sources(as_of)
        print("CANONICAL_SOURCE_DISCOVERY_OK")
        for row in sorted(rows.values(), key=lambda item: (item["precedence_tier"], item["source_id"])):
            print(
                f"tier={row['precedence_tier']} {row['source_id']} "
                f"freshness={row['freshness']} generated_at={row['generated_at']} "
                f"path={row['path']}"
            )
        return 0

    if args.resolve:
        report = build_canonical_truth()
        persist(report)
        print(report["status"])
        print_status(report)
        return 0 if report["status"] == "CANONICAL_TRUTH_OK" else 2

    if args.validate:
        report = load_canonical_truth()
        if not report:
            print("CANONICAL_TRUTH_NOT_RUN")
            return 2
        result = validate_report(report)
        print(result["status"])
        for finding in result["findings"]:
            print(f"finding={finding}")
        return 0 if not result["findings"] else 2

    report = load_canonical_truth()
    if not report:
        print("CANONICAL_TRUTH_NOT_RUN")
        return 1
    print_status(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
