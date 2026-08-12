#!/usr/bin/env python3
"""Sentinel production pipeline — Phase 10.20 orchestrator, Phase 10.21 canonical order.

Fixed sequence (Phase 10.21 section 25):
1. collect current inputs
2. evaluate freshness
3. build canonical truth
4. validate canonical invariants
5. determine owner priority
6. build the master report
7. build the daily summary
8. build the public summary
9. audit

The daily summary is never produced before canonical truth. Every operational
value in the summary comes from `sentinel_canonical_truth.py`; the pipeline itself
derives no runtime state and holds no legacy fallback value.

No free commands, hosts, or paths. All subprocess calls use fixed allowlists.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import sentinel_canonical_invariants as invariants
import sentinel_canonical_truth as canonical_truth


PROJECT_DIR = Path("/srv/sentinel-defense")
SCHEMA_VERSION = "sentinel-production-pipeline-10.21"

REPORT_DIR = PROJECT_DIR / "reports/latest"
STATE_DIR = PROJECT_DIR / "state/adaptive-learning"
AUDIT_DIR = PROJECT_DIR / "audit"
PLAYBOOK_DIR = PROJECT_DIR / "playbooks"

REPORT_JSON = REPORT_DIR / "sentinel-production-pipeline.json"
REPORT_MD = REPORT_DIR / "sentinel-production-pipeline.md"
SOURCE_PRECEDENCE_MD = REPORT_DIR / "sentinel-production-source-precedence.md"
FRESHNESS_MD = REPORT_DIR / "sentinel-production-freshness.md"
OWNER_PRIORITY_MD = REPORT_DIR / "sentinel-production-owner-priority.md"
DAILY_VALIDATION_MD = REPORT_DIR / "sentinel-production-daily-summary-validation.md"
PUBLIC_MD = REPORT_DIR / "sentinel-production-public-summary.md"

STATE_JSON = STATE_DIR / "production_pipeline.json"
LATEST_STATE_JSON = STATE_DIR / "latest_production_pipeline.json"
HISTORY_JSON = STATE_DIR / "production_pipeline_history.json"
AUDIT_JSONL = AUDIT_DIR / "sentinel-production-pipeline.jsonl"

PLAYBOOKS = (
    PLAYBOOK_DIR / "sentinel-production-pipeline.playbook.json",
    PLAYBOOK_DIR / "sentinel-current-source-precedence.playbook.json",
    PLAYBOOK_DIR / "sentinel-monitoring-go-live.playbook.json",
)

OUTPUT_JSONS = (REPORT_JSON, STATE_JSON, LATEST_STATE_JSON, HISTORY_JSON, *PLAYBOOKS)
OUTPUT_MARKDOWN = (
    REPORT_MD,
    SOURCE_PRECEDENCE_MD,
    FRESHNESS_MD,
    OWNER_PRIORITY_MD,
    DAILY_VALIDATION_MD,
    PUBLIC_MD,
)
OUTPUT_ROOTS = (REPORT_DIR, STATE_DIR, AUDIT_DIR, PLAYBOOK_DIR)

# Canonical freshness vocabulary, owned by sentinel_canonical_truth.
CURRENT = canonical_truth.CURRENT
STALE_INFORMATIONAL = canonical_truth.STALE_INFORMATIONAL
STALE_EXCLUDED = canonical_truth.STALE_EXCLUDED
MISSING = canonical_truth.MISSING
INVALID = canonical_truth.INVALID
SUPERSEDED = canonical_truth.SUPERSEDED
UNKNOWN = canonical_truth.UNKNOWN

PIPELINE_STEPS = (
    "collect_current_inputs",
    "evaluate_freshness",
    "build_canonical_truth",
    "validate_canonical_invariants",
    "determine_owner_priority",
    "build_master_report",
    "build_daily_summary",
    "build_public_summary",
    "audit",
)

FIXED_SUBPROCESS_COMMANDS = {
    "website_observe": (
        "/usr/bin/python3", "/srv/sentinel-defense/sentinel_defense_bot.py",
        "--mode", "observe",
        "--report", "/srv/sentinel-defense/cloudflare-monitor/latest/cloudflare-daily-monitor.md",
    ),
    "master_consistency": (
        "/usr/bin/python3", "/srv/sentinel-defense/sentinel_master_report_consistency.py",
        "--collect",
    ),
    "origin_diagnostics": (
        "/usr/bin/python3", "/srv/sentinel-defense/sentinel_origin_failure_diagnostics.py",
        "--collect",
    ),
    "runtime_status": (
        "/usr/bin/python3", "/srv/sentinel-defense/sentinel_guarded_runtime_activation.py",
        "--status",
    ),
    "runtime_self_test": (
        "/usr/bin/python3", "/srv/sentinel-defense/sentinel_guarded_runtime_activation.py",
        "--self-test",
    ),
    "master_build": (
        "/usr/bin/python3", "/srv/sentinel-defense/sentinel_master.py",
    ),
}

SECRET_RE = re.compile(
    r"(?i)(?:password|passwd|secret|api[_-]?key|access[_-]?token|private[_-]?key)\s*[:=]\s*[^\s,;]+"
)
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def ensure_dirs() -> None:
    for directory in OUTPUT_ROOTS:
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
    return canonical_truth.read_json(path)


def load_dict(path: Path) -> Dict[str, Any]:
    data, status = read_json(path)
    return data if status == "ok" and isinstance(data, dict) else {}


def run_fixed_command(command_id: str, timeout: int = 180) -> Dict[str, Any]:
    command = FIXED_SUBPROCESS_COMMANDS.get(command_id)
    if command is None:
        return {"command_id": command_id, "returncode": 126, "stdout": "", "stderr": "command_not_allowlisted"}
    try:
        result = subprocess.run(
            list(command),
            cwd=str(PROJECT_DIR),
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        return {"command_id": command_id, "returncode": 124, "stdout": "", "stderr": "timeout"}
    except OSError as exc:
        return {"command_id": command_id, "returncode": 127, "stdout": "", "stderr": type(exc).__name__}
    return {
        "command_id": command_id,
        "returncode": result.returncode,
        "stdout": result.stdout.strip()[:2000],
        "stderr": result.stderr.strip()[:1000],
    }


# --------------------------------------------------------------------------- #
# Step 1 — collect current inputs
# --------------------------------------------------------------------------- #

DISCOVERY_INPUTS = {
    "website_report": REPORT_DIR / "sentinel-defense-report.json",
    "local_report": PROJECT_DIR / "inbox/local/local-defense-report.json",
    "consistency_report": REPORT_DIR / "sentinel-master-consistency.json",
    "origin_diagnostics": REPORT_DIR / "sentinel-origin-failure-diagnostics.json",
    "runtime_guarded_autonomy": REPORT_DIR / "sentinel-guarded-autonomy.json",
    "runtime_activation": REPORT_DIR / "sentinel-guarded-runtime-activation.json",
    "nowplaying_recovery": REPORT_DIR / "sentinel-nowplaying-recovery.json",
    "canonical_truth": REPORT_DIR / "sentinel-canonical-truth.json",
    "sourcemap_report": REPORT_DIR / "sourcemap-prevention-report.json",
    "ai_radio_report": REPORT_DIR / "ai-radio-api-timeout-diagnosis.json",
    "microcache_status": REPORT_DIR / "ai-radio-nowplaying-microcache-status.json",
    "challenge_diagnosis": REPORT_DIR / "cloudflare-challenge-diagnosis.json",
    "master_report": REPORT_DIR / "sentinel-master-report.json",
}


def discover_inputs() -> Dict[str, Any]:
    found = {}
    missing = []
    for name, path in DISCOVERY_INPUTS.items():
        if path.exists():
            found[name] = str(path.relative_to(PROJECT_DIR))
        else:
            missing.append(name)
    return {
        "status": "INPUT_DISCOVERY_OK" if not missing else "INPUT_DISCOVERY_PARTIAL",
        "found": found,
        "missing": missing,
    }


def collect_current_inputs() -> Dict[str, Any]:
    """Refresh the components that own current evidence, then discover inputs."""
    commands = [
        run_fixed_command("master_consistency"),
        run_fixed_command("origin_diagnostics"),
        run_fixed_command("runtime_status"),
    ]
    discovery = discover_inputs()
    return {
        "status": "CURRENT_INPUTS_COLLECTED",
        "commands": commands,
        "failed_commands": [row["command_id"] for row in commands if row["returncode"] != 0],
        "discovery": discovery,
    }


def collect_website_snapshot(canonical: Dict[str, Any]) -> Dict[str, Any]:
    """Website facts, taken from canonical truth only."""
    def value(field: str, default: Any = None) -> Any:
        block = canonical.get(field)
        if not isinstance(block, dict) or block.get("resolution") != "RESOLVED":
            return default
        return block.get("value")

    total_5xx = value("total_5xx", 0) or 0
    nowplaying_504 = value("nowplaying_504", 0) or 0
    return {
        "status": "WEBSITE_SNAPSHOT_COLLECTED",
        "overall_status": value("website_status", UNKNOWN),
        "correlation_status": value("website_correlation_status", UNKNOWN),
        "generated_at_utc": (canonical.get("website_status") or {}).get("generated_at"),
        "snapshot_id": value("current_snapshot_id"),
        "total_5xx": total_5xx,
        "http_504": value("http_504", 0),
        "http_503": value("http_503", 0),
        "http_522": value("http_522", 0),
        "http_526": value("http_526", 0),
        "nowplaying_504": nowplaying_504,
        "nowplaying_share_percent": round((nowplaying_504 / total_5xx) * 100, 2) if total_5xx else 0.0,
        "wp_users_me_504": value("wp_users_me_504", 0),
        "wp_users_me_classification": value("wp_users_me_classification", UNKNOWN),
        "source_map_404": value("source_map_404"),
        "source_map_status": value("source_map_status", UNKNOWN),
        "rolling_window_status": value("rolling_window_status", UNKNOWN),
        "current_growth": value("current_growth", UNKNOWN),
        "nowplaying_classification": value("nowplaying_classification", UNKNOWN),
        "nowplaying_automatic_repair_allowed": value("nowplaying_automatic_repair_allowed"),
    }


def collect_local_snapshot(canonical: Dict[str, Any]) -> Dict[str, Any]:
    block = canonical.get("local_status") if isinstance(canonical.get("local_status"), dict) else {}
    resolved = block.get("resolution") == "RESOLVED"
    return {
        "status": "LOCAL_SNAPSHOT_COLLECTED" if resolved else "LOCAL_SNAPSHOT_MISSING",
        "overall_status": block.get("value") if resolved else UNKNOWN,
        "generated_at_utc": block.get("generated_at"),
    }


def collect_consistency(canonical: Dict[str, Any]) -> Dict[str, Any]:
    data = load_dict(REPORT_DIR / "sentinel-master-consistency.json")
    block = canonical.get("consistency_status") if isinstance(canonical.get("consistency_status"), dict) else {}
    return {
        "status": "CONSISTENCY_COLLECTED" if data else "CONSISTENCY_MISSING",
        "report_status": block.get("value") if block.get("resolution") == "RESOLVED" else (
            data.get("status", UNKNOWN) if data else UNKNOWN
        ),
        "freshness": block.get("freshness", MISSING),
        "generated_at_utc": data.get("generated_at_utc") if data else None,
        "owner_priority": (data.get("owner_priority") or {}).get("selected_priority") if data else None,
    }


def collect_origin_diagnostics(canonical: Dict[str, Any]) -> Dict[str, Any]:
    data = load_dict(REPORT_DIR / "sentinel-origin-failure-diagnostics.json")
    block = canonical.get("origin_diagnostic_status") if isinstance(
        canonical.get("origin_diagnostic_status"), dict
    ) else {}
    wp_users_me = data.get("wp_users_me_diagnostic") if isinstance(
        data.get("wp_users_me_diagnostic"), dict
    ) else {}
    return {
        "status": "ORIGIN_DIAGNOSTICS_COLLECTED" if data else "ORIGIN_DIAGNOSTICS_MISSING",
        "report_status": block.get("value") if block.get("resolution") == "RESOLVED" else (
            data.get("status", UNKNOWN) if data else UNKNOWN
        ),
        "freshness": block.get("freshness", MISSING),
        "generated_at_utc": data.get("generated_at_utc") if data else None,
        "tls_status": (data.get("origin_tls_diagnostic") or {}).get("status") if data else None,
        "wp_users_me_classification": wp_users_me.get("classification"),
        "wp_users_me_confidence": wp_users_me.get("confidence"),
        "wp_users_me_productive_rule_applied": wp_users_me.get("productive_rule_applied", False),
    }


# --------------------------------------------------------------------------- #
# Step 2 — freshness, from the canonical source evaluation
# --------------------------------------------------------------------------- #

def build_freshness_report(canonical_report: Dict[str, Any]) -> Dict[str, Any]:
    """Freshness is owned by the canonical resolver; the pipeline only presents it."""
    sources = canonical_report.get("sources", [])
    legacy = canonical_report.get("legacy_supersession", {})
    rows = [
        {
            "report_name": row.get("source_id"),
            "path": row.get("path"),
            "source_class": row.get("source_class"),
            "precedence_tier": row.get("precedence_tier"),
            "generated_at": row.get("generated_at"),
            "age_seconds": row.get("age_seconds"),
            "freshness_status": row.get("freshness"),
            "included_in_master_status": bool(row.get("usable_as_canonical_input")),
            "reason": row.get("reason"),
        }
        for row in sources
    ]
    counts = {
        status: sum(1 for row in rows if row["freshness_status"] == status)
        for status in (CURRENT, STALE_INFORMATIONAL, STALE_EXCLUDED, MISSING, INVALID)
    }
    counts[SUPERSEDED] = len(legacy.get("superseded_field_claims", []))
    return {
        "status": "FRESHNESS_EVALUATION_OK" if rows else "FRESHNESS_EVALUATION_UNAVAILABLE",
        "evaluated_at": utc_now(),
        "vocabulary": list(canonical_truth.FRESHNESS_VOCABULARY),
        "reports": rows,
        "status_counts": counts,
        "excluded_from_master_status": [
            row["report_name"] for row in rows
            if row["freshness_status"] in {STALE_EXCLUDED, MISSING, INVALID}
        ],
        "superseded_field_claims": legacy.get("superseded_field_claims", []),
        "legacy_conflicts_neutralized": legacy.get("counts", {}).get("conflicts_neutralized", 0),
    }


# --------------------------------------------------------------------------- #
# Step 3 — canonical truth
# --------------------------------------------------------------------------- #

def build_canonical_truth() -> Dict[str, Any]:
    report = canonical_truth.build_canonical_truth()
    canonical_truth.persist(report)
    return report


# --------------------------------------------------------------------------- #
# Step 5 — owner priority, resolved canonically
# --------------------------------------------------------------------------- #

def determine_owner_priority(canonical: Dict[str, Any]) -> Dict[str, Any]:
    block = canonical.get("owner_priority") if isinstance(canonical.get("owner_priority"), dict) else {}
    selected = block.get("value") or "OWNER_PRIORITY_UNRESOLVED"
    return {
        "status": f"OWNER_PRIORITY_{selected}",
        "selected_priority": selected,
        "rank": block.get("rank"),
        "reason": block.get("rank_reason"),
        "suppressed_priorities": block.get("suppressed_lower_priorities", []),
        "legacy_seo_checklist_allowed": block.get("legacy_seo_checklist_allowed", False),
        "legacy_seo_checklist_reason": block.get("legacy_seo_checklist_reason"),
        "ladder": block.get("ladder", []),
        "source": block.get("source"),
        "inputs": block.get("inputs", {}),
    }


# --------------------------------------------------------------------------- #
# Step 7 — daily summary, assembled only from canonical blocks
# --------------------------------------------------------------------------- #

def build_runtime_summary(canonical: Dict[str, Any]) -> Dict[str, Any]:
    """Runtime facts for downstream consumers — canonical values, no derivation."""
    def value(field: str) -> Any:
        block = canonical.get(field)
        if not isinstance(block, dict) or block.get("resolution") != "RESOLVED":
            return None
        return block.get("value")

    return {
        "runtime_stage": value("runtime_stage") or UNKNOWN,
        "autonomy_level": value("autonomy_level") or UNKNOWN,
        "runtime_status": value("runtime_status") or UNKNOWN,
        "monitoring_enabled": value("monitoring_enabled"),
        "systemd_timer_active": value("timer_active"),
        "systemd_timer_enabled": value("timer_enabled"),
        "scheduler_verification_status": value("scheduler_status") or UNKNOWN,
        "scheduler_successful_cycles": value("scheduler_successful_cycles"),
        "guarded_live_autonomy_enabled": value("guarded_live_autonomy_enabled"),
        "low_live_apply_enabled": value("low_live_enabled"),
        "medium_live_apply_enabled": value("medium_live_enabled"),
        "high_live_apply_enabled": value("high_live_enabled"),
        "production_apply_lock": value("production_apply_lock"),
        "emergency_stop": value("emergency_stop"),
        "circuit_breaker_status": value("circuit_breaker_status") or UNKNOWN,
        "rollback_status": value("rollback_status") or UNKNOWN,
        "write_canary_status": value("write_canary_status") or UNKNOWN,
        "promotion_status": value("promotion_status") or UNKNOWN,
        "promotion_blockers": value("promotion_blockers") or [],
        "last_cycle_id": value("last_cycle_id"),
        "last_decision": value("last_decision"),
        "breach": value("breach"),
    }


def build_daily_summary(canonical_report: Dict[str, Any], freshness: Dict[str, Any]) -> str:
    """The daily summary is a rendering of canonical blocks, never a new evaluation."""
    blocks = canonical_report.get("daily_summary_blocks", {})
    if not blocks:
        return (
            "# Sentinel Production Daily Summary\n\n"
            f"Generated: `{utc_now()}`\n\n"
            "Status: `CANONICAL_TRUTH_INCOMPLETE`\n\n"
            "No canonical daily header is available. No legacy value is substituted.\n"
        )
    lines = [
        "# Sentinel Production Daily Summary",
        "",
        f"Canonical Truth: `{canonical_report.get('status')}`",
        "",
        "## Executive Header",
        "",
        "```text",
        *blocks["header"],
        "```",
        "",
        "## Runtime Status",
        "",
        "```text",
        *blocks["runtime_section"],
        "```",
        "",
        "## Current Website Evidence",
        "",
        "```text",
        *blocks["website_section"],
        "```",
        "",
        "## Owner Priority",
        "",
        "```text",
        *blocks["owner_priority_section"],
        "```",
        "",
        "## Freshness",
        "",
        f"- Status: `{freshness.get('status')}`",
    ]
    for row in freshness.get("reports", []):
        lines.append(
            f"- `{row['report_name']}`: `{row['freshness_status']}` "
            f"(tier={row['precedence_tier']}, included={str(row['included_in_master_status']).lower()})"
        )
    lines.extend([
        "",
        f"- Superseded legacy field claims: `{freshness.get('status_counts', {}).get(SUPERSEDED, 0)}`",
        f"- Legacy conflicts neutralized: `{freshness.get('legacy_conflicts_neutralized', 0)}`",
        "",
        "## Legacy / Historical Modules",
        "",
        "```text",
        *blocks["legacy_section"],
        "```",
        "",
        "## Safety",
        "",
        "- Phase 10.21 is reporting, state resolution, source precedence, diagnostic and validation only.",
        "- No Cloudflare write, no WAF/DNS/TLS change, no systemd or timer change.",
        "- No LOW_LIVE/MEDIUM/HIGH activation, no WordPress/database/nginx write.",
    ])
    return "\n".join(lines) + "\n"


def build_public_summary(canonical_report: Dict[str, Any]) -> str:
    """Sanitized owner-external summary derived from canonical status values only."""
    canonical = canonical_report.get("canonical", {})

    def show(field: str) -> str:
        return canonical_truth.show(canonical.get(field, {}))

    return "\n".join([
        "# Sentinel Public Status Summary",
        "",
        f"- overall status: `{show('overall_status')}`",
        f"- website status: `{show('website_status')}`",
        f"- monitoring: `{show('monitoring_enabled')}`",
        f"- productive automation: `{'locked' if canonical.get('production_apply_lock', {}).get('value') is True else show('production_apply_lock')}`",
        f"- breach: `{show('breach')}`",
        f"- operational priority: `{show('owner_priority')}`",
        "",
        "Private infrastructure identifiers, detailed paths, host mappings and security "
        "configuration are intentionally omitted from this public summary.",
        "",
        "Elevated origin timeout pressure is handled through owner-led diagnosis. Live "
        "automation stays disabled and no new broad security rule is recommended from the "
        "current evidence.",
    ]) + "\n"


# --------------------------------------------------------------------------- #
# Pipeline
# --------------------------------------------------------------------------- #

def run_pipeline(build_master: bool = True) -> Dict[str, Any]:
    ensure_dirs()
    started_at = utc_now()

    # Step 1 — collect current inputs.
    inputs = collect_current_inputs()

    # Step 3 must not be preceded by any summary rendering: canonical truth first.
    canonical_report = build_canonical_truth()
    canonical = canonical_report.get("canonical", {})

    # Step 2 — freshness, as evaluated by the canonical resolver.
    freshness = build_freshness_report(canonical_report)

    # Step 4 — canonical invariants (pre-master gate).
    pre_invariants = invariants.build_report()
    pre_daily = invariants.build_daily_consistency(pre_invariants)
    invariants.persist(pre_invariants, pre_daily)

    # Step 5 — owner priority.
    priority = determine_owner_priority(canonical)

    website = collect_website_snapshot(canonical)
    local = collect_local_snapshot(canonical)
    consistency = collect_consistency(canonical)
    origin = collect_origin_diagnostics(canonical)
    runtime_summary = build_runtime_summary(canonical)

    # Step 7 — daily summary (only now, after canonical truth exists).
    daily_summary = build_daily_summary(canonical_report, freshness)
    public_summary = build_public_summary(canonical_report)

    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "started_at_utc": started_at,
        "status": "PRODUCTION_PIPELINE_OK",
        "pipeline_steps": list(PIPELINE_STEPS),
        "canonical_truth_status": canonical_report.get("status"),
        "canonical_truth_generated_at": canonical_report.get("generated_at_utc"),
        "canonical_missing_fields": canonical_report.get("missing_fields", []),
        "inputs": inputs,
        "website": website,
        "local": local,
        "consistency": consistency,
        "origin_diagnostics": origin,
        "runtime": runtime_summary,
        "owner_priority": priority,
        "freshness": freshness,
        "canonical_invariants_pre": {
            "status": pre_invariants["status"],
            "violations": len(pre_invariants["violations"]),
            "daily_summary_consistency": pre_daily["status"],
        },
        "daily_summary_text": daily_summary,
        "public_summary_text": public_summary,
        "breach": runtime_summary.get("breach") is True,
    }

    # Write the pipeline artifacts before the master report reads them.
    persist(report, freshness, priority, inputs, daily_summary, public_summary)

    # Step 6 — master report, which now consumes canonical truth.
    if build_master:
        master = run_fixed_command("master_build", timeout=300)
        report["master_build"] = {
            "returncode": master["returncode"],
            "stderr": master["stderr"][:400],
        }
        if master["returncode"] != 0:
            report["status"] = "PRODUCTION_PIPELINE_MASTER_BUILD_FAILED"

    # Step 4 again after rendering — the binding post-render validation.
    post_invariants = invariants.build_report()
    post_daily = invariants.build_daily_consistency(post_invariants)
    invariants.persist(post_invariants, post_daily)
    report["canonical_invariants"] = {
        "status": post_invariants["status"],
        "violations": len(post_invariants["violations"]),
        "violation_detail": [
            {"invariant": row["invariant"], "location": row["location"], "detail": row["detail"]}
            for row in post_invariants["violations"]
        ],
        "daily_summary_consistency": post_daily["status"],
        "mismatched_fields": post_daily["mismatched_fields"],
    }

    if canonical_report.get("status") != "CANONICAL_TRUTH_OK":
        report["status"] = "PRODUCTION_PIPELINE_CANONICAL_TRUTH_INCOMPLETE"
    elif post_invariants["violations"]:
        report["status"] = "PRODUCTION_PIPELINE_INVARIANT_VIOLATION"

    # Step 9 — audit and final persist with the validation outcome.
    persist(report, freshness, priority, inputs, daily_summary, public_summary)
    return report


def persist(
    report: Dict[str, Any],
    freshness: Dict[str, Any],
    priority: Dict[str, Any],
    inputs: Dict[str, Any],
    daily_summary: str,
    public_summary: str,
) -> None:
    write_json(REPORT_JSON, report)
    write_json(STATE_JSON, report)
    write_json(LATEST_STATE_JSON, report)
    history, status = read_json(HISTORY_JSON)
    if status != "ok" or not isinstance(history, list):
        history = []
    history.append({
        "timestamp_utc": report["generated_at_utc"],
        "status": report["status"],
        "canonical_truth_status": report.get("canonical_truth_status"),
        "website_status": report["website"]["overall_status"],
        "priority": priority["selected_priority"],
        "runtime_level": report["runtime"]["autonomy_level"],
        "timer_active": report["runtime"]["systemd_timer_active"],
        "breach": report["breach"],
    })
    write_json(HISTORY_JSON, history[-200:])
    append_jsonl(AUDIT_JSONL, {
        "timestamp_utc": report["generated_at_utc"],
        "event": "production_pipeline_run",
        "status": report["status"],
        "canonical_truth_status": report.get("canonical_truth_status"),
        "priority": priority["selected_priority"],
        "runtime_level": report["runtime"]["autonomy_level"],
        "timer_active": report["runtime"]["systemd_timer_active"],
        "emergency_stop": report["runtime"]["emergency_stop"],
        "breach": report["breach"],
        "invariants": report.get("canonical_invariants", {}).get("status"),
    })
    write_text(REPORT_MD, daily_summary)
    write_text(PUBLIC_MD, public_summary)
    write_text(
        SOURCE_PRECEDENCE_MD,
        "# Sentinel Production Source Precedence\n\n"
        "Canonical precedence is owned by `sentinel_canonical_truth.py`.\n\n"
        f"```json\n{json.dumps(inputs, indent=2, sort_keys=True)}\n```\n",
    )
    write_text(
        FRESHNESS_MD,
        f"# Sentinel Production Freshness\n\n```json\n{json.dumps(freshness, indent=2, sort_keys=True)}\n```\n",
    )
    write_text(
        OWNER_PRIORITY_MD,
        f"# Sentinel Production Owner Priority\n\n```json\n{json.dumps(priority, indent=2, sort_keys=True)}\n```\n",
    )
    write_text(DAILY_VALIDATION_MD, render_daily_validation(report))
    for playbook in PLAYBOOKS:
        write_json(playbook, build_playbook(playbook.name))


def render_daily_validation(report: Dict[str, Any]) -> str:
    checks = report.get("canonical_invariants") or report.get("canonical_invariants_pre") or {}
    lines = [
        "# Sentinel Production Daily Summary Validation",
        "",
        f"- pipeline status: `{report.get('status')}`",
        f"- canonical truth: `{report.get('canonical_truth_status')}`",
        f"- canonical invariants: `{checks.get('status', 'NOT_RUN')}`",
        f"- daily summary consistency: `{checks.get('daily_summary_consistency', 'NOT_RUN')}`",
        f"- invariant violations: `{checks.get('violations', 'unknown')}`",
        "",
        "## Fixed Order",
        "",
    ]
    for index, step in enumerate(PIPELINE_STEPS, start=1):
        lines.append(f"{index}. `{step}`")
    lines.extend([
        "",
        "The daily summary is never rendered before canonical truth exists.",
    ])
    for row in checks.get("violation_detail", []):
        lines.append(f"- violation `{row['invariant']}` at `{row['location']}`: {row['detail']}")
    if checks.get("mismatched_fields"):
        lines.append(f"- mismatched fields: `{', '.join(checks['mismatched_fields'])}`")
    return "\n".join(lines) + "\n"


def build_playbook(name: str) -> Dict[str, Any]:
    base = {
        "schema_version": SCHEMA_VERSION,
        "status": "PLAYBOOK_ACTIVE",
        "name": name.replace(".playbook.json", ""),
        "fixed_order": list(PIPELINE_STEPS),
        "rule": "canonical truth precedes every summary; no legacy fallback value is permitted",
        "execution_boundaries": dict(canonical_truth.EXECUTION_BOUNDARIES),
    }
    if name == "sentinel-current-source-precedence.playbook.json":
        base["precedence"] = [
            {"tier": tier, "source_class": source_class, "description": description}
            for tier, source_class, description in canonical_truth.PRECEDENCE_TIERS
        ]
        base["source_registry"] = canonical_truth.canonical_source_registry()
    if name == "sentinel-monitoring-go-live.playbook.json":
        base["monitoring_contract"] = {
            "runtime_fields_from": "current guarded runtime state",
            "never_from": "Level-1 draft-only modules",
            "promotion_requires": "cloudflare write canary unblocked",
        }
    return base


# --------------------------------------------------------------------------- #
# Validation and self-test
# --------------------------------------------------------------------------- #

def validate_output() -> Dict[str, Any]:
    findings: List[str] = []
    report = load_dict(REPORT_JSON)
    if not report:
        return {"status": "OUTPUT_INVALID", "findings": ["pipeline report missing"]}
    for path in OUTPUT_JSONS:
        if not path.exists():
            findings.append(f"missing_json:{path.name}")
            continue
        data, status = read_json(path)
        if status != "ok":
            findings.append(f"invalid_json:{path.name}")
    for path in OUTPUT_MARKDOWN:
        if not path.exists() or not path.read_text(encoding="utf-8").strip():
            findings.append(f"missing_markdown:{path.name}")
    if report.get("canonical_truth_status") != "CANONICAL_TRUTH_OK":
        findings.append(f"canonical_truth:{report.get('canonical_truth_status')}")
    checks = report.get("canonical_invariants", {})
    if checks.get("violations"):
        findings.append(f"invariant_violations:{checks.get('violations')}")
    if checks.get("daily_summary_consistency") not in {None, "DAILY_SUMMARY_CONSISTENCY_OK"}:
        findings.append(f"daily_summary_consistency:{checks.get('daily_summary_consistency')}")
    # Labelled legacy regions are documentation; only current-truth text is scanned.
    summary = invariants.current_truth_text(report.get("daily_summary_text", ""))
    canonical = load_dict(REPORT_DIR / "sentinel-canonical-truth.json").get("canonical", {})
    for token, reason in invariants.legacy_token_map(canonical).items():
        if re.search(rf"(?<![\w-]){re.escape(token)}(?![\w-])", summary):
            findings.append(f"legacy_token_in_summary:{token}")
    if report.get("status") != "PRODUCTION_PIPELINE_OK":
        findings.append(f"pipeline_status:{report.get('status')}")
    return {
        "status": "OUTPUT_VALID" if not findings else "OUTPUT_INVALID",
        "findings": findings,
    }


def run_self_test() -> Dict[str, Any]:
    checks: Dict[str, Any] = {}
    checks["discover_inputs"] = discover_inputs()["status"] in {
        "INPUT_DISCOVERY_OK", "INPUT_DISCOVERY_PARTIAL"
    }
    checks["fixed_order"] = list(PIPELINE_STEPS).index("build_canonical_truth") < list(
        PIPELINE_STEPS
    ).index("build_daily_summary")
    checks["invariants_before_owner_priority"] = list(PIPELINE_STEPS).index(
        "validate_canonical_invariants"
    ) < list(PIPELINE_STEPS).index("determine_owner_priority")

    # A canonical snapshot with a LEVEL_2 runtime must never render LEVEL_1 text.
    fixture_canonical = invariants._canonical_fixture()
    fixture_report = {
        "status": "CANONICAL_TRUTH_OK",
        "missing_fields": [],
        "canonical": fixture_canonical["canonical"],
        "legacy_supersession": {"legacy_modules": [], "counts": {}, "superseded_field_claims": []},
    }
    fixture_report["daily_summary_blocks"] = canonical_truth.build_daily_summary_blocks(fixture_report)
    summary = build_daily_summary(fixture_report, {"status": "FRESHNESS_EVALUATION_OK", "reports": []})
    checks["summary_uses_canonical_runtime"] = "LEVEL_2_MONITORING_ACTIVE" in summary
    checks["summary_has_no_legacy_runtime"] = "LEVEL_1_DRAFT_ONLY" not in summary
    checks["summary_has_no_not_installed"] = "not_installed" not in summary
    checks["summary_owner_priority"] = "WEBSITE_ORIGIN_STABILITY" in summary

    # Fail-closed: without canonical blocks the summary must say so, not guess.
    empty_summary = build_daily_summary({"status": "CANONICAL_TRUTH_INCOMPLETE"}, {})
    checks["summary_fail_closed"] = "CANONICAL_TRUTH_INCOMPLETE" in empty_summary and (
        "LEVEL_1_DRAFT_ONLY" not in empty_summary
    )

    # Runtime summary carries no hardcoded value.
    runtime = build_runtime_summary(fixture_canonical["canonical"])
    checks["runtime_summary_canonical"] = (
        runtime["autonomy_level"] == "LEVEL_2_MONITORING_ACTIVE"
        and runtime["emergency_stop"] is False
        and runtime["systemd_timer_active"] is True
    )
    empty_runtime = build_runtime_summary({})
    checks["runtime_summary_fail_closed"] = (
        empty_runtime["autonomy_level"] == UNKNOWN
        and empty_runtime["emergency_stop"] is None
        and empty_runtime["systemd_timer_active"] is None
    )
    priority = determine_owner_priority(fixture_canonical["canonical"])
    checks["owner_priority_from_canonical"] = priority["selected_priority"] == "WEBSITE_ORIGIN_STABILITY"
    checks["owner_priority_fail_closed"] = determine_owner_priority({})["selected_priority"] == (
        "OWNER_PRIORITY_UNRESOLVED"
    )
    website = collect_website_snapshot(fixture_canonical["canonical"])
    checks["website_snapshot_canonical"] = (
        website["nowplaying_504"] == 133 and website["source_map_status"] == "OK"
    )

    source_text = Path(__file__).read_text(encoding="utf-8")
    checks["no_shell_true"] = (
        "subprocess.run(" in source_text
        and "shell=False" in source_text
        and not re.search(r"shell\s*=\s*True", source_text)
    )
    checks["fixed_commands_only"] = all(
        isinstance(value, tuple) for value in FIXED_SUBPROCESS_COMMANDS.values()
    )
    # The pipeline must not own runtime vocabulary: every runtime status string it
    # emits has to come from canonical truth, so no such constant may be defined here.
    checks["no_runtime_status_constants"] = not re.search(
        r"^\s*[A-Z_]+\s*=\s*[\"']LEVEL_\d", source_text, re.MULTILINE
    )

    findings = [name for name, value in checks.items() if not value]
    return {
        "status": "PRODUCTION_PIPELINE_SELF_TEST_OK" if not findings else "PRODUCTION_PIPELINE_SELF_TEST_FAILED",
        "checks": checks,
        "findings": findings,
        "breach": False,
    }


def print_status(report: Dict[str, Any]) -> None:
    if not report:
        print("NOT_RUN")
        return
    print(report.get("status", "NOT_RUN"))
    runtime = report.get("runtime", {})
    website = report.get("website", {})
    checks = report.get("canonical_invariants", {})
    print(f"canonical_truth={report.get('canonical_truth_status')}")
    print(f"canonical_invariants={checks.get('status')}")
    print(f"daily_summary_consistency={checks.get('daily_summary_consistency')}")
    print(f"website_status={website.get('overall_status')}")
    print(f"runtime_level={runtime.get('autonomy_level')}")
    print(f"timer_active={runtime.get('systemd_timer_active')}")
    print(f"low_live_enabled={runtime.get('low_live_apply_enabled')}")
    print(f"emergency_stop={runtime.get('emergency_stop')}")
    print(f"breach={runtime.get('breach')}")
    print(f"owner_priority={report.get('owner_priority', {}).get('selected_priority')}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Sentinel production pipeline")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--discover", action="store_true")
    group.add_argument("--validate-inputs", action="store_true")
    group.add_argument("--run-components", action="store_true")
    group.add_argument("--build-canonical-truth", action="store_true")
    group.add_argument("--build-master", action="store_true")
    group.add_argument("--build-daily-summary", action="store_true")
    group.add_argument("--validate-output", action="store_true")
    group.add_argument("--run", action="store_true")
    group.add_argument("--status", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        result = run_self_test()
        print(result["status"])
        for name in result["findings"]:
            print(f"finding={name}")
        return 0 if not result["findings"] else 1

    if args.discover:
        print(discover_inputs()["status"])
        return 0

    if args.validate_inputs:
        result = discover_inputs()
        print(result["status"])
        return 0 if result["status"] == "INPUT_DISCOVERY_OK" else 2

    if args.build_canonical_truth:
        report = build_canonical_truth()
        print(report["status"])
        return 0 if report["status"] == "CANONICAL_TRUTH_OK" else 2

    if args.run_components:
        report = run_pipeline(build_master=False)
        print(report["status"])
        return 0

    if args.build_master or args.build_daily_summary or args.run:
        report = run_pipeline(build_master=True)
        print(report["status"])
        if args.run:
            print_status(report)
        return 0 if report["status"] == "PRODUCTION_PIPELINE_OK" else 2

    if args.validate_output:
        result = validate_output()
        print(result["status"])
        for item in result["findings"]:
            print(f"finding={item}")
        return 0 if result["status"] == "OUTPUT_VALID" else 2

    print_status(load_dict(REPORT_JSON))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
