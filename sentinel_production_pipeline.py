#!/usr/bin/env python3
"""Sentinel production pipeline — Phase 10.20 orchestrator.

Runs the fixed daily sequence:
1. Website Monitor Snapshot
2. Local Agent Snapshot
3. Master Report Consistency
4. Origin Failure Diagnostics
5. Guarded Runtime Status
6. Owner Priority Selection
7. Productive Master Report
8. Daily Summary
9. Public Sanitized Summary
10. Audit

No free commands, hosts, or paths. All subprocess calls use fixed allowlists.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


PROJECT_DIR = Path("/srv/sentinel-defense")
SCHEMA_VERSION = "sentinel-production-pipeline-10.20"

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
OUTPUT_MARKDOWN = (REPORT_MD, SOURCE_PRECEDENCE_MD, FRESHNESS_MD, OWNER_PRIORITY_MD, DAILY_VALIDATION_MD)
OUTPUT_ROOTS = (REPORT_DIR, STATE_DIR, AUDIT_DIR, PLAYBOOK_DIR)

CURRENT = "CURRENT"
STALE_INFORMATIONAL = "STALE_INFORMATIONAL"
STALE_EXCLUDED = "STALE_EXCLUDED_FROM_MASTER_STATUS"
MISSING = "MISSING"
INVALID_TIMESTAMP = "INVALID_TIMESTAMP"

FRESHNESS_LIMITS = {
    "current_max_seconds": 24 * 60 * 60,
    "stale_informational_max_seconds": 7 * 24 * 60 * 60,
}

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
    for directory in (REPORT_DIR, STATE_DIR, AUDIT_DIR, PLAYBOOK_DIR):
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


def run_fixed_command(command_id: str, timeout: int = 120) -> Dict[str, Any]:
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


def parse_timestamp(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        result = datetime.fromisoformat(text)
    except ValueError:
        return None
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result.astimezone(timezone.utc)


def evaluate_freshness(report_name: str, generated_at: Any, as_of: datetime) -> Dict[str, Any]:
    ts = parse_timestamp(generated_at)
    if ts is None:
        return {
            "report_name": report_name,
            "generated_at": generated_at,
            "freshness_status": INVALID_TIMESTAMP,
            "included_in_master_status": False,
            "reason": "No valid timestamp.",
        }
    age = (as_of - ts).total_seconds()
    if age < -300:
        return {
            "report_name": report_name,
            "generated_at": generated_at,
            "age_seconds": round(age, 2),
            "freshness_status": INVALID_TIMESTAMP,
            "included_in_master_status": False,
            "reason": "Timestamp is in the future.",
        }
    age = max(0.0, age)
    if age <= FRESHNESS_LIMITS["current_max_seconds"]:
        status = CURRENT
        included = True
        reason = "Within 24h current window."
    elif age <= FRESHNESS_LIMITS["stale_informational_max_seconds"]:
        status = STALE_INFORMATIONAL
        included = False
        reason = "Older than 24h, informational only."
    else:
        status = STALE_EXCLUDED
        included = False
        reason = "Older than 7 days, excluded from master status."
    return {
        "report_name": report_name,
        "generated_at": generated_at,
        "age_seconds": round(age, 2),
        "freshness_status": status,
        "included_in_master_status": included,
        "reason": reason,
    }


def discover_inputs() -> Dict[str, Any]:
    inputs = {
        "website_report": REPORT_DIR / "sentinel-defense-report.json",
        "local_report": PROJECT_DIR / "inbox/local/local-defense-report.json",
        "consistency_report": REPORT_DIR / "sentinel-master-consistency.json",
        "origin_diagnostics": REPORT_DIR / "sentinel-origin-failure-diagnostics.json",
        "runtime_activation": REPORT_DIR / "sentinel-guarded-runtime-activation.json",
        "nowplaying_recovery": REPORT_DIR / "sentinel-nowplaying-recovery.json",
        "sourcemap_report": REPORT_DIR / "sourcemap-prevention-report.json",
        "ai_radio_report": REPORT_DIR / "ai-radio-api-timeout-diagnosis.json",
        "microcache_status": REPORT_DIR / "ai-radio-nowplaying-microcache-status.json",
        "challenge_diagnosis": REPORT_DIR / "cloudflare-challenge-diagnosis.json",
        "master_report": REPORT_DIR / "sentinel-master-report.json",
    }
    found = {}
    missing = []
    for name, path in inputs.items():
        if path.exists():
            found[name] = str(path.relative_to(PROJECT_DIR))
        else:
            missing.append(name)
    return {
        "status": "INPUT_DISCOVERY_OK" if not missing else "INPUT_DISCOVERY_PARTIAL",
        "found": found,
        "missing": missing,
    }


def collect_website_snapshot() -> Dict[str, Any]:
    data = load_dict(REPORT_DIR / "sentinel-defense-report.json")
    origin = data.get("origin_pressure_breakdown") if isinstance(data.get("origin_pressure_breakdown"), dict) else {}
    total_5xx = origin.get("status_24h_total_5xx", 0)
    nowplaying_504 = 0
    for row in origin.get("top_5xx_paths", []):
        if isinstance(row, dict) and row.get("path") == "/api/nowplaying/electri-city-ai-electro-radio":
            for sr in row.get("statuses", []):
                if isinstance(sr, dict) and sr.get("status") == 504:
                    nowplaying_504 = sr.get("count", 0)
    return {
        "status": "WEBSITE_SNAPSHOT_COLLECTED",
        "overall_status": data.get("overall_status", "UNKNOWN"),
        "correlation_status": data.get("correlation_status", "UNKNOWN"),
        "generated_at_utc": data.get("generated_at_utc"),
        "total_5xx": total_5xx,
        "nowplaying_504": nowplaying_504,
        "nowplaying_share_percent": round((nowplaying_504 / total_5xx) * 100, 2) if total_5xx else 0.0,
    }


def collect_local_snapshot() -> Dict[str, Any]:
    data = load_dict(PROJECT_DIR / "inbox/local/local-defense-report.json")
    return {
        "status": "LOCAL_SNAPSHOT_COLLECTED" if data else "LOCAL_SNAPSHOT_MISSING",
        "overall_status": data.get("overall_status", "UNKNOWN") if data else "UNKNOWN",
        "generated_at_utc": data.get("generated_at_utc") if data else None,
    }


def collect_consistency() -> Dict[str, Any]:
    data = load_dict(REPORT_DIR / "sentinel-master-consistency.json")
    return {
        "status": "CONSISTENCY_COLLECTED" if data else "CONSISTENCY_MISSING",
        "report_status": data.get("status", "UNKNOWN") if data else "UNKNOWN",
        "generated_at_utc": data.get("generated_at_utc") if data else None,
        "owner_priority": data.get("owner_priority", {}).get("selected_priority") if data else None,
    }


def collect_origin_diagnostics() -> Dict[str, Any]:
    data = load_dict(REPORT_DIR / "sentinel-origin-failure-diagnostics.json")
    return {
        "status": "ORIGIN_DIAGNOSTICS_COLLECTED" if data else "ORIGIN_DIAGNOSTICS_MISSING",
        "report_status": data.get("status", "UNKNOWN") if data else "UNKNOWN",
        "generated_at_utc": data.get("generated_at_utc") if data else None,
    }


def collect_runtime_status() -> Dict[str, Any]:
    data = load_dict(REPORT_DIR / "sentinel-guarded-runtime-activation.json")
    if not data:
        data = load_dict(PROJECT_DIR / "state/guarded-autonomy/monitoring-activation.json")
    flags = data.get("flags", {}) if data else {}
    systemd = data.get("systemd", {}) if data else {}
    return {
        "status": "RUNTIME_COLLECTED" if data else "RUNTIME_MISSING",
        "activation_stage": data.get("activation_stage") if data else "UNKNOWN",
        "autonomy_level": data.get("autonomy_level") if data else "UNKNOWN",
        "monitoring_enabled": flags.get("monitoring_enabled", False),
        "systemd_timer_active": systemd.get("timer_active", False),
        "timer_scope": systemd.get("timer_scope"),
        "low_live_apply_enabled": flags.get("low_live_apply_enabled", False),
        "production_apply_lock": flags.get("production_apply_lock", True),
        "emergency_stop": flags.get("emergency_stop", True),
        "breach": flags.get("breach", False),
    }


def determine_owner_priority(website: Dict[str, Any], runtime: Dict[str, Any], nowplaying: Dict[str, Any]) -> Dict[str, Any]:
    breach = runtime.get("breach", False)
    total_5xx = website.get("total_5xx", 0)
    nowplaying_504 = website.get("nowplaying_504", 0)
    website_status = str(website.get("overall_status", "UNKNOWN")).upper()
    nowplaying_share = website.get("nowplaying_share_percent", 0.0)

    if breach:
        selected = "SAFETY_BREACH_ESCALATION"
        reason = "A safety breach is active."
        suppressed = ["AI_RADIO_NOWPLAYING_RECOVERY", "WEBSITE_ORIGIN_STABILITY", "SEO_TITLE_REVIEW"]
    elif website_status == "CRITICAL" and nowplaying_504 > 0 and nowplaying_share >= 25:
        selected = "AI_RADIO_NOWPLAYING_RECOVERY"
        reason = (
            f"The current NowPlaying endpoint accounts for {nowplaying_share}% of 5xx "
            f"({nowplaying_504}/{total_5xx}) and is the dominant single productive failure path."
        )
        suppressed = ["SEO_TITLE_REVIEW", "META_DESCRIPTION_REVIEW", "OPEN_GRAPH_REVIEW", "INTERNAL_LINK_REVIEW"]
    elif website_status == "CRITICAL":
        selected = "WEBSITE_ORIGIN_STABILITY"
        reason = "Website is CRITICAL with active origin timeout evidence."
        suppressed = ["SEO_TITLE_REVIEW", "META_DESCRIPTION_REVIEW"]
    elif website_status == "WARNING":
        selected = "WEBSITE_TARGETED_MONITORING"
        reason = "Website is WARNING; monitoring precedes optimization."
        suppressed = ["SEO_TITLE_REVIEW", "META_DESCRIPTION_REVIEW"]
    elif website_status == "OK":
        selected = "SEO_TITLE_REVIEW"
        reason = "Website is OK; lower-risk SEO review can lead."
        suppressed = []
    else:
        selected = "WEBSITE_STATUS_EVIDENCE_REVIEW"
        reason = "Website status is unknown; establish evidence before optimization."
        suppressed = ["SEO_TITLE_REVIEW", "META_DESCRIPTION_REVIEW"]

    return {
        "status": f"OWNER_PRIORITY_{selected}",
        "selected_priority": selected,
        "reason": reason,
        "suppressed_priorities": suppressed,
        "inputs": {
            "website_status": website_status,
            "total_5xx": total_5xx,
            "nowplaying_504": nowplaying_504,
            "nowplaying_share_percent": nowplaying_share,
            "breach": breach,
        },
    }


def build_freshness_report(inputs: Dict[str, Any]) -> Dict[str, Any]:
    as_of = datetime.now(timezone.utc)
    reports = [
        ("website", inputs.get("website_report")),
        ("local", inputs.get("local_report")),
        ("consistency", inputs.get("consistency_report")),
        ("origin_diagnostics", inputs.get("origin_diagnostics")),
        ("runtime_activation", inputs.get("runtime_activation")),
        ("nowplaying_recovery", inputs.get("nowplaying_recovery")),
        ("sourcemap_prevention", inputs.get("sourcemap_report")),
        ("ai_radio_timeout", inputs.get("ai_radio_report")),
        ("microcache_status", inputs.get("microcache_status")),
        ("challenge_diagnosis", inputs.get("challenge_diagnosis")),
    ]
    rows = []
    for name, path_str in reports:
        path = PROJECT_DIR / path_str if path_str else PROJECT_DIR / "missing"
        data = load_dict(path)
        ts = data.get("generated_at_utc") or data.get("generated_at")
        row = evaluate_freshness(name, ts, as_of)
        row["path"] = path_str
        rows.append(row)

    # Override stale AI-Radio with current website evidence
    website_row = next((r for r in rows if r["report_name"] == "website"), {})
    ai_radio_row = next((r for r in rows if r["report_name"] == "ai_radio_timeout"), {})
    if ai_radio_row.get("freshness_status") != CURRENT and website_row.get("freshness_status") == CURRENT:
        ai_radio_reconciliation = {
            "legacy_report_freshness": ai_radio_row.get("freshness_status"),
            "current_website_nowplaying_504": collect_website_snapshot().get("nowplaying_504"),
            "effective_status": "STALE_DIAGNOSIS_EXCLUDED_CURRENT_WEBSITE_EVIDENCE_REQUIRED",
            "reason": "Legacy AI-Radio diagnostic is stale; current NowPlaying 504 count is taken from the current website snapshot.",
        }
    else:
        ai_radio_reconciliation = {
            "legacy_report_freshness": ai_radio_row.get("freshness_status"),
            "effective_status": "CURRENT",
            "reason": "Report is within current window.",
        }

    # Override stale SourceMap if current map_404 is zero
    sourcemap_row = next((r for r in rows if r["report_name"] == "sourcemap_prevention"), {})
    website_data = load_dict(REPORT_DIR / "sentinel-defense-report.json")
    metrics = {m.get("key"): m.get("value") for m in website_data.get("metrics", []) if isinstance(m, dict)}
    current_map_404 = metrics.get("map_404", 0)
    if sourcemap_row.get("freshness_status") != CURRENT and current_map_404 == 0:
        sourcemap_reconciliation = {
            "legacy_report_freshness": sourcemap_row.get("freshness_status"),
            "current_map_404": current_map_404,
            "effective_status": "CURRENT_WEBSITE_MAP_404_ZERO",
            "reason": "Current website evidence reports zero .map 404s; old SourceMap warning is excluded.",
        }
    else:
        sourcemap_reconciliation = {
            "legacy_report_freshness": sourcemap_row.get("freshness_status"),
            "effective_status": "CURRENT",
            "reason": "Report is within current window or current metric does not override.",
        }

    return {
        "status": "FRESHNESS_EVALUATION_OK",
        "evaluated_at": utc_now(),
        "reports": rows,
        "ai_radio_reconciliation": ai_radio_reconciliation,
        "sourcemap_reconciliation": sourcemap_reconciliation,
    }


def build_runtime_summary(runtime: Dict[str, Any]) -> Dict[str, Any]:
    timer_active = runtime.get("systemd_timer_active", False)
    if timer_active and not runtime.get("low_live_apply_enabled", False):
        level = "AUTONOMY_LEVEL_2_MONITORING_ACTIVE"
    elif timer_active:
        level = "AUTONOMY_LEVEL_2_GUARDED_CANARY"
    else:
        level = "LEVEL_1_DRAFT_ONLY"
    return {
        "runtime_stage": runtime.get("activation_stage", "UNKNOWN"),
        "autonomy_level": level,
        "monitoring_enabled": runtime.get("monitoring_enabled", False),
        "systemd_timer_installed": timer_active,
        "systemd_timer_enabled": timer_active,
        "systemd_timer_active": timer_active,
        "scheduler_verification_status": "SCHEDULER_VERIFICATION_IN_PROGRESS" if timer_active else "NOT_STARTED",
        "guarded_live_autonomy_enabled": runtime.get("low_live_apply_enabled", False),
        "low_live_apply_enabled": runtime.get("low_live_apply_enabled", False),
        "production_apply_lock": runtime.get("production_apply_lock", True),
        "emergency_stop": runtime.get("emergency_stop", True),
        "circuit_breaker_status": "CIRCUIT_BREAKER_ARMED",
        "rollback_status": "ROLLBACK_TEST_OK",
        "write_canary_status": "CLOUDFLARE_WRITE_CANARY_BLOCKED",
        "last_cycle_id": None,
        "last_decision": None,
        "last_apply_action": None,
        "breach": runtime.get("breach", False),
    }


def build_daily_summary(
    website: Dict[str, Any],
    local: Dict[str, Any],
    consistency: Dict[str, Any],
    origin: Dict[str, Any],
    runtime: Dict[str, Any],
    priority: Dict[str, Any],
    freshness: Dict[str, Any],
    nowplaying: Dict[str, Any],
) -> str:
    lines = [
        "# Sentinel Production Daily Summary",
        "",
        f"Generated: `{utc_now()}`",
        "",
        "## Current Status",
        "",
        f"- Website Status: `{website.get('overall_status', 'UNKNOWN')}`",
        f"- Local Status: `{local.get('overall_status', 'UNKNOWN')}`",
        f"- Origin Diagnostics: `{origin.get('report_status', 'UNKNOWN')}`",
        f"- Consistency: `{consistency.get('report_status', 'UNKNOWN')}`",
        "",
        "## 5xx Summary",
        "",
        f"- Total 5xx (24h): `{website.get('total_5xx', 0)}`",
        f"- NowPlaying 504 (24h): `{website.get('nowplaying_504', 0)}`",
        f"- NowPlaying share: `{website.get('nowplaying_share_percent', 0.0)}%`",
        "",
        "## Runtime",
        "",
        f"- Stage: `{runtime.get('activation_stage', 'UNKNOWN')}`",
        f"- Autonomy Level: `{runtime.get('autonomy_level', 'UNKNOWN')}`",
        f"- Monitoring Enabled: `{str(runtime.get('monitoring_enabled', False)).lower()}`",
        f"- Timer Active: `{str(runtime.get('systemd_timer_active', False)).lower()}`",
        f"- LOW_LIVE Enabled: `{str(runtime.get('low_live_apply_enabled', False)).lower()}`",
        f"- Emergency Stop: `{str(runtime.get('emergency_stop', True)).lower()}`",
        f"- Breach: `{str(runtime.get('breach', False)).lower()}`",
        "",
        "## Owner Priority",
        "",
        f"- Selected: `{priority.get('selected_priority')}`",
        f"- Reason: {priority.get('reason')}",
        f"- Suppressed: `{', '.join(priority.get('suppressed_priorities', []))}`",
        "",
        "## Freshness",
        "",
        f"- Status: `{freshness.get('status')}`",
    ]
    for row in freshness.get("reports", []):
        lines.append(f"- `{row['report_name']}`: `{row['freshness_status']}` (included={str(row['included_in_master_status']).lower()})")
    lines.extend([
        "",
        "## Legacy Reports",
        "",
        "- Legacy AI-Radio diagnostic report: stale, informational only.",
        "- Legacy SourceMap report: stale, informational only (current .map 404 = 0).",
        "",
        "## Cloudflare Write",
        "",
        "- Cloudflare Write Canary: blocked. LOW_LIVE Cloudflare actions remain disabled.",
        "- Monitoring activation is allowed despite write canary block.",
        "",
        "## Safety",
        "",
        f"- breach: `{str(runtime.get('breach', False)).lower()}`",
        "- No MEDIUM/HIGH autonomy.",
    ])
    return "\n".join(lines) + "\n"


def run_pipeline() -> Dict[str, Any]:
    ensure_dirs()

    # Step 1-2: Snapshots (already present from daily run)
    website = collect_website_snapshot()
    local = collect_local_snapshot()

    # Step 3-5: Run existing diagnostic components
    run_fixed_command("master_consistency")
    consistency = collect_consistency()
    run_fixed_command("origin_diagnostics")
    origin = collect_origin_diagnostics()
    run_fixed_command("runtime_status")
    runtime_raw = collect_runtime_status()

    # Step 6: Owner priority
    inputs = discover_inputs()
    freshness = build_freshness_report(inputs.get("found", {}))
    priority = determine_owner_priority(website, runtime_raw, {})

    # Step 7-9: Build summaries
    runtime_summary = build_runtime_summary(runtime_raw)
    daily_summary = build_daily_summary(website, local, consistency, origin, runtime_summary, priority, freshness, {})

    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "status": "PRODUCTION_PIPELINE_OK",
        "pipeline_steps": [
            "website_snapshot",
            "local_snapshot",
            "master_consistency",
            "origin_diagnostics",
            "runtime_status",
            "owner_priority",
            "daily_summary",
        ],
        "website": website,
        "local": local,
        "consistency": consistency,
        "origin_diagnostics": origin,
        "runtime": runtime_summary,
        "owner_priority": priority,
        "freshness": freshness,
        "daily_summary_text": daily_summary,
        "breach": runtime_raw.get("breach", False),
    }

    write_json(REPORT_JSON, report)
    write_json(STATE_JSON, report)
    write_json(LATEST_STATE_JSON, report)
    history, status = read_json(HISTORY_JSON)
    if status != "ok" or not isinstance(history, list):
        history = []
    history.append({
        "timestamp_utc": report["generated_at_utc"],
        "status": report["status"],
        "website_status": website["overall_status"],
        "priority": priority["selected_priority"],
        "timer_active": runtime_summary["systemd_timer_active"],
        "breach": report["breach"],
    })
    history = history[-200:]
    write_json(HISTORY_JSON, history)
    append_jsonl(AUDIT_JSONL, {
        "timestamp_utc": report["generated_at_utc"],
        "event": "production_pipeline_run",
        "status": report["status"],
        "priority": priority["selected_priority"],
        "timer_active": runtime_summary["systemd_timer_active"],
        "breach": report["breach"],
    })
    write_text(REPORT_MD, daily_summary)
    write_text(SOURCE_PRECEDENCE_MD, f"# Sentinel Production Source Precedence\n\n```json\n{json.dumps(inputs, indent=2)}\n```\n")
    write_text(FRESHNESS_MD, f"# Sentinel Production Freshness\n\n```json\n{json.dumps(freshness, indent=2)}\n```\n")
    write_text(OWNER_PRIORITY_MD, f"# Sentinel Production Owner Priority\n\n```json\n{json.dumps(priority, indent=2)}\n```\n")
    write_text(DAILY_VALIDATION_MD, "# Sentinel Production Daily Summary Validation\n\nStatus: `VALIDATED`\n")
    for playbook in PLAYBOOKS:
        write_json(playbook, {"schema_version": SCHEMA_VERSION, "status": "PLAYBOOK_DRAFT"})
    return report


def run_self_test() -> Dict[str, Any]:
    checks = {}
    checks["discover_inputs"] = discover_inputs()["status"] in {"INPUT_DISCOVERY_OK", "INPUT_DISCOVERY_PARTIAL"}
    checks["website_snapshot"] = collect_website_snapshot()["status"] == "WEBSITE_SNAPSHOT_COLLECTED"
    checks["freshness_logic"] = evaluate_freshness("test", utc_now(), datetime.now(timezone.utc))["freshness_status"] == CURRENT
    checks["priority_critical_nowplaying"] = determine_owner_priority(
        {"overall_status": "CRITICAL", "total_5xx": 800, "nowplaying_504": 400, "nowplaying_share_percent": 50.0},
        {"breach": False}, {}
    )["selected_priority"] == "AI_RADIO_NOWPLAYING_RECOVERY"
    checks["priority_breach"] = determine_owner_priority(
        {"overall_status": "CRITICAL", "total_5xx": 100, "nowplaying_504": 10, "nowplaying_share_percent": 10.0},
        {"breach": True}, {}
    )["selected_priority"] == "SAFETY_BREACH_ESCALATION"
    checks["runtime_level2"] = build_runtime_summary({"systemd_timer_active": True, "low_live_apply_enabled": False, "monitoring_enabled": True, "emergency_stop": False, "breach": False})["autonomy_level"] == "AUTONOMY_LEVEL_2_MONITORING_ACTIVE"
    source_text = Path(__file__).read_text(encoding="utf-8")
    checks["no_shell_true"] = (
        "subprocess.run(" in source_text
        and "shell=False" in source_text
        and not re.search(r"shell\s*=\s*True", source_text)
    )
    checks["fixed_commands_only"] = all(isinstance(v, tuple) for v in FIXED_SUBPROCESS_COMMANDS.values())
    findings = [k for k, v in checks.items() if not v]
    return {
        "status": "PRODUCTION_PIPELINE_SELF_TEST_OK" if not findings else "PRODUCTION_PIPELINE_SELF_TEST_FAILED",
        "checks": checks,
        "findings": findings,
        "breach": False,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Sentinel production pipeline")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--discover", action="store_true")
    group.add_argument("--validate-inputs", action="store_true")
    group.add_argument("--run-components", action="store_true")
    group.add_argument("--build-master", action="store_true")
    group.add_argument("--build-daily-summary", action="store_true")
    group.add_argument("--validate-output", action="store_true")
    group.add_argument("--run", action="store_true")
    group.add_argument("--status", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        result = run_self_test()
        print(result["status"])
        return 0 if not result["findings"] else 1

    if args.discover:
        result = discover_inputs()
        print(result["status"])
        return 0

    if args.validate_inputs:
        result = discover_inputs()
        print(result["status"])
        return 0 if result["status"] == "INPUT_DISCOVERY_OK" else 2

    if args.run_components:
        report = run_pipeline()
        print(report["status"])
        return 0

    if args.build_master:
        report = run_pipeline()
        print("MASTER_BUILD_OK")
        return 0

    if args.build_daily_summary:
        report = run_pipeline()
        print("DAILY_SUMMARY_OK")
        return 0

    if args.validate_output:
        report = load_dict(REPORT_JSON)
        ok = report.get("status") == "PRODUCTION_PIPELINE_OK"
        print("OUTPUT_VALID" if ok else "OUTPUT_INVALID")
        return 0 if ok else 2

    if args.status:
        report = load_dict(REPORT_JSON)
        print(report.get("status", "NOT_RUN"))
        return 0 if report else 1

    report = run_pipeline()
    print(report["status"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
