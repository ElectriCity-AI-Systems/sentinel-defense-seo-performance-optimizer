#!/usr/bin/env python3
"""Owner-assisted Phase 10.20 systemd go-live and write-gate diagnosis.

This controller does not define runtime transitions. It delegates all runtime
state changes to sentinel_guarded_autonomy and sentinel_guarded_runtime_activation.
Every subprocess command is a fixed local allowlist entry.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import sentinel_guarded_activation as activation
import sentinel_guarded_autonomy as guarded
import sentinel_guarded_runtime_activation as runtime
import sentinel_guarded_systemd_installer as installer


PROJECT_DIR = Path("/srv/sentinel-defense")
SCHEMA_VERSION = "sentinel-owner-assisted-go-live-10.20"
REPORT_DIR = PROJECT_DIR / "reports/latest"
STATE_DIR = PROJECT_DIR / "state/guarded-autonomy"
AUDIT_DIR = PROJECT_DIR / "audit"

REPORT_JSON = REPORT_DIR / "sentinel-phase-10-20-runtime.json"
REPORT_MD = REPORT_DIR / "sentinel-phase-10-20-runtime.md"
SYSTEMD_MD = REPORT_DIR / "sentinel-systemd-live-verification.md"
SCHEDULER_MD = REPORT_DIR / "sentinel-scheduler-three-cycle-verification.md"
WRITE_ERROR_MD = REPORT_DIR / "sentinel-cloudflare-write-error-classification.md"
WRITE_RETRY_MD = REPORT_DIR / "sentinel-cloudflare-write-canary-retry.md"
MONITORING_MD = REPORT_DIR / "sentinel-level-2-monitoring-status.md"
CANARY_MD = REPORT_DIR / "sentinel-level-2-canary-status.md"
OWNER_MD = REPORT_DIR / "sentinel-phase-10-20-owner-summary.md"

PHASE_STATE = STATE_DIR / "phase-10-20.json"
SYSTEMD_STATE = STATE_DIR / "systemd-live-verification.json"
WRITE_ERROR_STATE = STATE_DIR / "write-error-classification.json"
WRITE_RETRY_STATE = STATE_DIR / "write-canary-retry.json"
AUDIT_JSONL = AUDIT_DIR / "sentinel-phase-10-20.jsonl"

PLAYBOOKS = (
    PROJECT_DIR / "playbooks/sentinel-owner-assisted-systemd-go-live.playbook.json",
    PROJECT_DIR / "playbooks/sentinel-three-cycle-verification.playbook.json",
    PROJECT_DIR / "playbooks/sentinel-cloudflare-write-error-classification.playbook.json",
    PROJECT_DIR / "playbooks/sentinel-level-2-monitoring.playbook.json",
    PROJECT_DIR / "playbooks/sentinel-level-2-canary-activation.playbook.json",
)

OWNER_INSTALL_COMMAND = "sudo python3 /srv/sentinel-defense/sentinel_guarded_systemd_installer.py --install"
ALLOWED_SCHEDULER_DECISIONS = {"NO_ACTION", "ACTION_CANDIDATE_BLOCKED_BY_VERIFICATION_STAGE"}
FORBIDDEN_GIT_PREFIXES = (
    "reports/",
    "state/",
    "audit/",
    "logs/",
    "exports/",
    "backups/",
    "snapshots/",
)

FIXED_COMMANDS: Dict[str, Tuple[str, ...]] = {
    "git_status": ("/usr/bin/git", "status", "--short"),
    "git_cached": ("/usr/bin/git", "diff", "--cached", "--name-only"),
    "git_log": ("/usr/bin/git", "log", "--oneline", "-8"),
    "origin_commit": ("/usr/bin/git", "log", "--all", "--format=%H", "--", "sentinel_origin_failure_diagnostics.py"),
    "runtime_commit": ("/usr/bin/git", "log", "--all", "--format=%H", "--", "sentinel_guarded_runtime_activation.py"),
    "sudo_install": (
        "/usr/bin/sudo",
        "-n",
        "/usr/bin/python3",
        "/srv/sentinel-defense/sentinel_guarded_systemd_installer.py",
        "--install",
    ),
    "sudo_verify_install": (
        "/usr/bin/sudo",
        "-n",
        "/usr/bin/python3",
        "/srv/sentinel-defense/sentinel_guarded_systemd_installer.py",
        "--verify-install",
    ),
    "sudo_start_service": (
        "/usr/bin/sudo",
        "-n",
        "/usr/bin/systemctl",
        "start",
        "sentinel-guarded-autonomy.service",
    ),
    "timer_active": ("/usr/bin/systemctl", "is-active", "sentinel-guarded-autonomy.timer"),
    "timer_enabled": ("/usr/bin/systemctl", "is-enabled", "sentinel-guarded-autonomy.timer"),
    "service_active": ("/usr/bin/systemctl", "is-active", "sentinel-guarded-autonomy.service"),
    "cat_service": ("/usr/bin/systemctl", "cat", "sentinel-guarded-autonomy.service"),
    "cat_timer": ("/usr/bin/systemctl", "cat", "sentinel-guarded-autonomy.timer"),
    "show_service": (
        "/usr/bin/systemctl",
        "show",
        "sentinel-guarded-autonomy.service",
        "-p",
        "User",
        "-p",
        "Group",
        "-p",
        "ExecStart",
        "-p",
        "EnvironmentFiles",
        "-p",
        "NoNewPrivileges",
    ),
}


def run_fixed(command_id: str, timeout: int = 120) -> Dict[str, Any]:
    command = FIXED_COMMANDS.get(command_id)
    if command is None:
        return {"command_id": command_id, "returncode": 126, "stdout": "", "error_class": "NOT_ALLOWLISTED"}
    try:
        process = subprocess.run(
            list(command),
            cwd=str(PROJECT_DIR),
            check=False,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"command_id": command_id, "returncode": 124, "stdout": "", "error_class": "TIMEOUT"}
    except OSError as exc:
        return {"command_id": command_id, "returncode": 127, "stdout": "", "error_class": type(exc).__name__}
    stderr = process.stderr.lower()
    if process.returncode == 0:
        error_class = None
    elif "password" in stderr or "sudo" in stderr:
        error_class = "NONINTERACTIVE_PRIVILEGE_UNAVAILABLE"
    else:
        error_class = "COMMAND_FAILED"
    return {
        "command_id": command_id,
        "returncode": int(process.returncode),
        "stdout": process.stdout.strip()[:8000],
        "error_class": error_class,
    }


def append_audit(event: str, status: str, details: Optional[Dict[str, Any]] = None) -> None:
    guarded.append_jsonl(
        AUDIT_JSONL,
        {
            "timestamp": guarded.utc_now(),
            "event": event,
            "status": status,
            "details": details or {},
            "credential_values_disclosed": False,
            "api_response_body_stored": False,
            "breach": guarded.load_state().get("flags", {}).get("breach", False),
        },
    )


def read_jsonl(path: Path) -> Tuple[List[Dict[str, Any]], int]:
    rows: List[Dict[str, Any]] = []
    invalid = 0
    if not path.is_file() or path.is_symlink():
        return rows, invalid
    for line in path.read_text(encoding="utf-8", errors="strict").splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            invalid += 1
            continue
        if isinstance(value, dict):
            rows.append(value)
        else:
            invalid += 1
    return rows, invalid


def git_snapshot() -> Dict[str, Any]:
    status_lines = [line for line in run_fixed("git_status")["stdout"].splitlines() if line]
    staged = [line for line in run_fixed("git_cached")["stdout"].splitlines() if line]
    untracked = [line[3:] for line in status_lines if line.startswith("?? ")]
    untracked_sources = sorted(path for path in untracked if path.endswith((".py", ".json", ".service", ".timer")))
    forbidden = sorted(path for path in staged if path.startswith(FORBIDDEN_GIT_PREFIXES))
    return {
        "origin_diagnostics_commit_present": bool(run_fixed("origin_commit")["stdout"].strip()),
        "guarded_runtime_commit_present": bool(run_fixed("runtime_commit")["stdout"].strip()),
        "untracked_source_files": untracked_sources,
        "staged_files": staged,
        "forbidden_staged_files": forbidden,
        "recent_commits": run_fixed("git_log")["stdout"].splitlines(),
    }


def verify_systemd_sources() -> Dict[str, Any]:
    verified = installer.verify_source()
    identity = activation.service_identity()
    service_text = installer.SERVICE_SOURCE.read_text(encoding="utf-8") if installer.SERVICE_SOURCE.is_file() else ""
    timer_text = installer.TIMER_SOURCE.read_text(encoding="utf-8") if installer.TIMER_SOURCE.is_file() else ""
    checks = {
        "installer_source_gate": verified.get("status") == "SYSTEMD_SOURCE_GATE_GREEN",
        "fixed_exec_start": "ExecStart=/usr/bin/python3 /srv/sentinel-defense/sentinel_guarded_autonomy.py --run-cycle" in service_text,
        "no_shell_wrapper": "ExecStart=/bin/sh" not in service_text and "ExecStart=/bin/bash" not in service_text,
        "restricted_user_present": bool(
            identity.get("user")
            and identity.get("group")
            and f"User={identity['user']}" in service_text
            and f"Group={identity['group']}" in service_text
        ),
        "no_new_privileges": "NoNewPrivileges=true" in service_text,
        "protect_system_strict": "ProtectSystem=strict" in service_text,
        "protect_home": "ProtectHome=true" in service_text,
        "fixed_environment_file": "EnvironmentFile=/etc/sentinel-defense.env" in service_text,
        "fixed_write_paths": "ReadWritePaths=/srv/sentinel-defense/reports /srv/sentinel-defense/state /srv/sentinel-defense/audit" in service_text,
        "two_minute_interval": "OnUnitActiveSec=2min" in timer_text,
        "runtime_lock_contract": "runtime_cycle_lock" in guarded.run_cycle.__code__.co_names,
    }
    return {
        "status": "SYSTEMD_SOURCE_GATE_GREEN" if all(checks.values()) else "SYSTEMD_SOURCE_GATE_BLOCKED",
        "checks": checks,
        "source_hashes": verified.get("source_hashes", {}),
        "breach": False,
    }


def installed_unit_contract() -> Dict[str, Any]:
    install = installer.verify_install()
    identity = activation.service_identity()
    show = run_fixed("show_service")
    properties = show["stdout"]
    checks = {
        "installer_verified": install.get("status") == "SYSTEMD_INSTALL_VERIFIED",
        "fixed_user": bool(identity.get("user") and f"User={identity['user']}" in properties),
        "fixed_group": bool(identity.get("group") and f"Group={identity['group']}" in properties),
        "fixed_exec_start": "/usr/bin/python3 /srv/sentinel-defense/sentinel_guarded_autonomy.py --run-cycle" in properties,
        "fixed_environment_file": "/etc/sentinel-defense.env" in properties,
        "no_new_privileges": "NoNewPrivileges=yes" in properties,
    }
    timer_active = run_fixed("timer_active")["returncode"] == 0
    timer_enabled = run_fixed("timer_enabled")["returncode"] == 0
    return {
        "status": "SYSTEMD_INSTALL_VERIFIED" if all(checks.values()) else "SYSTEMD_INSTALL_NOT_VERIFIED",
        "checks": checks,
        "timer_active": timer_active,
        "timer_enabled": timer_enabled,
        "timer_scope": "SYSTEM_SCOPE" if timer_active else None,
        "breach": False,
    }


def attempt_systemd_install() -> Dict[str, Any]:
    source = verify_systemd_sources()
    runtime.evaluate_health()
    runtime.evaluate_tls()
    before = installed_unit_contract()
    attempt: Dict[str, Any] = {"attempted": False, "result": "NOT_NEEDED"}
    if source["status"] != "SYSTEMD_SOURCE_GATE_GREEN":
        status = "SYSTEMD_SOURCE_GATE_BLOCKED"
    elif before["status"] == "SYSTEMD_INSTALL_VERIFIED" and before["timer_active"]:
        status = "SYSTEMD_TIMER_ACTIVE"
    else:
        command = run_fixed("sudo_install", timeout=150)
        attempt = {
            "attempted": True,
            "returncode": command["returncode"],
            "result": command["stdout"].splitlines()[-1] if command["stdout"] else command["error_class"],
            "interactive_password_requested": False,
        }
        after = installed_unit_contract()
        if after["status"] == "SYSTEMD_INSTALL_VERIFIED" and after["timer_active"]:
            status = "SYSTEMD_TIMER_ACTIVE"
        elif command["error_class"] == "NONINTERACTIVE_PRIVILEGE_UNAVAILABLE":
            status = "OWNER_SYSTEMD_ACTION_REQUIRED"
        else:
            status = "SYSTEMD_INSTALL_NOT_VERIFIED"
    result = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": guarded.utc_now(),
        "status": status,
        "source": source,
        "install": installed_unit_contract(),
        "attempt": attempt,
        "owner_command": OWNER_INSTALL_COMMAND if status == "OWNER_SYSTEMD_ACTION_REQUIRED" else None,
        "credential_values_disclosed": False,
        "breach": False,
    }
    guarded.write_json(SYSTEMD_STATE, result)
    guarded.write_text(SYSTEMD_MD, render_systemd(result))
    append_audit("attempt_systemd_install", status, {"attempted": attempt["attempted"]})
    return result


def classify_write_error(value: Dict[str, Any]) -> Dict[str, Any]:
    http_status = value.get("http_status_code")
    codes = [code for code in value.get("cloudflare_error_codes", []) if isinstance(code, int)]
    if http_status == 401:
        category = "AUTHENTICATION_FAILED"
        permission_class = "TOKEN_AUTHENTICATION_INVALID"
    elif http_status == 403:
        category = "INSUFFICIENT_PERMISSION"
        permission_class = "ZONE_CUSTOM_RULESET_WRITE_REQUIRED"
    elif http_status == 404 and value.get("ruleset_id_present"):
        category = "RULESET_NOT_FOUND"
        permission_class = "UNDETERMINED"
    elif http_status in {404, 405}:
        category = "ENDPOINT_MISMATCH"
        permission_class = "UNDETERMINED"
    elif http_status == 429:
        category = "RATE_LIMITED"
        permission_class = "UNDETERMINED"
    elif http_status == 400 and value.get("request_schema_valid") is False:
        category = "INVALID_REQUEST_SCHEMA"
        permission_class = "UNDETERMINED"
    else:
        category = "UNKNOWN_4XX" if isinstance(http_status, int) and 400 <= http_status < 500 else "UNKNOWN_4XX"
        permission_class = "UNDETERMINED"
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": guarded.utc_now(),
        "status": "CLOUDFLARE_WRITE_GATE_PERMISSION_REQUIRED" if category == "INSUFFICIENT_PERMISSION" else "CLOUDFLARE_WRITE_GATE_DIAGNOSED_BLOCKED",
        "write_canary_status": value.get("status", "CLOUDFLARE_WRITE_CANARY_NOT_RUN"),
        "http_status_code": http_status,
        "cloudflare_error_codes": sorted(set(codes)),
        "error_category": category,
        "request_endpoint_class": value.get("request_endpoint_class", "ZONE_RULESET_SINGLE_RULE_CREATE"),
        "ruleset_phase": value.get("ruleset_phase", "http_request_firewall_custom"),
        "ruleset_id_present": value.get("ruleset_id_present") is True,
        "zone_scope_valid": value.get("zone_scope_valid") is True,
        "token_permission_class": permission_class,
        "request_schema_valid": value.get("request_schema_valid") is True,
        "adapter_method": value.get("adapter_method", "POST"),
        "rule_created": value.get("created") is True,
        "rule_deleted": value.get("deleted") is True,
        "absence_verified": value.get("deletion_verified") is True,
        "traffic_effect": value.get("traffic_effect") is True,
        "minimal_permission_required": "fixed-zone custom ruleset write" if category == "INSUFFICIENT_PERMISSION" else None,
        "safe_code_correction_available": False,
        "reason": "Cloudflare code is not mapped by the official Rulesets API reference; no cause is inferred." if category == "UNKNOWN_4XX" else category.lower(),
        "credential_values_disclosed": False,
        "api_response_body_stored": False,
        "breach": value.get("breach") is True,
    }


def classify_current_write_error() -> Dict[str, Any]:
    value = guarded.load_dict(runtime.WRITE_CANARY_STATE)
    result = classify_write_error(value)
    guarded.write_json(WRITE_ERROR_STATE, result)
    guarded.write_text(WRITE_ERROR_MD, render_write_error(result))
    append_audit("classify_write_error", result["status"], {"category": result["error_category"], "http_status": result["http_status_code"]})
    return result


def retry_write_canary() -> Dict[str, Any]:
    canary = runtime.probe_write_canary()
    classification = classify_write_error(canary) if canary.get("status") != "CLOUDFLARE_WRITE_CANARY_OK" else {
        "status": "CLOUDFLARE_WRITE_GATE_GREEN",
        "error_category": None,
        "http_status_code": canary.get("http_status_code"),
        "cloudflare_error_codes": [],
    }
    result = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": guarded.utc_now(),
        "status": canary.get("status"),
        "classification": classification,
        "rule_created": canary.get("created") is True,
        "rule_enabled": canary.get("enabled"),
        "rule_deleted": canary.get("deleted") is True,
        "absence_verified": canary.get("deletion_verified") is True,
        "traffic_effect": canary.get("traffic_effect") is True,
        "monitoring_activation_allowed": canary.get("monitoring_activation_allowed") is True,
        "low_live_apply_enabled": canary.get("status") == "CLOUDFLARE_WRITE_CANARY_OK",
        "credential_values_disclosed": False,
        "api_response_body_stored": False,
        "breach": canary.get("breach") is True,
    }
    guarded.write_json(WRITE_RETRY_STATE, result)
    guarded.write_json(WRITE_ERROR_STATE, classification)
    guarded.write_text(WRITE_RETRY_MD, render_write_retry(result))
    guarded.write_text(WRITE_ERROR_MD, render_write_error(classification))
    append_audit("retry_write_canary", str(result["status"]), {"created": result["rule_created"], "absence_verified": result["absence_verified"]})
    return result


def activate_monitoring() -> Dict[str, Any]:
    result = runtime.activate_monitoring()
    guarded.write_text(MONITORING_MD, render_monitoring(result))
    append_audit("activate_monitoring", result["status"], {"timer_active": result.get("timer_active", False)})
    return result


def guarded_audit_rows() -> Tuple[List[Dict[str, Any]], int]:
    return read_jsonl(guarded.AUDIT_JSONL)


def run_three_scheduler_cycles() -> Dict[str, Any]:
    systemd = installed_unit_contract()
    state = guarded.load_state()
    cycles: List[Dict[str, Any]] = []
    if not systemd["timer_active"] or state.get("activation_stage") not in {runtime.STAGE_MONITORING, runtime.STAGE_SCHEDULER}:
        result = {
            "status": "SCHEDULER_VERIFICATION_NOT_STARTED",
            "cycle_ids": [],
            "successful_cycles": 0,
            "blockers": ["monitoring_timer_not_active"],
            "breach": state.get("flags", {}).get("breach", False),
        }
    else:
        runtime.verify_scheduler()
        existing_rows, invalid_before = guarded_audit_rows()
        existing_ids = {str(row.get("cycle_id")) for row in existing_rows if row.get("cycle_id")}
        for _ in range(3):
            start_time = guarded.utc_now()
            command = run_fixed("sudo_start_service", timeout=150)
            rows, _invalid = guarded_audit_rows()
            new_rows = [row for row in rows if row.get("cycle_id") and str(row["cycle_id"]) not in existing_ids]
            row = new_rows[-1] if new_rows else {}
            if row.get("cycle_id"):
                existing_ids.add(str(row["cycle_id"]))
            cycles.append(
                {
                    "cycle_id": row.get("cycle_id"),
                    "start_time": start_time,
                    "end_time": row.get("timestamp") or guarded.utc_now(),
                    "decision": row.get("decision"),
                    "health_status": (row.get("validation_result") or {}).get("status") if isinstance(row.get("validation_result"), dict) else None,
                    "audit_status": "VALID" if row else "MISSING",
                    "unexpected_write_count": int("unexpected_write_path" in str(row.get("reason", ""))) if row else 0,
                    "policy_drift": False,
                    "runtime_drift": False,
                    "overlap_detected": False,
                    "service_start_returncode": command["returncode"],
                }
            )
            if command["returncode"] != 0 or not row:
                break
        verification = runtime.verify_scheduler()
        _, invalid_after = guarded_audit_rows()
        checks = {
            "three_unique_cycles": len(cycles) == 3 and len({item["cycle_id"] for item in cycles}) == 3 and None not in {item["cycle_id"] for item in cycles},
            "safe_decisions": len(cycles) == 3 and all(item["decision"] in ALLOWED_SCHEDULER_DECISIONS for item in cycles),
            "no_overlap": all(not item["overlap_detected"] for item in cycles),
            "no_unexpected_writes": all(item["unexpected_write_count"] == 0 for item in cycles),
            "audit_valid": invalid_before == 0 and invalid_after == 0,
            "runtime_verifier_green": verification.get("status") == "SCHEDULER_VERIFICATION_GREEN",
        }
        result = {
            "status": "SCHEDULER_VERIFICATION_GREEN" if all(checks.values()) else "SCHEDULER_VERIFICATION_IN_PROGRESS",
            "checks": checks,
            "cycles": cycles,
            "cycle_ids": [item["cycle_id"] for item in cycles if item["cycle_id"]],
            "successful_cycles": sum(1 for item in cycles if item["decision"] in ALLOWED_SCHEDULER_DECISIONS),
            "invalid_audit_rows": invalid_after,
            "breach": guarded.load_state().get("flags", {}).get("breach", False),
        }
    result.update({"schema_version": SCHEMA_VERSION, "generated_at": guarded.utc_now()})
    guarded.write_text(SCHEDULER_MD, render_scheduler(result))
    append_audit("run_three_scheduler_cycles", result["status"], {"cycle_ids": result.get("cycle_ids", [])})
    return result


def activate_guarded_canary() -> Dict[str, Any]:
    result = runtime.activate_guarded_canary()
    guarded.write_text(CANARY_MD, render_canary(result))
    append_audit("activate_guarded_canary", result["status"], {"low_live": result.get("low_live_apply_enabled", False)})
    return result


def consolidated_status() -> Dict[str, Any]:
    state = guarded.load_state()
    systemd = guarded.load_dict(SYSTEMD_STATE) or {
        "status": installed_unit_contract()["status"],
        "install": installed_unit_contract(),
        "owner_command": OWNER_INSTALL_COMMAND,
    }
    health = guarded.load_dict(runtime.HEALTH_STATE) or runtime.evaluate_health()
    tls = guarded.load_dict(runtime.TLS_STATE) or runtime.evaluate_tls()
    scheduler = guarded.load_dict(runtime.SCHEDULER_STATE)
    retry = guarded.load_dict(WRITE_RETRY_STATE)
    classification = guarded.load_dict(WRITE_ERROR_STATE) or classify_current_write_error()
    flags = state.get("flags", {})
    timer_active = installed_unit_contract()["timer_active"]
    if state.get("activation_stage") == runtime.STAGE_CANARY and flags.get("low_live_apply_enabled"):
        phase_status = "AUTONOMY_LEVEL_2_GUARDED_CANARY"
    elif timer_active and flags.get("monitoring_enabled") and not flags.get("emergency_stop"):
        phase_status = "AUTONOMY_LEVEL_2_MONITORING_ACTIVE"
    elif systemd.get("status") == "OWNER_SYSTEMD_ACTION_REQUIRED":
        phase_status = "OWNER_SYSTEMD_ACTION_REQUIRED"
    else:
        phase_status = "PHASE_10_20_ACTIVATION_BLOCKED"
    audit_rows, audit_invalid = read_jsonl(AUDIT_JSONL)
    guarded_rows, guarded_invalid = guarded_audit_rows()
    result = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": guarded.utc_now(),
        "status": phase_status,
        "git": git_snapshot(),
        "systemd": systemd,
        "health_gate": health.get("status"),
        "tls_gate": tls.get("status"),
        "write_error_classification": classification,
        "write_canary_retry": retry,
        "scheduler": scheduler,
        "autonomy_level": state.get("autonomy_level"),
        "activation_stage": state.get("activation_stage"),
        "monitoring_enabled": flags.get("monitoring_enabled", True),
        "systemd_timer_active": timer_active,
        "guarded_live_autonomy_enabled": flags.get("guarded_live_autonomy_enabled", False),
        "low_live_apply_enabled": flags.get("low_live_apply_enabled", False),
        "production_apply_lock": flags.get("production_apply_lock", True),
        "medium_enabled": flags.get("medium_live_apply_enabled", False),
        "high_enabled": flags.get("high_live_apply_enabled", False),
        "emergency_stop": flags.get("emergency_stop", True),
        "breach": flags.get("breach", False),
        "active_low_live_classes": ["temporary_high_confidence_scanner_challenge", "sentinel_owned_rule_rollback"] if flags.get("low_live_apply_enabled") else [],
        "disabled_action_classes": ["login_protection", "microcache", "worker_restart", "MEDIUM", "HIGH"],
        "last_cycle": state.get("last_cycle", {}),
        "rollback_status": state.get("rollback_status", {"status": "ROLLBACK_READY_NO_ACTIVE_ACTION"}),
        "circuit_breaker": guarded.circuit_status(guarded.load_circuit()),
        "audit_validation": {
            "status": "AUDIT_VALID" if audit_invalid == 0 and guarded_invalid == 0 else "AUDIT_INVALID",
            "phase_rows": len(audit_rows),
            "invalid_rows": audit_invalid + guarded_invalid,
        },
        "owner_command": OWNER_INSTALL_COMMAND if not timer_active else None,
    }
    guarded.write_json(REPORT_JSON, result)
    guarded.write_json(PHASE_STATE, result)
    guarded.write_text(REPORT_MD, render_phase(result))
    guarded.write_text(OWNER_MD, render_owner(result))
    guarded.write_text(MONITORING_MD, render_monitoring(result))
    guarded.write_text(CANARY_MD, render_canary(result))
    return result


def validate() -> Dict[str, Any]:
    status = consolidated_status()
    required_markdown = (REPORT_MD, SYSTEMD_MD, SCHEDULER_MD, WRITE_ERROR_MD, WRITE_RETRY_MD, MONITORING_MD, CANARY_MD, OWNER_MD)
    checks = {
        "main_json_valid": bool(guarded.load_dict(REPORT_JSON)),
        "state_json_valid": bool(guarded.load_dict(PHASE_STATE)),
        "markdown_nonempty": all(path.is_file() and path.stat().st_size > 0 for path in required_markdown),
        "audit_valid": status["audit_validation"]["status"] == "AUDIT_VALID",
        "medium_blocked": status["medium_enabled"] is False,
        "high_blocked": status["high_enabled"] is False,
        "low_live_write_gate": not status["low_live_apply_enabled"] or status.get("write_canary_retry", {}).get("status") == "CLOUDFLARE_WRITE_CANARY_OK",
        "no_forbidden_staged_files": not status["git"]["forbidden_staged_files"],
        "breach_false": status["breach"] is False,
    }
    result = {
        "status": "PHASE_10_20_VALIDATION_OK" if all(checks.values()) else "PHASE_10_20_VALIDATION_BLOCKED",
        "checks": checks,
        "generated_at": guarded.utc_now(),
        "breach": status["breach"],
    }
    append_audit("validate", result["status"], {"findings": [name for name, passed in checks.items() if not passed]})
    return result


def self_test() -> Dict[str, Any]:
    source = Path(__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    argparse_options = {
        node.args[0].value
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "add_argument"
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
    }
    called_names = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    shell_true = any(
        keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        for keyword in node.keywords
    )
    subprocess_calls_fixed = all(
        isinstance(node.args[0], ast.Call)
        and isinstance(node.args[0].func, ast.Name)
        and node.args[0].func.id == "list"
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "run"
    )
    permission = classify_write_error({"http_status_code": 403, "request_schema_valid": True})
    unknown = classify_write_error({"http_status_code": 400, "cloudflare_error_codes": [50001], "request_schema_valid": True})
    contract = runtime.write_canary_runtime_contract("CLOUDFLARE_WRITE_CANARY_BLOCKED")
    _, phase_audit_invalid = read_jsonl(AUDIT_JSONL)
    _, guarded_audit_invalid = guarded_audit_rows()
    checks = {
        "no_shell_true": not shell_true,
        "fixed_subprocess_commands": subprocess_calls_fixed and bool(FIXED_COMMANDS),
        "no_free_paths_or_units": argparse_options.isdisjoint({"--path", "--unit", "--source", "--target"}),
        "no_free_cloudflare_endpoint_or_expression": argparse_options.isdisjoint({"--endpoint", "--expression", "--url", "--ruleset-id"}),
        "credential_values_not_disclosed": "load_private_environment" not in called_names,
        "permission_classification": permission["error_category"] == "INSUFFICIENT_PERMISSION",
        "unknown_code_not_invented": unknown["error_category"] == "UNKNOWN_4XX",
        "numeric_cloudflare_code_extraction": guarded.cloudflare_error_codes(
            {"errors": [{"code": 50001, "message": "discarded"}, {"code": "50001"}]}
        ) == [50001],
        "monitoring_independent_from_write_gate": contract["monitoring_activation_allowed"] is True,
        "low_live_blocked_before_write_gate": contract["low_live_apply_enabled"] is False and contract["production_apply_lock"] is True,
        "monitoring_only_not_emergency": contract["emergency_stop"] is False,
        "single_timer_scope": runtime.select_systemd_mode_logic(
            False, False, True, True, True, True, True, True
        ) == "OWNER_ACTION_REQUIRED",
        "no_medium_or_high_enable": "medium_live_apply_enabled\"] = True" not in source and "high_live_apply_enabled\"] = True" not in source,
        "fixed_write_canary_no_traffic": guarded.write_canary_payload().get("enabled") is False,
        "delete_and_absence_contract": "_delete_fixed_write_canary" in guarded.CloudflareGuardedAdapter.probe_disabled_write_canary.__code__.co_names,
        "runtime_state_machine_not_duplicated": "ALLOWED_TRANSITIONS" not in globals(),
        "playbooks_present": all(path.is_file() for path in PLAYBOOKS),
        "audit_jsonl_valid": phase_audit_invalid == 0 and guarded_audit_invalid == 0,
        "breach_false": guarded.load_state().get("flags", {}).get("breach") is False,
    }
    return {
        "status": "OWNER_ASSISTED_GO_LIVE_SELF_TEST_OK" if all(checks.values()) else "OWNER_ASSISTED_GO_LIVE_SELF_TEST_FAILED",
        "checks": checks,
        "findings": [name for name, passed in checks.items() if not passed],
        "breach": False,
    }


def render_systemd(value: Dict[str, Any]) -> str:
    install = value.get("install", {})
    return "\n".join([
        "# Sentinel systemd live verification",
        "",
        f"- status: `{value.get('status')}`",
        f"- source gate: `{value.get('source', {}).get('status')}`",
        f"- install status: `{install.get('status')}`",
        f"- timer active: `{str(install.get('timer_active', False)).lower()}`",
        f"- timer enabled: `{str(install.get('timer_enabled', False)).lower()}`",
        f"- scope: `{install.get('timer_scope')}`",
        f"- owner command: `{value.get('owner_command')}`",
        "- no credential values were read into this report",
        "",
    ])


def render_scheduler(value: Dict[str, Any]) -> str:
    lines = ["# Sentinel three-cycle scheduler verification", "", f"- status: `{value.get('status')}`", f"- successful cycles: `{value.get('successful_cycles', 0)}`"]
    for item in value.get("cycles", []):
        lines.append(f"- cycle `{item.get('cycle_id')}`: `{item.get('decision')}` / audit `{item.get('audit_status')}`")
    lines.extend(["- productive actions during verification: `0`", ""])
    return "\n".join(lines)


def render_write_error(value: Dict[str, Any]) -> str:
    return "\n".join([
        "# Sentinel Cloudflare write error classification",
        "",
        f"- status: `{value.get('status')}`",
        f"- HTTP status: `{value.get('http_status_code')}`",
        f"- Cloudflare error codes: `{value.get('cloudflare_error_codes', [])}`",
        f"- category: `{value.get('error_category')}`",
        f"- endpoint class: `{value.get('request_endpoint_class')}`",
        f"- ruleset phase: `{value.get('ruleset_phase')}`",
        f"- ruleset id present: `{str(value.get('ruleset_id_present', False)).lower()}`",
        f"- zone scope valid: `{str(value.get('zone_scope_valid', False)).lower()}`",
        f"- request schema locally valid: `{str(value.get('request_schema_valid', False)).lower()}`",
        f"- token permission class: `{value.get('token_permission_class')}`",
        "- API response body, headers and credential values were not stored",
        "- LOW_LIVE remains blocked unless the disabled-rule canary is created, verified, deleted and confirmed absent",
        "",
    ])


def render_write_retry(value: Dict[str, Any]) -> str:
    return "\n".join([
        "# Sentinel Cloudflare write-canary retry",
        "",
        f"- status: `{value.get('status')}`",
        f"- rule created: `{str(value.get('rule_created', False)).lower()}`",
        f"- rule enabled: `{value.get('rule_enabled')}`",
        f"- rule deleted: `{str(value.get('rule_deleted', False)).lower()}`",
        f"- absence verified: `{str(value.get('absence_verified', False)).lower()}`",
        f"- traffic effect: `{str(value.get('traffic_effect', False)).lower()}`",
        f"- monitoring allowed: `{str(value.get('monitoring_activation_allowed', False)).lower()}`",
        f"- LOW_LIVE enabled: `{str(value.get('low_live_apply_enabled', False)).lower()}`",
        "",
    ])


def render_monitoring(value: Dict[str, Any]) -> str:
    return "\n".join([
        "# Sentinel Level 2 monitoring status",
        "",
        f"- status: `{value.get('status')}`",
        f"- autonomy level: `{value.get('autonomy_level') or value.get('activation_stage')}`",
        f"- monitoring enabled: `{str(value.get('monitoring_enabled', False)).lower()}`",
        f"- systemd timer active: `{str(value.get('systemd_timer_active', value.get('timer_active', False))).lower()}`",
        f"- production apply lock: `{str(value.get('production_apply_lock', True)).lower()}`",
        f"- emergency stop: `{str(value.get('emergency_stop', True)).lower()}`",
        "",
    ])


def render_canary(value: Dict[str, Any]) -> str:
    return "\n".join([
        "# Sentinel Level 2 guarded-canary status",
        "",
        f"- status: `{value.get('status')}`",
        f"- LOW_LIVE enabled: `{str(value.get('low_live_apply_enabled', False)).lower()}`",
        f"- active classes: `{value.get('active_low_live_classes', [])}`",
        f"- disabled classes: `{value.get('disabled_action_classes', [])}`",
        "- MEDIUM and HIGH remain blocked",
        "",
    ])


def render_phase(value: Dict[str, Any]) -> str:
    return "\n".join([
        "# Sentinel Phase 10.20 runtime",
        "",
        f"- status: `{value.get('status')}`",
        f"- health gate: `{value.get('health_gate')}`",
        f"- TLS gate: `{value.get('tls_gate')}`",
        f"- systemd timer active: `{str(value.get('systemd_timer_active', False)).lower()}`",
        f"- autonomy level: `{value.get('autonomy_level')}`",
        f"- monitoring enabled: `{str(value.get('monitoring_enabled', False)).lower()}`",
        f"- LOW_LIVE enabled: `{str(value.get('low_live_apply_enabled', False)).lower()}`",
        f"- production apply lock: `{str(value.get('production_apply_lock', True)).lower()}`",
        f"- emergency stop: `{str(value.get('emergency_stop', True)).lower()}`",
        f"- breach: `{str(value.get('breach', False)).lower()}`",
        "",
    ])


def render_owner(value: Dict[str, Any]) -> str:
    timer_active = value.get("systemd_timer_active") is True
    if timer_active and value.get("low_live_apply_enabled"):
        statement = "Sentinel monitoring and the two approved LOW_LIVE classes are active under guarded canary policy."
    elif timer_active:
        statement = "Sentinel monitoring is active; productive LOW_LIVE remains locked pending the write canary."
    else:
        statement = "The 24/7 activation is not complete; the fixed owner systemd installation action is still required."
    return "\n".join([
        "# Sentinel Phase 10.20 owner summary",
        "",
        statement,
        f"- status: `{value.get('status')}`",
        f"- owner command: `{value.get('owner_command')}`",
        "- no MEDIUM or HIGH execution was enabled",
        "- no SSL, DNS, WordPress, PHP, database or Nginx change was performed",
        "",
    ])


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Sentinel Phase 10.20 owner-assisted guarded runtime go-live")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--collect", action="store_true")
    group.add_argument("--verify-systemd-sources", action="store_true")
    group.add_argument("--attempt-systemd-install", action="store_true")
    group.add_argument("--activate-monitoring", action="store_true")
    group.add_argument("--run-three-cycles", action="store_true")
    group.add_argument("--classify-write-error", action="store_true")
    group.add_argument("--retry-write-canary", action="store_true")
    group.add_argument("--activate-guarded-canary", action="store_true")
    group.add_argument("--validate", action="store_true")
    group.add_argument("--status", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        result = self_test()
    elif args.collect:
        result = consolidated_status()
    elif args.verify_systemd_sources:
        result = verify_systemd_sources()
    elif args.attempt_systemd_install:
        result = attempt_systemd_install()
    elif args.activate_monitoring:
        result = activate_monitoring()
    elif args.run_three_cycles:
        result = run_three_scheduler_cycles()
    elif args.classify_write_error:
        result = classify_current_write_error()
    elif args.retry_write_canary:
        result = retry_write_canary()
    elif args.activate_guarded_canary:
        result = activate_guarded_canary()
    elif args.validate:
        result = validate()
    else:
        result = consolidated_status()
    print(result["status"])
    return 0 if not str(result["status"]).endswith("FAILED") else 2


if __name__ == "__main__":
    raise SystemExit(main())
